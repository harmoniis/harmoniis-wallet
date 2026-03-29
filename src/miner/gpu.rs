//! GPU mining backend using wgpu compute shaders.
//!
//! Supports range-based mining over the fixed 1M nonce space using dynamic
//! dispatch sizing and adapter capability limits.
//!
//! The shader outputs only (best_difficulty, nonce_id).  The host re-computes
//! the full hash from the winning nonce to guarantee correctness — the same
//! approach used by the CUDA backend.

use async_trait::async_trait;
use wgpu::util::DeviceExt;

use super::sha256::{leading_zero_bits_words, state_words_to_bytes, Sha256Midstate};
use super::work_unit::NonceTable;
use super::{CancelFlag, MinerBackend, MiningChunkResult, MiningResult, NONCE_SPACE_SIZE};

/// Default workgroup size (must match `@workgroup_size` in shader).
const WORKGROUP_SIZE: u32 = 256;

/// Input buffer words:
/// [0..8] = midstate words
/// [8] = difficulty
/// [9] = prefix_len
/// [10] = nonce_offset
/// [11] = nonce_count
const INPUT_WORDS: usize = 12;

/// Result buffer words:
/// [0] = best difficulty found (0 = no valid solution)
/// [1] = flat nonce id of the winner
/// [2] = reserved
const RESULT_WORDS: usize = 3;
const RESULT_BUFFER_SIZE: u64 = (RESULT_WORDS * 4) as u64;

/// Backends used for compute — Vulkan (cross-platform primary), DX12 (Windows),
/// Metal (macOS).  OpenGL is excluded.
pub const COMPUTE_BACKENDS: wgpu::Backends = wgpu::Backends::VULKAN
    .union(wgpu::Backends::DX12)
    .union(wgpu::Backends::METAL);

/// Run a GPU pipeline probe for a specific adapter index.
///
/// This is called from the `--gpu-probe` subprocess.  It creates a device,
/// compiles the WGSL shader, and builds the compute pipeline.  If the GPU
/// driver segfaults (known AMD Vulkan bug on Polaris), the subprocess dies
/// and the parent skips that adapter.
pub async fn probe_adapter(adapter_idx: usize) -> anyhow::Result<()> {
    let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
        backends: COMPUTE_BACKENDS,
        ..Default::default()
    });
    let adapters = instance.enumerate_adapters(COMPUTE_BACKENDS);
    let adapter = adapters
        .into_iter()
        .nth(adapter_idx)
        .ok_or_else(|| anyhow::anyhow!("adapter index {adapter_idx} out of range"))?;
    let info = adapter.get_info();
    eprintln!(
        "[gpu-probe] testing adapter {adapter_idx}: {} ({:?})",
        info.name, info.backend
    );
    let (device, _queue) = adapter
        .request_device(
            &wgpu::DeviceDescriptor {
                label: Some("probe"),
                required_features: wgpu::Features::empty(),
                required_limits: wgpu::Limits::downlevel_defaults(),
                ..Default::default()
            },
            None,
        )
        .await
        .map_err(|e| anyhow::anyhow!("device request failed: {e}"))?;

    let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: Some("probe_shader"),
        source: wgpu::ShaderSource::Wgsl(include_str!("shader/sha256_mine.wgsl").into()),
    });

    let bgl = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
        label: None,
        entries: &[
            wgpu::BindGroupLayoutEntry {
                binding: 0,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            wgpu::BindGroupLayoutEntry {
                binding: 1,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            wgpu::BindGroupLayoutEntry {
                binding: 2,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: false },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
        ],
    });
    let pl = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
        label: None,
        bind_group_layouts: &[&bgl],
        push_constant_ranges: &[],
    });
    // This is the call that can segfault on buggy AMD Vulkan drivers.
    let _pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
        label: Some("probe_pipeline"),
        layout: Some(&pl),
        module: &shader,
        entry_point: Some("main"),
        compilation_options: Default::default(),
        cache: None,
    });
    eprintln!("[gpu-probe] adapter {adapter_idx} OK");
    Ok(())
}

/// Probe an adapter by spawning the current binary with `--gpu-probe`.
/// Returns `true` if the adapter is safe to use.
pub(crate) fn subprocess_probe(adapter_idx: usize) -> bool {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let status = std::process::Command::new(exe)
        .arg("gpu-probe")
        .arg("--adapter-idx")
        .arg(adapter_idx.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .status();
    match status {
        Ok(s) => s.success(),
        Err(_) => false,
    }
}

pub struct GpuMiner {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::ComputePipeline,
    bind_group: wgpu::BindGroup,
    input_buffer: wgpu::Buffer,
    result_buffer: wgpu::Buffer,
    nonce_words: Vec<u32>,
    adapter_name: String,
    adapter_backend: wgpu::Backend,
    max_dispatch_nonces: u32,
}

impl GpuMiner {
    /// Try to initialize the default high-performance adapter.
    pub async fn try_new() -> Option<Self> {
        let compute_backends = COMPUTE_BACKENDS;
        let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
            backends: compute_backends,
            ..Default::default()
        });

        // Fast path: ask wgpu for a high-performance adapter.
        let preferred = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                compatible_surface: None,
                force_fallback_adapter: false,
            })
            .await;
        if let Some(adapter) = preferred {
            if let Some(miner) = Self::try_from_adapter(adapter).await {
                return Some(miner);
            }
        }

        // Fallback: scan all adapters and pick the first one we can open.
        let adapters = instance.enumerate_adapters(wgpu::Backends::all());
        if adapters.is_empty() {
            eprintln!("No GPU adapters visible to wgpu (enumerate_adapters returned 0)");
            return None;
        }
        for adapter in adapters {
            if let Some(miner) = Self::try_from_adapter(adapter).await {
                return Some(miner);
            }
        }

        eprintln!("No compatible GPU adapter could be initialized");
        None
    }

    /// Try to initialize from a specific adapter.
    pub async fn try_from_adapter(adapter: wgpu::Adapter) -> Option<Self> {
        let info = adapter.get_info();
        if info.device_type == wgpu::DeviceType::Cpu {
            return None;
        }

        let adapter_name = info.name.clone();
        println!("GPU adapter: {} ({:?})", adapter_name, info.backend);

        let req_default = adapter
            .request_device(
                &wgpu::DeviceDescriptor {
                    label: Some("webminer"),
                    required_features: wgpu::Features::empty(),
                    required_limits: wgpu::Limits::default(),
                    ..Default::default()
                },
                None,
            )
            .await;
        let (device, queue) = match req_default {
            Ok(ok) => ok,
            Err(err_default) => {
                eprintln!(
                    "GPU adapter '{}' failed default limits ({}), retrying with downlevel limits",
                    adapter_name, err_default
                );
                adapter
                    .request_device(
                        &wgpu::DeviceDescriptor {
                            label: Some("webminer-downlevel"),
                            required_features: wgpu::Features::empty(),
                            required_limits: wgpu::Limits::downlevel_defaults(),
                            ..Default::default()
                        },
                        None,
                    )
                    .await
                    .ok()?
            }
        };

        let shader_source = include_str!("shader/sha256_mine.wgsl");
        let shader_module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("sha256_mine"),
            source: wgpu::ShaderSource::Wgsl(shader_source.into()),
        });

        let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("miner_bind_group_layout"),
            entries: &[
                // binding 0: nonce_table (read-only storage)
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                // binding 1: input (midstate + run params, read-only storage)
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                // binding 2: output (result buffer, read-write storage)
                wgpu::BindGroupLayoutEntry {
                    binding: 2,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
            ],
        });

        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("miner_pipeline_layout"),
            bind_group_layouts: &[&bind_group_layout],
            push_constant_ranges: &[],
        });

        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("sha256_mine_pipeline"),
            layout: Some(&pipeline_layout),
            module: &shader_module,
            entry_point: Some("main"),
            compilation_options: Default::default(),
            cache: None,
        });

        let nonce_table = NonceTable::new();
        let nonce_words = nonce_table.as_u32_slice();
        let nonce_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("nonce_table"),
            contents: bytemuck::cast_slice(&nonce_words),
            usage: wgpu::BufferUsages::STORAGE,
        });

        // Pre-allocate persistent input and result buffers (reused every dispatch).
        let input_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("input"),
            size: (INPUT_WORDS * 4) as u64,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let result_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("result"),
            size: RESULT_BUFFER_SIZE,
            usage: wgpu::BufferUsages::STORAGE
                | wgpu::BufferUsages::COPY_SRC
                | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("miner_bind_group"),
            layout: &bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: nonce_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: input_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: result_buffer.as_entire_binding(),
                },
            ],
        });

        let limits = device.limits();
        let max_dispatch_nonces = limits
            .max_compute_workgroups_per_dimension
            .max(1)
            .saturating_mul(WORKGROUP_SIZE)
            .max(WORKGROUP_SIZE);

        Some(GpuMiner {
            device,
            queue,
            pipeline,
            bind_group,
            input_buffer,
            result_buffer,
            nonce_words,
            adapter_name,
            adapter_backend: info.backend,
            max_dispatch_nonces,
        })
    }

    pub fn adapter_name(&self) -> &str {
        &self.adapter_name
    }

    pub fn max_dispatch_nonces(&self) -> u32 {
        self.max_dispatch_nonces
    }

    async fn dispatch_range(
        &self,
        midstate: &Sha256Midstate,
        difficulty: u32,
        nonce_offset: u32,
        nonce_count: u32,
    ) -> anyhow::Result<Option<MiningResult>> {
        // Write input params to pre-allocated buffer (no allocation).
        let mut input_data = [0u32; INPUT_WORDS];
        input_data[..8].copy_from_slice(midstate.state_words());
        input_data[8] = difficulty;
        input_data[9] = midstate.prefix_len as u32;
        input_data[10] = nonce_offset;
        input_data[11] = nonce_count;
        self.queue
            .write_buffer(&self.input_buffer, 0, bytemuck::cast_slice(&input_data));

        // Clear result buffer.
        self.queue
            .write_buffer(&self.result_buffer, 0, &[0u8; RESULT_WORDS * 4]);

        // Only the staging buffer needs per-dispatch creation (map/unmap cycle).
        let staging_buffer = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("staging"),
            size: RESULT_BUFFER_SIZE,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("miner_encoder"),
            });

        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("sha256_mine"),
                timestamp_writes: None,
            });
            pass.set_pipeline(&self.pipeline);
            pass.set_bind_group(0, &self.bind_group, &[]);

            let num_workgroups = nonce_count.div_ceil(WORKGROUP_SIZE);
            pass.dispatch_workgroups(num_workgroups, 1, 1);
        }

        encoder.copy_buffer_to_buffer(
            &self.result_buffer,
            0,
            &staging_buffer,
            0,
            RESULT_BUFFER_SIZE,
        );
        let submission = self.queue.submit(std::iter::once(encoder.finish()));

        let buffer_slice = staging_buffer.slice(..);
        let (tx, rx) = tokio::sync::oneshot::channel();
        buffer_slice.map_async(wgpu::MapMode::Read, move |result| {
            let _ = tx.send(result);
        });
        self.device
            .poll(wgpu::Maintain::WaitForSubmissionIndex(submission));
        rx.await??;

        let data = buffer_slice.get_mapped_range();
        let result_words: &[u32] = bytemuck::cast_slice(&data[..RESULT_BUFFER_SIZE as usize]);

        let best_zeros = result_words[0];
        let nonce_id = result_words[1];

        drop(data);
        staging_buffer.unmap();

        // Host-side re-verification (matches CUDA's best_result_from_packed):
        // re-compute hash from the nonce to guarantee correctness.
        if best_zeros < difficulty {
            return Ok(None);
        }
        if nonce_id >= NONCE_SPACE_SIZE {
            return Ok(None);
        }

        let n1 = (nonce_id / 1000) as usize;
        let n2 = (nonce_id % 1000) as usize;
        let state_words =
            midstate.finalize_words_from_nonce_u32(self.nonce_words[n1], self.nonce_words[n2]);
        let achieved = leading_zero_bits_words(&state_words);

        if achieved < difficulty {
            return Ok(None);
        }

        Ok(Some(MiningResult {
            nonce1_idx: n1 as u16,
            nonce2_idx: n2 as u16,
            hash: state_words_to_bytes(&state_words),
            difficulty_achieved: achieved,
        }))
    }
}

#[async_trait]
impl MinerBackend for GpuMiner {
    fn name(&self) -> &str {
        &self.adapter_name
    }

    fn startup_summary(&self) -> Vec<String> {
        vec![
            format!("gpu_name={}", self.adapter_name),
            format!("gpu_backend={:?}", self.adapter_backend),
            format!("workgroup_size={}", WORKGROUP_SIZE),
            format!("max_dispatch_nonces={}", self.max_dispatch_nonces),
        ]
    }

    async fn benchmark(&self) -> anyhow::Result<f64> {
        let nonce_table = NonceTable::new();
        let midstate = Sha256Midstate::from_prefix(&[0u8; 64]);

        // Warm up GPU pipeline/driver state.
        let _ = self
            .mine_range(&midstate, &nonce_table, 256, 0, NONCE_SPACE_SIZE, None)
            .await?;

        let mut samples = Vec::with_capacity(8);
        for _ in 0..8 {
            let chunk = self
                .mine_range(&midstate, &nonce_table, 256, 0, NONCE_SPACE_SIZE, None)
                .await?;
            let secs = chunk.elapsed.as_secs_f64();
            if secs > 0.0 {
                samples.push(chunk.attempted as f64 / secs);
            }
        }

        if samples.is_empty() {
            return Ok(0.0);
        }
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        Ok(samples[samples.len() / 2])
    }

    fn max_batch_hint(&self) -> u32 {
        NONCE_SPACE_SIZE
    }

    async fn mine_range(
        &self,
        midstate: &Sha256Midstate,
        _nonce_table: &NonceTable,
        difficulty: u32,
        start_nonce: u32,
        nonce_count: u32,
        _cancel: Option<CancelFlag>,
    ) -> anyhow::Result<MiningChunkResult> {
        let range_start = start_nonce.min(NONCE_SPACE_SIZE);
        let range_end = range_start
            .saturating_add(nonce_count)
            .min(NONCE_SPACE_SIZE);
        if range_start >= range_end {
            return Ok(MiningChunkResult::empty());
        }

        let started = std::time::Instant::now();
        // Single large dispatch for GPU stability (especially AMD consumer GPUs).
        let result = self
            .dispatch_range(midstate, difficulty, range_start, range_end - range_start)
            .await?;

        Ok(MiningChunkResult {
            result,
            attempted: (range_end - range_start) as u64,
            elapsed: started.elapsed(),
        })
    }
}
