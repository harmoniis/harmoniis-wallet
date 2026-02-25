//! GPU mining backend using wgpu compute shaders.
//!
//! Supports range-based mining over the fixed 1M nonce space using dynamic
//! dispatch sizing and adapter capability limits.

use async_trait::async_trait;
use std::sync::atomic::Ordering;
use wgpu::util::DeviceExt;

use super::sha256::Sha256Midstate;
use super::work_unit::NonceTable;
use super::{
    choose_best_result, CancelFlag, MinerBackend, MiningChunkResult, MiningResult, NONCE_SPACE_SIZE,
};

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
/// [1] = nonce1_idx
/// [2] = nonce2_idx
/// [3..11] = hash (8 x u32, big-endian)
const RESULT_WORDS: usize = 11;
const RESULT_BUFFER_SIZE: u64 = (RESULT_WORDS * 4) as u64;

pub struct GpuMiner {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::ComputePipeline,
    bind_group_layout: wgpu::BindGroupLayout,
    nonce_buffer: wgpu::Buffer,
    adapter_name: String,
    adapter_backend: wgpu::Backend,
    max_dispatch_nonces: u32,
}

impl GpuMiner {
    /// Try to initialize the default high-performance adapter.
    pub async fn try_new() -> Option<Self> {
        let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
            backends: wgpu::Backends::all(),
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
        let nonce_data = nonce_table.as_u32_slice();
        let nonce_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("nonce_table"),
            contents: bytemuck::cast_slice(&nonce_data),
            usage: wgpu::BufferUsages::STORAGE,
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
            bind_group_layout,
            nonce_buffer,
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

    fn create_bind_group(
        &self,
        midstate: &Sha256Midstate,
        difficulty: u32,
        nonce_offset: u32,
        nonce_count: u32,
    ) -> (wgpu::BindGroup, wgpu::Buffer, wgpu::Buffer) {
        let mut input_data = [0u32; INPUT_WORDS];
        input_data[..8].copy_from_slice(midstate.state_words());
        input_data[8] = difficulty;
        input_data[9] = midstate.prefix_len as u32;
        input_data[10] = nonce_offset;
        input_data[11] = nonce_count;

        let input_buffer = self
            .device
            .create_buffer_init(&wgpu::util::BufferInitDescriptor {
                label: Some("input"),
                contents: bytemuck::cast_slice(&input_data),
                usage: wgpu::BufferUsages::STORAGE,
            });

        let result_buffer = self
            .device
            .create_buffer_init(&wgpu::util::BufferInitDescriptor {
                label: Some("result"),
                contents: &[0u8; RESULT_WORDS * 4],
                usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            });

        let staging_buffer = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("staging"),
            size: RESULT_BUFFER_SIZE,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("miner_bind_group"),
            layout: &self.bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: self.nonce_buffer.as_entire_binding(),
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

        (bind_group, result_buffer, staging_buffer)
    }

    async fn dispatch_range(
        &self,
        midstate: &Sha256Midstate,
        difficulty: u32,
        nonce_offset: u32,
        nonce_count: u32,
    ) -> anyhow::Result<Option<MiningResult>> {
        let (bind_group, result_buffer, staging_buffer) =
            self.create_bind_group(midstate, difficulty, nonce_offset, nonce_count);

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
            pass.set_bind_group(0, &bind_group, &[]);

            let num_workgroups = nonce_count.div_ceil(WORKGROUP_SIZE);
            pass.dispatch_workgroups(num_workgroups, 1, 1);
        }

        encoder.copy_buffer_to_buffer(&result_buffer, 0, &staging_buffer, 0, RESULT_BUFFER_SIZE);
        self.queue.submit(std::iter::once(encoder.finish()));

        let buffer_slice = staging_buffer.slice(..);
        let (tx, rx) = tokio::sync::oneshot::channel();
        buffer_slice.map_async(wgpu::MapMode::Read, move |result| {
            let _ = tx.send(result);
        });
        self.device.poll(wgpu::Maintain::Wait);
        rx.await??;

        let data = buffer_slice.get_mapped_range();
        let result_words: &[u32] = bytemuck::cast_slice(&data[..RESULT_BUFFER_SIZE as usize]);

        let best_difficulty = result_words[0];
        let out = if best_difficulty >= difficulty {
            let nonce1_idx = result_words[1] as u16;
            let nonce2_idx = result_words[2] as u16;

            let mut hash = [0u8; 32];
            for i in 0..8 {
                hash[i * 4..(i + 1) * 4].copy_from_slice(&result_words[3 + i].to_be_bytes());
            }

            Some(MiningResult {
                nonce1_idx,
                nonce2_idx,
                hash,
                difficulty_achieved: best_difficulty,
            })
        } else {
            None
        };

        drop(data);
        staging_buffer.unmap();
        Ok(out)
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

        let mut total_attempts = 0u64;
        let mut total_elapsed = 0.0f64;
        for _ in 0..8 {
            let chunk = self
                .mine_range(&midstate, &nonce_table, 256, 0, NONCE_SPACE_SIZE, None)
                .await?;
            total_attempts = total_attempts.saturating_add(chunk.attempted);
            total_elapsed += chunk.elapsed.as_secs_f64();
        }

        if total_elapsed <= 0.0 {
            return Ok(0.0);
        }
        Ok(total_attempts as f64 / total_elapsed)
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
        cancel: Option<CancelFlag>,
    ) -> anyhow::Result<MiningChunkResult> {
        let range_start = start_nonce.min(NONCE_SPACE_SIZE);
        let range_end = range_start
            .saturating_add(nonce_count)
            .min(NONCE_SPACE_SIZE);
        if range_start >= range_end {
            return Ok(MiningChunkResult::empty());
        }

        let started = std::time::Instant::now();
        let mut best: Option<MiningResult> = None;
        let mut attempted = 0u64;
        let mut cursor = range_start;

        while cursor < range_end {
            if let Some(flag) = cancel.as_ref() {
                if flag.load(Ordering::Relaxed) {
                    break;
                }
            }

            let remaining = range_end - cursor;
            let chunk_count = remaining.min(self.max_dispatch_nonces());
            if chunk_count == 0 {
                break;
            }

            let chunk_best = self
                .dispatch_range(midstate, difficulty, cursor, chunk_count)
                .await?;
            attempted += chunk_count as u64;
            best = choose_best_result(best, chunk_best);

            if best.is_some() {
                if let Some(flag) = cancel.as_ref() {
                    flag.store(true, Ordering::Relaxed);
                }
                break;
            }

            cursor = cursor.saturating_add(chunk_count);
        }

        Ok(MiningChunkResult {
            result: best,
            attempted,
            elapsed: started.elapsed(),
        })
    }
}
