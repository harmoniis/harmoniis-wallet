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

/// Identity that uniquely identifies a wgpu adapter across processes.
///
/// Uses PCI bus ID (e.g. "0000:01:00.0") as the primary physical device
/// key — unique per PCIe slot, provided by VK_EXT_pci_bus_info on all
/// modern Vulkan drivers (RADV, NVIDIA, ANV since 2018+).
///
/// Falls back to (vendor, device, backend) only on platforms without PCI
/// (Metal/macOS, mobile).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AdapterIdentity {
    pub vendor: u32,
    pub device: u32,
    pub backend: String,
    /// PCI bus address (e.g. "0000:01:00.0"). Empty on Metal/non-PCI.
    pub pci_bus: String,
}

impl AdapterIdentity {
    /// Extract identity from a wgpu AdapterInfo.
    pub fn from_info(info: &wgpu::AdapterInfo) -> Self {
        Self {
            vendor: info.vendor,
            device: info.device,
            backend: format!("{:?}", info.backend).to_lowercase(),
            pci_bus: info.device_pci_bus_id.trim().to_string(),
        }
    }

    /// Find the matching adapter from a list by identity.
    ///
    /// When PCI bus ID is available, matches on it (distinguishes identical
    /// cards in different PCIe slots). Falls back to vendor+device+backend
    /// on platforms without PCI bus info (Metal).
    pub fn find_matching(&self, adapters: Vec<wgpu::Adapter>) -> Option<wgpu::Adapter> {
        adapters.into_iter().find(|a| {
            let info = a.get_info();
            let backend_match = format!("{:?}", info.backend).to_lowercase() == self.backend;
            if !self.pci_bus.is_empty() {
                // PCI bus ID is the definitive physical device key.
                info.device_pci_bus_id.trim() == self.pci_bus && backend_match
            } else {
                // Fallback for Metal/non-PCI platforms.
                info.vendor == self.vendor && info.device == self.device && backend_match
            }
        })
    }

    /// Physical device key (ignores backend).
    ///
    /// Two backends (Vulkan + DX12) for the same GPU produce the same key.
    /// Uses PCI bus ID when available, falls back to vendor:device.
    pub fn device_key(&self) -> String {
        if !self.pci_bus.is_empty() {
            format!("pci:{}", self.pci_bus)
        } else if self.vendor != 0 || self.device != 0 {
            format!("dev:{}:{}", self.vendor, self.device)
        } else {
            format!("unknown:{}", self.backend)
        }
    }
}

/// Run a GPU pipeline probe for an adapter identified by vendor+device+backend.
///
/// This is called from the `--gpu-probe` subprocess.  It creates a device,
/// compiles the WGSL shader, and builds the compute pipeline.  If the GPU
/// driver segfaults (known AMD Vulkan bug on Polaris), the subprocess dies
/// and the parent skips that adapter.
pub async fn probe_adapter(identity: &AdapterIdentity) -> anyhow::Result<()> {
    let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
        backends: COMPUTE_BACKENDS,
        ..Default::default()
    });
    let adapters = instance.enumerate_adapters(COMPUTE_BACKENDS).await;
    let adapter = identity.find_matching(adapters).ok_or_else(|| {
        anyhow::anyhow!(
            "no adapter matches vendor={} device={} backend={} pci_bus={}",
            identity.vendor,
            identity.device,
            identity.backend,
            if identity.pci_bus.is_empty() {
                "(any)"
            } else {
                &identity.pci_bus
            },
        )
    })?;
    let _info = adapter.get_info();
    // Probe runs in a subprocess — keep quiet.
    let (device, _queue) = adapter
        .request_device(&wgpu::DeviceDescriptor {
            label: Some("probe"),
            required_features: wgpu::Features::empty(),
            required_limits: wgpu::Limits::downlevel_defaults(),
            ..Default::default()
        })
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
        immediate_size: 0,
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
    // Success — parent process will use this adapter.
    Ok(())
}

/// Probe an adapter by spawning the current binary with `gpu-probe`.
/// Returns `true` if the adapter is safe to use.
pub(crate) fn subprocess_probe(identity: &AdapterIdentity) -> bool {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "GPU probe: cannot find exe for {} ({}) — {e}",
                identity.backend, identity.vendor,
            );
            return false;
        }
    };
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("gpu-probe")
        .arg("--vendor")
        .arg(identity.vendor.to_string())
        .arg("--device")
        .arg(identity.device.to_string())
        .arg("--backend")
        .arg(&identity.backend);
    if !identity.pci_bus.is_empty() {
        cmd.arg("--pci-bus").arg(&identity.pci_bus);
    }
    let status = cmd
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let ok = match status {
        Ok(s) => s.success(),
        Err(e) => {
            eprintln!(
                "GPU probe: failed to spawn for {} ({}) — {e}",
                identity.backend, identity.vendor,
            );
            false
        }
    };
    if !ok {
        eprintln!(
            "GPU probe: adapter {} (vendor={:#x}, device={:#x}) failed — skipping",
            identity.backend, identity.vendor, identity.device,
        );
    }
    ok
}

/// Maximum work units batched per GPU in a single submit (matches CUDA MAX_BATCH).
const MAX_BATCH: usize = 8;

/// One slot = one concurrent dispatch with its own input/result/staging/bind_group.
struct BatchSlot {
    input_buffer: wgpu::Buffer,
    result_buffer: wgpu::Buffer,
    staging_buffer: wgpu::Buffer,
    bind_group: wgpu::BindGroup,
}

pub struct GpuMiner {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::ComputePipeline,
    slots: Vec<BatchSlot>,
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
        if let Ok(adapter) = preferred {
            let info = adapter.get_info();
            eprintln!(
                "GPU: preferred adapter: {} ({:?}, {:?})",
                info.name, info.backend, info.device_type
            );
            if let Some(miner) = Self::try_from_adapter(adapter).await {
                return Some(miner);
            }
        }

        // Fallback: scan all adapters and pick the first one we can open.
        let adapters = instance.enumerate_adapters(wgpu::Backends::all()).await;
        if adapters.is_empty() {
            eprintln!("GPU: no adapters visible to wgpu (enumerate_adapters returned 0)");
            return None;
        }
        eprintln!("GPU: scanning {} adapters for fallback...", adapters.len());
        for adapter in adapters {
            let info = adapter.get_info();
            eprintln!("GPU: trying {} ({:?})", info.name, info.backend);
            if let Some(miner) = Self::try_from_adapter(adapter).await {
                return Some(miner);
            }
        }

        eprintln!("GPU: no compatible adapter could be initialized");
        None
    }

    /// Try to initialize from a specific adapter.
    pub async fn try_from_adapter(adapter: wgpu::Adapter) -> Option<Self> {
        let info = adapter.get_info();
        if info.device_type == wgpu::DeviceType::Cpu {
            eprintln!("GPU: skipping CPU adapter: {}", info.name);
            return None;
        }

        let adapter_name = info.name.clone();
        eprintln!(
            "GPU: initializing {} ({:?}, vendor={:#x}, device={:#x})",
            adapter_name, info.backend, info.vendor, info.device,
        );

        let req_default = adapter
            .request_device(&wgpu::DeviceDescriptor {
                label: Some("webminer"),
                required_features: wgpu::Features::empty(),
                required_limits: wgpu::Limits::default(),
                ..Default::default()
            })
            .await;
        let (device, queue) = match req_default {
            Ok(ok) => ok,
            Err(err_default) => {
                eprintln!(
                    "GPU adapter '{}' failed default limits ({}), retrying with downlevel limits",
                    adapter_name, err_default
                );
                adapter
                    .request_device(&wgpu::DeviceDescriptor {
                        label: Some("webminer-downlevel"),
                        required_features: wgpu::Features::empty(),
                        required_limits: wgpu::Limits::downlevel_defaults(),
                        ..Default::default()
                    })
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
            immediate_size: 0,
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

        // Pre-allocate MAX_BATCH slots (input + result + staging + bind_group).
        // This enables mine_batch: encode N dispatches in one command buffer,
        // submit once, sync once — matching CUDA's batched sync-once pattern.
        let mut slots = Vec::with_capacity(MAX_BATCH);
        for i in 0..MAX_BATCH {
            let input_buffer = device.create_buffer(&wgpu::BufferDescriptor {
                label: Some(&format!("input_{i}")),
                size: (INPUT_WORDS * 4) as u64,
                usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });
            let result_buffer = device.create_buffer(&wgpu::BufferDescriptor {
                label: Some(&format!("result_{i}")),
                size: RESULT_BUFFER_SIZE,
                usage: wgpu::BufferUsages::STORAGE
                    | wgpu::BufferUsages::COPY_SRC
                    | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });
            let staging_buffer = device.create_buffer(&wgpu::BufferDescriptor {
                label: Some(&format!("staging_{i}")),
                size: RESULT_BUFFER_SIZE,
                usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });
            let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
                label: Some(&format!("bind_{i}")),
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
            slots.push(BatchSlot {
                input_buffer,
                result_buffer,
                staging_buffer,
                bind_group,
            });
        }

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
            slots,
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

    /// Mine a batch of midstates with ONE submit + ONE sync (matches CUDA
    /// mine_batch). All dispatches are encoded into a single command buffer.
    pub async fn mine_batch(
        &self,
        midstates: &[Sha256Midstate],
        difficulty: u32,
    ) -> anyhow::Result<Vec<MiningChunkResult>> {
        let batch_size = midstates.len().min(self.slots.len());
        if batch_size == 0 {
            return Ok(Vec::new());
        }

        // Phase 1: write inputs + clear results for all slots.
        for (i, midstate) in midstates[..batch_size].iter().enumerate() {
            let slot = &self.slots[i];
            let mut input_data = [0u32; INPUT_WORDS];
            input_data[..8].copy_from_slice(midstate.state_words());
            input_data[8] = difficulty;
            input_data[9] = midstate.prefix_len as u32;
            input_data[10] = 0; // nonce_offset
            input_data[11] = NONCE_SPACE_SIZE; // nonce_count
            self.queue
                .write_buffer(&slot.input_buffer, 0, bytemuck::cast_slice(&input_data));
            self.queue
                .write_buffer(&slot.result_buffer, 0, &[0u8; RESULT_WORDS * 4]);
        }

        // Phase 2: encode ALL dispatches + copies in ONE command buffer.
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("batch_encoder"),
            });

        let num_workgroups = NONCE_SPACE_SIZE.div_ceil(WORKGROUP_SIZE);
        for i in 0..batch_size {
            let slot = &self.slots[i];
            {
                let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                    label: None,
                    timestamp_writes: None,
                });
                pass.set_pipeline(&self.pipeline);
                pass.set_bind_group(0, &slot.bind_group, &[]);
                pass.dispatch_workgroups(num_workgroups, 1, 1);
            }
            encoder.copy_buffer_to_buffer(
                &slot.result_buffer,
                0,
                &slot.staging_buffer,
                0,
                RESULT_BUFFER_SIZE,
            );
        }

        // Phase 3: ONE submit, ONE sync.
        let submission = self.queue.submit(std::iter::once(encoder.finish()));

        // Map all staging buffers for reading.
        let mut receivers = Vec::with_capacity(batch_size);
        for i in 0..batch_size {
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.slots[i]
                .staging_buffer
                .slice(..)
                .map_async(wgpu::MapMode::Read, move |result| {
                    let _ = tx.send(result);
                });
            receivers.push(rx);
        }
        let _ = self.device.poll(wgpu::PollType::Wait {
            submission_index: Some(submission),
            timeout: None,
        });

        // Phase 4: read all results.
        let started = std::time::Instant::now();
        let mut results = Vec::with_capacity(batch_size);
        for (i, rx) in receivers.into_iter().enumerate() {
            rx.await??;
            let data = self.slots[i].staging_buffer.slice(..).get_mapped_range();
            let words: &[u32] = bytemuck::cast_slice(&data[..RESULT_BUFFER_SIZE as usize]);
            let best_zeros = words[0];
            let nonce_id = words[1];
            drop(data);
            self.slots[i].staging_buffer.unmap();

            let result = self.verify_result(&midstates[i], difficulty, best_zeros, nonce_id);
            results.push(MiningChunkResult {
                result,
                attempted: NONCE_SPACE_SIZE as u64,
                elapsed: started.elapsed(),
            });
        }
        Ok(results)
    }

    fn verify_result(
        &self,
        midstate: &Sha256Midstate,
        difficulty: u32,
        best_zeros: u32,
        nonce_id: u32,
    ) -> Option<MiningResult> {
        if best_zeros < difficulty || nonce_id >= NONCE_SPACE_SIZE {
            return None;
        }
        let n1 = (nonce_id / 1000) as usize;
        let n2 = (nonce_id % 1000) as usize;
        let state_words =
            midstate.finalize_words_from_nonce_u32(self.nonce_words[n1], self.nonce_words[n2]);
        let achieved = leading_zero_bits_words(&state_words);
        if achieved < difficulty {
            return None;
        }
        Some(MiningResult {
            nonce1_idx: n1 as u16,
            nonce2_idx: n2 as u16,
            hash: state_words_to_bytes(&state_words),
            difficulty_achieved: achieved,
        })
    }

    async fn dispatch_range(
        &self,
        midstate: &Sha256Midstate,
        difficulty: u32,
        nonce_offset: u32,
        nonce_count: u32,
    ) -> anyhow::Result<Option<MiningResult>> {
        let slot = &self.slots[0];
        let mut input_data = [0u32; INPUT_WORDS];
        input_data[..8].copy_from_slice(midstate.state_words());
        input_data[8] = difficulty;
        input_data[9] = midstate.prefix_len as u32;
        input_data[10] = nonce_offset;
        input_data[11] = nonce_count;
        self.queue
            .write_buffer(&slot.input_buffer, 0, bytemuck::cast_slice(&input_data));
        self.queue
            .write_buffer(&slot.result_buffer, 0, &[0u8; RESULT_WORDS * 4]);

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
            pass.set_bind_group(0, &slot.bind_group, &[]);
            pass.dispatch_workgroups(nonce_count.div_ceil(WORKGROUP_SIZE), 1, 1);
        }
        encoder.copy_buffer_to_buffer(
            &slot.result_buffer,
            0,
            &slot.staging_buffer,
            0,
            RESULT_BUFFER_SIZE,
        );
        let submission = self.queue.submit(std::iter::once(encoder.finish()));

        let buffer_slice = slot.staging_buffer.slice(..);
        let (tx, rx) = tokio::sync::oneshot::channel();
        buffer_slice.map_async(wgpu::MapMode::Read, move |result| {
            let _ = tx.send(result);
        });
        let _ = self.device.poll(wgpu::PollType::Wait {
            submission_index: Some(submission),
            timeout: None,
        });
        rx.await??;

        let data = buffer_slice.get_mapped_range();
        let words: &[u32] = bytemuck::cast_slice(&data[..RESULT_BUFFER_SIZE as usize]);
        let best_zeros = words[0];
        let nonce_id = words[1];
        drop(data);
        slot.staging_buffer.unmap();

        Ok(self.verify_result(midstate, difficulty, best_zeros, nonce_id))
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

#[cfg(test)]
mod tests {
    use super::AdapterIdentity;

    #[test]
    fn device_key_same_physical_device_different_backends() {
        let vulkan = AdapterIdentity {
            vendor: 4098,
            device: 26591,
            backend: "vulkan".into(),
            pci_bus: "0000:01:00.0".into(),
        };
        let dx12 = AdapterIdentity {
            vendor: 4098,
            device: 26591,
            backend: "dx12".into(),
            pci_bus: "0000:01:00.0".into(),
        };
        assert_eq!(vulkan.device_key(), dx12.device_key());
    }

    #[test]
    fn device_key_distinguishes_identical_cards_by_pci_bus() {
        let gpu1 = AdapterIdentity {
            vendor: 4098,
            device: 26591,
            backend: "vulkan".into(),
            pci_bus: "0000:01:00.0".into(),
        };
        let gpu2 = AdapterIdentity {
            vendor: 4098,
            device: 26591,
            backend: "vulkan".into(),
            pci_bus: "0000:41:00.0".into(),
        };
        // Same model, different PCIe slots → different device keys.
        assert_ne!(gpu1.device_key(), gpu2.device_key());
    }

    #[test]
    fn device_key_same_card_different_backends() {
        let vulkan = AdapterIdentity {
            vendor: 4098,
            device: 26591,
            backend: "vulkan".into(),
            pci_bus: "0000:01:00.0".into(),
        };
        let dx12 = AdapterIdentity {
            vendor: 4098,
            device: 26591,
            backend: "dx12".into(),
            pci_bus: "0000:01:00.0".into(),
        };
        // Same PCI bus → same device key (regardless of backend).
        assert_eq!(vulkan.device_key(), dx12.device_key());
    }

    #[test]
    fn device_key_fallback_when_no_pci_bus() {
        let id = AdapterIdentity {
            vendor: 0,
            device: 0,
            backend: "metal".into(),
            pci_bus: String::new(),
        };
        assert!(id.device_key().starts_with("unknown:"));
    }
}
