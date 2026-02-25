//! GPU mining backend using wgpu compute shaders.
//!
//! Dispatches 1M threads on the GPU, each computing one SHA256 hash from midstate.
//! Uses WGSL shader with atomicMax for the best solution found.

use async_trait::async_trait;
use wgpu::util::DeviceExt;

use super::sha256::Sha256Midstate;
use super::work_unit::NonceTable;
use super::{MinerBackend, MiningResult};

/// Number of nonce combinations per dispatch (1000 × 1000).
const TOTAL_NONCES: u32 = 1_000_000;

/// Workgroup size (must match @workgroup_size in the WGSL shader).
const WORKGROUP_SIZE: u32 = 256;

/// Result buffer layout (u32 words):
/// [0] = best difficulty found (0 = no solution)
/// [1] = nonce1_idx
/// [2] = nonce2_idx
/// [3..11] = hash (8 × u32, big-endian)
const RESULT_BUFFER_SIZE: u64 = 11 * 4; // 11 u32s = 44 bytes

pub struct GpuMiner {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::ComputePipeline,
    bind_group_layout: wgpu::BindGroupLayout,
    adapter_name: String,
}

impl GpuMiner {
    /// Try to initialize a GPU miner. Returns None if no compatible GPU is found.
    pub async fn try_new() -> Option<Self> {
        let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
            backends: wgpu::Backends::all(),
            ..Default::default()
        });

        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                compatible_surface: None,
                force_fallback_adapter: false,
            })
            .await?;

        let adapter_name = adapter.get_info().name.clone();
        println!("GPU adapter: {} ({:?})", adapter_name, adapter.get_info().backend);

        let (device, queue) = adapter
            .request_device(
                &wgpu::DeviceDescriptor {
                    label: Some("webminer"),
                    required_features: wgpu::Features::empty(),
                    required_limits: wgpu::Limits::default(),
                    ..Default::default()
                },
                None,
            )
            .await
            .ok()?;

        // Load the WGSL shader
        let shader_source = include_str!("shader/sha256_mine.wgsl");
        let shader_module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("sha256_mine"),
            source: wgpu::ShaderSource::Wgsl(shader_source.into()),
        });

        // Bind group layout: 3 storage buffers
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
                // binding 1: input (midstate + difficulty, read-only storage)
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

        Some(GpuMiner {
            device,
            queue,
            pipeline,
            bind_group_layout,
            adapter_name,
        })
    }

    /// Create GPU buffers and bind group for a mining work unit.
    fn create_bind_group(
        &self,
        midstate: &Sha256Midstate,
        nonce_table: &NonceTable,
        difficulty: u32,
    ) -> (wgpu::BindGroup, wgpu::Buffer, wgpu::Buffer) {
        // Nonce table buffer: 1000 × u32
        let nonce_data = nonce_table.as_u32_slice();
        let nonce_buffer = self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("nonce_table"),
            contents: bytemuck::cast_slice(&nonce_data),
            usage: wgpu::BufferUsages::STORAGE,
        });

        // Input buffer: midstate (8 × u32) + difficulty (1 × u32) + prefix_len (1 × u32) = 10 × u32
        let mut input_data = [0u32; 10];
        input_data[..8].copy_from_slice(midstate.state_words());
        input_data[8] = difficulty;
        input_data[9] = midstate.prefix_len as u32;
        let input_buffer = self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("input"),
            contents: bytemuck::cast_slice(&input_data),
            usage: wgpu::BufferUsages::STORAGE,
        });

        // Result buffer: 11 × u32 (initialized to zero)
        let result_buffer = self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("result"),
            contents: &[0u8; 44], // 11 × 4
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
        });

        // Staging buffer for reading results back to CPU
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

        (bind_group, result_buffer, staging_buffer)
    }
}

#[async_trait]
impl MinerBackend for GpuMiner {
    fn name(&self) -> &str {
        &self.adapter_name
    }

    async fn benchmark(&self) -> anyhow::Result<f64> {
        let nonce_table = NonceTable::new();
        let midstate = Sha256Midstate::from_prefix(&[0u8; 64]);

        let start = std::time::Instant::now();

        // Run one full dispatch (1M hashes) for benchmark
        let _ = self
            .mine_work_unit(&midstate, &nonce_table, 256) // impossibly high difficulty
            .await?;

        let elapsed = start.elapsed().as_secs_f64();
        Ok(TOTAL_NONCES as f64 / elapsed)
    }

    async fn mine_work_unit(
        &self,
        midstate: &Sha256Midstate,
        nonce_table: &NonceTable,
        difficulty: u32,
    ) -> anyhow::Result<Option<MiningResult>> {
        let (bind_group, result_buffer, staging_buffer) =
            self.create_bind_group(midstate, nonce_table, difficulty);

        // Encode and submit compute pass
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

            let num_workgroups = (TOTAL_NONCES + WORKGROUP_SIZE - 1) / WORKGROUP_SIZE;
            pass.dispatch_workgroups(num_workgroups, 1, 1);
        }

        // Copy result to staging buffer
        encoder.copy_buffer_to_buffer(&result_buffer, 0, &staging_buffer, 0, RESULT_BUFFER_SIZE);

        self.queue.submit(std::iter::once(encoder.finish()));

        // Read back results
        let buffer_slice = staging_buffer.slice(..);
        let (tx, rx) = tokio::sync::oneshot::channel();
        buffer_slice.map_async(wgpu::MapMode::Read, move |result| {
            let _ = tx.send(result);
        });
        self.device.poll(wgpu::Maintain::Wait);
        rx.await??;

        let data = buffer_slice.get_mapped_range();
        let result_words: &[u32] =
            bytemuck::cast_slice(&data[..RESULT_BUFFER_SIZE as usize]);

        let best_difficulty = result_words[0];

        if best_difficulty >= difficulty {
            let nonce1_idx = result_words[1] as u16;
            let nonce2_idx = result_words[2] as u16;

            // Reconstruct hash from u32 words (big-endian)
            let mut hash = [0u8; 32];
            for i in 0..8 {
                hash[i * 4..(i + 1) * 4].copy_from_slice(&result_words[3 + i].to_be_bytes());
            }

            Ok(Some(MiningResult {
                nonce1_idx,
                nonce2_idx,
                hash,
                difficulty_achieved: best_difficulty,
            }))
        } else {
            Ok(None)
        }
    }
}
