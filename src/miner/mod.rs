//! Webcash mining engine with GPU (wgpu) and CPU (rayon) backends.
//!
//! Implements the midstate SHA256 optimization from the C++ webminer: the JSON
//! preimage prefix is padded to exactly one SHA256 block (64 bytes), the midstate
//! is computed once, and each nonce attempt processes a single additional block.

pub mod cloud;
pub mod collect;
pub mod composite;
pub mod cpu;
#[cfg(feature = "cuda")]
pub mod cuda;
#[cfg(feature = "cuda")]
pub mod cuda_detect;
pub mod daemon;
#[cfg(feature = "gpu")]
pub mod gpu;
#[cfg(feature = "cuda")]
pub mod multi_cuda;
#[cfg(feature = "gpu")]
pub mod multi_gpu;
#[cfg(feature = "cuda")]
pub mod persistent_cuda;
pub mod protocol;
pub mod sha256;
pub mod simd_cpu;
pub mod stats;
pub mod work_unit;

use async_trait::async_trait;
#[cfg(all(feature = "gpu", target_os = "windows"))]
use std::collections::HashSet;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use sha256::Sha256Midstate;
use work_unit::NonceTable;

/// The full nonce combination space: 1000 x 1000.
pub const NONCE_SPACE_SIZE: u32 = 1_000_000;

/// Shared cancellation flag for cooperative early exit across backends.
pub type CancelFlag = Arc<AtomicBool>;

/// Backend selection preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendChoice {
    /// Auto-detect fastest backend (GPU preferred).
    Auto,
    /// Force GPU only.
    Gpu,
    /// Force CPU only.
    Cpu,
}

impl BackendChoice {
    pub fn as_cli_str(self) -> &'static str {
        match self {
            BackendChoice::Auto => "auto",
            BackendChoice::Gpu => "gpu",
            BackendChoice::Cpu => "cpu",
        }
    }
}

/// Configuration for the miner daemon.
#[derive(Debug, Clone)]
pub struct MinerConfig {
    pub server_url: String,
    pub wallet_path: std::path::PathBuf,
    pub webcash_wallet_path: std::path::PathBuf,
    pub max_difficulty: u32,
    pub backend: BackendChoice,
    pub cpu_threads: Option<usize>,
    pub accept_terms: bool,
    /// Specific device IDs to mine on (from `list-devices`).  `None` = all GPUs.
    pub devices: Option<Vec<usize>>,
}

/// Result of finding a valid proof-of-work solution.
#[derive(Debug, Clone)]
pub struct MiningResult {
    /// Index into the nonce table for the first nonce (0..999).
    pub nonce1_idx: u16,
    /// Index into the nonce table for the second nonce (0..999).
    pub nonce2_idx: u16,
    /// The SHA256 hash that meets difficulty.
    pub hash: [u8; 32],
    /// Achieved difficulty (leading zero bits).
    pub difficulty_achieved: u32,
}

/// Output from mining one nonce range chunk.
#[derive(Debug, Clone)]
pub struct MiningChunkResult {
    pub result: Option<MiningResult>,
    pub attempted: u64,
    pub elapsed: Duration,
}

impl MiningChunkResult {
    pub fn empty() -> Self {
        MiningChunkResult {
            result: None,
            attempted: 0,
            elapsed: Duration::from_secs(0),
        }
    }
}

/// Trait abstracting GPU vs CPU mining backends.
#[async_trait]
pub trait MinerBackend: Send + Sync {
    /// Human-readable name of this backend.
    fn name(&self) -> &str;

    /// Startup diagnostics displayed before mining begins.
    fn startup_summary(&self) -> Vec<String> {
        Vec::new()
    }

    /// Run a quick benchmark and return estimated hashes per second.
    async fn benchmark(&self) -> anyhow::Result<f64>;

    /// Suggested nonce chunk size for one work unit.
    fn max_batch_hint(&self) -> u32 {
        NONCE_SPACE_SIZE
    }

    /// Suggested number of independent work units to mine in parallel.
    ///
    /// Backends with many physical devices (e.g. Multi-CUDA) can return >1
    /// to keep all devices busy with full nonce-space work units.
    fn recommended_pipeline_depth(&self) -> usize {
        1
    }

    /// Mine a nonce range [start_nonce, start_nonce + nonce_count).
    ///
    /// Backends should clamp to `NONCE_SPACE_SIZE`.
    async fn mine_range(
        &self,
        midstate: &Sha256Midstate,
        nonce_table: &NonceTable,
        difficulty: u32,
        start_nonce: u32,
        nonce_count: u32,
        cancel: Option<CancelFlag>,
    ) -> anyhow::Result<MiningChunkResult>;

    /// Mine multiple independent work units.
    ///
    /// Default behavior mines them sequentially. High-throughput backends can
    /// override this to run them concurrently.
    async fn mine_work_units(
        &self,
        midstates: &[Sha256Midstate],
        nonce_table: &NonceTable,
        difficulty: u32,
        cancel: Option<CancelFlag>,
    ) -> anyhow::Result<Vec<MiningChunkResult>> {
        let mut out = Vec::with_capacity(midstates.len());
        for midstate in midstates {
            out.push(
                self.mine_range(
                    midstate,
                    nonce_table,
                    difficulty,
                    0,
                    NONCE_SPACE_SIZE,
                    cancel.clone(),
                )
                .await?,
            );
        }
        Ok(out)
    }

    /// Mine a single work unit (1M nonce combinations from a midstate).
    ///
    /// Returns `Some(result)` if a solution meeting `difficulty` is found.
    async fn mine_work_unit(
        &self,
        midstate: &Sha256Midstate,
        nonce_table: &NonceTable,
        difficulty: u32,
    ) -> anyhow::Result<MiningChunkResult> {
        self.mine_range(midstate, nonce_table, difficulty, 0, NONCE_SPACE_SIZE, None)
            .await
    }
}

pub fn choose_best_result(
    a: Option<MiningResult>,
    b: Option<MiningResult>,
) -> Option<MiningResult> {
    match (a, b) {
        (None, None) => None,
        (Some(x), None) => Some(x),
        (None, Some(y)) => Some(y),
        (Some(x), Some(y)) => {
            if y.difficulty_achieved > x.difficulty_achieved {
                Some(y)
            } else {
                Some(x)
            }
        }
    }
}

/// Split a nonce range across devices proportionally to their hash-rate weights.
///
/// Shared by both `MultiGpuMiner` and `MultiCudaMiner`.
pub(crate) fn split_assignments_for_weights(
    weights: &[f64],
    start_nonce: u32,
    nonce_count: u32,
) -> Vec<(usize, u32, u32)> {
    if weights.is_empty() {
        return Vec::new();
    }

    let start = start_nonce.min(NONCE_SPACE_SIZE);
    let end = start.saturating_add(nonce_count).min(NONCE_SPACE_SIZE);
    if start >= end {
        return Vec::new();
    }

    let total = end - start;
    let weight_sum = weights.iter().sum::<f64>().max(1.0);

    let mut assignments = Vec::with_capacity(weights.len());
    let mut assigned = 0u32;

    for idx in 0..weights.len() {
        let remaining = total.saturating_sub(assigned);
        if remaining == 0 {
            break;
        }

        let chunk = if idx == weights.len() - 1 {
            remaining
        } else {
            let ideal = ((total as f64) * (weights[idx] / weight_sum)).round() as u32;
            ideal.clamp(1, remaining)
        };

        assignments.push((idx, start + assigned, chunk));
        assigned = assigned.saturating_add(chunk);
    }

    assignments
}

/// Query CUDA device count, suppressing cudarc's panic when CUDA DLLs are missing.
#[cfg(feature = "cuda")]
fn cuda_device_count() -> usize {
    cuda_detect::ensure_cuda_libraries();

    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let n = std::panic::catch_unwind(|| cudarc::driver::CudaContext::device_count())
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or(0) as usize;
    std::panic::set_hook(prev);
    n
}

// ---------------------------------------------------------------------------
// Unified device discovery
// ---------------------------------------------------------------------------

/// What kind of GPU device this is.  CPU is not a device — it has its own
/// `--cpu-threads` option and is never mixed with GPU mining.
#[derive(Debug, Clone)]
pub enum DeviceKind {
    #[cfg(feature = "cuda")]
    Cuda { ordinal: usize },
    /// One physical GPU on the chosen backend. `adapter_index` is the
    /// position in `EnumeratedDevices::wgpu_adapters` — used to consume
    /// the adapter handle without re-enumerating.
    #[cfg(feature = "gpu")]
    Wgpu {
        adapter: gpu::AdapterIdentity,
        adapter_index: usize,
    },
}

/// Result of `enumerate_all_devices()`.  Carries adapter handles alongside
/// device metadata so callers can consume adapters directly without
/// re-enumerating (eliminates identity-matching bugs on DX12).
pub struct EnumeratedDevices {
    pub devices: Vec<DeviceInfo>,
    #[cfg(feature = "gpu")]
    pub wgpu_adapters: Vec<wgpu::Adapter>,
}

/// One entry in the device list = one physical GPU.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub id: usize,
    pub label: String,
    pub kind: DeviceKind,
}

/// Enumerate all physical GPU devices across all backends.
///
/// CUDA: one ordinal = one physical GPU.
/// wgpu: pick the single best backend (DX12 on Windows, Metal on macOS,
/// Vulkan on Linux), then each adapter on that backend = one physical GPU.
///
/// Adapter handles are returned in `EnumeratedDevices::wgpu_adapters` so
/// callers can consume them directly without re-enumerating.
///
/// Order: CUDA devices first, then wgpu devices.
pub async fn enumerate_all_devices() -> EnumeratedDevices {
    let mut devices = Vec::new();
    #[allow(unused_mut, unused_variables)]
    let mut next_id = 0usize;

    // 1. CUDA devices — one ordinal = one physical NVIDIA GPU.
    #[cfg(feature = "cuda")]
    {
        let cuda_count = cuda_device_count();
        for ordinal in 0..cuda_count {
            let name = cudarc::driver::CudaContext::new(ordinal)
                .ok()
                .and_then(|ctx| ctx.name().ok())
                .unwrap_or_else(|| format!("CUDA device {ordinal}"));
            devices.push(DeviceInfo {
                id: next_id,
                label: format!("{name} (CUDA)"),
                kind: DeviceKind::Cuda { ordinal },
            });
            next_id += 1;
        }
    }

    // 2. wgpu — one backend per platform, each adapter = one physical GPU.
    //
    // On Windows DX12: wgpu-hal's get_adapter_pci_info() matches SetupDi by
    // vendor+device and returns the FIRST hit, so identical GPUs all report
    // the same PCI bus ID.  DXGI EnumAdapters1 can also return duplicates or
    // collapse identical headless cards.  When duplicate PCI bus IDs are
    // detected, we probe Vulkan for the true physical GPU topology and either
    // trim DX12 duplicates or add Vulkan adapters for headless GPUs that DX12
    // cannot see.
    #[cfg(feature = "gpu")]
    let wgpu_adapters = {
        let backend = gpu::platform_backend();
        let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
            backends: backend,
            ..Default::default()
        });
        let raw = instance.enumerate_adapters(backend).await;
        #[allow(unused_mut)]
        let mut adapters: Vec<wgpu::Adapter> = raw
            .into_iter()
            .filter(|a| a.get_info().device_type != wgpu::DeviceType::Cpu)
            .collect();

        // --- Windows DX12: cross-reference with Vulkan probe ---
        #[cfg(target_os = "windows")]
        {
            let dx_buses: Vec<String> = adapters
                .iter()
                .map(|a| a.get_info().device_pci_bus_id.trim().to_string())
                .collect();
            let unique_buses: HashSet<&str> = dx_buses.iter().map(|s| s.as_str()).collect();
            let has_dup_buses = unique_buses.len() < dx_buses.len() && adapters.len() > 1;

            if has_dup_buses || adapters.is_empty() {
                // DX12 returned duplicate PCI bus IDs (impossible for distinct
                // physical GPUs) or found no adapters.  Ask Vulkan for truth.
                if let Some(vk_adapters) = gpu::enumerate_vulkan_gpus().await {
                    let vk_count = vk_adapters.len();
                    let dx_count = adapters.len();

                    if dx_count > vk_count {
                        // More DX12 adapters than physical GPUs → duplicates.
                        eprintln!(
                            "GPU: DX12 enumerated {} adapters but Vulkan found {} physical \
                             GPUs — trimming DX12 duplicates",
                            dx_count, vk_count,
                        );
                        adapters.truncate(vk_count);
                    } else if dx_count < vk_count {
                        // DX12 missed headless GPUs. Add Vulkan adapters for them.
                        eprintln!(
                            "GPU: DX12 found {} adapters, Vulkan found {} physical GPUs — \
                             adding {} headless via Vulkan",
                            dx_count,
                            vk_count,
                            vk_count - dx_count,
                        );
                        let dx_bus_set: HashSet<String> = adapters
                            .iter()
                            .map(|a| a.get_info().device_pci_bus_id.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        for vk_a in vk_adapters {
                            let bus = vk_a.get_info().device_pci_bus_id.trim().to_string();
                            if !bus.is_empty() && !dx_bus_set.contains(&bus) {
                                adapters.push(vk_a);
                                if adapters.len() >= vk_count {
                                    break;
                                }
                            }
                        }
                    } else if has_dup_buses {
                        // Same count but DX12 has duplicate bus IDs.  The DX12
                        // adapters are likely N copies of one GPU while Vulkan
                        // found N distinct GPUs.  Replace with Vulkan adapters
                        // which are guaranteed unique (VK_EXT_pci_bus_info).
                        eprintln!(
                            "GPU: DX12 adapters share PCI bus IDs (wgpu-hal SetupDi \
                             first-match bug) — switching to Vulkan adapters for \
                             reliable multi-GPU ({} devices)",
                            vk_count,
                        );
                        adapters = vk_adapters;
                    }
                }
            }
        }

        let mut kept = Vec::new();
        for adapter in adapters {
            let info = adapter.get_info();
            let identity = gpu::AdapterIdentity::from_info(&info);
            let adapter_index = kept.len();
            eprintln!(
                "GPU:   [{}] {} ({}) pci_bus={}",
                next_id,
                identity.name,
                identity.backend,
                if identity.pci_bus.is_empty() {
                    "(none)"
                } else {
                    &identity.pci_bus
                },
            );
            devices.push(DeviceInfo {
                id: next_id,
                label: identity.name.clone(),
                kind: DeviceKind::Wgpu {
                    adapter: identity,
                    adapter_index,
                },
            });
            kept.push(adapter);
            next_id += 1;
        }
        kept
    };

    EnumeratedDevices {
        devices,
        #[cfg(feature = "gpu")]
        wgpu_adapters,
    }
}

/// Create a mining backend for specific GPU device IDs.
///
/// Adapters are consumed from `EnumeratedDevices` by index — no
/// re-enumeration needed.
pub async fn select_backend_for_devices(
    device_ids: &[usize],
) -> anyhow::Result<Box<dyn MinerBackend>> {
    let enumerated = enumerate_all_devices().await;

    #[cfg(feature = "gpu")]
    let mut adapter_slots: Vec<Option<wgpu::Adapter>> =
        enumerated.wgpu_adapters.into_iter().map(Some).collect();

    let mut backends: Vec<Arc<dyn MinerBackend>> = Vec::new();

    for &id in device_ids {
        let dev = enumerated
            .devices
            .iter()
            .find(|d| d.id == id)
            .ok_or_else(|| {
                anyhow::anyhow!("device {id} not found (run `webminer list-devices`)")
            })?;

        #[allow(unreachable_code, unused_variables)]
        let backend: Option<Arc<dyn MinerBackend>> = match &dev.kind {
            #[cfg(feature = "cuda")]
            DeviceKind::Cuda { ordinal } => {
                let m = cuda::CudaMiner::try_new(*ordinal).await;
                m.map(|m| Arc::new(m) as Arc<dyn MinerBackend>)
            }
            #[cfg(feature = "gpu")]
            DeviceKind::Wgpu { adapter_index, .. } => {
                if let Some(adapter) = adapter_slots
                    .get_mut(*adapter_index)
                    .and_then(|slot| slot.take())
                {
                    if let Some(m) = gpu::GpuMiner::try_from_adapter(adapter).await {
                        println!("Device {id}: {}", dev.label);
                        backends.push(Arc::new(m) as _);
                    } else {
                        eprintln!("Device {id}: {} — device init failed", dev.label);
                    }
                } else {
                    eprintln!("Device {id}: {} — adapter not found", dev.label);
                }
                continue;
            }
            #[allow(unreachable_patterns)]
            _ => None,
        };

        if let Some(b) = backend {
            println!("Device {id}: {}", dev.label);
            backends.push(b);
        } else {
            eprintln!("Device {id}: {} — failed to initialize", dev.label);
        }
    }

    if backends.is_empty() {
        anyhow::bail!("no devices could be initialized from --device selection");
    }

    Ok(Box::new(composite::CompositeBackend::new(backends).await))
}

/// Initialize wgpu GPU miners from enumerated devices.
///
/// Adapters are consumed directly from `EnumeratedDevices::wgpu_adapters`
/// by index — no re-enumeration, no identity matching.  This eliminates
/// the DX12 bug where identity matching via duplicate PCI bus IDs would
/// map N device entries to the same physical GPU.
#[cfg(feature = "gpu")]
pub async fn init_wgpu_miners_from_devices() -> Vec<gpu::GpuMiner> {
    let enumerated = enumerate_all_devices().await;
    let wgpu_devices: Vec<&DeviceInfo> = enumerated
        .devices
        .iter()
        .filter(|d| matches!(&d.kind, DeviceKind::Wgpu { .. }))
        .collect();

    if wgpu_devices.is_empty() {
        return Vec::new();
    }
    eprintln!("GPU: {} device(s) found", wgpu_devices.len());

    // Convert to Option slots so we can take() individual adapters by index.
    let mut adapter_slots: Vec<Option<wgpu::Adapter>> =
        enumerated.wgpu_adapters.into_iter().map(Some).collect();

    let mut miners = Vec::new();
    for dev in &wgpu_devices {
        if let DeviceKind::Wgpu { adapter_index, .. } = &dev.kind {
            if let Some(adapter) = adapter_slots
                .get_mut(*adapter_index)
                .and_then(|slot| slot.take())
            {
                if let Some(miner) = gpu::GpuMiner::try_from_adapter(adapter).await {
                    eprintln!("GPU[{}]: {} ready", dev.id, dev.label);
                    miners.push(miner);
                } else {
                    eprintln!("GPU[{}]: {} — device init failed", dev.id, dev.label);
                }
            } else {
                eprintln!("GPU[{}]: {} — adapter already consumed", dev.id, dev.label);
            }
        }
    }

    eprintln!(
        "GPU: {}/{} device(s) initialized",
        miners.len(),
        wgpu_devices.len()
    );
    miners
}

/// Select the best available mining backend.
pub async fn select_backend(
    choice: BackendChoice,
    cpu_threads: Option<usize>,
) -> anyhow::Result<Box<dyn MinerBackend>> {
    match choice {
        BackendChoice::Cpu => {
            let miner = simd_cpu::SimdCpuMiner::from_option(cpu_threads);
            println!(
                "Mining backend: {} ({} threads)",
                miner.name(),
                miner.thread_count()
            );
            Ok(Box::new(miner))
        }
        BackendChoice::Gpu => {
            // --backend gpu = wgpu/Vulkan only (no CUDA).
            // Use --backend auto for CUDA+wgpu fallback.
            #[cfg(feature = "gpu")]
            {
                let gpu_miners = init_wgpu_miners_from_devices().await;
                if let Some(miner) = multi_gpu::MultiGpuMiner::from_miners(gpu_miners).await {
                    println!("Mining backend: {} (Vulkan/wgpu)", miner.name());
                    return Ok(Box::new(miner));
                }
            }
            #[cfg(not(feature = "gpu"))]
            {
                anyhow::bail!("wgpu/Vulkan GPU support not compiled (enable 'gpu' feature)")
            }
            #[cfg(feature = "gpu")]
            {
                anyhow::bail!("No compatible Vulkan/wgpu GPU found. Try --backend auto for CUDA.")
            }
        }
        BackendChoice::Auto => {
            #[cfg(feature = "cuda")]
            {
                let cuda_ok = cuda_device_count();
                if cuda_ok > 0 {
                    if let Some(multi_cuda) = multi_cuda::MultiCudaMiner::try_new().await {
                        println!("Selected: {} (auto prefers CUDA)", multi_cuda.name());
                        return Ok(Box::new(multi_cuda));
                    }
                }
            }

            #[cfg(feature = "gpu")]
            {
                let gpu_miners = init_wgpu_miners_from_devices().await;
                if let Some(multi_gpu) = multi_gpu::MultiGpuMiner::from_miners(gpu_miners).await {
                    println!(
                        "Selected: {} (auto fallback: Vulkan/wgpu)",
                        multi_gpu.name()
                    );
                    return Ok(Box::new(multi_gpu));
                }
            }

            let miner = simd_cpu::SimdCpuMiner::from_option(cpu_threads);
            println!("Mining backend: {} (no GPU available)", miner.name());
            Ok(Box::new(miner))
        }
    }
}
