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
    /// One physical GPU with all its adapters (Vulkan, DX12, Metal).
    /// The system tries adapters in order — the first that passes the
    /// subprocess probe is used.  The user never sees adapter details.
    #[cfg(feature = "gpu")]
    Wgpu { adapters: Vec<gpu::AdapterIdentity> },
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
/// Each physical GPU gets exactly one device ID, regardless of how many
/// adapters (Vulkan, DX12, Metal) it exposes.  Adapters are grouped by
/// GPU name and stored internally for automatic fallback.
///
/// Order: CUDA devices first, then wgpu devices.
pub async fn enumerate_all_devices() -> Vec<DeviceInfo> {
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

    // 2. wgpu — group adapters by physical device.
    //
    //    Primary key: `device_pci_bus_id` (e.g. "0000:01:00.0") — unique per
    //    PCIe slot, even for identical cards.  Available on Vulkan via
    //    VkPhysicalDevicePCIBusInfoPropertiesEXT.
    //
    //    Fallback (DX12/Metal or when bus ID is empty): `(vendor, device, name)`
    //    tuple.  This correctly groups Vulkan+DX12 adapters for the same card
    //    but cannot distinguish two identical cards (rare edge case).
    //
    //    Each physical device gets one entry with all its adapters stored for
    //    automatic fallback during init.
    #[cfg(feature = "gpu")]
    {
        use std::collections::BTreeMap;

        let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
            backends: gpu::COMPUTE_BACKENDS,
            ..Default::default()
        });
        let adapters = instance.enumerate_adapters(gpu::COMPUTE_BACKENDS).await;

        // Pass 1: collect all adapter info and PCI bus IDs.
        struct AdapterEntry {
            name: String,
            vendor: u32,
            device: u32,
            pci_bus: String,
            identity: gpu::AdapterIdentity,
        }
        let mut entries = Vec::new();
        for adapter in adapters {
            let info = adapter.get_info();
            if info.device_type == wgpu::DeviceType::Cpu {
                continue;
            }
            entries.push(AdapterEntry {
                name: info.name.clone(),
                vendor: info.vendor,
                device: info.device,
                pci_bus: info.device_pci_bus_id.trim().to_string(),
                identity: gpu::AdapterIdentity::from_info(&info),
            });
        }

        // Build a lookup: (vendor, device, name) → PCI bus ID from any
        // adapter that reports one (Vulkan usually does, DX12 often doesn't).
        let mut known_bus_ids: std::collections::HashMap<(u32, u32, String), String> =
            std::collections::HashMap::new();
        for e in &entries {
            if !e.pci_bus.is_empty() {
                known_bus_ids
                    .entry((e.vendor, e.device, e.name.clone()))
                    .or_insert_with(|| e.pci_bus.clone());
            }
        }

        // Pass 2: group by physical device key.
        let mut device_groups: BTreeMap<String, (String, Vec<gpu::AdapterIdentity>)> =
            BTreeMap::new();
        for e in entries {
            // Use PCI bus ID if this adapter has one, or borrow from another
            // adapter for the same (vendor, device, name) that does.
            let bus = if !e.pci_bus.is_empty() {
                e.pci_bus.clone()
            } else {
                known_bus_ids
                    .get(&(e.vendor, e.device, e.name.clone()))
                    .cloned()
                    .unwrap_or_default()
            };

            let phys_key = if !bus.is_empty() {
                format!("pci:{bus}")
            } else {
                format!("dev:{}:{}:{}", e.vendor, e.device, e.name)
            };

            device_groups
                .entry(phys_key)
                .or_insert_with(|| (e.name.clone(), Vec::new()))
                .1
                .push(e.identity);
        }

        for (_phys_key, (name, adapters_for_device)) in device_groups {
            if adapters_for_device.is_empty() {
                continue;
            }
            devices.push(DeviceInfo {
                id: next_id,
                label: name,
                kind: DeviceKind::Wgpu {
                    adapters: adapters_for_device,
                },
            });
            next_id += 1;
        }
    }

    devices
}

/// Create a mining backend for specific GPU device IDs.
pub async fn select_backend_for_devices(
    device_ids: &[usize],
) -> anyhow::Result<Box<dyn MinerBackend>> {
    let all = enumerate_all_devices().await;

    let mut backends: Vec<Arc<dyn MinerBackend>> = Vec::new();

    for &id in device_ids {
        let dev = all.iter().find(|d| d.id == id).ok_or_else(|| {
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
            DeviceKind::Wgpu { adapters } => {
                // Try each adapter for this physical GPU until one works.
                // Order: Vulkan first, then DX12, then Metal (as enumerated).
                let mut result: Option<(Arc<dyn MinerBackend>, String)> = None;
                for identity in adapters {
                    if !gpu::subprocess_probe(identity) {
                        continue;
                    }
                    let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
                        backends: gpu::COMPUTE_BACKENDS,
                        ..Default::default()
                    });
                    let found = instance.enumerate_adapters(gpu::COMPUTE_BACKENDS).await;
                    if let Some(adapter) = identity.find_matching(found) {
                        if let Some(m) = gpu::GpuMiner::try_from_adapter(adapter).await {
                            result = Some((Arc::new(m) as _, identity.backend.clone()));
                            break;
                        }
                    }
                }
                if let Some((m, adapter_backend)) = result {
                    println!("Device {id}: {} ({adapter_backend})", dev.label);
                    backends.push(m);
                } else {
                    eprintln!("Device {id}: {} — no working adapter found", dev.label);
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

/// Initialize wgpu GPU miners from the unified device list.
///
/// Uses `enumerate_all_devices()` to discover physical GPUs (PCI bus ID
/// dedup), then probes and initializes each wgpu device.  This is the single
/// source of truth for wgpu adapter discovery — `multi_gpu.rs` no longer has
/// its own enumeration logic.
#[cfg(feature = "gpu")]
pub async fn init_wgpu_miners_from_devices() -> Vec<gpu::GpuMiner> {
    let devices = enumerate_all_devices().await;
    let wgpu_count = devices
        .iter()
        .filter(|d| matches!(&d.kind, DeviceKind::Wgpu { .. }))
        .count();
    if wgpu_count > 0 {
        eprintln!("GPU: {wgpu_count} physical device(s) found, probing...");
    }

    let mut miners = Vec::new();

    for dev in &devices {
        #[allow(irrefutable_let_patterns)]
        if let DeviceKind::Wgpu { adapters } = &dev.kind {
            eprintln!(
                "GPU[{}]: {} ({} adapter backend(s))",
                dev.id,
                dev.label,
                adapters.len(),
            );
            // Try ALL adapter backends, benchmark each, pick the fastest.
            // This fixes the DX12→Vulkan regression where Vulkan was 4x slower
            // on NVIDIA Pascal but got picked first because its probe passed.
            let mut best_miner: Option<(gpu::GpuMiner, String, f64)> = None;
            for identity in adapters {
                if !gpu::subprocess_probe(identity) {
                    continue;
                }
                let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
                    backends: gpu::COMPUTE_BACKENDS,
                    ..Default::default()
                });
                let found = instance.enumerate_adapters(gpu::COMPUTE_BACKENDS).await;
                if let Some(adapter) = identity.find_matching(found) {
                    if let Some(miner) = gpu::GpuMiner::try_from_adapter(adapter).await {
                        let hps = miner.benchmark().await.unwrap_or(0.0);
                        eprintln!(
                            "GPU[{}]: {} ({}) — {:.2} Mh/s",
                            dev.id,
                            dev.label,
                            identity.backend,
                            hps / 1_000_000.0,
                        );
                        let is_better = best_miner
                            .as_ref()
                            .map_or(true, |(_, _, best_hps)| hps > *best_hps);
                        if is_better {
                            best_miner = Some((miner, identity.backend.clone(), hps));
                        }
                    }
                }
            }
            if let Some((miner, backend, hps)) = best_miner {
                eprintln!(
                    "GPU[{}]: {} ready ({}, {:.2} Mh/s)",
                    dev.id,
                    dev.label,
                    backend,
                    hps / 1_000_000.0,
                );
                miners.push(miner);
            } else {
                eprintln!("GPU[{}]: {} — no working adapter found", dev.id, dev.label);
            }
        }
    }

    if wgpu_count > 0 {
        eprintln!("GPU: {}/{} device(s) initialized", miners.len(), wgpu_count);
    }
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
