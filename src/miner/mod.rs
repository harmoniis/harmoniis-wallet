//! Webcash mining engine with GPU (wgpu) and CPU (rayon) backends.
//!
//! Implements the midstate SHA256 optimization from the C++ webminer: the JSON
//! preimage prefix is padded to exactly one SHA256 block (64 bytes), the midstate
//! is computed once, and each nonce attempt processes a single additional block.

pub mod cpu;
#[cfg(all(feature = "cuda", target_os = "linux"))]
pub mod cuda;
pub mod daemon;
#[cfg(feature = "gpu")]
pub mod gpu;
#[cfg(all(feature = "cuda", target_os = "linux"))]
pub mod multi_cuda;
#[cfg(feature = "gpu")]
pub mod multi_gpu;
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
#[derive(Debug)]
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
            #[cfg(all(feature = "cuda", target_os = "linux"))]
            {
                if let Some(miner) = multi_cuda::MultiCudaMiner::try_new().await {
                    println!("Mining backend: {}", miner.name());
                    return Ok(Box::new(miner));
                }
            }
            #[cfg(feature = "gpu")]
            {
                if let Some(miner) = multi_gpu::MultiGpuMiner::try_new().await {
                    println!("Mining backend: {}", miner.name());
                    return Ok(Box::new(miner));
                }
            }
            #[cfg(not(any(feature = "gpu", all(feature = "cuda", target_os = "linux"))))]
            {
                anyhow::bail!("GPU support not compiled (enable 'gpu' and/or 'cuda' feature)")
            }
            #[cfg(any(feature = "gpu", all(feature = "cuda", target_os = "linux")))]
            {
                anyhow::bail!("GPU requested but no compatible CUDA/Vulkan GPU found")
            }
        }
        BackendChoice::Auto => {
            #[cfg(all(feature = "cuda", target_os = "linux"))]
            {
                if let Some(multi_cuda) = multi_cuda::MultiCudaMiner::try_new().await {
                    println!("Selected: {} (auto prefers CUDA)", multi_cuda.name());
                    return Ok(Box::new(multi_cuda));
                }
            }

            #[cfg(feature = "gpu")]
            {
                if let Some(multi_gpu) = multi_gpu::MultiGpuMiner::try_new().await {
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
