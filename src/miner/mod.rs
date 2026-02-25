//! Webcash mining engine with GPU (wgpu) and CPU (rayon) backends.
//!
//! Implements the midstate SHA256 optimization from the C++ webminer: the JSON
//! preimage prefix is padded to exactly one SHA256 block (64 bytes), the midstate
//! is computed once, and each nonce attempt processes a single additional block.

pub mod cpu;
pub mod daemon;
#[cfg(feature = "gpu")]
pub mod gpu;
pub mod protocol;
pub mod sha256;
pub mod stats;
pub mod work_unit;

use async_trait::async_trait;

use sha256::Sha256Midstate;
use work_unit::NonceTable;

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

/// Configuration for the miner daemon.
#[derive(Debug, Clone)]
pub struct MinerConfig {
    pub server_url: String,
    pub wallet_path: std::path::PathBuf,
    pub webcash_wallet_path: std::path::PathBuf,
    pub max_difficulty: u32,
    pub backend: BackendChoice,
    pub accept_terms: bool,
}

/// Result of finding a valid proof-of-work solution.
#[derive(Debug)]
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

/// Trait abstracting GPU vs CPU mining backends.
#[async_trait]
pub trait MinerBackend: Send + Sync {
    /// Human-readable name of this backend.
    fn name(&self) -> &str;

    /// Run a quick benchmark and return estimated hashes per second.
    async fn benchmark(&self) -> anyhow::Result<f64>;

    /// Mine a single work unit (1M nonce combinations from a midstate).
    ///
    /// Returns `Some(result)` if a solution meeting `difficulty` is found.
    async fn mine_work_unit(
        &self,
        midstate: &Sha256Midstate,
        nonce_table: &NonceTable,
        difficulty: u32,
    ) -> anyhow::Result<Option<MiningResult>>;
}

/// Select the best available mining backend.
pub async fn select_backend(choice: BackendChoice) -> anyhow::Result<Box<dyn MinerBackend>> {
    match choice {
        BackendChoice::Cpu => {
            let miner = cpu::CpuMiner::new();
            println!("Mining backend: {} ({} threads)", miner.name(), num_cpus());
            Ok(Box::new(miner))
        }
        BackendChoice::Gpu => {
            #[cfg(feature = "gpu")]
            {
                match gpu::GpuMiner::try_new().await {
                    Some(miner) => {
                        println!("Mining backend: {}", miner.name());
                        Ok(Box::new(miner))
                    }
                    None => anyhow::bail!("GPU requested but no compatible GPU found"),
                }
            }
            #[cfg(not(feature = "gpu"))]
            {
                anyhow::bail!("GPU support not compiled (enable 'gpu' feature)")
            }
        }
        BackendChoice::Auto => {
            #[cfg(feature = "gpu")]
            {
                if let Some(gpu_miner) = gpu::GpuMiner::try_new().await {
                    let gpu_name = gpu_miner.name().to_string();
                    let cpu_miner = cpu::CpuMiner::new();

                    // Benchmark both
                    println!("Benchmarking GPU...");
                    let gpu_hps = gpu_miner.benchmark().await.unwrap_or(0.0);
                    println!("  GPU: {:.2} Mh/s", gpu_hps / 1_000_000.0);

                    println!("Benchmarking CPU...");
                    let cpu_hps = cpu_miner.benchmark().await.unwrap_or(0.0);
                    println!("  CPU: {:.2} Mh/s", cpu_hps / 1_000_000.0);

                    if gpu_hps > cpu_hps {
                        println!("Selected: {} (GPU)", gpu_name);
                        return Ok(Box::new(gpu_miner));
                    } else {
                        println!("Selected: {} (CPU faster)", cpu_miner.name());
                        return Ok(Box::new(cpu_miner));
                    }
                }
            }

            let miner = cpu::CpuMiner::new();
            println!("Mining backend: {} (no GPU available)", miner.name());
            Ok(Box::new(miner))
        }
    }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}
