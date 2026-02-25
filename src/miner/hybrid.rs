//! Hybrid mining backend: CPU + multi-GPU in parallel.

use async_trait::async_trait;
use std::sync::atomic::Ordering;

use super::cpu::CpuMiner;
use super::multi_gpu::MultiGpuMiner;
use super::sha256::Sha256Midstate;
use super::work_unit::NonceTable;
use super::{
    choose_best_result, CancelFlag, MinerBackend, MiningChunkResult, MiningResult, NONCE_SPACE_SIZE,
};

pub struct HybridMiner {
    cpu: std::sync::Arc<CpuMiner>,
    gpus: std::sync::Arc<MultiGpuMiner>,
    cpu_share: std::sync::Mutex<f64>,
    aggregate_hash_rate: f64,
    cpu_hps_estimate: f64,
    gpu_hps_estimate: f64,
    name: String,
}

impl HybridMiner {
    const MIN_HYBRID_CPU_HPS: f64 = 90_000_000.0;
    const MIN_CPU_TO_GPU_RATIO: f64 = 0.35;
    const MIN_RUNTIME_CPU_HPS: f64 = 45_000_000.0;
    const MIN_RUNTIME_CPU_TO_GPU_RATIO: f64 = 0.20;
    const MAX_CPU_SHARE: f64 = 0.15;
    const MIN_ACTIVE_CPU_SHARE: f64 = 0.01;

    fn default_hybrid_cpu_threads() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .saturating_sub(2)
            .max(1)
    }

    fn cpu_is_startup_viable(cpu_hps: f64, gpu_hps: f64) -> bool {
        cpu_hps >= Self::MIN_HYBRID_CPU_HPS && cpu_hps >= gpu_hps * Self::MIN_CPU_TO_GPU_RATIO
    }

    fn cpu_is_runtime_viable(cpu_hps: f64, gpu_hps: f64) -> bool {
        cpu_hps >= Self::MIN_RUNTIME_CPU_HPS
            && cpu_hps >= gpu_hps * Self::MIN_RUNTIME_CPU_TO_GPU_RATIO
    }

    pub async fn try_new(cpu_threads: Option<usize>) -> Option<Self> {
        let cpu_threads = cpu_threads.unwrap_or_else(Self::default_hybrid_cpu_threads);
        let cpu = std::sync::Arc::new(CpuMiner::with_threads(cpu_threads));
        let cpu_hps = cpu.benchmark().await.unwrap_or(1.0).max(1.0);

        let gpus = std::sync::Arc::new(MultiGpuMiner::try_new().await?);
        let gpu_hps = gpus.estimated_hash_rate().max(1.0);
        let initial_share = if Self::cpu_is_startup_viable(cpu_hps, gpu_hps) {
            (cpu_hps / (cpu_hps + gpu_hps)).clamp(Self::MIN_ACTIVE_CPU_SHARE, Self::MAX_CPU_SHARE)
        } else {
            0.0
        };

        let name = format!("Hybrid ({} + {})", cpu.name(), gpus.name());

        Some(HybridMiner {
            cpu,
            gpus,
            cpu_share: std::sync::Mutex::new(initial_share),
            aggregate_hash_rate: cpu_hps + gpu_hps,
            cpu_hps_estimate: cpu_hps,
            gpu_hps_estimate: gpu_hps,
            name,
        })
    }

    fn current_cpu_share(&self) -> f64 {
        *self.cpu_share.lock().expect("cpu_share mutex poisoned")
    }

    fn cpu_enabled(&self) -> bool {
        self.current_cpu_share() > Self::MIN_ACTIVE_CPU_SHARE
    }

    fn update_cpu_share(&self, cpu_chunk: &MiningChunkResult, gpu_chunk: &MiningChunkResult) {
        let cpu_secs = cpu_chunk.elapsed.as_secs_f64();
        let gpu_secs = gpu_chunk.elapsed.as_secs_f64();
        if cpu_secs <= 0.0 || gpu_secs <= 0.0 {
            return;
        }
        if cpu_chunk.attempted == 0 || gpu_chunk.attempted == 0 {
            return;
        }

        let cpu_rate = cpu_chunk.attempted as f64 / cpu_secs;
        let gpu_rate = gpu_chunk.attempted as f64 / gpu_secs;
        if cpu_rate <= 0.0 || gpu_rate <= 0.0 {
            return;
        }

        if !Self::cpu_is_runtime_viable(cpu_rate, gpu_rate) {
            let mut share = self.cpu_share.lock().expect("cpu_share mutex poisoned");
            *share *= 0.85;
            if *share < Self::MIN_ACTIVE_CPU_SHARE {
                *share = 0.0;
            }
            return;
        }

        let target = (cpu_rate / (cpu_rate + gpu_rate))
            .clamp(Self::MIN_ACTIVE_CPU_SHARE, Self::MAX_CPU_SHARE);
        let mut share = self.cpu_share.lock().expect("cpu_share mutex poisoned");
        *share = (*share * 0.7) + (target * 0.3);
    }
}

#[async_trait]
impl MinerBackend for HybridMiner {
    fn name(&self) -> &str {
        &self.name
    }

    fn startup_summary(&self) -> Vec<String> {
        vec![
            format!("cpu_threads={}", self.cpu.thread_count()),
            format!("gpu_devices={}", self.gpus.device_count()),
            format!(
                "cpu_estimate={:.2} Mh/s",
                self.cpu_hps_estimate / 1_000_000.0
            ),
            format!(
                "gpu_estimate={:.2} Mh/s",
                self.gpu_hps_estimate / 1_000_000.0
            ),
            format!(
                "hybrid_cpu_min_required={:.2} Mh/s",
                Self::MIN_HYBRID_CPU_HPS / 1_000_000.0
            ),
            format!(
                "hybrid_cpu_ratio_min={:.0}%",
                Self::MIN_CPU_TO_GPU_RATIO * 100.0
            ),
            format!(
                "hybrid_cpu_runtime_min={:.2} Mh/s",
                Self::MIN_RUNTIME_CPU_HPS / 1_000_000.0
            ),
            format!("hybrid_cpu_enabled={}", self.cpu_enabled()),
            format!(
                "hybrid_cpu_share_initial={:.1}%",
                self.current_cpu_share() * 100.0
            ),
            format!(
                "hybrid_total_estimate={:.2} Mh/s",
                self.aggregate_hash_rate / 1_000_000.0
            ),
        ]
    }

    async fn benchmark(&self) -> anyhow::Result<f64> {
        let nonce_table = NonceTable::new();
        let midstate = Sha256Midstate::from_prefix(&[0u8; 64]);

        // Warm up hybrid scheduling and backend state.
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
        nonce_table: &NonceTable,
        difficulty: u32,
        start_nonce: u32,
        nonce_count: u32,
        cancel: Option<CancelFlag>,
    ) -> anyhow::Result<MiningChunkResult> {
        if let Some(flag) = cancel.as_ref() {
            if flag.load(Ordering::Relaxed) {
                return Ok(MiningChunkResult::empty());
            }
        }

        let start = start_nonce.min(NONCE_SPACE_SIZE);
        let end = start.saturating_add(nonce_count).min(NONCE_SPACE_SIZE);
        if start >= end {
            return Ok(MiningChunkResult::empty());
        }

        // If CPU contribution is disabled, run pure GPU.
        if !self.cpu_enabled() {
            return self
                .gpus
                .mine_range(
                    midstate,
                    nonce_table,
                    difficulty,
                    start,
                    end - start,
                    cancel,
                )
                .await;
        }

        let total = end - start;
        let started = std::time::Instant::now();

        if total <= 1 {
            return self
                .gpus
                .mine_range(midstate, nonce_table, difficulty, start, total, cancel)
                .await;
        }

        let mut cpu_count = ((total as f64) * self.current_cpu_share()).round() as u32;
        cpu_count = cpu_count.clamp(1, total - 1);
        let gpu_count = total - cpu_count;

        let cancel_flag = cancel
            .unwrap_or_else(|| std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)));

        let cpu_mid = midstate.clone();
        let cpu_nonce = nonce_table.clone();
        let cpu_cancel = Some(cancel_flag.clone());

        let gpu_mid = midstate.clone();
        let gpu_nonce = nonce_table.clone();
        let gpu_cancel = Some(cancel_flag.clone());

        let cpu = self.cpu.clone();
        let gpus = self.gpus.clone();
        let cpu_task = tokio::spawn(async move {
            cpu.mine_range(
                &cpu_mid, &cpu_nonce, difficulty, start, cpu_count, cpu_cancel,
            )
            .await
        });
        let gpu_task = tokio::spawn(async move {
            gpus.mine_range(
                &gpu_mid,
                &gpu_nonce,
                difficulty,
                start + cpu_count,
                gpu_count,
                gpu_cancel,
            )
            .await
        });

        tokio::pin!(cpu_task);
        tokio::pin!(gpu_task);

        let (cpu_chunk, gpu_chunk) = tokio::select! {
            cpu_done = &mut cpu_task => {
                let cpu_chunk = cpu_done
                    .map_err(|e| anyhow::anyhow!("hybrid CPU task join error: {}", e))??;

                if cpu_chunk.result.is_some() {
                    cancel_flag.store(true, Ordering::Relaxed);
                    gpu_task.as_mut().abort();
                    let attempted = cpu_chunk.attempted;
                    return Ok(MiningChunkResult {
                        result: cpu_chunk.result,
                        attempted,
                        elapsed: started.elapsed(),
                    });
                }

                let gpu_chunk = gpu_task
                    .await
                    .map_err(|e| anyhow::anyhow!("hybrid GPU task join error: {}", e))??;
                (cpu_chunk, gpu_chunk)
            }
            gpu_done = &mut gpu_task => {
                let gpu_chunk = gpu_done
                    .map_err(|e| anyhow::anyhow!("hybrid GPU task join error: {}", e))??;

                if gpu_chunk.result.is_some() {
                    cancel_flag.store(true, Ordering::Relaxed);
                    cpu_task.as_mut().abort();
                    let attempted = gpu_chunk.attempted;
                    return Ok(MiningChunkResult {
                        result: gpu_chunk.result,
                        attempted,
                        elapsed: started.elapsed(),
                    });
                }

                let cpu_chunk = cpu_task
                    .await
                    .map_err(|e| anyhow::anyhow!("hybrid CPU task join error: {}", e))??;
                (cpu_chunk, gpu_chunk)
            }
        };

        self.update_cpu_share(&cpu_chunk, &gpu_chunk);

        let attempted = cpu_chunk.attempted.saturating_add(gpu_chunk.attempted);
        let best: Option<MiningResult> = choose_best_result(cpu_chunk.result, gpu_chunk.result);

        Ok(MiningChunkResult {
            result: best,
            attempted,
            elapsed: started.elapsed(),
        })
    }
}
