//! Multi-GPU mining backend (wgpu).
//!
//! Reuses the unified device discovery from `mod.rs` to avoid duplicating
//! adapter enumeration and deduplication logic.

use async_trait::async_trait;
use tokio::task::JoinSet;

use super::gpu::GpuMiner;
use super::sha256::Sha256Midstate;
use super::work_unit::NonceTable;
use super::{
    choose_best_result, split_assignments_for_weights, CancelFlag, MinerBackend, MiningChunkResult,
    MiningResult, NONCE_SPACE_SIZE,
};

pub struct MultiGpuMiner {
    miners: Vec<std::sync::Arc<GpuMiner>>,
    weights: Vec<f64>,
    device_names: Vec<String>,
    aggregate_hash_rate: f64,
    name: String,
}

impl MultiGpuMiner {
    /// Create a multi-GPU miner from pre-initialized GPU miners.
    ///
    /// Called by `select_backend` after `enumerate_all_devices()` identifies
    /// physical GPUs.  This avoids duplicating adapter enumeration logic.
    pub async fn from_miners(gpu_miners: Vec<GpuMiner>) -> Option<Self> {
        if gpu_miners.is_empty() {
            return None;
        }

        let mut miners = Vec::with_capacity(gpu_miners.len());
        let mut weights = Vec::with_capacity(gpu_miners.len());
        let mut device_names = Vec::with_capacity(gpu_miners.len());
        let mut aggregate_hash_rate = 0.0;

        for (idx, miner) in gpu_miners.into_iter().enumerate() {
            let name = miner.adapter_name().to_string();
            eprintln!("GPU[{idx}]: benchmarking {}...", name);
            let hps = miner.benchmark().await.unwrap_or(1.0).max(1.0);
            eprintln!("GPU[{idx}]: {} — {:.2} Mh/s", name, hps / 1_000_000.0,);
            aggregate_hash_rate += hps;
            weights.push(hps);
            device_names.push(name);
            miners.push(std::sync::Arc::new(miner));
        }

        let name = if miners.len() == 1 {
            format!("GPU ({})", miners[0].adapter_name())
        } else {
            format!("Multi-GPU ({} devices)", miners.len())
        };

        Some(MultiGpuMiner {
            miners,
            weights,
            device_names,
            aggregate_hash_rate,
            name,
        })
    }

    pub fn device_count(&self) -> usize {
        self.miners.len()
    }

    pub fn estimated_hash_rate(&self) -> f64 {
        self.aggregate_hash_rate
    }

    fn split_assignments(&self, start_nonce: u32, nonce_count: u32) -> Vec<(usize, u32, u32)> {
        split_assignments_for_weights(&self.weights, start_nonce, nonce_count)
    }
}

#[async_trait]
impl MinerBackend for MultiGpuMiner {
    fn name(&self) -> &str {
        &self.name
    }

    fn startup_summary(&self) -> Vec<String> {
        let mut out = vec![
            format!("gpu_devices={}", self.miners.len()),
            format!(
                "gpu_total_estimate={:.2} Mh/s",
                self.aggregate_hash_rate / 1_000_000.0
            ),
        ];

        let weight_sum = self.weights.iter().sum::<f64>().max(1.0);
        for (idx, name) in self.device_names.iter().enumerate() {
            let pct = (self.weights[idx] / weight_sum) * 100.0;
            out.push(format!("gpu[{idx}]={name} share={pct:.1}%"));
        }
        out
    }

    async fn benchmark(&self) -> anyhow::Result<f64> {
        let nonce_table = NonceTable::new();
        let midstate = Sha256Midstate::from_prefix(&[0u8; 64]);

        // Warm up backend state.
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

    fn recommended_pipeline_depth(&self) -> usize {
        // Each GPU gets one full 1M-nonce work unit. Unlike the CUDA backend,
        // wgpu cannot overlap dispatches on the same device (shared input/result
        // buffers, single command queue). Pipeline depth = GPU count.
        self.miners.len().max(1)
    }

    async fn mine_work_units(
        &self,
        midstates: &[Sha256Midstate],
        nonce_table: &NonceTable,
        difficulty: u32,
        cancel: Option<CancelFlag>,
    ) -> anyhow::Result<Vec<MiningChunkResult>> {
        // Single GPU or single midstate: direct call, zero overhead.
        if self.miners.len() <= 1 || midstates.len() <= 1 {
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
            return Ok(out);
        }

        // Multi-GPU: each GPU gets its own full 1M nonce work unit in parallel.
        let mut tasks = JoinSet::new();
        for (idx, midstate) in midstates.iter().enumerate() {
            let miner = self.miners[idx % self.miners.len()].clone();
            let midstate = midstate.clone();
            let nonce_table = nonce_table.clone();
            let cancel = cancel.clone();
            tasks.spawn(async move {
                let chunk = miner
                    .mine_range(
                        &midstate,
                        &nonce_table,
                        difficulty,
                        0,
                        NONCE_SPACE_SIZE,
                        cancel,
                    )
                    .await?;
                Ok::<(usize, MiningChunkResult), anyhow::Error>((idx, chunk))
            });
        }

        let mut ordered: Vec<Option<MiningChunkResult>> =
            (0..midstates.len()).map(|_| None).collect();
        while let Some(joined) = tasks.join_next().await {
            let (idx, chunk) =
                joined.map_err(|e| anyhow::anyhow!("GPU task join error: {}", e))??;
            ordered[idx] = Some(chunk);
        }
        ordered
            .into_iter()
            .enumerate()
            .map(|(i, opt)| opt.ok_or_else(|| anyhow::anyhow!("missing GPU result {i}")))
            .collect()
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
        if self.miners.len() == 1 {
            return self.miners[0]
                .mine_range(
                    midstate,
                    nonce_table,
                    difficulty,
                    start_nonce,
                    nonce_count,
                    cancel,
                )
                .await;
        }

        let assignments = self.split_assignments(start_nonce, nonce_count);
        if assignments.is_empty() {
            return Ok(MiningChunkResult::empty());
        }

        let mut tasks = JoinSet::new();
        for (idx, sub_start, sub_count) in assignments {
            let miner = self.miners[idx].clone();
            let midstate = midstate.clone();
            let nonce_table = nonce_table.clone();
            let cancel = cancel.clone();
            tasks.spawn(async move {
                miner
                    .mine_range(
                        &midstate,
                        &nonce_table,
                        difficulty,
                        sub_start,
                        sub_count,
                        cancel,
                    )
                    .await
            });
        }

        let mut best: Option<MiningResult> = None;
        let mut total_attempted = 0u64;
        let mut max_elapsed = std::time::Duration::ZERO;
        while let Some(joined) = tasks.join_next().await {
            let chunk = joined.map_err(|e| anyhow::anyhow!("GPU task join error: {}", e))??;
            total_attempted = total_attempted.saturating_add(chunk.attempted);
            if chunk.elapsed > max_elapsed {
                max_elapsed = chunk.elapsed;
            }
            best = choose_best_result(best, chunk.result);
        }

        Ok(MiningChunkResult {
            result: best,
            attempted: total_attempted,
            elapsed: max_elapsed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::split_assignments_for_weights;

    #[test]
    fn split_simple_weights() {
        let weights = [1.0, 1.0];
        let assignments = split_assignments_for_weights(&weights, 0, 100);
        assert_eq!(assignments.len(), 2);
        let (i0, s0, c0) = assignments[0];
        let (i1, s1, c1) = assignments[1];
        assert_eq!(i0, 0);
        assert_eq!(i1, 1);
        assert_eq!(s0, 0);
        assert_eq!(s1, 50);
        assert_eq!(c0 + c1, 100);
    }

    #[test]
    fn split_unequal_weights() {
        let weights = [3.0, 1.0];
        let assignments = split_assignments_for_weights(&weights, 0, 100);
        let (_, _, c0) = assignments[0];
        let (_, _, c1) = assignments[1];
        assert!(c0 > c1, "GPU 0 should get more nonces");
        assert_eq!(c0 + c1, 100);
    }

    #[test]
    fn split_empty() {
        let assignments = split_assignments_for_weights(&[], 0, 100);
        assert!(assignments.is_empty());
    }
}
