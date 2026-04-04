//! Multi-device CUDA mining backend.

use async_trait::async_trait;
use cudarc::driver::CudaContext;
use tokio::task::JoinSet;

use super::cuda::CudaMiner;
use super::sha256::Sha256Midstate;
use super::work_unit::NonceTable;
use super::{
    choose_best_result, split_assignments_for_weights, CancelFlag, MinerBackend, MiningChunkResult,
    MiningResult, NONCE_SPACE_SIZE,
};

pub struct MultiCudaMiner {
    miners: Vec<std::sync::Arc<CudaMiner>>,
    weights: Vec<f64>,
    device_names: Vec<String>,
    aggregate_hash_rate: f64,
    name: String,
}

impl MultiCudaMiner {
    pub async fn try_new() -> Option<Self> {
        // Ensure CUDA libraries are discoverable before any cudarc call.
        #[cfg(feature = "cuda")]
        {
            if let Some(ver) = super::cuda_detect::ensure_cuda_libraries() {
                eprintln!("CUDA toolkit detected: {ver}");
            }
        }

        let device_count = match CudaContext::device_count() {
            Ok(n) => n,
            Err(e) => {
                eprintln!("CUDA: failed to query device count: {e}");
                return None;
            }
        };
        if device_count <= 0 {
            eprintln!("CUDA: no devices found");
            return None;
        }
        eprintln!("CUDA: {device_count} device(s) detected, initializing...");

        let mut miners = Vec::new();
        for ordinal in 0..(device_count as usize) {
            match CudaMiner::try_new(ordinal).await {
                Some(miner) => miners.push(std::sync::Arc::new(miner)),
                None => {
                    // Retry once after a short delay (cloud GPU driver locking).
                    eprintln!("CUDA[{ordinal}]: retrying after 500ms...");
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    if let Some(miner) = CudaMiner::try_new(ordinal).await {
                        miners.push(std::sync::Arc::new(miner));
                    } else {
                        eprintln!("CUDA[{ordinal}]: skipped (init failed twice)");
                    }
                }
            }
        }
        if miners.is_empty() {
            eprintln!("CUDA: no devices initialized successfully");
            return None;
        }
        eprintln!(
            "CUDA: {}/{} device(s) initialized",
            miners.len(),
            device_count
        );

        let mut weights = Vec::with_capacity(miners.len());
        let mut device_names = Vec::with_capacity(miners.len());
        let mut aggregate_hash_rate = 0.0;
        for miner in &miners {
            let hps = miner.benchmark().await.unwrap_or(1.0).max(1.0);
            aggregate_hash_rate += hps;
            weights.push(hps);
            device_names.push(miner.device_name().to_string());
        }

        let name = if miners.len() == 1 {
            format!("CUDA ({})", miners[0].device_name())
        } else {
            format!("Multi-CUDA ({} devices)", miners.len())
        };

        Some(Self {
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

    fn split_assignments(&self, start_nonce: u32, nonce_count: u32) -> Vec<(usize, u32, u32)> {
        split_assignments_for_weights(&self.weights, start_nonce, nonce_count)
    }
}

#[async_trait]
impl MinerBackend for MultiCudaMiner {
    fn name(&self) -> &str {
        &self.name
    }

    fn startup_summary(&self) -> Vec<String> {
        let mut out = vec![
            format!("cuda_devices={}", self.miners.len()),
            format!(
                "cuda_total_estimate={:.2} Mh/s",
                self.aggregate_hash_rate / 1_000_000.0
            ),
        ];
        let weight_sum = self.weights.iter().sum::<f64>().max(1.0);
        for (idx, name) in self.device_names.iter().enumerate() {
            let pct = (self.weights[idx] / weight_sum) * 100.0;
            out.push(format!("cuda[{idx}]={name} share={pct:.1}%"));
        }
        out
    }

    async fn benchmark(&self) -> anyhow::Result<f64> {
        let nonce_table = NonceTable::new();
        let midstate = Sha256Midstate::from_prefix(&[0u8; 64]);

        let _ = self
            .mine_range(&midstate, &nonce_table, 256, 0, NONCE_SPACE_SIZE, None)
            .await?;

        let mut samples = Vec::with_capacity(6);
        for _ in 0..6 {
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
        // Each GPU finishes 1M nonces in <0.1ms. With pipeline_depth = GPU count,
        // the CPU loop overhead (work unit creation, task spawning) dominates and
        // throughput doesn't scale with more GPUs. Multiply by 4 so each GPU
        // processes multiple work units per cycle, keeping it busy longer.
        (self.miners.len() * 4).max(1)
    }

    async fn mine_work_units(
        &self,
        midstates: &[Sha256Midstate],
        _nonce_table: &NonceTable,
        difficulty: u32,
        cancel: Option<CancelFlag>,
    ) -> anyhow::Result<Vec<MiningChunkResult>> {
        if midstates.is_empty() {
            return Ok(Vec::new());
        }

        let gpu_count = self.miners.len();

        // Batch dispatch per GPU: fire all kernels into separate result buffers,
        // sync ONCE, read all results. Eliminates N-1 redundant sync calls per
        // GPU (the main source of dispatch overhead at sub-ms kernel times).
        let mut tasks = JoinSet::new();
        for gpu_idx in 0..gpu_count {
            let miner = self.miners[gpu_idx].clone();
            let gpu_indices: Vec<usize> = (gpu_idx..midstates.len())
                .step_by(gpu_count)
                .collect();
            let gpu_midstates: Vec<Sha256Midstate> = gpu_indices
                .iter()
                .map(|&i| midstates[i].clone())
                .collect();
            tasks.spawn(async move {
                let chunks = miner.mine_batch(&gpu_midstates, difficulty)?;
                let results: Vec<(usize, MiningChunkResult)> = gpu_indices
                    .into_iter()
                    .zip(chunks)
                    .collect();
                Ok::<Vec<(usize, MiningChunkResult)>, anyhow::Error>(results)
            });
        }

        let mut ordered: Vec<Option<MiningChunkResult>> =
            (0..midstates.len()).map(|_| None).collect();
        while let Some(joined) = tasks.join_next().await {
            let gpu_results =
                joined.map_err(|e| anyhow::anyhow!("CUDA task join error: {}", e))??;
            for (idx, chunk) in gpu_results {
                ordered[idx] = Some(chunk);
            }
        }

        let mut out = Vec::with_capacity(midstates.len());
        for item in ordered {
            out.push(item.ok_or_else(|| anyhow::anyhow!("missing CUDA mining chunk result"))?);
        }
        Ok(out)
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
        if self.miners.len() == 1 {
            return self.miners[0]
                .mine_range_direct(midstate, difficulty, start_nonce, nonce_count, cancel)
                .await;
        }

        let assignments = self.split_assignments(start_nonce, nonce_count);
        if assignments.is_empty() {
            return Ok(MiningChunkResult::empty());
        }

        let started = std::time::Instant::now();
        let mut tasks = JoinSet::new();
        for (idx, range_start, range_count) in assignments {
            let miner = self.miners[idx].clone();
            let midstate = midstate.clone();
            let cancel = cancel.clone();
            tasks.spawn(async move {
                miner
                    .mine_range_direct(&midstate, difficulty, range_start, range_count, cancel)
                    .await
            });
        }

        let mut attempted = 0u64;
        let mut best: Option<MiningResult> = None;
        while let Some(joined) = tasks.join_next().await {
            let chunk = joined.map_err(|e| anyhow::anyhow!("CUDA task join error: {}", e))??;
            attempted = attempted.saturating_add(chunk.attempted);
            best = choose_best_result(best, chunk.result);
        }

        Ok(MiningChunkResult {
            result: best,
            attempted,
            elapsed: started.elapsed(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_assignments_cover_range_without_gaps() {
        let assignments = split_assignments_for_weights(&[1.0, 2.0, 1.0], 77, 333_333);
        assert_eq!(assignments.len(), 3);

        let mut cursor = 77u32;
        let mut total = 0u32;
        for (_idx, start, count) in assignments {
            assert_eq!(start, cursor);
            assert!(count > 0);
            cursor = cursor.saturating_add(count);
            total = total.saturating_add(count);
        }

        assert_eq!(total, 333_333);
        assert_eq!(cursor, 77 + 333_333);
    }
}
