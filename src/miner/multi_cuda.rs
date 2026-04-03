//! Multi-device CUDA mining backend.
//!
//! Distributes work units across GPUs via persistent worker threads.
//! mine_work_units sends to all workers then collects — no thread spawn per cycle.

use async_trait::async_trait;
use cudarc::driver::CudaContext;
use tokio::task::JoinSet;

use super::cuda::{CudaMiner, PIPELINE_SLOTS};
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
        let device_count = CudaContext::device_count().ok()?;
        if device_count <= 0 {
            return None;
        }

        let mut miners = Vec::new();
        for ordinal in 0..(device_count as usize) {
            if let Some(miner) = CudaMiner::try_new(ordinal).await {
                miners.push(std::sync::Arc::new(miner));
            }
        }
        if miners.is_empty() {
            return None;
        }

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
        (self.miners.len() * PIPELINE_SLOTS).max(1)
    }

    async fn mine_work_units(
        &self,
        midstates: &[Sha256Midstate],
        _nonce_table: &NonceTable,
        difficulty: u32,
        _cancel: Option<CancelFlag>,
    ) -> anyhow::Result<Vec<MiningChunkResult>> {
        if midstates.is_empty() {
            return Ok(Vec::new());
        }

        let num_gpus = self.miners.len();
        let mut gpu_batches: Vec<Vec<(usize, Sha256Midstate)>> =
            (0..num_gpus).map(|_| Vec::new()).collect();
        for (idx, midstate) in midstates.iter().enumerate() {
            gpu_batches[idx % num_gpus].push((idx, midstate.clone()));
        }

        // Send work to all persistent GPU workers via short-lived dispatch threads.
        // Each thread sends then blocks on recv — all GPUs compute in parallel.
        // Thread overhead (~0.3ms) is the cost of true parallelism since async
        // recv would serialize on the tokio worker thread.
        let mut handles = Vec::with_capacity(num_gpus);
        for (gpu_idx, batch) in gpu_batches.into_iter().enumerate() {
            if batch.is_empty() {
                continue;
            }
            let miner = self.miners[gpu_idx].clone();
            handles.push(std::thread::spawn(move || {
                let indices: Vec<usize> = batch.iter().map(|(i, _)| *i).collect();
                let mids: Vec<Sha256Midstate> = batch.into_iter().map(|(_, m)| m).collect();
                miner.send_work(mids, difficulty)?;
                let chunks = miner.recv_result()?;
                Ok::<Vec<(usize, MiningChunkResult)>, anyhow::Error>(
                    indices
                        .into_iter()
                        .zip(chunks)
                        .collect(),
                )
            }));
        }

        let mut ordered: Vec<Option<MiningChunkResult>> =
            (0..midstates.len()).map(|_| None).collect();
        for handle in handles {
            let pairs = handle
                .join()
                .map_err(|_| anyhow::anyhow!("GPU dispatch thread panicked"))??;
            for (idx, chunk) in pairs {
                ordered[idx] = Some(chunk);
            }
        }

        Ok(ordered
            .into_iter()
            .map(|o| o.unwrap_or_else(MiningChunkResult::empty))
            .collect())
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
