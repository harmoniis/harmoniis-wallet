//! Multi-GPU mining backend.

use async_trait::async_trait;
use tokio::task::JoinSet;

use super::gpu::GpuMiner;
use super::sha256::Sha256Midstate;
use super::work_unit::NonceTable;
use super::{
    choose_best_result, CancelFlag, MinerBackend, MiningChunkResult, MiningResult, NONCE_SPACE_SIZE,
};

pub struct MultiGpuMiner {
    miners: Vec<std::sync::Arc<GpuMiner>>,
    weights: Vec<f64>,
    device_names: Vec<String>,
    aggregate_hash_rate: f64,
    name: String,
}

impl MultiGpuMiner {
    pub async fn try_new() -> Option<Self> {
        let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
            backends: wgpu::Backends::all(),
            ..Default::default()
        });

        let mut adapters = instance.enumerate_adapters(wgpu::Backends::all());
        if adapters.is_empty() {
            // Fallback for environments where enumerate returns none but request_adapter may work.
            if let Some(adapter) = instance
                .request_adapter(&wgpu::RequestAdapterOptions {
                    power_preference: wgpu::PowerPreference::HighPerformance,
                    compatible_surface: None,
                    force_fallback_adapter: false,
                })
                .await
            {
                adapters.push(adapter);
            }
        }
        let mut miners = Vec::new();

        for adapter in adapters {
            if let Some(miner) = GpuMiner::try_from_adapter(adapter).await {
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
            device_names.push(miner.adapter_name().to_string());
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

fn split_assignments_for_weights(
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

        let started = std::time::Instant::now();
        let mut tasks = JoinSet::new();

        for (idx, range_start, range_count) in assignments {
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
                        range_start,
                        range_count,
                        cancel,
                    )
                    .await
            });
        }

        let mut attempted = 0u64;
        let mut best: Option<MiningResult> = None;

        while let Some(joined) = tasks.join_next().await {
            let chunk = joined.map_err(|e| anyhow::anyhow!("GPU task join error: {}", e))??;
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
        let assignments = split_assignments_for_weights(&[1.0, 2.0, 1.0], 123, 777_777);
        assert_eq!(assignments.len(), 3);

        let mut cursor = 123u32;
        let mut total = 0u32;
        for (_idx, start, count) in assignments {
            assert_eq!(start, cursor);
            assert!(count > 0);
            cursor = cursor.saturating_add(count);
            total = total.saturating_add(count);
        }

        assert_eq!(total, 777_777);
        assert_eq!(cursor, 123 + 777_777);
    }

    #[test]
    fn split_assignments_follow_weight_ratio() {
        let assignments = split_assignments_for_weights(&[3.0, 1.0], 0, 1_000_000);
        assert_eq!(assignments.len(), 2);
        assert!(assignments[0].2 > assignments[1].2);
        assert_eq!(assignments[0].2 + assignments[1].2, 1_000_000);
    }

    #[test]
    fn split_assignments_clamps_to_nonce_space_size() {
        let assignments = split_assignments_for_weights(&[1.0, 1.0], NONCE_SPACE_SIZE - 10, 100);
        assert_eq!(assignments.len(), 2);
        assert_eq!(assignments[0].2 + assignments[1].2, 10);
        assert_eq!(assignments[0].1, NONCE_SPACE_SIZE - 10);
        assert_eq!(assignments[1].1 + assignments[1].2, NONCE_SPACE_SIZE);
    }
}
