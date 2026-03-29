//! Multi-GPU mining backend.

use async_trait::async_trait;
use tokio::task::JoinSet;

use super::gpu::{AdapterIdentity, GpuMiner, COMPUTE_BACKENDS};
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
    pub async fn try_new() -> Option<Self> {
        let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
            backends: COMPUTE_BACKENDS,
            ..Default::default()
        });

        let mut adapters = instance.enumerate_adapters(COMPUTE_BACKENDS);
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

        // Probe each adapter in a subprocess first — if the GPU driver
        // segfaults during shader compilation (known AMD Vulkan bug on Polaris),
        // the subprocess dies and we skip that adapter.  This means we do NOT
        // dedup by physical device beforehand: if Vulkan crashes for a card,
        // the DX12 adapter for the same card may still work.
        let total = adapters.len();
        let mut miners = Vec::new();
        let mut used_devices: std::collections::HashSet<String> = std::collections::HashSet::new();

        for adapter in adapters.into_iter() {
            let info = adapter.get_info();
            if info.device_type == wgpu::DeviceType::Cpu {
                continue;
            }

            let identity = AdapterIdentity::from_info(&info);

            // Skip if we already have a working miner for this physical device.
            let device_key = identity.device_key();
            if used_devices.contains(&device_key) {
                continue;
            }

            // Probe in a subprocess — survives driver segfaults.
            if !super::gpu::subprocess_probe(&identity) {
                eprintln!(
                    "GPU probe failed: {} ({:?}) — skipping",
                    info.name, info.backend
                );
                continue;
            }

            if let Some(miner) = GpuMiner::try_from_adapter(adapter).await {
                used_devices.insert(device_key);
                miners.push(std::sync::Arc::new(miner));
            }
        }
        if total > 0 && miners.len() < total {
            eprintln!(
                "GPU: {} adapters enumerated, {} usable",
                total,
                miners.len()
            );
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
