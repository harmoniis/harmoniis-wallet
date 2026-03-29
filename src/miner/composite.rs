//! Composite mining backend that dispatches across multiple heterogeneous
//! backends (e.g. CUDA + Vulkan GPUs together).

use std::sync::Arc;

use async_trait::async_trait;
use tokio::task::JoinSet;

use super::sha256::Sha256Midstate;
use super::work_unit::NonceTable;
use super::{
    choose_best_result, split_assignments_for_weights, CancelFlag, MinerBackend, MiningChunkResult,
    MiningResult, NONCE_SPACE_SIZE,
};

pub struct CompositeBackend {
    backends: Vec<Arc<dyn MinerBackend>>,
    weights: Vec<f64>,
    name: String,
}

impl CompositeBackend {
    /// Create a composite from pre-created backends.  Benchmarks each to
    /// establish proportional weights for work splitting.
    pub async fn new(backends: Vec<Arc<dyn MinerBackend>>) -> Self {
        let mut weights = Vec::with_capacity(backends.len());
        let mut names = Vec::with_capacity(backends.len());
        for b in &backends {
            let hps = b.benchmark().await.unwrap_or(1.0).max(1.0);
            weights.push(hps);
            names.push(b.name().to_string());
        }

        let name = if backends.len() == 1 {
            names[0].clone()
        } else {
            format!("Composite ({} devices)", backends.len())
        };

        Self {
            backends,
            weights,
            name,
        }
    }
}

#[async_trait]
impl MinerBackend for CompositeBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn startup_summary(&self) -> Vec<String> {
        let mut out = vec![format!("composite_devices={}", self.backends.len())];
        let weight_sum = self.weights.iter().sum::<f64>().max(1.0);
        for (idx, b) in self.backends.iter().enumerate() {
            let pct = (self.weights[idx] / weight_sum) * 100.0;
            out.push(format!("device[{idx}]={} share={pct:.1}%", b.name()));
        }
        out
    }

    async fn benchmark(&self) -> anyhow::Result<f64> {
        let mut total = 0.0;
        for w in &self.weights {
            total += w;
        }
        Ok(total)
    }

    fn max_batch_hint(&self) -> u32 {
        NONCE_SPACE_SIZE
    }

    fn recommended_pipeline_depth(&self) -> usize {
        self.backends
            .iter()
            .map(|b| b.recommended_pipeline_depth())
            .sum::<usize>()
            .max(1)
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
        if self.backends.len() == 1 {
            return self.backends[0]
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

        let assignments = split_assignments_for_weights(&self.weights, start_nonce, nonce_count);
        if assignments.is_empty() {
            return Ok(MiningChunkResult::empty());
        }

        let started = std::time::Instant::now();
        let mut tasks = JoinSet::new();

        for (idx, range_start, range_count) in assignments {
            let backend = self.backends[idx].clone();
            let midstate = midstate.clone();
            let nonce_table = nonce_table.clone();
            let cancel = cancel.clone();
            tasks.spawn(async move {
                backend
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
            let chunk = joined.map_err(|e| anyhow::anyhow!("composite task error: {e}"))??;
            attempted = attempted.saturating_add(chunk.attempted);
            best = choose_best_result(best, chunk.result);
        }

        Ok(MiningChunkResult {
            result: best,
            attempted,
            elapsed: started.elapsed(),
        })
    }

    async fn mine_work_units(
        &self,
        midstates: &[Sha256Midstate],
        nonce_table: &NonceTable,
        difficulty: u32,
        cancel: Option<CancelFlag>,
    ) -> anyhow::Result<Vec<MiningChunkResult>> {
        if midstates.is_empty() {
            return Ok(Vec::new());
        }

        let mut tasks = JoinSet::new();
        for (idx, midstate) in midstates.iter().enumerate() {
            let backend = self.backends[idx % self.backends.len()].clone();
            let midstate = midstate.clone();
            let nonce_table = nonce_table.clone();
            let cancel = cancel.clone();
            tasks.spawn(async move {
                let chunk = backend
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
                joined.map_err(|e| anyhow::anyhow!("composite task error: {e}"))??;
            ordered[idx] = Some(chunk);
        }

        ordered
            .into_iter()
            .enumerate()
            .map(|(i, opt)| opt.ok_or_else(|| anyhow::anyhow!("missing result for midstate {i}")))
            .collect()
    }
}
