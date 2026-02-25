//! CPU mining backend using rayon for parallel nonce iteration.

use async_trait::async_trait;

use super::sha256::{check_proof_of_work, leading_zero_bits, Sha256Midstate};
use super::work_unit::{NonceTable, WorkUnit};
use super::{MinerBackend, MiningResult};

/// CPU miner using rayon thread pool.
pub struct CpuMiner {
    _thread_count: usize,
}

impl CpuMiner {
    pub fn new() -> Self {
        let thread_count = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        CpuMiner { _thread_count: thread_count }
    }
}

#[async_trait]
impl MinerBackend for CpuMiner {
    fn name(&self) -> &str {
        "CPU (rayon)"
    }

    async fn benchmark(&self) -> anyhow::Result<f64> {
        let nonce_table = NonceTable::new();
        // Use a dummy midstate for benchmarking
        let midstate = Sha256Midstate::from_prefix(&[0u8; 64]);
        let _difficulty = 256; // impossibly high → no early exit, measures raw throughput

        let nonce_table_clone = nonce_table.clone();
        let midstate_clone = midstate.clone();

        let elapsed = tokio::task::spawn_blocking(move || {
            use rayon::prelude::*;
            let start = std::time::Instant::now();

            // Mine 100K nonces for benchmark
            let count = 100_000u32;
            (0..count).into_par_iter().for_each(|idx| {
                let n1 = (idx / 1000) as u16;
                let n2 = (idx % 1000) as u16;
                let tail = WorkUnit::build_tail(&nonce_table_clone, n1, n2);
                let hash = midstate_clone.finalize(&tail);
                // Prevent optimizer from eliminating the computation
                std::hint::black_box(hash);
            });

            let elapsed = start.elapsed();
            (count as f64) / elapsed.as_secs_f64()
        })
        .await?;

        Ok(elapsed)
    }

    async fn mine_work_unit(
        &self,
        midstate: &Sha256Midstate,
        nonce_table: &NonceTable,
        difficulty: u32,
    ) -> anyhow::Result<Option<MiningResult>> {
        let midstate = midstate.clone();
        let nonce_table = nonce_table.clone();

        tokio::task::spawn_blocking(move || {
            use rayon::prelude::*;

            let result = (0..1_000_000u32).into_par_iter().find_map_any(|idx| {
                let n1 = (idx / 1000) as u16;
                let n2 = (idx % 1000) as u16;

                let tail = WorkUnit::build_tail(&nonce_table, n1, n2);
                let hash = midstate.finalize(&tail);

                // Quick reject: first 2 bytes must be zero for difficulty >= 16
                if hash[0] != 0 || hash[1] != 0 {
                    return None;
                }

                if check_proof_of_work(&hash, difficulty) {
                    Some(MiningResult {
                        nonce1_idx: n1,
                        nonce2_idx: n2,
                        hash,
                        difficulty_achieved: leading_zero_bits(&hash),
                    })
                } else {
                    None
                }
            });

            Ok(result)
        })
        .await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webylib::Amount;

    #[tokio::test]
    async fn cpu_mining_low_difficulty() {
        let cpu = CpuMiner::new();
        let nonce_table = NonceTable::new();
        let wu = WorkUnit::new(
            8, // very low difficulty — should find solution quickly
            Amount::from_wats(20_000_000_000_000),
            Amount::from_wats(1_000_000_000_000),
        );

        let result = cpu
            .mine_work_unit(&wu.midstate, &nonce_table, 8)
            .await
            .unwrap();

        assert!(result.is_some(), "should find solution at difficulty 8");
        let result = result.unwrap();
        assert!(result.difficulty_achieved >= 8);
        assert!(result.nonce1_idx < 1000);
        assert!(result.nonce2_idx < 1000);

        // Verify the hash is correct
        let tail = WorkUnit::build_tail(&nonce_table, result.nonce1_idx, result.nonce2_idx);
        let verify_hash = wu.midstate.finalize(&tail);
        assert_eq!(verify_hash, result.hash);
    }
}
