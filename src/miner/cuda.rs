//! CUDA mining backend using `cudarc` + NVRTC.
//!
//! This backend mirrors the WGSL miner algorithm and is used as a fallback
//! when Vulkan/wgpu adapters are unavailable.

use async_trait::async_trait;
use cudarc::driver::{
    CudaContext, CudaFunction, CudaSlice, CudaStream, LaunchConfig, PushKernelArg,
};
use cudarc::nvrtc::compile_ptx;
use std::sync::Arc;

use super::sha256::{leading_zero_bits_words, state_words_to_bytes, Sha256Midstate};
use super::work_unit::NonceTable;
use super::{CancelFlag, MinerBackend, MiningChunkResult, MiningResult, NONCE_SPACE_SIZE};

const CUDA_BLOCK_SIZE: u32 = 256;

pub struct CudaMiner {
    stream: Arc<CudaStream>,
    kernel: CudaFunction,
    nonce_table_dev: CudaSlice<u32>,
    nonce_words: Vec<u32>,
    device_name: String,
    ordinal: usize,
}

impl CudaMiner {
    pub async fn try_new(ordinal: usize) -> Option<Self> {
        let ctx = CudaContext::new(ordinal).ok()?;
        let stream = ctx.default_stream();
        let device_name = ctx.name().ok()?;

        let ptx = compile_ptx(include_str!("shader/sha256_mine.cu")).ok()?;
        let module = ctx.load_module(ptx).ok()?;
        let kernel = module.load_function("mine_sha256").ok()?;

        let nonce_words = NonceTable::new().as_u32_slice();
        let nonce_table_dev = stream.clone_htod(&nonce_words).ok()?;

        Some(Self {
            stream,
            kernel,
            nonce_table_dev,
            nonce_words,
            device_name,
            ordinal,
        })
    }

    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    fn nonce_indices(nonce: u32) -> (usize, usize) {
        ((nonce / 1000) as usize, (nonce % 1000) as usize)
    }

    fn best_result_from_scores(
        &self,
        midstate: &Sha256Midstate,
        difficulty: u32,
        start_nonce: u32,
        scores: &[u32],
    ) -> Option<MiningResult> {
        let mut best_zeros = 0u32;
        let mut best_idx = 0usize;
        for (idx, &score) in scores.iter().enumerate() {
            if score > best_zeros {
                best_zeros = score;
                best_idx = idx;
            }
        }
        if best_zeros < difficulty {
            return None;
        }

        let nonce = start_nonce + best_idx as u32;
        let (n1, n2) = Self::nonce_indices(nonce);
        let state =
            midstate.finalize_words_from_nonce_u32(self.nonce_words[n1], self.nonce_words[n2]);
        let achieved = leading_zero_bits_words(&state);
        if achieved < difficulty {
            return None;
        }

        Some(MiningResult {
            nonce1_idx: n1 as u16,
            nonce2_idx: n2 as u16,
            hash: state_words_to_bytes(&state),
            difficulty_achieved: achieved,
        })
    }

    fn dispatch_range(
        &self,
        midstate: &Sha256Midstate,
        difficulty: u32,
        start_nonce: u32,
        nonce_count: u32,
    ) -> anyhow::Result<Option<MiningResult>> {
        let mut out_scores = self.stream.alloc_zeros::<u32>(nonce_count as usize)?;
        let s = midstate.state_words();
        let s0 = s[0];
        let s1 = s[1];
        let s2 = s[2];
        let s3 = s[3];
        let s4 = s[4];
        let s5 = s[5];
        let s6 = s[6];
        let s7 = s[7];
        let prefix_len = midstate.prefix_len as u32;
        let cfg = LaunchConfig {
            grid_dim: (nonce_count.div_ceil(CUDA_BLOCK_SIZE), 1, 1),
            block_dim: (CUDA_BLOCK_SIZE, 1, 1),
            shared_mem_bytes: 0,
        };

        let mut launch = self.stream.launch_builder(&self.kernel);
        launch.arg(&self.nonce_table_dev);
        launch.arg(&s0);
        launch.arg(&s1);
        launch.arg(&s2);
        launch.arg(&s3);
        launch.arg(&s4);
        launch.arg(&s5);
        launch.arg(&s6);
        launch.arg(&s7);
        launch.arg(&difficulty);
        launch.arg(&prefix_len);
        launch.arg(&start_nonce);
        launch.arg(&nonce_count);
        launch.arg(&mut out_scores);
        unsafe { launch.launch(cfg) }?;

        self.stream.synchronize()?;
        let host_scores = self.stream.clone_dtoh(&out_scores)?;
        Ok(self.best_result_from_scores(midstate, difficulty, start_nonce, &host_scores))
    }
}

#[async_trait]
impl MinerBackend for CudaMiner {
    fn name(&self) -> &str {
        &self.device_name
    }

    fn startup_summary(&self) -> Vec<String> {
        vec![
            format!("cuda_device={}", self.device_name),
            format!("cuda_ordinal={}", self.ordinal),
            format!("cuda_block_size={}", CUDA_BLOCK_SIZE),
        ]
    }

    async fn benchmark(&self) -> anyhow::Result<f64> {
        let nonce_table = NonceTable::new();
        let midstate = Sha256Midstate::from_prefix(&[0u8; 64]);

        // Warmup.
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

    async fn mine_range(
        &self,
        midstate: &Sha256Midstate,
        _nonce_table: &NonceTable,
        difficulty: u32,
        start_nonce: u32,
        nonce_count: u32,
        cancel: Option<CancelFlag>,
    ) -> anyhow::Result<MiningChunkResult> {
        if let Some(flag) = cancel.as_ref() {
            if flag.load(std::sync::atomic::Ordering::Relaxed) {
                return Ok(MiningChunkResult::empty());
            }
        }

        let range_start = start_nonce.min(NONCE_SPACE_SIZE);
        let range_end = range_start
            .saturating_add(nonce_count)
            .min(NONCE_SPACE_SIZE);
        if range_start >= range_end {
            return Ok(MiningChunkResult::empty());
        }

        let started = std::time::Instant::now();
        let result =
            self.dispatch_range(midstate, difficulty, range_start, range_end - range_start)?;

        Ok(MiningChunkResult {
            result,
            attempted: (range_end - range_start) as u64,
            elapsed: started.elapsed(),
        })
    }
}
