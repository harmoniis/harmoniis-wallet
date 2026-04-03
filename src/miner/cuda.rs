//! CUDA mining backend using `cudarc` + NVRTC.
//!
//! Multi-GPU pipelining: each GPU gets a dedicated OS thread that binds its
//! CUDA context and creates a fresh stream per batch. Kernel and nonce table
//! are compiled/uploaded once during init and reused across batches.

use async_trait::async_trait;
use cudarc::driver::{
    CudaContext, CudaFunction, CudaSlice, CudaStream, LaunchConfig, PushKernelArg,
};
use cudarc::nvrtc::compile_ptx;
use std::sync::{Arc, Mutex};

use super::sha256::{leading_zero_bits_words, state_words_to_bytes, Sha256Midstate};
use super::work_unit::NonceTable;
use super::{CancelFlag, MinerBackend, MiningChunkResult, MiningResult, NONCE_SPACE_SIZE};

const CUDA_BLOCK_SIZE: u32 = 256;

/// Work units per GPU per mining cycle.
pub(crate) const PIPELINE_SLOTS: usize = 3;

pub struct CudaMiner {
    ctx: Arc<CudaContext>,
    stream: Arc<CudaStream>,
    kernel: CudaFunction,
    nonce_table_dev: CudaSlice<u32>,
    result_dev: Mutex<CudaSlice<u64>>,
    nonce_words: Vec<u32>,
    device_name: String,
    ordinal: usize,
}

impl CudaMiner {
    pub async fn try_new(ordinal: usize) -> Option<Self> {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Self::try_new_inner(ordinal)
        }));
        std::panic::set_hook(prev);
        result.ok().flatten()
    }

    fn try_new_inner(ordinal: usize) -> Option<Self> {
        let ctx = CudaContext::new(ordinal).ok()?;
        let stream = ctx.default_stream();
        let device_name = ctx.name().ok()?;

        let ptx = match compile_ptx(include_str!("shader/sha256_mine.cu")) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("CUDA[{}] NVRTC compilation failed: {}", ordinal, e);
                return None;
            }
        };
        let module = match ctx.load_module(ptx) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("CUDA[{}] module load failed: {}", ordinal, e);
                return None;
            }
        };
        let kernel = match module.load_function("mine_sha256") {
            Ok(k) => k,
            Err(e) => {
                eprintln!("CUDA[{}] kernel load failed: {}", ordinal, e);
                return None;
            }
        };

        let nonce_words = NonceTable::new().as_u32_slice();
        let nonce_table_dev = stream.clone_htod(&nonce_words).ok()?;
        let result_dev = stream.alloc_zeros::<u64>(1).ok()?;

        Some(Self {
            ctx,
            stream,
            kernel,
            nonce_table_dev,
            result_dev: Mutex::new(result_dev),
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

    fn best_result_from_packed(
        &self,
        midstate: &Sha256Midstate,
        difficulty: u32,
        packed_best: u64,
    ) -> Option<MiningResult> {
        let best_zeros = (packed_best >> 32) as u32;
        if best_zeros < difficulty {
            return None;
        }

        let nonce = (packed_best & 0xFFFF_FFFF) as u32;
        if nonce >= NONCE_SPACE_SIZE {
            return None;
        }

        let (n1, n2) = Self::nonce_indices(nonce);
        let state_words =
            midstate.finalize_words_from_nonce_u32(self.nonce_words[n1], self.nonce_words[n2]);
        let achieved = leading_zero_bits_words(&state_words);
        if achieved < difficulty {
            return None;
        }

        Some(MiningResult {
            nonce1_idx: n1 as u16,
            nonce2_idx: n2 as u16,
            hash: state_words_to_bytes(&state_words),
            difficulty_achieved: achieved,
        })
    }

    /// Single synchronous dispatch on self.stream (for benchmark).
    pub fn dispatch_range(
        &self,
        midstate: &Sha256Midstate,
        difficulty: u32,
        nonce_offset: u32,
        nonce_count: u32,
    ) -> anyhow::Result<Option<MiningResult>> {
        let mut result_dev = self
            .result_dev
            .lock()
            .map_err(|_| anyhow::anyhow!("cuda result buffer mutex poisoned"))?;

        self.stream.memset_zeros(&mut *result_dev)?;

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
        launch.arg(&nonce_offset);
        launch.arg(&nonce_count);
        launch.arg(&mut *result_dev);
        unsafe { launch.launch(cfg) }?;

        let mut host_best = [0u64; 1];
        self.stream.memcpy_dtoh(&*result_dev, &mut host_best)?;
        self.stream.synchronize()?;

        Ok(self.best_result_from_packed(midstate, difficulty, host_best[0]))
    }

    /// Pipeline multiple work units with FIFO enqueue + single sync.
    ///
    /// Key: ctx.bind_to_thread() + ctx.new_stream() creates a fresh stream
    /// bound to this GPU on the calling thread. The stored self.kernel and
    /// self.nonce_table_dev are reused (same context, no recompilation).
    pub fn mine_batch(
        &self,
        midstates: &[Sha256Midstate],
        difficulty: u32,
    ) -> anyhow::Result<Vec<MiningChunkResult>> {
        if midstates.is_empty() {
            return Ok(Vec::new());
        }

        self.ctx.bind_to_thread()
            .map_err(|e| anyhow::anyhow!("CUDA[{}] bind: {}", self.ordinal, e))?;
        let stream = self.ctx.new_stream()
            .map_err(|e| anyhow::anyhow!("CUDA[{}] stream: {}", self.ordinal, e))?;

        let n = midstates.len();
        let started = std::time::Instant::now();
        let nonce_count = NONCE_SPACE_SIZE;
        let nonce_offset = 0u32;
        let cfg = LaunchConfig {
            grid_dim: (nonce_count.div_ceil(CUDA_BLOCK_SIZE), 1, 1),
            block_dim: (CUDA_BLOCK_SIZE, 1, 1),
            shared_mem_bytes: 0,
        };

        // Allocate result buffers + enqueue all dispatches in one pass.
        let mut result_bufs: Vec<CudaSlice<u64>> = Vec::with_capacity(n);
        for i in 0..n {
            let mut rbuf = stream.alloc_zeros::<u64>(1)
                .map_err(|e| anyhow::anyhow!("CUDA[{}] alloc: {}", self.ordinal, e))?;

            let s = midstates[i].state_words();
            let prefix_len = midstates[i].prefix_len as u32;
            let mut launch = stream.launch_builder(&self.kernel);
            launch.arg(&self.nonce_table_dev);
            launch.arg(&s[0]); launch.arg(&s[1]); launch.arg(&s[2]); launch.arg(&s[3]);
            launch.arg(&s[4]); launch.arg(&s[5]); launch.arg(&s[6]); launch.arg(&s[7]);
            launch.arg(&difficulty);
            launch.arg(&prefix_len);
            launch.arg(&nonce_offset);
            launch.arg(&nonce_count);
            launch.arg(&mut rbuf);
            unsafe { launch.launch(cfg) }?;

            result_bufs.push(rbuf);
        }

        // Single sync — all kernels are done.
        stream.synchronize()?;

        // Batch readback — enqueue all DtoH copies then sync once.
        let mut host_results = vec![0u64; n];
        for i in 0..n {
            stream.memcpy_dtoh(&result_bufs[i], &mut host_results[i..i + 1])?;
        }
        stream.synchronize()?;

        // Parse results on CPU.
        let elapsed = started.elapsed();
        let results = host_results
            .iter()
            .enumerate()
            .map(|(i, &packed)| MiningChunkResult {
                result: self.best_result_from_packed(&midstates[i], difficulty, packed),
                attempted: NONCE_SPACE_SIZE as u64,
                elapsed,
            })
            .collect();

        Ok(results)
    }

    pub async fn mine_range_direct(
        &self,
        midstate: &Sha256Midstate,
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
            format!("cuda_pipeline_slots={}", PIPELINE_SLOTS),
            "cuda_result_mode=atomic_best_u64".to_string(),
        ]
    }

    async fn benchmark(&self) -> anyhow::Result<f64> {
        let midstate = Sha256Midstate::from_prefix(&[0u8; 64]);

        let _ = self
            .mine_range_direct(&midstate, 256, 0, NONCE_SPACE_SIZE, None)
            .await?;

        let mut samples = Vec::with_capacity(6);
        for _ in 0..6 {
            let chunk = self
                .mine_range_direct(&midstate, 256, 0, NONCE_SPACE_SIZE, None)
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
        self.mine_range_direct(midstate, difficulty, start_nonce, nonce_count, cancel)
            .await
    }
}
