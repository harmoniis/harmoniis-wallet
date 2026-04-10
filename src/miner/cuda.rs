//! CUDA mining backend using `cudarc` + NVRTC.
//!
//! This backend mirrors the WGSL miner algorithm and is used as a fallback
//! when Vulkan/wgpu adapters are unavailable.

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

/// Maximum number of work units batched per GPU in a single sync cycle.
const MAX_BATCH: usize = 64;

pub struct CudaMiner {
    stream: Arc<CudaStream>,
    kernel: CudaFunction,
    nonce_table_dev: CudaSlice<u32>,
    /// Pre-allocated result buffers — one per batch slot. Launching N kernels
    /// into N separate buffers then sync-ing once avoids N-1 redundant syncs.
    result_slots: Mutex<Vec<CudaSlice<u64>>>,
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
        match result {
            Ok(opt) => opt,
            Err(_) => {
                eprintln!("CUDA[{ordinal}]: initialization panicked (driver issue)");
                None
            }
        }
    }

    fn try_new_inner(ordinal: usize) -> Option<Self> {
        let ctx = match CudaContext::new(ordinal) {
            Ok(ctx) => ctx,
            Err(e) => {
                eprintln!("CUDA[{ordinal}]: context creation failed: {e}");
                return None;
            }
        };
        let stream = ctx.new_stream().unwrap_or_else(|_| ctx.default_stream());
        let device_name = match ctx.name() {
            Ok(name) => name,
            Err(e) => {
                eprintln!("CUDA[{ordinal}]: failed to get device name: {e}");
                return None;
            }
        };

        eprintln!("CUDA[{ordinal}]: compiling PTX for {device_name}...");
        let ptx = match compile_ptx(include_str!("shader/sha256_mine.cu")) {
            Ok(ptx) => ptx,
            Err(e) => {
                eprintln!("CUDA[{ordinal}]: PTX compilation failed: {e}");
                return None;
            }
        };
        let module = match ctx.load_module(ptx) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("CUDA[{ordinal}]: module load failed: {e}");
                return None;
            }
        };
        let kernel = match module.load_function("mine_sha256") {
            Ok(f) => f,
            Err(e) => {
                eprintln!("CUDA[{ordinal}]: kernel load failed: {e}");
                return None;
            }
        };

        let nonce_words = NonceTable::new().as_u32_slice();
        let nonce_table_dev = match stream.clone_htod(&nonce_words) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("CUDA[{ordinal}]: nonce table upload failed: {e}");
                return None;
            }
        };
        let mut result_slots = Vec::with_capacity(MAX_BATCH);
        for i in 0..MAX_BATCH {
            match stream.alloc_zeros::<u64>(1) {
                Ok(d) => result_slots.push(d),
                Err(e) => {
                    eprintln!("CUDA[{ordinal}]: result buffer {i} alloc failed: {e}");
                    return None;
                }
            }
        }

        eprintln!("CUDA[{ordinal}]: {device_name} ready");

        Some(Self {
            stream,
            kernel,
            nonce_table_dev,
            result_slots: Mutex::new(result_slots),
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

    /// Launch kernel into a specific result slot (async on stream, no sync).
    fn launch_into_slot(
        &self,
        slots: &mut [CudaSlice<u64>],
        slot: usize,
        midstate: &Sha256Midstate,
        difficulty: u32,
        nonce_offset: u32,
        nonce_count: u32,
    ) -> anyhow::Result<()> {
        // Kernel zeroes out_best itself (block 0, thread 0) — no host memset needed.

        let s = midstate.state_words();
        let cfg = LaunchConfig {
            grid_dim: (nonce_count.div_ceil(CUDA_BLOCK_SIZE), 1, 1),
            block_dim: (CUDA_BLOCK_SIZE, 1, 1),
            shared_mem_bytes: 0,
        };

        let prefix_len = midstate.prefix_len as u32;
        let mut launch = self.stream.launch_builder(&self.kernel);
        launch.arg(&self.nonce_table_dev);
        launch.arg(&s[0]);
        launch.arg(&s[1]);
        launch.arg(&s[2]);
        launch.arg(&s[3]);
        launch.arg(&s[4]);
        launch.arg(&s[5]);
        launch.arg(&s[6]);
        launch.arg(&s[7]);
        launch.arg(&difficulty);
        launch.arg(&prefix_len);
        launch.arg(&nonce_offset);
        launch.arg(&nonce_count);
        launch.arg(&mut slots[slot]);
        unsafe { launch.launch(cfg) }?;
        Ok(())
    }

    /// Mine a batch of midstates with ONE sync call instead of one per midstate.
    /// Each midstate gets its own result buffer slot, all kernels fire back-to-back
    /// on the same stream, then a single synchronize collects all results.
    pub fn mine_batch(
        &self,
        midstates: &[Sha256Midstate],
        difficulty: u32,
    ) -> anyhow::Result<Vec<MiningChunkResult>> {
        let mut slots = self
            .result_slots
            .lock()
            .map_err(|_| anyhow::anyhow!("cuda result slots mutex poisoned"))?;

        let batch_size = midstates.len().min(slots.len());
        let started = std::time::Instant::now();

        // Phase 1: fire all kernels (async, no sync between them).
        for (i, midstate) in midstates[..batch_size].iter().enumerate() {
            self.launch_into_slot(&mut slots, i, midstate, difficulty, 0, NONCE_SPACE_SIZE)?;
        }

        // Phase 2: single sync — wait for ALL kernels to complete.
        self.stream.synchronize()?;

        // Phase 3: read all results (device memory is stable after sync).
        let elapsed = started.elapsed();
        let mut results = Vec::with_capacity(batch_size);
        for (i, midstate) in midstates[..batch_size].iter().enumerate() {
            let mut host_best = [0u64; 1];
            self.stream.memcpy_dtoh(&slots[i], &mut host_best)?;
            results.push(MiningChunkResult {
                result: self.best_result_from_packed(midstate, difficulty, host_best[0]),
                attempted: NONCE_SPACE_SIZE as u64,
                elapsed,
            });
        }

        Ok(results)
    }

    pub fn dispatch_range(
        &self,
        midstate: &Sha256Midstate,
        difficulty: u32,
        nonce_offset: u32,
        nonce_count: u32,
    ) -> anyhow::Result<Option<MiningResult>> {
        let mut slots = self
            .result_slots
            .lock()
            .map_err(|_| anyhow::anyhow!("cuda result slots mutex poisoned"))?;

        self.launch_into_slot(
            &mut slots,
            0,
            midstate,
            difficulty,
            nonce_offset,
            nonce_count,
        )?;
        self.stream.synchronize()?;

        let mut host_best = [0u64; 1];
        self.stream.memcpy_dtoh(&slots[0], &mut host_best)?;

        Ok(self.best_result_from_packed(midstate, difficulty, host_best[0]))
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
            "cuda_result_mode=atomic_best_u64".to_string(),
        ]
    }

    async fn benchmark(&self) -> anyhow::Result<f64> {
        let midstate = Sha256Midstate::from_prefix(&[0u8; 64]);

        // Warmup.
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
