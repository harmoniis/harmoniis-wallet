//! CUDA mining backend using `cudarc` + NVRTC.
//!
//! Single-stream synchronous dispatch (v0.1.42 proven pattern).
//! Kernel uses LOP3/funnelshift/shared-memory optimizations compiled via
//! default NVRTC (compute_75 PTX, JIT to actual SM by driver).

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

const PIPELINE_SLOTS: usize = 3;

struct StreamSlot {
    stream: Arc<CudaStream>,
    result_dev: CudaSlice<u64>,
}

pub struct CudaMiner {
    stream: Arc<CudaStream>,
    kernel: CudaFunction,
    nonce_table_dev: CudaSlice<u32>,
    result_dev: Mutex<CudaSlice<u64>>,
    slots: Mutex<Vec<StreamSlot>>,
    nonce_words: Vec<u32>,
    device_name: String,
    ordinal: usize,
}

impl CudaMiner {
    pub async fn try_new(ordinal: usize) -> Option<Self> {
        // cudarc panics (instead of returning Err) when NVRTC is missing.
        // Catch the panic so we fall back to wgpu gracefully.
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

        // Compile with default NVRTC settings (compute_75 PTX, JIT to actual SM).
        // No arch/maxrregcount — those caused silent failures on some NVRTC versions.
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

        // Ensure nonce table upload is complete before other streams use it.
        stream.synchronize().ok()?;

        // Create pipeline slots with independent streams.
        let mut slots = Vec::with_capacity(PIPELINE_SLOTS);
        for i in 0..PIPELINE_SLOTS {
            let slot_stream = if i == 0 {
                stream.clone()
            } else {
                ctx.new_stream().ok()?
            };
            let slot_result = slot_stream.alloc_zeros::<u64>(1).ok()?;
            slots.push(StreamSlot {
                stream: slot_stream,
                result_dev: slot_result,
            });
        }

        // ctx is not stored — cudarc auto-binds context on stream operations.
        drop(ctx);

        Some(Self {
            stream,
            kernel,
            nonce_table_dev,
            result_dev: Mutex::new(result_dev),
            slots: Mutex::new(slots),
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

    /// Pipeline midstates across stream slots on this GPU.
    /// Dispatches to all slots first, then collects oldest while newest computes.
    pub fn mine_batch(
        &self,
        midstates: &[Sha256Midstate],
        difficulty: u32,
    ) -> anyhow::Result<Vec<MiningChunkResult>> {
        if midstates.is_empty() {
            return Ok(Vec::new());
        }

        let mut slots = self
            .slots
            .lock()
            .map_err(|_| anyhow::anyhow!("cuda slot mutex poisoned"))?;
        let num_slots = slots.len();
        let n = midstates.len();
        let started = std::time::Instant::now();

        let mut slot_mid: Vec<Option<usize>> = vec![None; num_slots];
        let mut results: Vec<Option<MiningChunkResult>> = (0..n).map(|_| None).collect();
        let mut next_dispatch = 0usize;
        let mut collected = 0usize;

        // Phase 1: Fill all slots (dispatch without waiting).
        for s in 0..num_slots.min(n) {
            self.dispatch_on_slot(&mut slots[s], &midstates[next_dispatch], difficulty)?;
            slot_mid[s] = Some(next_dispatch);
            next_dispatch += 1;
        }

        // Phase 2: Collect oldest, dispatch next on freed slot.
        let mut collect_idx = 0usize;
        while collected < n {
            let s = collect_idx % num_slots;
            if let Some(mid_idx) = slot_mid[s] {
                let result = self.collect_from_slot(&slots[s], &midstates[mid_idx], difficulty)?;
                results[mid_idx] = Some(MiningChunkResult {
                    result,
                    attempted: NONCE_SPACE_SIZE as u64,
                    elapsed: started.elapsed(),
                });
                collected += 1;

                if next_dispatch < n {
                    self.dispatch_on_slot(&mut slots[s], &midstates[next_dispatch], difficulty)?;
                    slot_mid[s] = Some(next_dispatch);
                    next_dispatch += 1;
                } else {
                    slot_mid[s] = None;
                }
            }
            collect_idx += 1;
        }

        Ok(results
            .into_iter()
            .map(|o| o.unwrap_or_else(MiningChunkResult::empty))
            .collect())
    }

    fn dispatch_on_slot(
        &self,
        slot: &mut StreamSlot,
        midstate: &Sha256Midstate,
        difficulty: u32,
    ) -> anyhow::Result<()> {
        slot.stream.memset_zeros(&mut slot.result_dev)?;

        let s = midstate.state_words();
        let prefix_len = midstate.prefix_len as u32;
        let zero = 0u32;
        let nonce_count = NONCE_SPACE_SIZE;

        let cfg = LaunchConfig {
            grid_dim: (NONCE_SPACE_SIZE.div_ceil(CUDA_BLOCK_SIZE), 1, 1),
            block_dim: (CUDA_BLOCK_SIZE, 1, 1),
            shared_mem_bytes: 0,
        };

        let mut launch = slot.stream.launch_builder(&self.kernel);
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
        launch.arg(&zero);
        launch.arg(&nonce_count);
        launch.arg(&mut slot.result_dev);
        unsafe { launch.launch(cfg) }?;
        Ok(())
    }

    fn collect_from_slot(
        &self,
        slot: &StreamSlot,
        midstate: &Sha256Midstate,
        difficulty: u32,
    ) -> anyhow::Result<Option<MiningResult>> {
        let mut host_best = [0u64; 1];
        slot.stream.memcpy_dtoh(&slot.result_dev, &mut host_best)?;
        slot.stream.synchronize()?;
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
