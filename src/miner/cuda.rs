//! CUDA mining backend using `cudarc` + NVRTC.
//!
//! Triple-buffered stream pipeline: while GPU computes work unit N on stream 0,
//! work unit N+1 is already enqueued on stream 1, and stream 2 is being collected.
//! GPU never idles between work units.

use async_trait::async_trait;
use cudarc::driver::{
    CudaContext, CudaFunction, CudaSlice, CudaStream, LaunchConfig, PushKernelArg,
};
use cudarc::nvrtc::{compile_ptx_with_opts, CompileOptions};
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
    kernel: CudaFunction,
    nonce_table_dev: CudaSlice<u32>,
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
        let default_stream = ctx.default_stream();
        let device_name = ctx.name().ok()?;

        // Target the actual GPU architecture for optimal code generation.
        // NVRTC defaults to compute_75 (Turing) which misses SM 8.6/8.9/12.0 optimizations.
        let arch = match ctx.compute_capability().ok()? {
            (major, minor) if major >= 12 => "compute_120",
            (8, minor) if minor >= 9 => "compute_89",
            (8, minor) if minor >= 6 => "compute_86",
            (8, _) => "compute_80",
            (7, _) => "compute_75",
            _ => "compute_75",
        };
        let opts = CompileOptions {
            arch: Some(arch),
            maxrregcount: Some(48),
            ..Default::default()
        };
        let ptx = compile_ptx_with_opts(include_str!("shader/sha256_mine.cu"), opts).ok()?;
        let module = ctx.load_module(ptx).ok()?;
        let kernel = module.load_function("mine_sha256").ok()?;

        let nonce_words = NonceTable::new().as_u32_slice();
        let nonce_table_dev = default_stream.clone_htod(&nonce_words).ok()?;

        // Ensure nonce table upload is visible to all streams.
        default_stream.synchronize().ok()?;

        // Create pipeline slots with independent streams.
        let mut slots = Vec::with_capacity(PIPELINE_SLOTS);
        for i in 0..PIPELINE_SLOTS {
            let stream = if i == 0 {
                default_stream.clone()
            } else {
                ctx.new_stream().ok()?
            };
            let result_dev = stream.alloc_zeros::<u64>(1).ok()?;
            slots.push(StreamSlot { stream, result_dev });
        }

        Some(Self {
            kernel,
            nonce_table_dev,
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

    /// Enqueue a kernel launch on a specific slot (non-blocking).
    fn dispatch_on_slot(
        &self,
        slot: &mut StreamSlot,
        midstate: &Sha256Midstate,
        difficulty: u32,
        nonce_offset: u32,
        nonce_count: u32,
    ) -> anyhow::Result<()> {
        slot.stream.memset_zeros(&mut slot.result_dev)?;

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

        let mut launch = slot.stream.launch_builder(&self.kernel);
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
        launch.arg(&mut slot.result_dev);
        unsafe { launch.launch(cfg) }?;

        Ok(())
    }

    /// Synchronize a slot's stream and read back the result (blocking).
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

    /// Single synchronous dispatch (backward compat for benchmark and mine_range).
    fn dispatch_range(
        &self,
        midstate: &Sha256Midstate,
        difficulty: u32,
        nonce_offset: u32,
        nonce_count: u32,
    ) -> anyhow::Result<Option<MiningResult>> {
        let mut slots = self
            .slots
            .lock()
            .map_err(|_| anyhow::anyhow!("cuda slot mutex poisoned"))?;

        let slot = &mut slots[0];
        self.dispatch_on_slot(slot, midstate, difficulty, nonce_offset, nonce_count)?;
        self.collect_from_slot(slot, midstate, difficulty)
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

    /// Pipeline-mine multiple work units with overlapping GPU compute.
    ///
    /// Uses round-robin across PIPELINE_SLOTS streams so the GPU is never idle
    /// between work units. While stream K is computing, stream K-1's result is
    /// being read back and stream K+1 is being dispatched.
    pub fn mine_batch(
        &self,
        midstates: &[Sha256Midstate],
        difficulty: u32,
        cancel: Option<CancelFlag>,
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

        let mut results: Vec<Option<MiningChunkResult>> = (0..n).map(|_| None).collect();

        // Track which midstate index is in-flight on each slot.
        let mut slot_midstate: Vec<Option<usize>> = vec![None; num_slots];

        // Phase 1: Fill the pipeline — dispatch up to num_slots work units.
        let mut next_dispatch = 0usize;
        for slot_idx in 0..num_slots.min(n) {
            self.dispatch_on_slot(
                &mut slots[slot_idx],
                &midstates[next_dispatch],
                difficulty,
                0,
                NONCE_SPACE_SIZE,
            )?;
            slot_midstate[slot_idx] = Some(next_dispatch);
            next_dispatch += 1;
        }

        // Phase 2: Steady-state — collect oldest, dispatch next, round-robin.
        let mut collected = 0usize;
        let mut collect_slot = 0usize;

        while collected < n {
            if let Some(flag) = cancel.as_ref() {
                if flag.load(std::sync::atomic::Ordering::Relaxed) {
                    // Fill remaining results as empty.
                    for r in results.iter_mut() {
                        if r.is_none() {
                            *r = Some(MiningChunkResult::empty());
                        }
                    }
                    break;
                }
            }

            let slot_idx = collect_slot % num_slots;
            if let Some(mid_idx) = slot_midstate[slot_idx] {
                // Collect result from this slot.
                let result =
                    self.collect_from_slot(&slots[slot_idx], &midstates[mid_idx], difficulty)?;

                results[mid_idx] = Some(MiningChunkResult {
                    result,
                    attempted: NONCE_SPACE_SIZE as u64,
                    elapsed: started.elapsed(),
                });
                collected += 1;

                // Dispatch next midstate on this now-free slot.
                if next_dispatch < n {
                    self.dispatch_on_slot(
                        &mut slots[slot_idx],
                        &midstates[next_dispatch],
                        difficulty,
                        0,
                        NONCE_SPACE_SIZE,
                    )?;
                    slot_midstate[slot_idx] = Some(next_dispatch);
                    next_dispatch += 1;
                } else {
                    slot_midstate[slot_idx] = None;
                }
            }
            collect_slot += 1;
        }

        Ok(results.into_iter().map(|r| r.unwrap()).collect())
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
