//! Persistent CUDA mining backend.
//!
//! Launches a single kernel per GPU that runs forever, reading work from a
//! device-memory ring buffer. Eliminates kernel launch overhead entirely.
//!
//! The ring buffer has RING_SLOTS work slots. The host writes midstate + params
//! to a slot and sets `ready = 1`. The persistent kernel hashes all 1M nonces
//! for that slot, writes the best result, and sets `ready = 2`. The host then
//! reads the result and can reuse the slot.

use async_trait::async_trait;
use cudarc::driver::{CudaContext, CudaSlice, CudaStream, LaunchConfig, PushKernelArg};
use cudarc::nvrtc::{compile_ptx_with_opts, CompileOptions};
use std::sync::{Arc, Mutex};

use super::sha256::{leading_zero_bits_words, state_words_to_bytes, Sha256Midstate};
use super::work_unit::NonceTable;
use super::{CancelFlag, MinerBackend, MiningChunkResult, MiningResult, NONCE_SPACE_SIZE};

const CUDA_BLOCK_SIZE: u32 = 256;
const RING_SLOTS: usize = 4;

/// Words per ring slot (must match SLOT_WORDS in persistent kernel).
const SLOT_WORDS: usize = 16;

// Slot field offsets (must match #defines in sha256_mine_persistent.cu).
const SLOT_S0: usize = 0;
const SLOT_DIFF: usize = 8;
const SLOT_PFXLEN: usize = 9;
const SLOT_READY: usize = 10;
const SLOT_COUNTER: usize = 11;
const SLOT_BEST_HI: usize = 12;
const SLOT_BEST_LO: usize = 13;

struct PersistentState {
    stream: Arc<CudaStream>,
    /// Flat ring buffer on device: RING_SLOTS * SLOT_WORDS u32s.
    ring_dev: CudaSlice<u32>,
    shutdown_dev: CudaSlice<u32>,
    /// Host-side shadow for reading results.
    ring_host: Vec<u32>,
}

pub struct PersistentCudaMiner {
    state: Mutex<PersistentState>,
    nonce_words: Vec<u32>,
    device_name: String,
    ordinal: usize,
}

impl PersistentCudaMiner {
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

        let arch = match ctx.compute_capability().ok()? {
            (major, _) if major >= 12 => "compute_120",
            (8, minor) if minor >= 9 => "compute_89",
            (8, minor) if minor >= 6 => "compute_86",
            (8, _) => "compute_80",
            _ => "compute_75",
        };
        let opts = CompileOptions {
            arch: Some(arch),
            maxrregcount: Some(48),
            ..Default::default()
        };
        let ptx =
            compile_ptx_with_opts(include_str!("shader/sha256_mine_persistent.cu"), opts).ok()?;
        let module = ctx.load_module(ptx).ok()?;
        let kernel = module.load_function("mine_persistent").ok()?;

        // Upload nonce table.
        let nonce_words = NonceTable::new().as_u32_slice();
        let nonce_table_dev = stream.clone_htod(&nonce_words).ok()?;

        // Allocate ring buffer (all zeros = all slots empty).
        let ring_total = RING_SLOTS * SLOT_WORDS;
        let mut ring_dev = stream.alloc_zeros::<u32>(ring_total).ok()?;
        let ring_host = vec![0u32; ring_total];

        // Allocate shutdown flag.
        let mut shutdown_dev = stream.alloc_zeros::<u32>(1).ok()?;

        // Grid covers 1M nonces.
        let total_blocks = NONCE_SPACE_SIZE.div_ceil(CUDA_BLOCK_SIZE);
        let ring_slots_u32 = RING_SLOTS as u32;

        // Ensure uploads complete before kernel launch.
        stream.synchronize().ok()?;

        // Launch persistent kernel (runs forever until shutdown_flag is set).
        let cfg = LaunchConfig {
            grid_dim: (total_blocks, 1, 1),
            block_dim: (CUDA_BLOCK_SIZE, 1, 1),
            shared_mem_bytes: 0,
        };

        let mut launch = stream.launch_builder(&kernel);
        launch.arg(&nonce_table_dev);
        launch.arg(&mut ring_dev);
        launch.arg(&ring_slots_u32);
        launch.arg(&total_blocks);
        launch.arg(&mut shutdown_dev);
        unsafe { launch.launch(cfg) }.ok()?;

        // Kernel is now running asynchronously. Do NOT synchronize.

        Some(Self {
            state: Mutex::new(PersistentState {
                stream,
                ring_dev,
                shutdown_dev,
                ring_host,
            }),
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

    fn best_result_from_slot(
        &self,
        ring_host: &[u32],
        slot_idx: usize,
        midstate: &Sha256Midstate,
        difficulty: u32,
    ) -> Option<MiningResult> {
        let base = slot_idx * SLOT_WORDS;
        // Packed u64: [zeros:32 | nonce:32] stored as two u32s (big-endian pair).
        let packed = ((ring_host[base + SLOT_BEST_HI] as u64) << 32)
            | (ring_host[base + SLOT_BEST_LO] as u64);
        let best_zeros = (packed >> 32) as u32;
        let nonce = (packed & 0xFFFF_FFFF) as u32;

        if best_zeros < difficulty {
            return None;
        }
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

    /// Write a work unit into a ring slot (host -> device, partial via slice).
    fn submit_work(
        state: &mut PersistentState,
        slot_idx: usize,
        midstate: &Sha256Midstate,
        difficulty: u32,
    ) -> anyhow::Result<()> {
        let base = slot_idx * SLOT_WORDS;
        let s = midstate.state_words();

        // Build slot data locally.
        let mut slot_data = [0u32; SLOT_WORDS];
        slot_data[SLOT_S0..SLOT_S0 + 8].copy_from_slice(s);
        slot_data[SLOT_DIFF] = difficulty;
        slot_data[SLOT_PFXLEN] = midstate.prefix_len as u32;
        slot_data[SLOT_READY] = 1; // Signal: work available.
        slot_data[SLOT_COUNTER] = 0;
        slot_data[SLOT_BEST_HI] = 0;
        slot_data[SLOT_BEST_LO] = 0;

        // Write just this slot via a mutable slice of the ring buffer.
        let mut slot_view = state.ring_dev.slice_mut(base..base + SLOT_WORDS);
        state.stream.memcpy_htod(&slot_data, &mut slot_view)?;

        Ok(())
    }

    /// Poll a ring slot until ready == 2 (done), then read the full slot.
    fn poll_slot(state: &mut PersistentState, slot_idx: usize) -> anyhow::Result<()> {
        let base = slot_idx * SLOT_WORDS;

        loop {
            // Read just the ready flag via a slice view.
            let ready_view = state
                .ring_dev
                .slice(base + SLOT_READY..base + SLOT_READY + 1);
            let mut ready_buf = [0u32; 1];
            state.stream.memcpy_dtoh(&ready_view, &mut ready_buf)?;
            state.stream.synchronize()?;

            if ready_buf[0] == 2 {
                break;
            }

            // Sleep briefly — 10 us is negligible vs ~100 us kernel compute per WU.
            // Avoids burning a full CPU core per GPU while polling.
            std::thread::sleep(std::time::Duration::from_micros(10));
        }

        // Read the full slot for result extraction.
        let slot_view = state.ring_dev.slice(base..base + SLOT_WORDS);
        state
            .stream
            .memcpy_dtoh(&slot_view, &mut state.ring_host[base..base + SLOT_WORDS])?;
        state.stream.synchronize()?;

        Ok(())
    }

    /// Pipeline-mine multiple work units through the persistent kernel's ring buffer.
    pub fn mine_batch(
        &self,
        midstates: &[Sha256Midstate],
        difficulty: u32,
        cancel: Option<CancelFlag>,
    ) -> anyhow::Result<Vec<MiningChunkResult>> {
        if midstates.is_empty() {
            return Ok(Vec::new());
        }

        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("persistent cuda state mutex poisoned"))?;

        let n = midstates.len();
        let num_slots = RING_SLOTS;
        let started = std::time::Instant::now();

        let mut results: Vec<Option<MiningChunkResult>> = (0..n).map(|_| None).collect();
        let mut slot_midstate: Vec<Option<usize>> = vec![None; num_slots];

        // Phase 1: Fill the ring.
        let mut next_dispatch = 0usize;
        for slot_idx in 0..num_slots.min(n) {
            Self::submit_work(&mut state, slot_idx, &midstates[next_dispatch], difficulty)?;
            slot_midstate[slot_idx] = Some(next_dispatch);
            next_dispatch += 1;
        }

        // Phase 2: Steady-state — poll oldest, submit next.
        let mut collected = 0usize;
        let mut collect_slot = 0usize;

        while collected < n {
            if let Some(flag) = cancel.as_ref() {
                if flag.load(std::sync::atomic::Ordering::Relaxed) {
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
                Self::poll_slot(&mut state, slot_idx)?;

                let result = self.best_result_from_slot(
                    &state.ring_host,
                    slot_idx,
                    &midstates[mid_idx],
                    difficulty,
                );

                results[mid_idx] = Some(MiningChunkResult {
                    result,
                    attempted: NONCE_SPACE_SIZE as u64,
                    elapsed: started.elapsed(),
                });
                collected += 1;

                if next_dispatch < n {
                    Self::submit_work(&mut state, slot_idx, &midstates[next_dispatch], difficulty)?;
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

    /// Signal the persistent kernel to exit.
    pub fn shutdown(&self) -> anyhow::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("persistent cuda state mutex poisoned"))?;

        let flag = [1u32; 1];
        let PersistentState {
            ref stream,
            ref mut shutdown_dev,
            ..
        } = *state;
        stream.memcpy_htod(&flag, shutdown_dev)?;
        stream.synchronize()?;

        Ok(())
    }
}

impl Drop for PersistentCudaMiner {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[async_trait]
impl MinerBackend for PersistentCudaMiner {
    fn name(&self) -> &str {
        &self.device_name
    }

    fn startup_summary(&self) -> Vec<String> {
        vec![
            format!("persistent_cuda_device={}", self.device_name),
            format!("persistent_cuda_ordinal={}", self.ordinal),
            format!("persistent_cuda_ring_slots={}", RING_SLOTS),
            "persistent_cuda_mode=ring_buffer".to_string(),
        ]
    }

    async fn benchmark(&self) -> anyhow::Result<f64> {
        let midstate = Sha256Midstate::from_prefix(&[0u8; 64]);
        let midstates = vec![midstate; RING_SLOTS];

        // Warmup.
        let _ = self.mine_batch(&midstates, 256, None)?;

        let mut samples = Vec::with_capacity(6);
        for _ in 0..6 {
            let started = std::time::Instant::now();
            let chunks = self.mine_batch(&midstates, 256, None)?;
            let elapsed = started.elapsed().as_secs_f64();
            let total: u64 = chunks.iter().map(|c| c.attempted).sum();
            if elapsed > 0.0 {
                samples.push(total as f64 / elapsed);
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
        _start_nonce: u32,
        _nonce_count: u32,
        cancel: Option<CancelFlag>,
    ) -> anyhow::Result<MiningChunkResult> {
        let chunks = self.mine_batch(&[midstate.clone()], difficulty, cancel)?;
        Ok(chunks
            .into_iter()
            .next()
            .unwrap_or_else(MiningChunkResult::empty))
    }
}
