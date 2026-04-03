//! CUDA mining backend — persistent GPU worker threads.
//!
//! Each GPU gets ONE dedicated OS thread spawned during init. The thread binds
//! the CUDA context, creates a stream, pre-allocates result buffers, then loops
//! forever waiting for work. Zero per-cycle overhead: no thread spawn, no stream
//! creation, no buffer allocation during mining.
//!
//! Architecture follows maaku/webminer's pattern: persistent threads, tight loop.

use async_trait::async_trait;
use cudarc::driver::{
    CudaContext, CudaFunction, CudaSlice, CudaStream, LaunchConfig, PushKernelArg,
};
use cudarc::nvrtc::compile_ptx;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use super::sha256::{leading_zero_bits_words, state_words_to_bytes, Sha256Midstate};
use super::work_unit::NonceTable;
use super::{CancelFlag, MinerBackend, MiningChunkResult, MiningResult, NONCE_SPACE_SIZE};

const CUDA_BLOCK_SIZE: u32 = 256;

/// Work units per GPU per mining cycle.
pub(crate) const PIPELINE_SLOTS: usize = 3;

/// Work request sent to a GPU worker thread.
struct WorkRequest {
    midstates: Vec<Sha256Midstate>,
    difficulty: u32,
}

/// A handle to a persistent GPU worker thread.
struct GpuWorker {
    work_tx: mpsc::Sender<WorkRequest>,
    result_rx: Mutex<mpsc::Receiver<anyhow::Result<Vec<MiningChunkResult>>>>,
}

pub struct CudaMiner {
    worker: GpuWorker,
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
        let init_stream = ctx.default_stream();
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
        let nonce_table_dev = init_stream.clone_htod(&nonce_words).ok()?;

        // Channels for work dispatch and result collection.
        let (work_tx, work_rx) = mpsc::channel::<WorkRequest>();
        let (result_tx, result_rx) = mpsc::channel();

        let nonce_words_clone = nonce_words.clone();

        // Spawn the persistent GPU worker thread.
        std::thread::Builder::new()
            .name(format!("cuda-gpu-{}", ordinal))
            .spawn(move || {
                gpu_worker_loop(
                    ctx,
                    kernel,
                    nonce_table_dev,
                    &nonce_words_clone,
                    ordinal,
                    work_rx,
                    result_tx,
                );
            })
            .ok()?;

        Some(Self {
            worker: GpuWorker {
                work_tx,
                result_rx: Mutex::new(result_rx),
            },
            nonce_words,
            device_name,
            ordinal,
        })
    }

    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    /// Send work to the persistent GPU thread and wait for results.
    pub fn mine_batch(
        &self,
        midstates: &[Sha256Midstate],
        difficulty: u32,
    ) -> anyhow::Result<Vec<MiningChunkResult>> {
        if midstates.is_empty() {
            return Ok(Vec::new());
        }

        self.worker
            .work_tx
            .send(WorkRequest {
                midstates: midstates.to_vec(),
                difficulty,
            })
            .map_err(|_| anyhow::anyhow!("CUDA[{}] worker thread dead", self.ordinal))?;

        self.worker
            .result_rx
            .lock()
            .map_err(|_| anyhow::anyhow!("CUDA[{}] result mutex poisoned", self.ordinal))?
            .recv()
            .map_err(|_| anyhow::anyhow!("CUDA[{}] worker thread dead", self.ordinal))?
    }

    /// Synchronous single-dispatch (used by benchmark).
    pub fn dispatch_range(
        &self,
        midstate: &Sha256Midstate,
        difficulty: u32,
        _nonce_offset: u32,
        _nonce_count: u32,
    ) -> anyhow::Result<Option<MiningResult>> {
        let chunks = self.mine_batch(&[midstate.clone()], difficulty)?;
        Ok(chunks.into_iter().next().and_then(|c| c.result))
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

/// Persistent GPU worker thread — runs forever, zero per-cycle allocation.
fn gpu_worker_loop(
    ctx: Arc<CudaContext>,
    kernel: CudaFunction,
    nonce_table_dev: CudaSlice<u32>,
    nonce_words: &[u32],
    ordinal: usize,
    work_rx: mpsc::Receiver<WorkRequest>,
    result_tx: mpsc::Sender<anyhow::Result<Vec<MiningChunkResult>>>,
) {
    // Bind context ONCE — this thread owns this GPU forever.
    if let Err(e) = ctx.bind_to_thread() {
        eprintln!("CUDA[{}] worker bind failed: {}", ordinal, e);
        return;
    }

    // Create stream ONCE.
    let stream = match ctx.new_stream() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("CUDA[{}] worker stream failed: {}", ordinal, e);
            return;
        }
    };

    // Pre-allocate result buffers (grow as needed, never shrink).
    let mut result_bufs: Vec<CudaSlice<u64>> = Vec::new();

    let cfg = LaunchConfig {
        grid_dim: (NONCE_SPACE_SIZE.div_ceil(CUDA_BLOCK_SIZE), 1, 1),
        block_dim: (CUDA_BLOCK_SIZE, 1, 1),
        shared_mem_bytes: 0,
    };
    let nonce_offset = 0u32;
    let nonce_count = NONCE_SPACE_SIZE;

    // Tight loop — wait for work, compute, send results.
    while let Ok(req) = work_rx.recv() {
        let started = std::time::Instant::now();
        let n = req.midstates.len();

        // Grow result buffer pool if needed.
        while result_bufs.len() < n {
            match stream.alloc_zeros::<u64>(1) {
                Ok(buf) => result_bufs.push(buf),
                Err(e) => {
                    let _ = result_tx.send(Err(anyhow::anyhow!(
                        "CUDA[{}] alloc: {}",
                        ordinal,
                        e
                    )));
                    continue;
                }
            }
        }

        // Enqueue ALL kernels — GPU processes FIFO, zero idle between them.
        let mut ok = true;
        for i in 0..n {
            if let Err(e) = stream.memset_zeros(&mut result_bufs[i]) {
                let _ = result_tx.send(Err(anyhow::anyhow!("CUDA[{}] memset: {}", ordinal, e)));
                ok = false;
                break;
            }

            let s = req.midstates[i].state_words();
            let prefix_len = req.midstates[i].prefix_len as u32;
            let mut launch = stream.launch_builder(&kernel);
            launch.arg(&nonce_table_dev);
            launch.arg(&s[0]);
            launch.arg(&s[1]);
            launch.arg(&s[2]);
            launch.arg(&s[3]);
            launch.arg(&s[4]);
            launch.arg(&s[5]);
            launch.arg(&s[6]);
            launch.arg(&s[7]);
            launch.arg(&req.difficulty);
            launch.arg(&prefix_len);
            launch.arg(&nonce_offset);
            launch.arg(&nonce_count);
            launch.arg(&mut result_bufs[i]);
            if let Err(e) = unsafe { launch.launch(cfg) } {
                let _ = result_tx.send(Err(anyhow::anyhow!("CUDA[{}] launch: {}", ordinal, e)));
                ok = false;
                break;
            }
        }
        if !ok {
            continue;
        }

        // Single sync — all kernels done.
        if let Err(e) = stream.synchronize() {
            let _ = result_tx.send(Err(anyhow::anyhow!("CUDA[{}] sync: {}", ordinal, e)));
            continue;
        }

        // Batch readback.
        let mut host_results = vec![0u64; n];
        let mut read_ok = true;
        for i in 0..n {
            if let Err(e) = stream.memcpy_dtoh(&result_bufs[i], &mut host_results[i..i + 1]) {
                let _ = result_tx.send(Err(anyhow::anyhow!("CUDA[{}] dtoh: {}", ordinal, e)));
                read_ok = false;
                break;
            }
        }
        if !read_ok {
            continue;
        }
        if let Err(e) = stream.synchronize() {
            let _ = result_tx.send(Err(anyhow::anyhow!("CUDA[{}] read sync: {}", ordinal, e)));
            continue;
        }

        // Parse results on CPU.
        let elapsed = started.elapsed();
        let results: Vec<MiningChunkResult> = host_results
            .iter()
            .enumerate()
            .map(|(i, &packed)| {
                let best_zeros = (packed >> 32) as u32;
                let nonce = (packed & 0xFFFF_FFFF) as u32;
                let result = if best_zeros >= req.difficulty && nonce < NONCE_SPACE_SIZE {
                    let n1 = (nonce / 1000) as usize;
                    let n2 = (nonce % 1000) as usize;
                    let state_words = req.midstates[i]
                        .finalize_words_from_nonce_u32(nonce_words[n1], nonce_words[n2]);
                    let achieved = leading_zero_bits_words(&state_words);
                    if achieved >= req.difficulty {
                        Some(MiningResult {
                            nonce1_idx: n1 as u16,
                            nonce2_idx: n2 as u16,
                            hash: state_words_to_bytes(&state_words),
                            difficulty_achieved: achieved,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                };
                MiningChunkResult {
                    result,
                    attempted: NONCE_SPACE_SIZE as u64,
                    elapsed,
                }
            })
            .collect();

        let _ = result_tx.send(Ok(results));
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
            "cuda_worker=persistent_thread".to_string(),
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
