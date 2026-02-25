//! CPU mining backend using rayon for parallel nonce iteration.
//!
//! This backend provides:
//! - Scalar fallback path on all architectures
//! - AVX2 8-way SIMD path on x86_64 when available at runtime

use async_trait::async_trait;
use rayon::prelude::*;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::sha256::{leading_zero_bits_words, state_words_to_bytes, Sha256Midstate};
use super::work_unit::NonceTable;
#[cfg(test)]
use super::work_unit::WorkUnit;
use super::{CancelFlag, MinerBackend, MiningChunkResult, MiningResult, NONCE_SPACE_SIZE};

/// SHA256 round constants.
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Per-task contiguous search block (nonce count) to reduce rayon scheduling overhead.
const CPU_PAR_BLOCK_NONCES: u32 = 16_384;

/// CPU miner using a dedicated rayon thread pool.
pub struct CpuMiner {
    thread_count: usize,
    pool: Arc<rayon::ThreadPool>,
    nonce_words: Arc<Vec<u32>>,
}

impl CpuMiner {
    pub fn new() -> Self {
        let default_threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        Self::with_threads(default_threads)
    }

    pub fn with_threads(thread_count: usize) -> Self {
        let max_threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let thread_count = thread_count.clamp(1, max_threads);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(thread_count)
            .build()
            .expect("failed to build rayon thread pool");

        let nonce_words = Arc::new(NonceTable::new().as_u32_slice());

        CpuMiner {
            thread_count,
            pool: Arc::new(pool),
            nonce_words,
        }
    }

    pub fn from_option(thread_count: Option<usize>) -> Self {
        match thread_count {
            Some(n) => Self::with_threads(n),
            None => Self::new(),
        }
    }

    pub fn thread_count(&self) -> usize {
        self.thread_count
    }
}

impl Default for CpuMiner {
    fn default() -> Self {
        Self::new()
    }
}

#[inline(always)]
fn nonce_indices(n: u32) -> (u16, u16) {
    ((n / 1000) as u16, (n % 1000) as u16)
}

#[inline(always)]
fn maybe_cancelled(cancel: Option<&CancelFlag>) -> bool {
    cancel
        .map(|flag| flag.load(Ordering::Relaxed))
        .unwrap_or(false)
}

#[inline(always)]
fn set_cancel(cancel: Option<&CancelFlag>) {
    if let Some(flag) = cancel {
        flag.store(true, Ordering::Relaxed);
    }
}

#[inline(always)]
fn score_state_and_build_result(
    n1: u16,
    n2: u16,
    state_words: &[u32; 8],
    difficulty: u32,
) -> Option<MiningResult> {
    if difficulty >= 16 && (state_words[0] & 0xFFFF_0000) != 0 {
        return None;
    }

    let difficulty_achieved = leading_zero_bits_words(state_words);
    if difficulty_achieved < difficulty {
        return None;
    }

    Some(MiningResult {
        nonce1_idx: n1,
        nonce2_idx: n2,
        hash: state_words_to_bytes(state_words),
        difficulty_achieved,
    })
}

fn search_scalar_range(
    midstate: &Sha256Midstate,
    nonce_words: &[u32],
    difficulty: u32,
    start_nonce: u32,
    end_nonce: u32,
    cancel: Option<&CancelFlag>,
) -> Option<MiningResult> {
    let mut idx = start_nonce;
    while idx < end_nonce {
        if maybe_cancelled(cancel) {
            return None;
        }

        let (n1, n2) = nonce_indices(idx);
        let nonce1_word = nonce_words[n1 as usize];
        let nonce2_word = nonce_words[n2 as usize];
        let state_words = midstate.finalize_words_from_nonce_u32(nonce1_word, nonce2_word);

        if let Some(result) = score_state_and_build_result(n1, n2, &state_words, difficulty) {
            set_cancel(cancel);
            return Some(result);
        }

        idx += 1;
    }

    None
}

fn search_best_range(
    midstate: &Sha256Midstate,
    nonce_words: &[u32],
    difficulty: u32,
    start_nonce: u32,
    end_nonce: u32,
    cancel: Option<&CancelFlag>,
) -> Option<MiningResult> {
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx2") {
            // SAFETY: runtime-guarded by is_x86_feature_detected!(\"avx2\").
            unsafe {
                return search_avx2_range(
                    midstate,
                    nonce_words,
                    difficulty,
                    start_nonce,
                    end_nonce,
                    cancel,
                );
            }
        }
    }

    search_scalar_range(
        midstate,
        nonce_words,
        difficulty,
        start_nonce,
        end_nonce,
        cancel,
    )
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn search_avx2_range(
    midstate: &Sha256Midstate,
    nonce_words: &[u32],
    difficulty: u32,
    start_nonce: u32,
    end_nonce: u32,
    cancel: Option<&CancelFlag>,
) -> Option<MiningResult> {
    use std::arch::x86_64::*;

    #[inline(always)]
    unsafe fn set1(v: u32) -> __m256i {
        _mm256_set1_epi32(v as i32)
    }

    #[inline(always)]
    unsafe fn add(a: __m256i, b: __m256i) -> __m256i {
        _mm256_add_epi32(a, b)
    }

    #[inline(always)]
    unsafe fn rotr(x: __m256i, n: i32) -> __m256i {
        match n {
            2 => _mm256_or_si256(_mm256_srli_epi32(x, 2), _mm256_slli_epi32(x, 30)),
            6 => _mm256_or_si256(_mm256_srli_epi32(x, 6), _mm256_slli_epi32(x, 26)),
            7 => _mm256_or_si256(_mm256_srli_epi32(x, 7), _mm256_slli_epi32(x, 25)),
            11 => _mm256_or_si256(_mm256_srli_epi32(x, 11), _mm256_slli_epi32(x, 21)),
            13 => _mm256_or_si256(_mm256_srli_epi32(x, 13), _mm256_slli_epi32(x, 19)),
            17 => _mm256_or_si256(_mm256_srli_epi32(x, 17), _mm256_slli_epi32(x, 15)),
            18 => _mm256_or_si256(_mm256_srli_epi32(x, 18), _mm256_slli_epi32(x, 14)),
            19 => _mm256_or_si256(_mm256_srli_epi32(x, 19), _mm256_slli_epi32(x, 13)),
            22 => _mm256_or_si256(_mm256_srli_epi32(x, 22), _mm256_slli_epi32(x, 10)),
            25 => _mm256_or_si256(_mm256_srli_epi32(x, 25), _mm256_slli_epi32(x, 7)),
            _ => unreachable!(),
        }
    }

    #[inline(always)]
    unsafe fn ch(x: __m256i, y: __m256i, z: __m256i) -> __m256i {
        _mm256_xor_si256(_mm256_and_si256(x, y), _mm256_andnot_si256(x, z))
    }

    #[inline(always)]
    unsafe fn maj(x: __m256i, y: __m256i, z: __m256i) -> __m256i {
        let xy = _mm256_and_si256(x, y);
        let xz = _mm256_and_si256(x, z);
        let yz = _mm256_and_si256(y, z);
        _mm256_xor_si256(_mm256_xor_si256(xy, xz), yz)
    }

    #[inline(always)]
    unsafe fn big_sigma0(x: __m256i) -> __m256i {
        _mm256_xor_si256(_mm256_xor_si256(rotr(x, 2), rotr(x, 13)), rotr(x, 22))
    }

    #[inline(always)]
    unsafe fn big_sigma1(x: __m256i) -> __m256i {
        _mm256_xor_si256(_mm256_xor_si256(rotr(x, 6), rotr(x, 11)), rotr(x, 25))
    }

    #[inline(always)]
    unsafe fn small_sigma0(x: __m256i) -> __m256i {
        let r1 = rotr(x, 7);
        let r2 = rotr(x, 18);
        let s = _mm256_srli_epi32(x, 3);
        _mm256_xor_si256(_mm256_xor_si256(r1, r2), s)
    }

    #[inline(always)]
    unsafe fn small_sigma1(x: __m256i) -> __m256i {
        let r1 = rotr(x, 17);
        let r2 = rotr(x, 19);
        let s = _mm256_srli_epi32(x, 10);
        _mm256_xor_si256(_mm256_xor_si256(r1, r2), s)
    }

    #[inline(always)]
    unsafe fn sha256_block_8(mid: &[u32; 8], w0: __m256i, w1: __m256i, w15: u32) -> [__m256i; 8] {
        let zero = _mm256_setzero_si256();
        let mut w = [zero; 64];

        w[0] = w0;
        w[1] = w1;
        w[2] = set1(0x6651_3d3d);
        w[3] = set1(0x8000_0000);
        w[14] = zero;
        w[15] = set1(w15);

        let mut i = 16usize;
        while i < 64 {
            let s1 = small_sigma1(w[i - 2]);
            let s0 = small_sigma0(w[i - 15]);
            w[i] = add(add(add(s1, w[i - 7]), s0), w[i - 16]);
            i += 1;
        }

        let mut a = set1(mid[0]);
        let mut b = set1(mid[1]);
        let mut c = set1(mid[2]);
        let mut d = set1(mid[3]);
        let mut e = set1(mid[4]);
        let mut f = set1(mid[5]);
        let mut g = set1(mid[6]);
        let mut h = set1(mid[7]);

        let mut round = 0usize;
        while round < 64 {
            let t1 = add(
                add(
                    add(add(h, big_sigma1(e)), ch(e, f, g)),
                    set1(SHA256_K[round]),
                ),
                w[round],
            );
            let t2 = add(big_sigma0(a), maj(a, b, c));

            h = g;
            g = f;
            f = e;
            e = add(d, t1);
            d = c;
            c = b;
            b = a;
            a = add(t1, t2);
            round += 1;
        }

        [
            add(a, set1(mid[0])),
            add(b, set1(mid[1])),
            add(c, set1(mid[2])),
            add(d, set1(mid[3])),
            add(e, set1(mid[4])),
            add(f, set1(mid[5])),
            add(g, set1(mid[6])),
            add(h, set1(mid[7])),
        ]
    }

    let mut idx = start_nonce;
    let w15 = ((midstate.prefix_len as u32) + 12) * 8;

    while idx + 8 <= end_nonce {
        if maybe_cancelled(cancel) {
            return None;
        }

        let mut n1_idx = [0u16; 8];
        let mut n2_idx = [0u16; 8];
        let mut n1_words = [0u32; 8];
        let mut n2_words = [0u32; 8];

        let mut lane = 0usize;
        while lane < 8 {
            let nonce = idx + lane as u32;
            let (n1, n2) = nonce_indices(nonce);
            n1_idx[lane] = n1;
            n2_idx[lane] = n2;
            n1_words[lane] = nonce_words[n1 as usize];
            n2_words[lane] = nonce_words[n2 as usize];
            lane += 1;
        }

        let w0 = _mm256_setr_epi32(
            n1_words[0] as i32,
            n1_words[1] as i32,
            n1_words[2] as i32,
            n1_words[3] as i32,
            n1_words[4] as i32,
            n1_words[5] as i32,
            n1_words[6] as i32,
            n1_words[7] as i32,
        );
        let w1 = _mm256_setr_epi32(
            n2_words[0] as i32,
            n2_words[1] as i32,
            n2_words[2] as i32,
            n2_words[3] as i32,
            n2_words[4] as i32,
            n2_words[5] as i32,
            n2_words[6] as i32,
            n2_words[7] as i32,
        );

        let states = sha256_block_8(&midstate.state, w0, w1, w15);

        let mut lanes_by_word = [[0u32; 8]; 8];
        let mut word = 0usize;
        while word < 8 {
            _mm256_storeu_si256(
                lanes_by_word[word].as_mut_ptr() as *mut __m256i,
                states[word],
            );
            word += 1;
        }

        lane = 0;
        while lane < 8 {
            let state_words = [
                lanes_by_word[0][lane],
                lanes_by_word[1][lane],
                lanes_by_word[2][lane],
                lanes_by_word[3][lane],
                lanes_by_word[4][lane],
                lanes_by_word[5][lane],
                lanes_by_word[6][lane],
                lanes_by_word[7][lane],
            ];

            if let Some(result) =
                score_state_and_build_result(n1_idx[lane], n2_idx[lane], &state_words, difficulty)
            {
                set_cancel(cancel);
                return Some(result);
            }
            lane += 1;
        }

        idx += 8;
    }

    if idx < end_nonce {
        return search_scalar_range(midstate, nonce_words, difficulty, idx, end_nonce, cancel);
    }

    None
}

#[async_trait]
impl MinerBackend for CpuMiner {
    fn name(&self) -> &str {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("avx2") {
                return "CPU (rayon+AVX2)";
            }
        }
        "CPU (rayon)"
    }

    fn startup_summary(&self) -> Vec<String> {
        #[cfg(target_arch = "x86_64")]
        {
            vec![
                format!("cpu_threads={}", self.thread_count),
                format!("cpu_avx2_enabled={}", std::is_x86_feature_detected!("avx2")),
            ]
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            vec![format!("cpu_threads={}", self.thread_count)]
        }
    }

    async fn benchmark(&self) -> anyhow::Result<f64> {
        let nonce_table = NonceTable::new();
        let midstate = Sha256Midstate::from_prefix(&[0u8; 64]);

        // Warm up thread pool and SIMD dispatch.
        let _ = self
            .mine_range(&midstate, &nonce_table, 256, 0, NONCE_SPACE_SIZE, None)
            .await?;

        let mut total_attempts = 0u64;
        let mut total_elapsed = 0.0f64;

        for _ in 0..5 {
            let chunk = self
                .mine_range(&midstate, &nonce_table, 256, 0, NONCE_SPACE_SIZE, None)
                .await?;
            total_attempts = total_attempts.saturating_add(chunk.attempted);
            total_elapsed += chunk.elapsed.as_secs_f64();
        }

        if total_elapsed <= 0.0 {
            return Ok(0.0);
        }

        Ok(total_attempts as f64 / total_elapsed)
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
        let start_nonce = start_nonce.min(NONCE_SPACE_SIZE);
        let end_nonce = start_nonce
            .saturating_add(nonce_count)
            .min(NONCE_SPACE_SIZE);
        if start_nonce >= end_nonce {
            return Ok(MiningChunkResult::empty());
        }

        let attempted = (end_nonce - start_nonce) as u64;
        let midstate = midstate.clone();
        let nonce_words = self.nonce_words.clone();
        let cancel = cancel.clone();
        let pool = self.pool.clone();

        tokio::task::spawn_blocking(move || {
            let started = std::time::Instant::now();

            let result = pool.install(|| {
                let total = end_nonce - start_nonce;
                let block_count = total.div_ceil(CPU_PAR_BLOCK_NONCES);

                (0..block_count).into_par_iter().find_map_any(|block_idx| {
                    if maybe_cancelled(cancel.as_ref()) {
                        return None;
                    }

                    let block_start =
                        start_nonce.saturating_add(block_idx.saturating_mul(CPU_PAR_BLOCK_NONCES));
                    let block_end = block_start
                        .saturating_add(CPU_PAR_BLOCK_NONCES)
                        .min(end_nonce);

                    search_best_range(
                        &midstate,
                        &nonce_words,
                        difficulty,
                        block_start,
                        block_end,
                        cancel.as_ref(),
                    )
                })
            });

            Ok(MiningChunkResult {
                result,
                attempted,
                elapsed: started.elapsed(),
            })
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
            8,
            Amount::from_wats(20_000_000_000_000),
            Amount::from_wats(1_000_000_000_000),
        );

        let result = cpu
            .mine_work_unit(&wu.midstate, &nonce_table, 8)
            .await
            .unwrap();

        assert!(
            result.result.is_some(),
            "should find solution at difficulty 8"
        );
        let result = result.result.unwrap();
        assert!(result.difficulty_achieved >= 8);
        assert!(result.nonce1_idx < 1000);
        assert!(result.nonce2_idx < 1000);

        let tail = WorkUnit::build_tail(&nonce_table, result.nonce1_idx, result.nonce2_idx);
        let verify_hash = wu.midstate.finalize(&tail);
        assert_eq!(verify_hash, result.hash);
    }
}
