//! SHA256 midstate computation for mining.
//!
//! The `sha2` crate does not expose internal state, so we implement the SHA256
//! compression function directly to support the midstate optimization: process
//! the fixed 64-byte prefix once, then resume from that saved state for each
//! nonce attempt (a single compression of the variable 64-byte tail block).

/// SHA256 round constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes).
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA256 initial hash values.
const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA256 midstate: the 8-word internal state after processing N complete 64-byte blocks.
#[derive(Clone)]
pub struct Sha256Midstate {
    pub state: [u32; 8],
    /// Number of prefix bytes already processed (always a multiple of 64).
    pub prefix_len: usize,
}

impl Sha256Midstate {
    /// Compute the midstate from a prefix that is a multiple of 64 bytes.
    ///
    /// The C++ webminer pads the raw JSON to a multiple of 48 bytes, then base64-
    /// encodes it. The result is a multiple of 64 bytes (one or more SHA256 blocks).
    pub fn from_prefix(prefix: &[u8]) -> Self {
        assert!(
            prefix.len() % 64 == 0 && !prefix.is_empty(),
            "prefix must be a non-zero multiple of 64 bytes, got {}",
            prefix.len()
        );
        let mut state = H_INIT;
        for chunk in prefix.chunks_exact(64) {
            let block: &[u8; 64] = chunk.try_into().unwrap();
            compress(&mut state, block);
        }
        Sha256Midstate {
            state,
            prefix_len: prefix.len(),
        }
    }

    /// Finalize: given a 12-byte tail (nonce1 + nonce2 + "fQ=="), pad it to a
    /// full 64-byte SHA256 block and compress from this midstate.
    ///
    /// Total message length = prefix_len + 12 bytes.
    pub fn finalize(&self, tail: &[u8; 12]) -> [u8; 32] {
        let mut block = [0u8; 64];

        // Bytes 0..12: the tail data
        block[..12].copy_from_slice(tail);

        // Byte 12: SHA256 padding bit
        block[12] = 0x80;

        // Bytes 13..55: zeros (already zero)

        // Bytes 56..64: big-endian 64-bit total message length in bits
        let total_bytes = (self.prefix_len + 12) as u64;
        let bit_len = total_bytes * 8;
        block[56..64].copy_from_slice(&bit_len.to_be_bytes());

        let mut state = self.state;
        compress(&mut state, &block);

        // Convert state words to big-endian bytes
        let mut hash = [0u8; 32];
        for (i, word) in state.iter().enumerate() {
            hash[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        hash
    }

    /// Expose state words for GPU upload.
    pub fn state_words(&self) -> &[u32; 8] {
        &self.state
    }
}

/// Count leading zero bits in a 32-byte hash.
pub fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut bits = 0u32;
    for &byte in hash.iter() {
        if byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

/// Check if a hash meets the given proof-of-work difficulty (leading zero bits).
pub fn check_proof_of_work(hash: &[u8; 32], difficulty: u32) -> bool {
    leading_zero_bits(hash) >= difficulty
}

/// SHA256 compression function: process one 64-byte block, updating `state` in place.
fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    // Parse block into 16 big-endian u32 words
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }

    // Extend to 64 words
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    // Compression rounds
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    // Add compressed chunk to running hash
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// Verify our midstate + finalize matches sha2 crate on a 64-byte prefix + 12-byte tail.
    #[test]
    fn midstate_matches_sha2_crate() {
        // Arbitrary 64-byte prefix (one block)
        let mut prefix = [0u8; 64];
        for (i, b) in prefix.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(13);
        }

        let tail: [u8; 12] = [0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x66, 0x51, 0x3d, 0x3d];

        let midstate = Sha256Midstate::from_prefix(&prefix);
        let our_hash = midstate.finalize(&tail);

        let mut hasher = Sha256::new();
        hasher.update(&prefix);
        hasher.update(&tail);
        let ref_hash: [u8; 32] = hasher.finalize().into();

        assert_eq!(our_hash, ref_hash, "midstate hash must match sha2 crate");
    }

    /// Test with all-zeros prefix + all-zeros tail.
    #[test]
    fn midstate_all_zeros() {
        let prefix = [0u8; 64];
        let tail = [0u8; 12];

        let midstate = Sha256Midstate::from_prefix(&prefix);
        let our_hash = midstate.finalize(&tail);

        let mut hasher = Sha256::new();
        hasher.update(&prefix);
        hasher.update(&tail);
        let ref_hash: [u8; 32] = hasher.finalize().into();

        assert_eq!(our_hash, ref_hash);
    }

    /// Test with multi-block prefix (512 bytes = 8 SHA256 blocks).
    #[test]
    fn midstate_multi_block_prefix() {
        let mut prefix = vec![0u8; 512];
        for (i, b) in prefix.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(3).wrapping_add(42);
        }

        let tail: [u8; 12] = *b"MDAwMDAyfQ==";

        let midstate = Sha256Midstate::from_prefix(&prefix);
        let our_hash = midstate.finalize(&tail);

        let mut hasher = Sha256::new();
        hasher.update(&prefix);
        hasher.update(&tail);
        let ref_hash: [u8; 32] = hasher.finalize().into();

        assert_eq!(our_hash, ref_hash);
    }

    #[test]
    fn leading_zero_bits_counting() {
        let mut hash = [0u8; 32];
        assert_eq!(leading_zero_bits(&hash), 256); // all zeros

        hash[0] = 0x01;
        assert_eq!(leading_zero_bits(&hash), 7);

        hash[0] = 0x80;
        assert_eq!(leading_zero_bits(&hash), 0);

        hash[0] = 0x00;
        hash[1] = 0x00;
        hash[2] = 0x0F;
        assert_eq!(leading_zero_bits(&hash), 20);

        hash[2] = 0x00;
        hash[3] = 0x01;
        assert_eq!(leading_zero_bits(&hash), 31);
    }

    #[test]
    fn proof_of_work_check() {
        let mut hash = [0u8; 32];
        hash[3] = 0x01; // 31 leading zeros
        assert!(check_proof_of_work(&hash, 28));
        assert!(check_proof_of_work(&hash, 31));
        assert!(!check_proof_of_work(&hash, 32));
    }

    /// Fuzz test: random inputs with varying prefix sizes (1..8 blocks).
    #[test]
    fn midstate_fuzz_vs_sha2() {
        use rand::RngCore;
        let mut rng = rand::thread_rng();

        for _ in 0..100 {
            // Random prefix size: 1..8 blocks of 64 bytes
            let num_blocks = (rng.next_u32() % 8 + 1) as usize;
            let mut prefix = vec![0u8; num_blocks * 64];
            let mut tail = [0u8; 12];
            rng.fill_bytes(&mut prefix);
            rng.fill_bytes(&mut tail);

            let midstate = Sha256Midstate::from_prefix(&prefix);
            let our_hash = midstate.finalize(&tail);

            let mut hasher = Sha256::new();
            hasher.update(&prefix);
            hasher.update(&tail);
            let ref_hash: [u8; 32] = hasher.finalize().into();

            assert_eq!(our_hash, ref_hash, "mismatch on fuzz iteration");
        }
    }
}
