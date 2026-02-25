//! SHA256 midstate computation for mining.
//!
//! The `sha2` crate does not expose internal state, so we implement the SHA256
//! compression function directly to support the midstate optimization: process
//! the fixed 64-byte prefix once, then resume from that saved state for each
//! nonce attempt (a single compression of the variable 64-byte tail block).

use sha2::digest::generic_array::typenum::U64;
use sha2::digest::generic_array::GenericArray;

/// SHA256 initial hash values.
const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA256 midstate: the 8-word internal state after processing N complete 64-byte blocks.
#[derive(Clone)]
pub struct Sha256Midstate {
    pub state: [u32; 8],
    /// Number of prefix bytes already processed (always a multiple of 64).
    pub prefix_len: usize,
    /// Pre-built padded tail block template. Bytes 0..12 are replaced per nonce.
    tail_template: [u8; 64],
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

        let mut tail_template = [0u8; 64];
        // Constant final suffix: base64(\"}\") = \"fQ==\"
        tail_template[8..12].copy_from_slice(b"fQ==");
        tail_template[12] = 0x80;
        let bit_len = ((prefix.len() + 12) as u64) * 8;
        tail_template[56..64].copy_from_slice(&bit_len.to_be_bytes());

        Sha256Midstate {
            state,
            prefix_len: prefix.len(),
            tail_template,
        }
    }

    /// Finalize: given a 12-byte tail (nonce1 + nonce2 + "fQ=="), pad it to a
    /// full 64-byte SHA256 block and compress from this midstate.
    ///
    /// Total message length = prefix_len + 12 bytes.
    pub fn finalize(&self, tail: &[u8; 12]) -> [u8; 32] {
        let state = self.finalize_words_from_tail(tail);
        state_words_to_bytes(&state)
    }

    /// Finalize and return the raw state words (big-endian hash words).
    pub fn finalize_words_from_tail(&self, tail: &[u8; 12]) -> [u32; 8] {
        let mut block = self.tail_template;
        block[..12].copy_from_slice(tail);
        let mut state = self.state;
        compress(&mut state, &block);
        state
    }

    /// Finalize directly from packed base64 nonce words (big-endian).
    pub fn finalize_words_from_nonce_u32(&self, nonce1_be: u32, nonce2_be: u32) -> [u32; 8] {
        let mut block = self.tail_template;
        block[0..4].copy_from_slice(&nonce1_be.to_be_bytes());
        block[4..8].copy_from_slice(&nonce2_be.to_be_bytes());
        let mut state = self.state;
        compress(&mut state, &block);
        state
    }

    /// Expose state words for GPU upload.
    pub fn state_words(&self) -> &[u32; 8] {
        &self.state
    }
}

/// Convert SHA256 state words into hash bytes (big-endian).
pub fn state_words_to_bytes(state: &[u32; 8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        hash[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    hash
}

/// Count leading zero bits in SHA256 state words (big-endian hash words).
pub fn leading_zero_bits_words(words: &[u32; 8]) -> u32 {
    let mut bits = 0u32;
    for &word in words {
        if word == 0 {
            bits += 32;
        } else {
            bits += word.leading_zeros();
            break;
        }
    }
    bits
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
    let ga: &GenericArray<u8, U64> = GenericArray::from_slice(block);
    sha2::compress256(state, std::slice::from_ref(ga));
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

        let tail: [u8; 12] = [
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x66, 0x51, 0x3d, 0x3d,
        ];

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
