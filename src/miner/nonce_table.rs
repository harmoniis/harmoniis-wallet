//! Pre-computed base64 nonce lookup table for mining.
//!
//! WASM-safe. Only depends on `base64` (Layer 0).
//! Used by both the native GPU/CPU miners and the WASM WebGPU miner.

use base64::{engine::general_purpose::STANDARD, Engine};

/// Pre-computed base64 nonce lookup table.
///
/// Each 3-digit string "000" through "999" is base64-encoded to a 4-char string.
/// The C++ webminer hardcodes these as a single concatenated string.
pub struct NonceTable {
    /// 4000 bytes: 1000 entries × 4 bytes each.
    data: Vec<u8>,
}

impl Default for NonceTable {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for NonceTable {
    fn clone(&self) -> Self {
        NonceTable {
            data: self.data.clone(),
        }
    }
}

impl NonceTable {
    /// Generate the nonce table (deterministic — same output every time).
    pub fn new() -> Self {
        let mut data = Vec::with_capacity(4000);
        for i in 0u16..1000 {
            let s = format!("{:03}", i);
            let encoded = STANDARD.encode(&s);
            assert_eq!(encoded.len(), 4, "base64 of 3-byte string must be 4 chars");
            data.extend_from_slice(encoded.as_bytes());
        }
        assert_eq!(data.len(), 4000);
        NonceTable { data }
    }

    /// Get the 4-byte base64 nonce for index 0..999.
    pub fn get(&self, idx: u16) -> &[u8] {
        let start = idx as usize * 4;
        &self.data[start..start + 4]
    }

    /// Get the 4-byte nonce as a u32 (for GPU upload, preserving byte order).
    pub fn get_u32(&self, idx: u16) -> u32 {
        let b = self.get(idx);
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    }

    /// Raw data for GPU upload (1000 × u32, big-endian byte order).
    pub fn as_u32_slice(&self) -> Vec<u32> {
        (0..1000).map(|i| self.get_u32(i)).collect()
    }
}
