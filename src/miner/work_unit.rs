//! Work unit construction: preimage prefix, nonce table, and midstate computation.
//!
//! Faithfully reproduces the C++ webminer's preimage format:
//! - JSON prefix padded to 48 raw bytes → 64 base64 bytes = one SHA256 block
//! - Nonce table: base64 of "000" through "999" (1000 entries × 4 chars each)
//! - Final suffix: "fQ==" (base64 of "}")

use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;
use webylib::{Amount, SecretWebcash};

use super::sha256::Sha256Midstate;

/// Pre-computed base64 nonce lookup table.
///
/// Each 3-digit string "000" through "999" is base64-encoded to a 4-char string.
/// The C++ webminer hardcodes these as a single concatenated string.
pub struct NonceTable {
    /// 4000 bytes: 1000 entries × 4 bytes each.
    data: Vec<u8>,
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

impl Clone for NonceTable {
    fn clone(&self) -> Self {
        NonceTable {
            data: self.data.clone(),
        }
    }
}

/// The final 4-byte suffix: base64 of "}".
pub const FINAL_SUFFIX: &[u8; 4] = b"fQ==";

/// A prepared work unit ready for mining.
pub struct WorkUnit {
    /// SHA256 midstate after processing the 64-byte prefix block.
    pub midstate: Sha256Midstate,
    /// The full base64-encoded prefix string (64 bytes).
    pub prefix_b64: String,
    /// The webcash secret the miner keeps (mining_amount - subsidy_amount).
    pub keep_secret: SecretWebcash,
    /// The subsidy secret (paid to Webcash LLC).
    pub subsidy_secret: SecretWebcash,
    /// Current difficulty target.
    pub difficulty: u32,
    /// Unix timestamp when the work unit was created.
    pub timestamp: f64,
}

impl WorkUnit {
    /// Build a new work unit with fresh random secrets and current parameters.
    ///
    /// This reproduces the C++ webminer's preimage construction exactly:
    /// 1. Format JSON prefix with keep/subsidy secrets, difficulty, timestamp
    /// 2. Pad to a multiple of 48 bytes (spaces, last char '1')
    /// 3. Base64 encode (becomes 64 bytes = one SHA256 block)
    /// 4. Compute midstate
    pub fn new(difficulty: u32, mining_amount: Amount, subsidy_amount: Amount) -> Self {
        let mut rng = rand::thread_rng();

        // Generate random 32-byte secrets
        let mut keep_sk = [0u8; 32];
        let mut subsidy_sk = [0u8; 32];
        rng.fill_bytes(&mut keep_sk);
        rng.fill_bytes(&mut subsidy_sk);

        let keep_amount = mining_amount - subsidy_amount;

        let keep_str_full = format!("e{}:secret:{}", keep_amount, hex::encode(keep_sk));
        let subsidy_str_full = format!("e{}:secret:{}", subsidy_amount, hex::encode(subsidy_sk));
        let keep_secret = SecretWebcash::parse(&keep_str_full).expect("valid keep secret format");
        let subsidy_secret = SecretWebcash::parse(&subsidy_str_full).expect("valid subsidy secret format");

        // Zero out raw key bytes
        keep_sk.fill(0);
        subsidy_sk.fill(0);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let keep_str = keep_secret.to_string();
        let subsidy_str = subsidy_secret.to_string();

        // Build the JSON prefix (matching C++ webminer format exactly)
        let mut prefix = format!(
            "{{\"legalese\": {{\"terms\": true}}, \"webcash\": [\"{}\", \"{}\"], \"subsidy\": [\"{}\"], \"difficulty\": {}, \"timestamp\": {}, \"nonce\": ",
            keep_str, subsidy_str, subsidy_str, difficulty, timestamp
        );

        // Pad to multiple of 48 bytes (space-fill, last char '1')
        let target_len = 48 * (1 + prefix.len() / 48);
        while prefix.len() < target_len {
            prefix.push(' ');
        }
        // Replace the last character with '1' to form a valid JSON nonce value
        prefix.pop();
        prefix.push('1');

        // Base64 encode → must be a multiple of 64 bytes (one or more SHA256 blocks)
        let prefix_b64 = STANDARD.encode(&prefix);
        assert_eq!(
            prefix_b64.len() % 64,
            0,
            "prefix_b64 must be a multiple of 64 bytes, got {}. Raw prefix was {} bytes.",
            prefix_b64.len(),
            prefix.len()
        );

        // Compute midstate from all prefix blocks
        let midstate = Sha256Midstate::from_prefix(prefix_b64.as_bytes());

        WorkUnit {
            midstate,
            prefix_b64,
            keep_secret,
            subsidy_secret,
            difficulty,
            timestamp,
        }
    }

    /// Reconstruct the full preimage string from nonce indices.
    ///
    /// Result = prefix_b64(64) + nonce1(4) + nonce2(4) + "fQ=="(4) = 76 chars.
    pub fn preimage_string(&self, nonce_table: &NonceTable, n1: u16, n2: u16) -> String {
        let mut s = String::with_capacity(76);
        s.push_str(&self.prefix_b64);
        s.push_str(std::str::from_utf8(nonce_table.get(n1)).unwrap());
        s.push_str(std::str::from_utf8(nonce_table.get(n2)).unwrap());
        s.push_str(std::str::from_utf8(FINAL_SUFFIX).unwrap());
        s
    }

    /// Build the 12-byte tail for a given nonce pair.
    pub fn build_tail(nonce_table: &NonceTable, n1: u16, n2: u16) -> [u8; 12] {
        let mut tail = [0u8; 12];
        tail[0..4].copy_from_slice(nonce_table.get(n1));
        tail[4..8].copy_from_slice(nonce_table.get(n2));
        tail[8..12].copy_from_slice(FINAL_SUFFIX);
        tail
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn nonce_table_first_entries() {
        let table = NonceTable::new();
        // "000" → base64 "MDAw"
        assert_eq!(table.get(0), b"MDAw");
        // "001" → base64 "MDAx"
        assert_eq!(table.get(1), b"MDAx");
        // "010" → base64 "MDEw"
        assert_eq!(table.get(10), b"MDEw");
        // "999" → base64 "OTk5"
        assert_eq!(table.get(999), b"OTk5");
    }

    #[test]
    fn nonce_table_matches_cpp_webminer() {
        let table = NonceTable::new();
        // The C++ webminer starts with "MDAwMDAx..." which is "MDAw" + "MDAx" = nonces[0]+nonces[1]
        assert_eq!(
            std::str::from_utf8(&table.data[0..8]).unwrap(),
            "MDAwMDAx"
        );
    }

    #[test]
    fn final_suffix_decodes_to_closing_brace() {
        let decoded = STANDARD.decode(FINAL_SUFFIX).unwrap();
        assert_eq!(decoded, b"}");
    }

    #[test]
    fn work_unit_prefix_is_multiple_of_64() {
        let wu = WorkUnit::new(28, Amount::from_wats(20_000_000_000_000), Amount::from_wats(1_000_000_000_000));
        assert_eq!(wu.prefix_b64.len() % 64, 0, "prefix must be a multiple of 64 bytes");
        assert!(wu.prefix_b64.len() >= 64, "prefix must be at least 64 bytes");
    }

    #[test]
    fn work_unit_preimage_length() {
        let table = NonceTable::new();
        let wu = WorkUnit::new(28, Amount::from_wats(20_000_000_000_000), Amount::from_wats(1_000_000_000_000));
        let preimage = wu.preimage_string(&table, 0, 0);
        // preimage = prefix_b64 + nonce1(4) + nonce2(4) + "fQ=="(4)
        assert_eq!(preimage.len(), wu.prefix_b64.len() + 12);
    }

    #[test]
    fn work_unit_preimage_hashes_correctly() {
        let table = NonceTable::new();
        let wu = WorkUnit::new(28, Amount::from_wats(20_000_000_000_000), Amount::from_wats(1_000_000_000_000));

        for n1 in [0u16, 42, 999] {
            for n2 in [0u16, 500, 999] {
                // Hash the full preimage with sha2
                let preimage = wu.preimage_string(&table, n1, n2);
                let ref_hash: [u8; 32] = Sha256::digest(preimage.as_bytes()).into();

                // Hash via midstate
                let tail = WorkUnit::build_tail(&table, n1, n2);
                let our_hash = wu.midstate.finalize(&tail);

                assert_eq!(our_hash, ref_hash, "mismatch at n1={}, n2={}", n1, n2);
            }
        }
    }
}
