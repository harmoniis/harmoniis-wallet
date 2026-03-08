use rand::RngCore;
use sha2::{Digest, Sha256};

/// Generate a random 32-byte secret as 64-char lowercase hex.
/// Matches backend arbitration.rs line 152 generation logic.
pub fn generate_secret_hex() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// SHA256 of raw bytes, returned as 64-char hex.
/// Used for computing witness proof: sha256_bytes(&hex::decode(secret_hex)).
/// This matches backend witness.rs `secret_hash()` logic.
pub fn sha256_bytes(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hex::encode(hash)
}
