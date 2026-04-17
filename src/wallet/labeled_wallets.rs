//! Labeled sub-wallet data types.
//!
//! Each wallet family (webcash, bitcoin, voucher, rgb) supports multiple
//! labeled wallets derived from the master keychain at different slot indices.
//!
//! The `LabeledWallet` struct is WASM-compatible (pure data).
//! SQLite-backed operations are in `core.rs` (native only).

use serde::{Deserialize, Serialize};

/// Descriptor for a labeled sub-wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabeledWallet {
    pub family: String,
    pub label: String,
    pub slot_index: u32,
    pub db_filename: String,
    pub descriptor: String,
}

/// Generate the DB filename for a labeled wallet.
pub fn wallet_db_filename(family: &str, label: &str) -> String {
    format!("{}_{}.db", label, family)
}
