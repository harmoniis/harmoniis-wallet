pub mod config;
pub mod crypto;
pub mod error;
pub mod identity;
pub mod types;
pub mod wallet;

// ── Always-available re-exports (WASM-compatible) ────────────────
pub use error::{Error, Result};
pub use identity::Identity;
pub use types::{
    Certificate, Contract, ContractStatus, ContractType, Role, StablecashProof, StablecashSecret,
    VoucherProof, VoucherSecret, WitnessProof, WitnessSecret,
};
pub use wallet::keychain;
pub use wallet::labeled_wallets::LabeledWallet;
pub use wallet::vault;
pub use vault::{VaultPublicIdentity, VaultRootMaterial};

// Webcash utilities (always available)
pub use wallet::webcash::extract_webcash_secret;

// Storage trait and types (always available)
pub use wallet::store::{
    HarmoniiStore, NewPaymentAttempt, NewPaymentTransaction, NewPaymentTransactionEvent,
    PaymentAttemptRecord, PaymentAttemptUpdate, PaymentBlacklistRecord, PaymentLossRecord,
    PaymentTransactionEventRecord, PaymentTransactionRecord, PaymentTransactionUpdate,
    PgpIdentityRecord, PgpIdentityRow, PgpIdentitySnapshot, WalletSlotRecord, WalletSnapshot,
};
pub use wallet::store_mem::MemHarmoniiStore;
pub use wallet::snapshots::FullBackup;

// Re-export webylib for downstream access to protocol defs (NetworkMode, endpoints)
pub use webylib;

// Webcash types from webylib (available on all targets)
pub use wallet::webcash::{Amount as WebcashAmount, PublicWebcash, SecretWebcash};
#[cfg(any(feature = "native", feature = "wasm"))]
pub use wallet::webcash::{WebcashServerClient, WebcashWallet};

// ── Native-only modules and re-exports ───────────────────────────
#[cfg(feature = "native")]
pub mod arbiter;
#[cfg(feature = "native")]
pub mod marketplace;
#[cfg(any(feature = "native", feature = "gpu-wasm"))]
pub mod miner;

#[cfg(feature = "native")]
pub mod voucher_wallet {
    pub use crate::wallet::voucher::*;
}

#[cfg(feature = "native")]
pub mod client {
    pub use crate::marketplace::*;
}

#[cfg(feature = "native")]
pub use voucher_wallet::{VoucherStats, VoucherWallet};

#[cfg(feature = "native")]
pub use wallet::store_sqlite::SqliteHarmoniiStore;

#[cfg(feature = "native")]
pub use wallet::RgbWallet;

// ── Optional features ────────────────────────────────────────────
#[cfg(feature = "ark")]
pub use wallet::ark;
#[cfg(feature = "bitcoin")]
pub use wallet::bitcoin;
#[cfg(feature = "actix-actors")]
pub mod actors;
#[cfg(feature = "securities")]
pub mod securities;
#[cfg(feature = "securities")]
pub use securities::{SecurityDeed, SecurityType, SecurityUnderlying};
