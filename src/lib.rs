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

// Webcash types re-exported from webylib.
pub use wallet::webcash::{
    extract_webcash_secret, Amount as WebcashAmount, PublicWebcash, SecretWebcash,
};

// ── Native-only modules and re-exports ───────────────────────────
#[cfg(feature = "native")]
pub mod arbiter;
#[cfg(feature = "native")]
pub mod marketplace;
#[cfg(feature = "native")]
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
pub use wallet::webcash::{WebcashServerClient, WebcashWallet};

#[cfg(feature = "native")]
pub use wallet::{
    NewPaymentAttempt, NewPaymentTransaction, NewPaymentTransactionEvent, PaymentAttemptRecord,
    PaymentAttemptUpdate, PaymentBlacklistRecord, PaymentLossRecord, PaymentTransactionEventRecord,
    PaymentTransactionRecord, PaymentTransactionUpdate, PgpIdentityRecord, PgpIdentitySnapshot,
    RgbWallet, WalletSlotRecord, WalletSnapshot,
};

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
