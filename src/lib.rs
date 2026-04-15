pub mod arbiter;
pub mod config;
pub mod crypto;
pub mod error;
pub mod identity;
pub mod marketplace;
pub mod miner;
pub mod types;
pub mod wallet;

// These modules moved into wallet/.
// Backward-compatible re-exports at crate root:
pub use wallet::ark;
pub use wallet::bitcoin;
pub use wallet::keychain;
pub use wallet::vault;
pub mod voucher_wallet {
    pub use crate::wallet::voucher::*;
}

/// Backward-compatible re-export. New code should use `marketplace` directly.
pub mod client {
    pub use crate::marketplace::*;
}

#[cfg(feature = "actix-actors")]
pub mod actors;

// Securities module — DORMANT. Compiled only when feature = "securities" is set.
// Do NOT enable in production until Phase 3 is released.
// Dependency order: Phase 1 (RGB21 contracts) → Phase 2 (Stablecash sandbox) → Phase 3 (securities)
#[cfg(feature = "securities")]
pub mod securities;

pub use error::{Error, Result};
pub use identity::Identity;
pub use types::{
    Certificate, Contract, ContractStatus, ContractType, Role, StablecashProof, StablecashSecret,
    VoucherProof, VoucherSecret, WitnessProof, WitnessSecret,
};
pub use vault::{VaultPublicIdentity, VaultRootMaterial};
pub use voucher_wallet::{VoucherStats, VoucherWallet};
pub use wallet::labeled_wallets::LabeledWallet;
pub use wallet::{
    NewPaymentAttempt, NewPaymentTransaction, NewPaymentTransactionEvent, PaymentAttemptRecord,
    PaymentAttemptUpdate, PaymentBlacklistRecord, PaymentLossRecord, PaymentTransactionEventRecord,
    PaymentTransactionRecord, PaymentTransactionUpdate, PgpIdentityRecord, PgpIdentitySnapshot,
    RgbWallet, WalletSlotRecord, WalletSnapshot,
};

// Webcash types re-exported from webylib (single dependency for consumers).
pub use wallet::webcash::{
    extract_webcash_secret, Amount as WebcashAmount, PublicWebcash, SecretWebcash,
    WebcashServerClient, WebcashWallet,
};

#[cfg(feature = "securities")]
pub use securities::{SecurityDeed, SecurityType, SecurityUnderlying};
