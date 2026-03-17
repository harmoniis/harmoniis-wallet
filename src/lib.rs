pub mod arbiter;
pub mod ark;
pub mod bitcoin;
pub mod client;
pub mod crypto;
pub mod error;
pub mod identity;
pub mod keychain;
pub mod miner;
pub mod types;
pub mod vault;
pub mod voucher_wallet;
pub mod wallet;

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
pub use wallet::{
    NewPaymentAttempt, PaymentAttemptRecord, PaymentAttemptUpdate, PaymentBlacklistRecord,
    PaymentLossRecord, PgpIdentityRecord, PgpIdentitySnapshot, RgbWallet, WalletSlotRecord,
    WalletSnapshot,
};

#[cfg(feature = "securities")]
pub use securities::{SecurityDeed, SecurityType, SecurityUnderlying};
