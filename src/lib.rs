pub mod arbiter;
pub mod client;
pub mod crypto;
pub mod error;
pub mod identity;
pub mod types;
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
    WitnessProof, WitnessSecret,
};
pub use wallet::{RgbWallet, WalletSnapshot};

#[cfg(feature = "securities")]
pub use securities::{SecurityDeed, SecurityType, SecurityUnderlying};
