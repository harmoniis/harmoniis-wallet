//! Actix actor wrappers for wallet components.
//!
//! Each actor owns its SQLite connection (solving the `!Send` constraint)
//! and communicates via typed [`actix::Message`] structs.
//!
//! Requires the `actix-actors` feature flag.

pub mod ark_actor;
pub mod bitcoin_actor;
pub mod payment_ledger_actor;
pub mod voucher_actor;
pub mod wallet_actor;
pub mod webcash_actor;
