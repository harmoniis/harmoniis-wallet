//! Cloud mining orchestration — provision GPU instances on Vast.ai,
//! upload an isolated webcash wallet, and run the miner remotely.
//!
//! Security: only a derived `{label}_webcash.db` is uploaded — never
//! the master wallet or any private key material.

pub mod config;
pub mod dispatch;
pub mod provision;
pub mod recovery;
pub mod slots;
pub mod ssh;
pub mod vast;
