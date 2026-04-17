//! Wallet engine — deterministic HD wallet for Webcash, Bitcoin, and RGB.
//!
//! # Module layout
//!
//! **Always available (WASM-compatible):**
//! - `keychain` — BIP32/BIP39 deterministic key derivation
//! - `vault` — HKDF-based vault key derivation (AEAD, signing, MQTT)
//! - `webcash` — Webcash type re-exports from webylib
//! - `labeled_wallets` — Labeled wallet data types
//!
//! **Native only (requires `native` feature — SQLite-backed):**
//! - `core` — `WalletCore` struct and all wallet operations
//! - `schema` — Database schema and migrations
//! - `contracts`, `identities`, `payments`, `snapshots`, `voucher`
//!
//! **Optional protocols:**
//! - `bitcoin` — BDK Bitcoin wallet (requires `bitcoin` feature)
//! - `ark` — ARK protocol VTXOs (requires `ark` feature)

// ── Always available (pure crypto, WASM-compatible) ──────────────
pub mod keychain;
pub mod vault;
pub mod webcash;
pub mod labeled_wallets;

// ── Native only (SQLite-backed WalletCore) ───────────────────────
#[cfg(feature = "native")]
mod core;
#[cfg(feature = "native")]
pub mod contracts;
#[cfg(feature = "native")]
pub mod identities;
#[cfg(feature = "native")]
pub mod payments;
#[cfg(feature = "native")]
pub mod schema;
#[cfg(feature = "native")]
pub mod snapshots;
#[cfg(feature = "native")]
pub mod voucher;

// ── Optional protocol modules ────────────────────────────────────
#[cfg(feature = "ark")]
pub mod ark;
#[cfg(feature = "bitcoin")]
pub mod bitcoin;

// ── Re-exports from native core ──────────────────────────────────
#[cfg(feature = "native")]
pub use self::core::*;
