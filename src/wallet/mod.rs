//! Wallet engine — deterministic HD wallet for Webcash, Bitcoin, and RGB.
//!
//! # Module layout
//!
//! **Always available (WASM-compatible):**
//! - `keychain` — BIP32/BIP39 deterministic key derivation
//! - `vault` — HKDF-based vault key derivation (AEAD, signing, MQTT)
//! - `webcash` — Webcash type re-exports from webylib
//! - `labeled_wallets` — Labeled wallet data types
//! - `store` — `HarmoniiStore` trait + all storage types
//! - `store_mem` — `MemHarmoniiStore` (in-memory, JSON-serializable)
//! - `core` — `WalletCore` struct + business logic
//! - `identities`, `payments`, `contracts`, `snapshots` — domain methods
//!
//! **Native only (requires `native` feature — SQLite-backed):**
//! - `store_sqlite` — `SqliteHarmoniiStore` (two SQLite connections)
//! - `schema` — Database schema and migrations
//! - `voucher` — Voucher wallet (separate SQLite store)
//!
//! **Optional protocols:**
//! - `bitcoin` — BDK Bitcoin wallet (requires `bitcoin` feature)
//! - `ark` — ARK protocol VTXOs (requires `ark` feature)

// ── Always available (pure crypto, WASM-compatible) ──────────────
pub mod keychain;
pub mod vault;
pub mod webcash;
pub mod labeled_wallets;
pub mod store;
pub mod store_mem;
pub mod browser_wallet;

// ── Always available (business logic, uses HarmoniiStore trait) ──
mod core;
pub mod contracts;
pub mod identities;
pub mod payments;
pub mod snapshots;

// ── Native only (SQLite-backed) ─────────────────────────────────
#[cfg(feature = "native")]
pub mod store_sqlite;
#[cfg(feature = "native")]
pub mod schema;
#[cfg(feature = "native")]
pub mod voucher;

// ── Optional protocol modules ────────────────────────────────────
#[cfg(feature = "ark")]
pub mod ark;
#[cfg(feature = "bitcoin")]
pub mod bitcoin;

// ── Re-exports from core ────────────────────────────────────────
pub use self::core::*;
