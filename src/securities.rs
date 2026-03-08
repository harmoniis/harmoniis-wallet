//! Security token types for Harmoniis — **DORMANT**.
//!
//! # Release gating
//!
//! This module is compiled only when the `securities` feature is enabled:
//!
//! ```toml
//! harmoniis-wallet = { ..., features = ["securities"] }
//! ```
//!
//! **Do not enable in production** until the securities module is officially
//! released. The dependency order is:
//!
//! ```text
//! Phase 1 (live)    — RGB21 Contract + Certificate
//! Phase 2 (sandbox) — RGB20 Stablecash / USDH
//! Phase 3 (dormant) — Securities (this module)
//! ```
//!
//! # Design
//!
//! A `SecurityDeed` is an RGB21 UDA (non-fungible, 1-to-1 transfer) that
//! represents ownership in a financial instrument built on top of Harmoniis
//! contracts and/or Stablecash. Security IDs use prefix `SEC_`.
//!
//! Three instrument types are scaffolded here. All are 1-to-1 RGB21 —
//! they transfer as a single unit (no splitting). Fungible security shares
//! would use a separate RGB20 extension not yet specified.
//!
//! # Atomic swaps
//!
//! Cross-contract atomics (swap SEC_A for CTR_B in one step) are **not** a
//! witness concern. The witness only tracks who owns what. Settlement logic
//! (locking, releasing) lives in the Arbitration Service.

use serde::{Deserialize, Serialize};

// ── SecurityType ──────────────────────────────────────────────────────────────

/// The kind of financial instrument a [`SecurityDeed`] represents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityType {
    /// Basket of RGB21 contracts — ETF-like.
    ///
    /// The deed holder receives a pro-rata share of proceeds when the
    /// underlying contracts are settled. Underlying assets are listed
    /// in `SecurityDeed::underlying`.
    ContractBasket,

    /// Fixed-term Stablecash-backed bond.
    ///
    /// The issuer borrows USDH and repays principal + interest at maturity.
    /// `face_value_units` holds the face value; `maturity_date` is ISO 8601.
    Bond,

    /// Revenue-share agreement.
    ///
    /// Holder receives `revenue_share_bps` basis points (1 bps = 0.01%) of
    /// future income from the listed contracts or certificates.
    RevenueShare,
}

impl SecurityType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::ContractBasket => "contract_basket",
            Self::Bond => "bond",
            Self::RevenueShare => "revenue_share",
        }
    }

    pub fn parse(s: &str) -> crate::error::Result<Self> {
        match s {
            "contract_basket" => Ok(Self::ContractBasket),
            "bond" => Ok(Self::Bond),
            "revenue_share" => Ok(Self::RevenueShare),
            _ => Err(crate::error::Error::InvalidFormat(format!(
                "unknown security type: {s}"
            ))),
        }
    }
}

// ── SecurityUnderlying ────────────────────────────────────────────────────────

/// One component of a security's underlying basket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecurityUnderlying {
    /// An RGB21 contract (CTR_ prefix).
    Contract { contract_id: String },

    /// An RGB21 certificate (CRT_ prefix).
    Certificate { certificate_id: String },

    /// A quantity of Stablecash backing (USDH, in atomic units; minimum unit is 0.00000001).
    /// Only valid once Stablecash is out of sandbox.
    Stablecash {
        amount_units: u64,
        contract_id: String,
    },
}

// ── SecurityDeed ──────────────────────────────────────────────────────────────

/// An RGB21 non-fungible bearer token representing a financial instrument.
///
/// **DORMANT** — not yet issued or traded. Enable the `securities` feature
/// to compile this type. Do not use in production until the securities
/// module is officially released.
///
/// Ownership is tracked by the witness identically to a Contract:
/// - Secret: `n:SEC_{id}:secret:{hex64}`
/// - Proof:  `n:SEC_{id}:public:{sha256_hex64}`
///
/// The `SEC_` prefix distinguishes securities from `CTR_` contracts and
/// `CRT_` certificates in the witness's ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityDeed {
    /// Unique ID, e.g. `SEC_2026_000001`.
    pub security_id: String,

    /// Instrument type.
    pub security_type: SecurityType,

    /// RGB21 witness secret (only the current owner holds this).
    /// Format: `n:SEC_{id}:secret:{hex64}`
    pub witness_secret: Option<String>,

    /// RGB21 witness proof (public, share freely to prove ownership).
    /// Format: `n:SEC_{id}:public:{sha256_hex64}`
    pub witness_proof: Option<String>,

    /// Fingerprint of the entity that issued this security.
    pub issuer_fingerprint: String,

    /// The assets this security represents a claim over.
    pub underlying: Vec<SecurityUnderlying>,

    /// Face value in atomic units (used for Bond instruments).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub face_value_units: Option<u64>,

    /// Maturity date in ISO 8601 (used for Bond instruments).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maturity_date: Option<String>,

    /// Revenue share in basis points (1 bps = 0.01%) for RevenueShare instruments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revenue_share_bps: Option<u16>,

    pub created_at: String,
    pub updated_at: String,
}

impl SecurityDeed {
    pub fn new(
        security_id: String,
        security_type: SecurityType,
        issuer_fingerprint: String,
        underlying: Vec<SecurityUnderlying>,
    ) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            security_id,
            security_type,
            witness_secret: None,
            witness_proof: None,
            issuer_fingerprint,
            underlying,
            face_value_units: None,
            maturity_date: None,
            revenue_share_bps: None,
            created_at: now.clone(),
            updated_at: now,
        }
    }
}

// ── SQLite schema (for wallet integration when ready) ─────────────────────────

/// DDL to extend the wallet schema when securities are enabled.
/// Add this table via a migration when the `securities` feature ships.
pub const SECURITIES_DDL: &str = "
    CREATE TABLE IF NOT EXISTS security_deeds (
        security_id        TEXT PRIMARY KEY,
        security_type      TEXT NOT NULL,
        witness_secret      TEXT,
        witness_proof       TEXT,
        issuer_fingerprint TEXT NOT NULL,
        underlying_json    TEXT NOT NULL DEFAULT '[]',
        face_value_units    INTEGER,
        maturity_date      TEXT,
        revenue_share_bps  INTEGER,
        created_at         TEXT NOT NULL,
        updated_at         TEXT NOT NULL
    );
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_type_roundtrip() {
        for st in [
            SecurityType::ContractBasket,
            SecurityType::Bond,
            SecurityType::RevenueShare,
        ] {
            let s = st.as_str();
            let parsed = SecurityType::parse(s).unwrap();
            assert_eq!(parsed, st);
        }
    }

    #[test]
    fn security_deed_new() {
        let deed = SecurityDeed::new(
            "SEC_2026_000001".to_string(),
            SecurityType::ContractBasket,
            "a".repeat(64),
            vec![SecurityUnderlying::Contract {
                contract_id: "CTR_2026_000123".to_string(),
            }],
        );
        assert_eq!(deed.security_id, "SEC_2026_000001");
        assert!(deed.witness_secret.is_none());
        assert_eq!(deed.underlying.len(), 1);
    }

    #[test]
    fn security_deed_serialise() {
        let deed = SecurityDeed::new(
            "SEC_2026_000001".to_string(),
            SecurityType::Bond,
            "b".repeat(64),
            vec![SecurityUnderlying::Stablecash {
                amount_units: 1_000_000_000,
                contract_id: "USDH_MAIN".to_string(),
            }],
        );
        let json = serde_json::to_string_pretty(&deed).unwrap();
        assert!(json.contains("bond"));
        assert!(json.contains("SEC_2026_000001"));
    }
}
