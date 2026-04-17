//! Storage abstraction for the Harmoniis wallet engine.
//!
//! [`HarmoniiStore`] defines the minimal interface the wallet needs from its backend.
//! - **Native**: `SqliteHarmoniiStore` wraps two `rusqlite::Connection`s (master + identity).
//! - **WASM**: `MemHarmoniiStore` uses in-memory structures, serializable to JSON.
//!
//! All data types referenced by the trait are defined here to avoid circular
//! module dependencies. Business logic lives on `WalletCore`; raw CRUD lives here.

use crate::error::Result;
use crate::types::{Certificate, Contract};
use serde::{Deserialize, Serialize};

// ── Constants ───────────────────────────────────────────────────

pub const MAX_PGP_KEYS: u32 = 1_000;

// ── Utilities ───────────────────────────────────────────────────

/// Canonicalize a label: trim whitespace, enforce non-empty and max 64 chars.
pub fn canonical_label(label: &str) -> Result<String> {
    let canonical = label.trim();
    if canonical.is_empty() {
        return Err(crate::error::Error::Other(anyhow::anyhow!(
            "label cannot be empty"
        )));
    }
    if canonical.len() > 64 {
        return Err(crate::error::Error::Other(anyhow::anyhow!(
            "label too long (max 64 chars)"
        )));
    }
    Ok(canonical.to_string())
}

// ── PGP Identity Types ─────────────────────────────────────────

/// Full PGP identity row including private key material (store-internal).
#[derive(Clone, Serialize, Deserialize)]
pub struct PgpIdentityRow {
    pub label: String,
    pub key_index: u32,
    pub private_key_hex: String,
    pub public_key_hex: String,
    pub created_at: String,
    pub is_active: bool,
}

impl std::fmt::Debug for PgpIdentityRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgpIdentityRow")
            .field("label", &self.label)
            .field("key_index", &self.key_index)
            .field("private_key_hex", &"[redacted]")
            .field("public_key_hex", &self.public_key_hex)
            .field("created_at", &self.created_at)
            .field("is_active", &self.is_active)
            .finish()
    }
}

/// Public PGP identity record (without private key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgpIdentityRecord {
    pub label: String,
    pub key_index: u32,
    pub public_key_hex: String,
    pub is_active: bool,
}

impl From<&PgpIdentityRow> for PgpIdentityRecord {
    fn from(row: &PgpIdentityRow) -> Self {
        Self {
            label: row.label.clone(),
            key_index: row.key_index,
            public_key_hex: row.public_key_hex.clone(),
            is_active: row.is_active,
        }
    }
}

// ── Wallet Slot Types ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSlotRecord {
    pub family: String,
    pub slot_index: u32,
    pub descriptor: String,
    pub db_rel_path: Option<String>,
    pub label: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

// ── Payment Attempt Types ───────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentAttemptRecord {
    pub attempt_id: String,
    pub created_at: String,
    pub updated_at: String,
    pub service_origin: String,
    pub endpoint_path: String,
    pub method: String,
    pub rail: String,
    pub action_hint: String,
    pub required_amount: String,
    pub payment_unit: String,
    pub payment_reference: Option<String>,
    pub request_hash: String,
    pub response_status: Option<u16>,
    pub response_code: Option<String>,
    pub response_body: Option<String>,
    pub recovery_state: String,
    pub final_state: String,
}

#[derive(Debug, Clone)]
pub struct NewPaymentAttempt<'a> {
    pub service_origin: &'a str,
    pub endpoint_path: &'a str,
    pub method: &'a str,
    pub rail: &'a str,
    pub action_hint: &'a str,
    pub required_amount: &'a str,
    pub payment_unit: &'a str,
    pub payment_reference: Option<&'a str>,
    pub request_hash: &'a str,
}

#[derive(Debug, Clone)]
pub struct PaymentAttemptUpdate<'a> {
    pub payment_reference: Option<&'a str>,
    pub response_status: Option<u16>,
    pub response_code: Option<&'a str>,
    pub response_body: Option<&'a str>,
    pub recovery_state: &'a str,
    pub final_state: &'a str,
}

// ── Payment Loss Types ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentLossRecord {
    pub loss_id: String,
    pub attempt_id: String,
    pub created_at: String,
    pub service_origin: String,
    pub endpoint_path: String,
    pub method: String,
    pub rail: String,
    pub amount: String,
    pub payment_reference: Option<String>,
    pub failure_stage: String,
    pub response_status: Option<u16>,
    pub response_code: Option<String>,
    pub response_body: Option<String>,
}

// ── Payment Blacklist Types ─────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentBlacklistRecord {
    pub service_origin: String,
    pub endpoint_path: String,
    pub method: String,
    pub rail: String,
    pub blacklisted_until: Option<String>,
    pub reason: String,
    pub triggered_by_loss_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

// ── Payment Transaction Types ───────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentTransactionRecord {
    pub txn_id: String,
    pub attempt_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub occurred_at: String,
    pub direction: String,
    pub role: String,
    pub source_system: String,
    pub service_origin: Option<String>,
    pub frontend_kind: Option<String>,
    pub transport_kind: Option<String>,
    pub endpoint_path: Option<String>,
    pub method: Option<String>,
    pub session_id: Option<String>,
    pub action_kind: String,
    pub resource_ref: Option<String>,
    pub contract_ref: Option<String>,
    pub invoice_ref: Option<String>,
    pub challenge_id: Option<String>,
    pub rail: String,
    pub payment_unit: String,
    pub quoted_amount: Option<String>,
    pub settled_amount: Option<String>,
    pub fee_amount: Option<String>,
    pub proof_ref: Option<String>,
    pub proof_kind: Option<String>,
    pub payer_ref: Option<String>,
    pub payee_ref: Option<String>,
    pub request_hash: Option<String>,
    pub response_code: Option<String>,
    pub status: String,
    pub metadata_json: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewPaymentTransaction<'a> {
    pub attempt_id: Option<&'a str>,
    pub occurred_at: Option<&'a str>,
    pub direction: &'a str,
    pub role: &'a str,
    pub source_system: &'a str,
    pub service_origin: Option<&'a str>,
    pub frontend_kind: Option<&'a str>,
    pub transport_kind: Option<&'a str>,
    pub endpoint_path: Option<&'a str>,
    pub method: Option<&'a str>,
    pub session_id: Option<&'a str>,
    pub action_kind: &'a str,
    pub resource_ref: Option<&'a str>,
    pub contract_ref: Option<&'a str>,
    pub invoice_ref: Option<&'a str>,
    pub challenge_id: Option<&'a str>,
    pub rail: &'a str,
    pub payment_unit: &'a str,
    pub quoted_amount: Option<&'a str>,
    pub settled_amount: Option<&'a str>,
    pub fee_amount: Option<&'a str>,
    pub proof_ref: Option<&'a str>,
    pub proof_kind: Option<&'a str>,
    pub payer_ref: Option<&'a str>,
    pub payee_ref: Option<&'a str>,
    pub request_hash: Option<&'a str>,
    pub response_code: Option<&'a str>,
    pub status: &'a str,
    pub metadata_json: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct PaymentTransactionUpdate<'a> {
    pub occurred_at: Option<&'a str>,
    pub service_origin: Option<&'a str>,
    pub frontend_kind: Option<&'a str>,
    pub transport_kind: Option<&'a str>,
    pub endpoint_path: Option<&'a str>,
    pub method: Option<&'a str>,
    pub session_id: Option<&'a str>,
    pub action_kind: Option<&'a str>,
    pub resource_ref: Option<&'a str>,
    pub contract_ref: Option<&'a str>,
    pub invoice_ref: Option<&'a str>,
    pub challenge_id: Option<&'a str>,
    pub quoted_amount: Option<&'a str>,
    pub settled_amount: Option<&'a str>,
    pub fee_amount: Option<&'a str>,
    pub proof_ref: Option<&'a str>,
    pub proof_kind: Option<&'a str>,
    pub payer_ref: Option<&'a str>,
    pub payee_ref: Option<&'a str>,
    pub request_hash: Option<&'a str>,
    pub response_code: Option<&'a str>,
    pub status: &'a str,
    pub metadata_json: Option<&'a str>,
}

// ── Payment Transaction Event Types ─────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentTransactionEventRecord {
    pub event_id: String,
    pub txn_id: String,
    pub created_at: String,
    pub event_type: String,
    pub status: String,
    pub actor: String,
    pub details_json: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewPaymentTransactionEvent<'a> {
    pub txn_id: &'a str,
    pub event_type: &'a str,
    pub status: &'a str,
    pub actor: &'a str,
    pub details_json: Option<&'a str>,
}

// ── Snapshot Types ──────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
pub struct PgpIdentitySnapshot {
    pub label: String,
    pub key_index: u32,
    pub private_key_hex: String,
    pub is_active: bool,
}

impl std::fmt::Debug for PgpIdentitySnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgpIdentitySnapshot")
            .field("label", &self.label)
            .field("key_index", &self.key_index)
            .field("private_key_hex", &"[redacted]")
            .field("is_active", &self.is_active)
            .finish()
    }
}

/// Serializable snapshot for backup/restore.
#[derive(Clone, Serialize, Deserialize)]
pub struct WalletSnapshot {
    pub private_key_hex: String,
    #[serde(default)]
    pub root_private_key_hex: Option<String>,
    #[serde(default)]
    pub root_mnemonic: Option<String>,
    #[serde(default)]
    pub wallet_label: Option<String>,
    #[serde(default)]
    pub pgp_identities: Vec<PgpIdentitySnapshot>,
    pub nickname: Option<String>,
    pub contracts: Vec<Contract>,
    pub certificates: Vec<Certificate>,
}

impl std::fmt::Debug for WalletSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletSnapshot")
            .field("private_key_hex", &"[redacted]")
            .field("root_private_key_hex", &"[redacted]")
            .field("root_mnemonic", &"[redacted]")
            .field("wallet_label", &self.wallet_label)
            .field(
                "pgp_identities",
                &format!("[{} keys]", self.pgp_identities.len()),
            )
            .field("nickname", &self.nickname)
            .field(
                "contracts",
                &format!("[{} contracts]", self.contracts.len()),
            )
            .field(
                "certificates",
                &format!("[{} certs]", self.certificates.len()),
            )
            .finish()
    }
}

// ── HarmoniiStore Trait ─────────────────────────────────────────

/// Minimal storage interface for the Harmoniis wallet engine.
///
/// Covers metadata, PGP identities, wallet slots, payment audit trail,
/// contracts, and certificates. Methods prefixed with `replace_` are
/// atomic (transactional in SQLite, sequential in memory stores).
pub trait HarmoniiStore {
    fn as_any(&self) -> &dyn std::any::Any;

    // ── Metadata ──────────────────────────────────────────────

    fn get_meta(&self, key: &str) -> Result<Option<String>>;
    fn set_meta(&self, key: &str, value: &str) -> Result<()>;

    // ── PGP Identities ───────────────────────────────────────

    /// All PGP identity rows (including private keys), ordered by key_index ASC.
    fn list_pgp_raw(&self) -> Result<Vec<PgpIdentityRow>>;

    /// Insert a single PGP identity row.
    fn insert_pgp(&self, row: &PgpIdentityRow) -> Result<()>;

    /// Rename a PGP identity label. Returns rows affected.
    fn rename_pgp(&self, from: &str, to: &str) -> Result<u64>;

    /// Count PGP identities with the given label.
    fn count_pgp_by_label(&self, label: &str) -> Result<i64>;

    /// Maximum key_index across all PGP identities (−1 if none).
    fn max_pgp_key_index(&self) -> Result<i64>;

    /// Look up the key_index for a PGP identity by label.
    fn pgp_index_for_label(&self, label: &str) -> Result<Option<u32>>;

    /// Atomic: clear all PGP identities, then insert batch.
    /// If no row is active, activates the one with lowest key_index.
    fn replace_all_pgp(&self, rows: &[PgpIdentityRow]) -> Result<()>;

    /// Atomic: delete by key_index, delete by label, optionally deactivate all, insert one.
    fn replace_pgp_at(
        &self,
        key_index: u32,
        label: &str,
        row: &PgpIdentityRow,
        set_active: bool,
    ) -> Result<()>;

    /// Atomic: deactivate all PGP identities, then activate one by label.
    fn activate_pgp_exclusive(&self, label: &str) -> Result<()>;

    // ── Wallet Slots ──────────────────────────────────────────

    /// List wallet slots, optionally filtered by family. Ordered by family ASC, slot_index ASC.
    fn list_wallet_slots(&self, family: Option<&str>) -> Result<Vec<WalletSlotRecord>>;

    /// Upsert a wallet slot, preserving existing `created_at` if the slot already exists.
    fn upsert_wallet_slot(&self, row: &WalletSlotRecord) -> Result<()>;

    /// Look up the slot_index for a family+label pair.
    fn get_slot_index_by_label(&self, family: &str, label: &str) -> Result<Option<u32>>;

    /// Maximum slot_index for a family (−1 if none).
    fn max_slot_index(&self, family: &str) -> Result<i64>;

    /// Atomic: delete slot by family+slot_index, delete by family+label, insert new slot.
    fn replace_slot_at(
        &self,
        family: &str,
        slot_index: u32,
        label: &str,
        descriptor: &str,
        now: &str,
    ) -> Result<()>;

    // ── Payment Attempts ──────────────────────────────────────

    fn insert_payment_attempt(&self, record: &PaymentAttemptRecord) -> Result<()>;

    fn update_payment_attempt(
        &self,
        attempt_id: &str,
        now: &str,
        update: &PaymentAttemptUpdate<'_>,
    ) -> Result<()>;

    // ── Payment Losses ────────────────────────────────────────

    fn insert_payment_loss(&self, record: &PaymentLossRecord) -> Result<()>;

    fn list_payment_losses(&self) -> Result<Vec<PaymentLossRecord>>;

    /// Count losses matching the given key fields with `created_at >= cutoff`.
    fn count_recent_losses(
        &self,
        service_origin: &str,
        endpoint_path: &str,
        method: &str,
        rail: &str,
        cutoff: &str,
    ) -> Result<i64>;

    // ── Payment Blacklist ─────────────────────────────────────

    /// Upsert blacklist entry, preserving existing `created_at`.
    fn upsert_payment_blacklist(&self, record: &PaymentBlacklistRecord) -> Result<()>;

    fn get_payment_blacklist_entry(
        &self,
        service_origin: &str,
        endpoint_path: &str,
        method: &str,
        rail: &str,
    ) -> Result<Option<PaymentBlacklistRecord>>;

    fn list_payment_blacklist(&self) -> Result<Vec<PaymentBlacklistRecord>>;

    /// Delete blacklist entry. Returns true if a row was deleted.
    fn delete_payment_blacklist(
        &self,
        service_origin: &str,
        endpoint_path: &str,
        method: &str,
        rail: &str,
    ) -> Result<bool>;

    // ── Payment Transactions ──────────────────────────────────

    fn insert_payment_transaction(&self, record: &PaymentTransactionRecord) -> Result<()>;

    fn update_payment_transaction(
        &self,
        txn_id: &str,
        now: &str,
        update: &PaymentTransactionUpdate<'_>,
    ) -> Result<()>;

    fn list_payment_transactions(&self) -> Result<Vec<PaymentTransactionRecord>>;

    // ── Payment Transaction Events ────────────────────────────

    fn insert_payment_transaction_event(&self, record: &PaymentTransactionEventRecord)
        -> Result<()>;

    fn list_payment_transaction_events(
        &self,
        txn_id: Option<&str>,
    ) -> Result<Vec<PaymentTransactionEventRecord>>;

    // ── Contracts ─────────────────────────────────────────────

    fn store_contract(&self, c: &Contract) -> Result<()>;
    fn get_contract(&self, id: &str) -> Result<Option<Contract>>;
    fn list_contracts(&self) -> Result<Vec<Contract>>;
    fn count_contracts(&self) -> Result<i64>;

    // ── Certificates ──────────────────────────────────────────

    fn store_certificate(&self, cert: &Certificate) -> Result<()>;
    fn list_certificates(&self) -> Result<Vec<Certificate>>;
    fn count_certificates(&self) -> Result<i64>;

    // ── Bulk Operations ───────────────────────────────────────

    /// Atomic: clear all contracts and certificates, then insert batches.
    fn replace_identity_data(
        &self,
        contracts: &[Contract],
        certificates: &[Certificate],
    ) -> Result<()>;
}
