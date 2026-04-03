//! Labeled sub-wallet management.
//!
//! Each wallet family (webcash, bitcoin, voucher, rgb) supports multiple
//! labeled wallets derived from the master keychain at different slot indices:
//!
//! - Slot 0 = "main" (default, backward-compatible)
//! - Slot 1+ = user-defined labels ("donation", "savings", etc.)
//!
//! DB file naming: `{label}_{type}.db` (e.g. `main_webcash.db`, `donation_webcash.db`)
//!
//! The wallet_slots table tracks all labeled wallets with their family, index,
//! label, and db_rel_path.

use rusqlite::params;
use serde::{Deserialize, Serialize};

use super::keychain::MAX_LABELED_WALLETS;
use crate::error::{Error, Result};

use super::schema::canonical_label;
use super::WalletCore;

/// Descriptor for a labeled sub-wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabeledWallet {
    pub family: String,
    pub label: String,
    pub slot_index: u32,
    pub db_filename: String,
    pub descriptor: String,
}

impl WalletCore {
    /// Generic: derive the master secret hex for any labeled wallet family.
    pub fn derive_secret_for_label(&self, family: &str, label: &str) -> Result<(String, u32)> {
        let index = self.resolve_or_create_wallet_slot(family, label)?;
        let secret = self.derive_slot_hex(family, index)?;
        Ok((secret, index))
    }

    pub fn derive_webcash_secret_for_label(&self, label: &str) -> Result<(String, u32)> {
        self.derive_secret_for_label("webcash", label)
    }

    pub fn derive_bitcoin_secret_for_label(&self, label: &str) -> Result<(String, u32)> {
        self.derive_secret_for_label("bitcoin", label)
    }

    pub fn derive_voucher_secret_for_label(&self, label: &str) -> Result<(String, u32)> {
        self.derive_secret_for_label("voucher", label)
    }

    pub fn derive_rgb_secret_for_label(&self, label: &str) -> Result<(String, u32)> {
        self.derive_secret_for_label("rgb", label)
    }

    /// List all labeled wallets for a family.
    pub fn list_labeled_wallets(&self, family: &str) -> Result<Vec<LabeledWallet>> {
        let mut stmt = self.master_conn.prepare(
            "SELECT family, slot_index, descriptor, db_rel_path, label
             FROM wallet_slots
             WHERE family = ?1
             ORDER BY slot_index ASC",
        )?;
        let rows = stmt.query_map(params![family], |row| {
            let family: String = row.get(0)?;
            let slot_index: u32 = row.get(1)?;
            let descriptor: String = row.get(2)?;
            let db_rel_path: Option<String> = row.get(3)?;
            let label: Option<String> = row.get(4)?;
            let label = label.unwrap_or_else(|| {
                if slot_index == 0 {
                    "main".to_string()
                } else {
                    format!("{family}-{slot_index}")
                }
            });
            let db_filename = db_rel_path.unwrap_or_else(|| format!("{}_{}.db", label, family));
            Ok(LabeledWallet {
                family,
                label,
                slot_index,
                db_filename,
                descriptor,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Error::Storage)
    }

    /// Get the DB filename for a labeled wallet.
    pub fn wallet_db_filename(family: &str, label: &str) -> String {
        format!("{}_{}.db", label, family)
    }

    /// Resolve an existing labeled wallet slot, or create a new one.
    fn resolve_or_create_wallet_slot(&self, family: &str, label: &str) -> Result<u32> {
        let canonical = canonical_label(label)?;

        // Check if this label already exists for this family
        let mut stmt = self.master_conn.prepare(
            "SELECT slot_index FROM wallet_slots WHERE family = ?1 AND label = ?2 LIMIT 1",
        )?;
        let mut rows = stmt.query(params![family, canonical])?;
        if let Some(row) = rows.next()? {
            let index: u32 = row.get(0)?;
            return Ok(index);
        }
        drop(rows);
        drop(stmt);

        // "main" always maps to slot 0
        if canonical == "main" {
            self.register_wallet_slot(family, 0, "main")?;
            return Ok(0);
        }

        // Find the next available slot index for this family
        let mut next_stmt = self
            .master_conn
            .prepare("SELECT COALESCE(MAX(slot_index), -1) FROM wallet_slots WHERE family = ?1")?;
        let max_idx: i64 = next_stmt.query_row(params![family], |row| row.get(0))?;
        let next = (max_idx + 1).max(1) as u32; // slot 0 reserved for main
        if next >= MAX_LABELED_WALLETS {
            return Err(Error::Other(anyhow::anyhow!(
                "too many {family} wallets (max {})",
                MAX_LABELED_WALLETS - 1
            )));
        }

        self.register_wallet_slot(family, next, &canonical)?;
        Ok(next)
    }

    /// Register a wallet slot in the wallet_slots table.
    fn register_wallet_slot(&self, family: &str, index: u32, label: &str) -> Result<()> {
        let descriptor = self.derive_slot_hex(family, index)?;
        let db_filename = Self::wallet_db_filename(family, label);
        let now = chrono::Utc::now().to_rfc3339();

        self.master_conn.execute(
            "INSERT OR REPLACE INTO wallet_slots (family, slot_index, descriptor, db_rel_path, label, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, COALESCE((SELECT created_at FROM wallet_slots WHERE family=?1 AND slot_index=?2), ?6), ?6)",
            params![family, i64::from(index), descriptor, db_filename, label, now],
        )?;
        Ok(())
    }
}
