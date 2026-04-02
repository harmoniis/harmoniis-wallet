use super::schema::canonical_label;
use super::WalletCore;
use super::MAX_PGP_KEYS;
use crate::error::{Error, Result};
use crate::identity::Identity;
use rusqlite::params;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgpIdentityRecord {
    pub label: String,
    pub key_index: u32,
    pub public_key_hex: String,
    pub is_active: bool,
}

impl WalletCore {
    // ── PGP identities (labeled, multi-key) ─────────────────────────────────

    pub fn active_pgp_identity(&self) -> Result<(PgpIdentityRecord, Identity)> {
        let mut stmt = self.master_conn.prepare(
            "SELECT label, key_index, private_key_hex, public_key_hex, is_active
             FROM pgp_identities
             WHERE is_active = 1
             ORDER BY key_index ASC
             LIMIT 1",
        )?;
        let mut rows = stmt.query([])?;
        let row = rows
            .next()?
            .ok_or_else(|| Error::Other(anyhow::anyhow!("no active PGP identity")))?;

        let label: String = row.get(0)?;
        let key_index_i: i64 = row.get(1)?;
        let private_key_hex: String = row.get(2)?;
        let public_key_hex: String = row.get(3)?;
        let is_active_i: i64 = row.get(4)?;
        let key_index = u32::try_from(key_index_i)
            .map_err(|_| Error::Other(anyhow::anyhow!("invalid PGP key index in wallet")))?;
        let identity = Identity::from_hex(&private_key_hex)?;

        Ok((
            PgpIdentityRecord {
                label,
                key_index,
                public_key_hex,
                is_active: is_active_i == 1,
            },
            identity,
        ))
    }

    pub fn pgp_identity_by_label(&self, label: &str) -> Result<(PgpIdentityRecord, Identity)> {
        let canonical = canonical_label(label)?;
        let mut stmt = self.master_conn.prepare(
            "SELECT label, key_index, private_key_hex, public_key_hex, is_active
             FROM pgp_identities WHERE label = ?1 LIMIT 1",
        )?;
        let mut rows = stmt.query(params![canonical])?;
        let row = rows
            .next()?
            .ok_or_else(|| Error::NotFound(format!("PGP identity label '{label}' not found")))?;

        let label: String = row.get(0)?;
        let key_index_i: i64 = row.get(1)?;
        let private_key_hex: String = row.get(2)?;
        let public_key_hex: String = row.get(3)?;
        let is_active_i: i64 = row.get(4)?;
        let key_index = u32::try_from(key_index_i)
            .map_err(|_| Error::Other(anyhow::anyhow!("invalid PGP key index in wallet")))?;
        let identity = Identity::from_hex(&private_key_hex)?;

        Ok((
            PgpIdentityRecord {
                label,
                key_index,
                public_key_hex,
                is_active: is_active_i == 1,
            },
            identity,
        ))
    }

    pub fn list_pgp_identities(&self) -> Result<Vec<PgpIdentityRecord>> {
        let mut stmt = self.master_conn.prepare(
            "SELECT label, key_index, public_key_hex, is_active
             FROM pgp_identities
             ORDER BY key_index ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let key_index: u32 = row.get(1)?;
            Ok(PgpIdentityRecord {
                label: row.get(0)?,
                key_index,
                public_key_hex: row.get(2)?,
                is_active: row.get::<_, i64>(3)? == 1,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Error::Storage)
    }

    pub fn create_pgp_identity(&self, label: &str) -> Result<PgpIdentityRecord> {
        let canonical = canonical_label(label)?;
        let mut exists_stmt = self
            .master_conn
            .prepare("SELECT COUNT(*) FROM pgp_identities WHERE label = ?1")?;
        let exists: i64 = exists_stmt.query_row(params![canonical.clone()], |row| row.get(0))?;
        if exists > 0 {
            return Err(Error::Other(anyhow::anyhow!(
                "PGP identity label '{canonical}' already exists"
            )));
        }

        let key_index = self.next_pgp_key_index()?;
        let private_key_hex = self.derive_slot_hex("pgp", key_index)?;
        let identity = Identity::from_hex(&private_key_hex)?;
        let public_key_hex = identity.public_key_hex();

        self.master_conn.execute(
            "INSERT INTO pgp_identities (label, key_index, private_key_hex, public_key_hex, created_at, is_active)
             VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            params![
                canonical,
                i64::from(key_index),
                private_key_hex,
                public_key_hex,
                chrono::Utc::now().to_rfc3339(),
            ],
        )?;

        self.refresh_slot_registry()?;
        self.pgp_identity_by_label(label).map(|(meta, _)| meta)
    }

    pub fn derive_pgp_identity_for_index(&self, key_index: u32) -> Result<Identity> {
        let private_key_hex = self.derive_slot_hex("pgp", key_index)?;
        Identity::from_hex(&private_key_hex)
    }

    pub fn ensure_pgp_identity_index(
        &self,
        key_index: u32,
        preferred_label: Option<&str>,
        set_active: bool,
    ) -> Result<PgpIdentityRecord> {
        if key_index >= MAX_PGP_KEYS {
            return Err(Error::Other(anyhow::anyhow!(
                "PGP key index out of range (max {})",
                MAX_PGP_KEYS - 1
            )));
        }

        let fallback_label = format!("pgp-{key_index}");
        let desired_raw = preferred_label.unwrap_or(fallback_label.as_str());
        let desired = canonical_label(desired_raw)?;
        let label = self.unique_pgp_label(&desired, key_index)?;
        let identity = self.derive_pgp_identity_for_index(key_index)?;
        let public_key_hex = identity.public_key_hex();

        let tx = self.master_conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM pgp_identities WHERE key_index = ?1",
            params![i64::from(key_index)],
        )?;
        tx.execute(
            "DELETE FROM pgp_identities WHERE label = ?1",
            params![label.clone()],
        )?;
        if set_active {
            tx.execute("UPDATE pgp_identities SET is_active = 0", [])?;
        }
        tx.execute(
            "INSERT INTO pgp_identities (label, key_index, private_key_hex, public_key_hex, created_at, is_active)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                label.clone(),
                i64::from(key_index),
                identity.private_key_hex(),
                public_key_hex.clone(),
                chrono::Utc::now().to_rfc3339(),
                if set_active { 1 } else { 0 },
            ],
        )?;
        tx.commit()?;
        self.refresh_slot_registry()?;
        Ok(PgpIdentityRecord {
            label,
            key_index,
            public_key_hex,
            is_active: set_active,
        })
    }

    pub fn set_active_pgp_identity(&self, label: &str) -> Result<()> {
        let canonical = canonical_label(label)?;
        let mut exists_stmt = self
            .master_conn
            .prepare("SELECT COUNT(*) FROM pgp_identities WHERE label = ?1")?;
        let exists: i64 = exists_stmt.query_row(params![canonical.clone()], |row| row.get(0))?;
        if exists == 0 {
            return Err(Error::NotFound(format!(
                "PGP identity label '{canonical}' not found"
            )));
        }
        let tx = self.master_conn.unchecked_transaction()?;
        tx.execute("UPDATE pgp_identities SET is_active = 0", [])?;
        tx.execute(
            "UPDATE pgp_identities SET is_active = 1 WHERE label = ?1",
            params![canonical],
        )?;
        tx.commit()?;
        self.refresh_slot_registry()?;
        Ok(())
    }

    pub fn rename_pgp_label(&self, from: &str, to: &str) -> Result<()> {
        let from_c = canonical_label(from)?;
        let to_c = canonical_label(to)?;
        if from_c == to_c {
            return Ok(());
        }
        self.master_conn.execute(
            "UPDATE pgp_identities SET label = ?1 WHERE label = ?2",
            params![to_c, from_c],
        )?;
        self.refresh_slot_registry()?;
        Ok(())
    }

    fn next_pgp_key_index(&self) -> Result<u32> {
        let mut stmt = self
            .master_conn
            .prepare("SELECT COALESCE(MAX(key_index), -1) FROM pgp_identities")?;
        let max_idx: i64 = stmt.query_row([], |row| row.get(0))?;
        let next = max_idx.saturating_add(1);
        let next = u32::try_from(next)
            .map_err(|_| Error::Other(anyhow::anyhow!("too many PGP identities in wallet")))?;
        if next >= MAX_PGP_KEYS {
            return Err(Error::Other(anyhow::anyhow!(
                "PGP key index out of range (max {})",
                MAX_PGP_KEYS - 1
            )));
        }
        Ok(next)
    }

    fn unique_pgp_label(&self, desired: &str, key_index: u32) -> Result<String> {
        let mut candidate = desired.to_string();
        let mut suffix = 1u32;
        loop {
            let mut stmt = self
                .master_conn
                .prepare("SELECT key_index FROM pgp_identities WHERE label = ?1 LIMIT 1")?;
            let mut rows = stmt.query(params![candidate.clone()])?;
            let Some(row) = rows.next()? else {
                return Ok(candidate);
            };
            let existing: u32 = row.get(0)?;
            if existing == key_index {
                return Ok(candidate);
            }
            candidate = format!("{desired}-{suffix}");
            suffix = suffix.saturating_add(1);
        }
    }
}
