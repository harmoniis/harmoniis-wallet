use super::store::{canonical_label, PgpIdentityRecord, PgpIdentityRow, MAX_PGP_KEYS};
use super::WalletCore;
use crate::error::{Error, Result};
use crate::identity::Identity;

impl WalletCore {
    // ── PGP identities (labeled, multi-key) ─────────────────────────────────

    pub fn active_pgp_identity(&self) -> Result<(PgpIdentityRecord, Identity)> {
        let rows = self.store().list_pgp_raw()?;
        let row = rows
            .iter()
            .find(|r| r.is_active)
            .or_else(|| rows.first())
            .ok_or_else(|| Error::Other(anyhow::anyhow!("no active PGP identity")))?;
        let identity = Identity::from_hex(&row.private_key_hex)?;
        Ok((PgpIdentityRecord::from(row), identity))
    }

    pub fn pgp_identity_by_label(&self, label: &str) -> Result<(PgpIdentityRecord, Identity)> {
        let canonical = canonical_label(label)?;
        let rows = self.store().list_pgp_raw()?;
        let row = rows
            .iter()
            .find(|r| r.label == canonical)
            .ok_or_else(|| Error::NotFound(format!("PGP identity label '{label}' not found")))?;
        let identity = Identity::from_hex(&row.private_key_hex)?;
        Ok((PgpIdentityRecord::from(row), identity))
    }

    pub fn list_pgp_identities(&self) -> Result<Vec<PgpIdentityRecord>> {
        let rows = self.store().list_pgp_raw()?;
        Ok(rows.iter().map(PgpIdentityRecord::from).collect())
    }

    pub fn create_pgp_identity(&self, label: &str) -> Result<PgpIdentityRecord> {
        let canonical = canonical_label(label)?;
        let exists = self.store().count_pgp_by_label(&canonical)?;
        if exists > 0 {
            return Err(Error::Other(anyhow::anyhow!(
                "PGP identity label '{canonical}' already exists"
            )));
        }

        let key_index = self.next_pgp_key_index()?;
        let private_key_hex = self.derive_slot_hex("pgp", key_index)?;
        let identity = Identity::from_hex(&private_key_hex)?;
        let public_key_hex = identity.public_key_hex();

        self.store().insert_pgp(&PgpIdentityRow {
            label: canonical.clone(),
            key_index,
            private_key_hex,
            public_key_hex: public_key_hex.clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
            is_active: false,
        })?;

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

        self.store().replace_pgp_at(
            key_index,
            &label,
            &PgpIdentityRow {
                label: label.clone(),
                key_index,
                private_key_hex: identity.private_key_hex(),
                public_key_hex: public_key_hex.clone(),
                created_at: chrono::Utc::now().to_rfc3339(),
                is_active: set_active,
            },
            set_active,
        )?;
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
        self.store().activate_pgp_exclusive(&canonical)?;
        self.refresh_slot_registry()?;
        Ok(())
    }

    pub fn rename_pgp_label(&self, from: &str, to: &str) -> Result<()> {
        let from_c = canonical_label(from)?;
        let to_c = canonical_label(to)?;
        if from_c == to_c {
            return Ok(());
        }
        self.store().rename_pgp(&from_c, &to_c)?;
        self.refresh_slot_registry()?;
        Ok(())
    }

    fn next_pgp_key_index(&self) -> Result<u32> {
        let max_idx = self.store().max_pgp_key_index()?;
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
            match self.store().pgp_index_for_label(&candidate)? {
                None => return Ok(candidate),
                Some(existing) if existing == key_index => return Ok(candidate),
                _ => {
                    candidate = format!("{desired}-{suffix}");
                    suffix = suffix.saturating_add(1);
                }
            }
        }
    }
}
