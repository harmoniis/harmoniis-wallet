use super::keychain::HdKeychain;
use super::store::{
    canonical_label, PgpIdentityRow, PgpIdentitySnapshot, WalletSnapshot,
};
use super::WalletCore;
use crate::error::{Error, Result};
use crate::identity::Identity;

impl WalletCore {
    // ── Snapshot ──────────────────────────────────────────────────────────────

    pub fn export_snapshot(&self) -> Result<WalletSnapshot> {
        let rgb_id = self.rgb_identity()?;
        let root = self.root_private_key_hex()?;
        let pgp_rows = self.store().list_pgp_raw()?;
        let pgp_identities = pgp_rows
            .iter()
            .map(|r| PgpIdentitySnapshot {
                label: r.label.clone(),
                key_index: r.key_index,
                private_key_hex: r.private_key_hex.clone(),
                is_active: r.is_active,
            })
            .collect();

        Ok(WalletSnapshot {
            private_key_hex: rgb_id.private_key_hex(),
            root_private_key_hex: Some(root),
            root_mnemonic: Some(self.export_recovery_mnemonic()?),
            wallet_label: self.wallet_label()?,
            pgp_identities,
            nickname: self.nickname()?,
            contracts: self.list_contracts()?,
            certificates: self.list_certificates()?,
        })
    }

    pub fn import_snapshot(&self, snap: &WalletSnapshot) -> Result<()> {
        let keychain = if let Some(words) = snap
            .root_mnemonic
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            HdKeychain::from_mnemonic_words(words)?
        } else {
            let root = snap.root_private_key_hex.clone().ok_or_else(|| {
                Error::Other(anyhow::anyhow!(
                    "snapshot missing root mnemonic/entropy; master key is mandatory"
                ))
            })?;
            HdKeychain::from_entropy_hex(&root)?
        };
        if let Some(root_hex) = &snap.root_private_key_hex {
            if !root_hex.trim().is_empty()
                && !root_hex.eq_ignore_ascii_case(&keychain.entropy_hex())
            {
                return Err(Error::Other(anyhow::anyhow!(
                    "snapshot root entropy does not match mnemonic entropy"
                )));
            }
        }
        let derived_rgb = keychain.derive_slot_hex("rgb", 0)?;
        if !snap.private_key_hex.trim().is_empty()
            && !snap.private_key_hex.eq_ignore_ascii_case(&derived_rgb)
        {
            return Err(Error::Other(anyhow::anyhow!(
                "snapshot RGB key does not match the derived RGB slot from root key"
            )));
        }

        self.set_master_keychain_material(&keychain)?;

        if let Some(label) = &snap.wallet_label {
            self.set_wallet_label(label)?;
        }

        if let Some(nick) = &snap.nickname {
            self.set_nickname(nick)?;
        }

        // Build PGP identity rows
        let pgp_rows: Vec<PgpIdentityRow> = if snap.pgp_identities.is_empty() {
            let wallet_label = self
                .wallet_label()?
                .unwrap_or_else(|| "default".to_string());
            let private_key_hex = keychain.derive_slot_hex("pgp", 0)?;
            let id = Identity::from_hex(&private_key_hex)?;
            vec![PgpIdentityRow {
                label: wallet_label,
                key_index: 0,
                private_key_hex,
                public_key_hex: id.public_key_hex(),
                created_at: chrono::Utc::now().to_rfc3339(),
                is_active: true,
            }]
        } else {
            let mut saw_active = false;
            snap.pgp_identities
                .iter()
                .map(|rec| {
                    let label = canonical_label(&rec.label)?;
                    let id = Identity::from_hex(&rec.private_key_hex)?;
                    let active = if rec.is_active && !saw_active {
                        saw_active = true;
                        true
                    } else {
                        false
                    };
                    Ok(PgpIdentityRow {
                        label,
                        key_index: rec.key_index,
                        private_key_hex: rec.private_key_hex.clone(),
                        public_key_hex: id.public_key_hex(),
                        created_at: chrono::Utc::now().to_rfc3339(),
                        is_active: active,
                    })
                })
                .collect::<Result<Vec<_>>>()?
        };
        self.store().replace_all_pgp(&pgp_rows)?;

        // Replace identity data (contracts + certificates)
        self.store()
            .replace_identity_data(&snap.contracts, &snap.certificates)?;

        self.refresh_slot_registry()?;
        Ok(())
    }
}
