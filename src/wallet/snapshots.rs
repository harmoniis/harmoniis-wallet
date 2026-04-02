use rusqlite::params;
use serde::{Deserialize, Serialize};

use super::keychain::HdKeychain;
use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::types::{Certificate, Contract};

use super::schema::canonical_label;
use super::WalletCore;

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

impl WalletCore {
    // ── Snapshot ──────────────────────────────────────────────────────────────

    pub fn export_snapshot(&self) -> Result<WalletSnapshot> {
        let rgb_id = self.rgb_identity()?;
        let root = self.root_private_key_hex()?;
        let mut stmt = self.master_conn.prepare(
            "SELECT label, key_index, private_key_hex, is_active
             FROM pgp_identities
             ORDER BY key_index ASC",
        )?;
        let pgp_rows = stmt.query_map([], |row| {
            let key_index: u32 = row.get(1)?;
            Ok(PgpIdentitySnapshot {
                label: row.get(0)?,
                key_index,
                private_key_hex: row.get(2)?,
                is_active: row.get::<_, i64>(3)? == 1,
            })
        })?;

        let pgp_identities = pgp_rows
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Error::Storage)?;

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

        let tx = self.master_conn.unchecked_transaction()?;
        tx.execute("DELETE FROM pgp_identities", [])?;
        if snap.pgp_identities.is_empty() {
            let wallet_label = self
                .wallet_label()?
                .unwrap_or_else(|| "default".to_string());
            let private_key_hex = keychain.derive_slot_hex("pgp", 0)?;
            let id = Identity::from_hex(&private_key_hex)?;
            tx.execute(
                "INSERT INTO pgp_identities (label, key_index, private_key_hex, public_key_hex, created_at, is_active)
                 VALUES (?1, 0, ?2, ?3, ?4, 1)",
                params![
                    wallet_label,
                    private_key_hex,
                    id.public_key_hex(),
                    chrono::Utc::now().to_rfc3339(),
                ],
            )?;
        } else {
            let mut saw_active = false;
            for rec in &snap.pgp_identities {
                let label = canonical_label(&rec.label)?;
                let id = Identity::from_hex(&rec.private_key_hex)?;
                let active = if rec.is_active && !saw_active {
                    saw_active = true;
                    1
                } else {
                    0
                };
                tx.execute(
                    "INSERT INTO pgp_identities (label, key_index, private_key_hex, public_key_hex, created_at, is_active)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        label,
                        i64::from(rec.key_index),
                        rec.private_key_hex,
                        id.public_key_hex(),
                        chrono::Utc::now().to_rfc3339(),
                        active,
                    ],
                )?;
            }
            if !saw_active {
                tx.execute(
                    "UPDATE pgp_identities SET is_active = 1 WHERE key_index = (
                        SELECT MIN(key_index) FROM pgp_identities
                    )",
                    [],
                )?;
            }
        }
        tx.commit()?;

        self.with_identity_conn(|conn| {
            conn.execute("DELETE FROM contracts", [])?;
            conn.execute("DELETE FROM certificates", [])?;
            for c in &snap.contracts {
                conn.execute(
                    "INSERT OR REPLACE INTO contracts (
                        contract_id, contract_type, status, witness_secret, witness_proof,
                        amount_units, work_spec, buyer_fingerprint, seller_fingerprint,
                        reference_post, delivery_deadline, role, delivered_text,
                        certificate_id, created_at, updated_at
                    ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
                    params![
                        c.contract_id,
                        c.contract_type.as_str(),
                        c.status.as_str(),
                        c.witness_secret,
                        c.witness_proof,
                        c.amount_units as i64,
                        c.work_spec,
                        c.buyer_fingerprint,
                        c.seller_fingerprint,
                        c.reference_post,
                        c.delivery_deadline,
                        c.role.as_str(),
                        c.delivered_text,
                        c.certificate_id,
                        c.created_at,
                        c.updated_at,
                    ],
                )?;
            }
            for cert in &snap.certificates {
                conn.execute(
                    "INSERT OR REPLACE INTO certificates (
                        certificate_id, contract_id, witness_secret, witness_proof, created_at
                    ) VALUES (?1,?2,?3,?4,?5)",
                    params![
                        cert.certificate_id,
                        cert.contract_id,
                        cert.witness_secret,
                        cert.witness_proof,
                        cert.created_at,
                    ],
                )?;
            }
            Ok(())
        })?;

        self.refresh_slot_registry()?;
        Ok(())
    }
}
