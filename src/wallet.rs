use std::collections::HashSet;
use std::path::Path;

use bip39::Mnemonic;
use hkdf::Hkdf;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{
    error::{Error, Result},
    identity::Identity,
    types::{Certificate, Contract, ContractStatus, ContractType, Role},
};

const META_PRIVATE_KEY_HEX: &str = "private_key_hex";
const META_RGB_PRIVATE_KEY_HEX: &str = "rgb_private_key_hex";
const META_ROOT_PRIVATE_KEY_HEX: &str = "root_private_key_hex";
const META_NICKNAME: &str = "nickname";
const META_WALLET_LABEL: &str = "wallet_label";
const META_KEY_MODEL_VERSION: &str = "key_model_version";

const HKDF_RGB_IDENTITY_V1: &[u8] = b"harmoniis/hrmw/rgb/identity/v1";
const HKDF_WEBCASH_MASTER_V1: &[u8] = b"harmoniis/hrmw/webcash/master/v1|chain:3";
const HKDF_BITCOIN_MASTER_V1: &[u8] = b"harmoniis/hrmw/bitcoin/master/v1";
const KEY_MODEL_VERSION_V2: &str = "v2";
const MAX_PGP_KEYS: u32 = 1_000;

/// SQLite-backed RGB wallet.
pub struct RgbWallet {
    conn: Connection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgpIdentityRecord {
    pub label: String,
    pub key_index: u32,
    pub public_key_hex: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgpIdentitySnapshot {
    pub label: String,
    pub key_index: u32,
    pub private_key_hex: String,
    pub is_active: bool,
}

/// Serializable snapshot for backup/restore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSnapshot {
    pub private_key_hex: String,
    #[serde(default)]
    pub root_private_key_hex: Option<String>,
    #[serde(default)]
    pub wallet_label: Option<String>,
    #[serde(default)]
    pub pgp_identities: Vec<PgpIdentitySnapshot>,
    pub nickname: Option<String>,
    pub contracts: Vec<Contract>,
    pub certificates: Vec<Certificate>,
}

impl RgbWallet {
    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;

            CREATE TABLE IF NOT EXISTS wallet_metadata (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS contracts (
                contract_id        TEXT PRIMARY KEY,
                contract_type      TEXT NOT NULL DEFAULT 'service',
                status             TEXT NOT NULL DEFAULT 'issued',
                witness_secret      TEXT,
                witness_proof       TEXT,
                amount_units        INTEGER NOT NULL DEFAULT 0,
                work_spec          TEXT NOT NULL DEFAULT '',
                buyer_fingerprint  TEXT NOT NULL DEFAULT '',
                seller_fingerprint TEXT,
                reference_post     TEXT,
                delivery_deadline  TEXT,
                role               TEXT NOT NULL DEFAULT 'buyer',
                delivered_text     TEXT,
                certificate_id     TEXT,
                created_at         TEXT NOT NULL,
                updated_at         TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS certificates (
                certificate_id TEXT PRIMARY KEY,
                contract_id    TEXT,
                witness_secret  TEXT,
                witness_proof   TEXT,
                created_at     TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pgp_identities (
                label           TEXT PRIMARY KEY,
                key_index       INTEGER NOT NULL UNIQUE,
                private_key_hex TEXT NOT NULL,
                public_key_hex  TEXT NOT NULL,
                created_at      TEXT NOT NULL,
                is_active       INTEGER NOT NULL DEFAULT 0
            );
            ",
        )?;
        migrate_legacy_schema(&conn)?;
        ensure_root_and_identity_materialized(&conn)?;
        ensure_default_pgp_identity(&conn)?;
        Ok(Self { conn })
    }

    /// Create a new wallet at the given path, generating a fresh root key.
    pub fn create(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Other(anyhow::anyhow!("cannot create wallet dir: {e}")))?;
        }
        let conn = Connection::open(path)?;
        let w = Self::init(conn)?;

        if w.wallet_label()?.as_deref().unwrap_or("default") == "default" {
            let derived = path
                .file_stem()
                .and_then(|x| x.to_str())
                .map(ToString::to_string)
                .unwrap_or_else(|| "wallet".to_string());
            w.set_wallet_label(&derived)?;
            // Keep default label in sync for fresh wallet.
            let _ = w.rename_pgp_label("default", &derived);
        }

        Ok(w)
    }

    /// Open an existing wallet at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        let w = Self::init(conn)?;
        if w.wallet_label()?.as_deref().unwrap_or("default") == "default" {
            let derived = path
                .file_stem()
                .and_then(|x| x.to_str())
                .map(ToString::to_string)
                .unwrap_or_else(|| "wallet".to_string());
            w.set_wallet_label(&derived)?;
        }
        Ok(w)
    }

    /// Open an in-memory wallet (for tests).
    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let w = Self::init(conn)?;
        if w.wallet_label()?.as_deref().unwrap_or("default") == "default" {
            w.set_wallet_label("memory-wallet")?;
            let _ = w.rename_pgp_label("default", "memory-wallet");
        }
        Ok(w)
    }

    // ── Identity material ────────────────────────────────────────────────────

    pub fn root_private_key_hex(&self) -> Result<String> {
        metadata_value(&self.conn, META_ROOT_PRIVATE_KEY_HEX)?
            .ok_or_else(|| Error::Other(anyhow::anyhow!("missing root private key")))
    }

    pub fn identity(&self) -> Result<Identity> {
        self.rgb_identity()
    }

    pub fn rgb_identity(&self) -> Result<Identity> {
        let hex = metadata_value(&self.conn, META_RGB_PRIVATE_KEY_HEX)?
            .ok_or_else(|| Error::Other(anyhow::anyhow!("missing RGB private key")))?;
        Identity::from_hex(&hex)
    }

    pub fn derive_webcash_master_secret_hex(&self) -> Result<String> {
        let root_hex = self.root_private_key_hex()?;
        let root_key = decode_fixed_32_hex(&root_hex, "root private key")?;
        derive_child_key_hex(&root_key, HKDF_WEBCASH_MASTER_V1)
    }

    pub fn derive_bitcoin_master_key_hex(&self) -> Result<String> {
        let root_hex = self.root_private_key_hex()?;
        let root_key = decode_fixed_32_hex(&root_hex, "root private key")?;
        derive_child_key_hex(&root_key, HKDF_BITCOIN_MASTER_V1)
    }

    pub fn derive_slot_hex(&self, family: &str, index: u32) -> Result<String> {
        let root_hex = self.root_private_key_hex()?;
        let root_key = decode_fixed_32_hex(&root_hex, "root private key")?;
        match family {
            "rgb" => {
                if index != 0 {
                    return Err(Error::Other(anyhow::anyhow!(
                        "rgb family only supports index 0"
                    )));
                }
                derive_child_key_hex(&root_key, HKDF_RGB_IDENTITY_V1)
            }
            "webcash" => {
                if index != 0 {
                    return Err(Error::Other(anyhow::anyhow!(
                        "webcash family only supports index 0"
                    )));
                }
                derive_child_key_hex(&root_key, HKDF_WEBCASH_MASTER_V1)
            }
            "bitcoin" => {
                if index != 0 {
                    return Err(Error::Other(anyhow::anyhow!(
                        "bitcoin family only supports index 0"
                    )));
                }
                derive_child_key_hex(&root_key, HKDF_BITCOIN_MASTER_V1)
            }
            "pgp" => derive_pgp_private_key_hex(&root_key, index),
            _ => Err(Error::Other(anyhow::anyhow!(
                "unknown key family '{family}'"
            ))),
        }
    }

    pub fn export_master_key_hex(&self) -> Result<String> {
        self.root_private_key_hex()
    }

    pub fn export_master_key_mnemonic(&self) -> Result<String> {
        let root_hex = self.root_private_key_hex()?;
        let root_key = decode_fixed_32_hex(&root_hex, "root private key")?;
        // 256-bit entropy => 24 words. This is reversible and preserves full root key.
        let mnemonic = Mnemonic::from_entropy(&root_key)
            .map_err(|e| Error::Other(anyhow::anyhow!("failed to encode mnemonic: {e}")))?;
        Ok(mnemonic.to_string())
    }

    pub fn apply_master_key_hex(&self, root_private_key_hex: &str) -> Result<()> {
        let root_key = decode_fixed_32_hex(root_private_key_hex, "root private key")?;
        let rgb_hex = derive_child_key_hex(&root_key, HKDF_RGB_IDENTITY_V1)?;
        set_metadata_value(&self.conn, META_ROOT_PRIVATE_KEY_HEX, root_private_key_hex)?;
        set_metadata_value(&self.conn, META_RGB_PRIVATE_KEY_HEX, &rgb_hex)?;
        set_metadata_value(&self.conn, META_PRIVATE_KEY_HEX, &rgb_hex)?;
        set_metadata_value(&self.conn, META_KEY_MODEL_VERSION, KEY_MODEL_VERSION_V2)?;

        let wallet_label = self
            .wallet_label()?
            .unwrap_or_else(|| "default".to_string());
        let label = canonical_label(&wallet_label)?;
        let pgp0_hex = derive_pgp_private_key_hex(&root_key, 0)?;
        let pgp0 = Identity::from_hex(&pgp0_hex)?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM pgp_identities", [])?;
        tx.execute(
            "INSERT INTO pgp_identities (label, key_index, private_key_hex, public_key_hex, created_at, is_active)
             VALUES (?1, 0, ?2, ?3, ?4, 1)",
            params![
                label,
                pgp0_hex,
                pgp0.public_key_hex(),
                chrono::Utc::now().to_rfc3339(),
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn apply_master_key_mnemonic(&self, mnemonic: &str) -> Result<()> {
        let parsed = Mnemonic::parse(mnemonic.trim())
            .map_err(|e| Error::Other(anyhow::anyhow!("invalid BIP39 mnemonic: {e}")))?;
        let entropy = parsed.to_entropy();
        let root = match entropy.len() {
            32 => entropy,
            16 | 20 | 24 | 28 => {
                let hk = Hkdf::<Sha256>::new(None, &entropy);
                let mut out = [0u8; 32];
                hk.expand(b"harmoniis/hrmw/root/from-bip39/v1", &mut out)
                    .map_err(|_| {
                        Error::Other(anyhow::anyhow!("failed to derive root from mnemonic"))
                    })?;
                out.to_vec()
            }
            n => {
                return Err(Error::Other(anyhow::anyhow!(
                    "unsupported mnemonic entropy length: {n}"
                )))
            }
        };
        self.apply_master_key_hex(&hex::encode(root))
    }

    pub fn has_local_state(&self) -> Result<bool> {
        let mut stmt = self.conn.prepare("SELECT COUNT(*) FROM contracts")?;
        let contracts: i64 = stmt.query_row([], |row| row.get(0))?;
        let mut stmt = self.conn.prepare("SELECT COUNT(*) FROM certificates")?;
        let certs: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(contracts > 0 || certs > 0)
    }

    // ── PGP identities (labeled, multi-key) ─────────────────────────────────

    pub fn active_pgp_identity(&self) -> Result<(PgpIdentityRecord, Identity)> {
        let mut stmt = self.conn.prepare(
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
        let mut stmt = self.conn.prepare(
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
        let mut stmt = self.conn.prepare(
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
            .conn
            .prepare("SELECT COUNT(*) FROM pgp_identities WHERE label = ?1")?;
        let exists: i64 = exists_stmt.query_row(params![canonical.clone()], |row| row.get(0))?;
        if exists > 0 {
            return Err(Error::Other(anyhow::anyhow!(
                "PGP identity label '{canonical}' already exists"
            )));
        }

        let key_index = self.next_pgp_key_index()?;
        let root_hex = self.root_private_key_hex()?;
        let root_key = decode_fixed_32_hex(&root_hex, "root private key")?;
        let private_key_hex = derive_pgp_private_key_hex(&root_key, key_index)?;
        let identity = Identity::from_hex(&private_key_hex)?;
        let public_key_hex = identity.public_key_hex();

        self.conn.execute(
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

        self.pgp_identity_by_label(label).map(|(meta, _)| meta)
    }

    pub fn derive_pgp_identity_for_index(&self, key_index: u32) -> Result<Identity> {
        let root_hex = self.root_private_key_hex()?;
        let root_key = decode_fixed_32_hex(&root_hex, "root private key")?;
        let private_key_hex = derive_pgp_private_key_hex(&root_key, key_index)?;
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

        let tx = self.conn.unchecked_transaction()?;
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
            .conn
            .prepare("SELECT COUNT(*) FROM pgp_identities WHERE label = ?1")?;
        let exists: i64 = exists_stmt.query_row(params![canonical.clone()], |row| row.get(0))?;
        if exists == 0 {
            return Err(Error::NotFound(format!(
                "PGP identity label '{canonical}' not found"
            )));
        }
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("UPDATE pgp_identities SET is_active = 0", [])?;
        tx.execute(
            "UPDATE pgp_identities SET is_active = 1 WHERE label = ?1",
            params![canonical],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn rename_pgp_label(&self, from: &str, to: &str) -> Result<()> {
        let from_c = canonical_label(from)?;
        let to_c = canonical_label(to)?;
        if from_c == to_c {
            return Ok(());
        }
        self.conn.execute(
            "UPDATE pgp_identities SET label = ?1 WHERE label = ?2",
            params![to_c, from_c],
        )?;
        Ok(())
    }

    fn next_pgp_key_index(&self) -> Result<u32> {
        let mut stmt = self
            .conn
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
                .conn
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

    // ── Wallet metadata ──────────────────────────────────────────────────────

    pub fn fingerprint(&self) -> Result<String> {
        Ok(self.rgb_identity()?.fingerprint())
    }

    pub fn nickname(&self) -> Result<Option<String>> {
        metadata_value(&self.conn, META_NICKNAME)
    }

    pub fn set_nickname(&self, nick: &str) -> Result<()> {
        set_metadata_value(&self.conn, META_NICKNAME, nick)
    }

    pub fn wallet_label(&self) -> Result<Option<String>> {
        metadata_value(&self.conn, META_WALLET_LABEL)
    }

    pub fn set_wallet_label(&self, label: &str) -> Result<()> {
        let canonical = canonical_label(label)?;
        set_metadata_value(&self.conn, META_WALLET_LABEL, &canonical)
    }

    // ── Contracts ─────────────────────────────────────────────────────────────

    pub fn store_contract(&self, c: &Contract) -> Result<()> {
        self.conn.execute(
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
        Ok(())
    }

    pub fn update_contract(&self, c: &Contract) -> Result<()> {
        self.store_contract(c)
    }

    pub fn get_contract(&self, id: &str) -> Result<Option<Contract>> {
        let mut stmt = self.conn.prepare(
            "SELECT contract_id, contract_type, status, witness_secret, witness_proof,
                    amount_units, work_spec, buyer_fingerprint, seller_fingerprint,
                    reference_post, delivery_deadline, role, delivered_text,
                    certificate_id, created_at, updated_at
             FROM contracts WHERE contract_id = ?1",
        )?;
        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row_to_contract(row)?))
        } else {
            Ok(None)
        }
    }

    pub fn list_contracts(&self) -> Result<Vec<Contract>> {
        let mut stmt = self.conn.prepare(
            "SELECT contract_id, contract_type, status, witness_secret, witness_proof,
                    amount_units, work_spec, buyer_fingerprint, seller_fingerprint,
                    reference_post, delivery_deadline, role, delivered_text,
                    certificate_id, created_at, updated_at
             FROM contracts ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            row_to_contract(row).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Error::Storage)
    }

    // ── Certificates ──────────────────────────────────────────────────────────

    pub fn store_certificate(&self, cert: &Certificate) -> Result<()> {
        self.conn.execute(
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
        Ok(())
    }

    pub fn list_certificates(&self) -> Result<Vec<Certificate>> {
        let mut stmt = self.conn.prepare(
            "SELECT certificate_id, contract_id, witness_secret, witness_proof, created_at
             FROM certificates ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Certificate {
                certificate_id: row.get(0)?,
                contract_id: row.get(1)?,
                witness_secret: row.get(2)?,
                witness_proof: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Error::Storage)
    }

    // ── Snapshot ──────────────────────────────────────────────────────────────

    pub fn export_snapshot(&self) -> Result<WalletSnapshot> {
        let rgb_id = self.rgb_identity()?;
        let root = self.root_private_key_hex()?;
        let mut stmt = self.conn.prepare(
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
            wallet_label: self.wallet_label()?,
            pgp_identities,
            nickname: self.nickname()?,
            contracts: self.list_contracts()?,
            certificates: self.list_certificates()?,
        })
    }

    pub fn import_snapshot(&self, snap: &WalletSnapshot) -> Result<()> {
        let root = snap
            .root_private_key_hex
            .clone()
            .unwrap_or_else(|| snap.private_key_hex.clone());

        set_metadata_value(&self.conn, META_ROOT_PRIVATE_KEY_HEX, &root)?;
        set_metadata_value(&self.conn, META_RGB_PRIVATE_KEY_HEX, &snap.private_key_hex)?;
        set_metadata_value(&self.conn, META_PRIVATE_KEY_HEX, &snap.private_key_hex)?;

        if let Some(label) = &snap.wallet_label {
            self.set_wallet_label(label)?;
        }

        if let Some(nick) = &snap.nickname {
            self.set_nickname(nick)?;
        }

        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM pgp_identities", [])?;
        if snap.pgp_identities.is_empty() {
            let wallet_label = self
                .wallet_label()?
                .unwrap_or_else(|| "default".to_string());
            let root_bytes = decode_fixed_32_hex(&root, "root private key")?;
            let private_key_hex = derive_pgp_private_key_hex(&root_bytes, 0)?;
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

        for c in &snap.contracts {
            self.store_contract(c)?;
        }
        for cert in &snap.certificates {
            self.store_certificate(cert)?;
        }
        Ok(())
    }
}

fn migrate_legacy_schema(conn: &Connection) -> Result<()> {
    ensure_columns(
        conn,
        "contracts",
        &[
            ("contract_type", "TEXT NOT NULL DEFAULT 'service'"),
            ("status", "TEXT NOT NULL DEFAULT 'issued'"),
            ("witness_secret", "TEXT"),
            ("witness_proof", "TEXT"),
            ("amount_units", "INTEGER NOT NULL DEFAULT 0"),
            ("work_spec", "TEXT NOT NULL DEFAULT ''"),
            ("buyer_fingerprint", "TEXT NOT NULL DEFAULT ''"),
            ("seller_fingerprint", "TEXT"),
            ("reference_post", "TEXT"),
            ("delivery_deadline", "TEXT"),
            ("role", "TEXT NOT NULL DEFAULT 'buyer'"),
            ("delivered_text", "TEXT"),
            ("certificate_id", "TEXT"),
            ("created_at", "TEXT NOT NULL DEFAULT ''"),
            ("updated_at", "TEXT NOT NULL DEFAULT ''"),
        ],
    )?;
    ensure_columns(
        conn,
        "certificates",
        &[
            ("contract_id", "TEXT"),
            ("witness_secret", "TEXT"),
            ("witness_proof", "TEXT"),
            ("created_at", "TEXT NOT NULL DEFAULT ''"),
        ],
    )?;
    Ok(())
}

fn ensure_root_and_identity_materialized(conn: &Connection) -> Result<()> {
    let legacy = metadata_value(conn, META_PRIVATE_KEY_HEX)?;
    let root = metadata_value(conn, META_ROOT_PRIVATE_KEY_HEX)?;
    let rgb = metadata_value(conn, META_RGB_PRIVATE_KEY_HEX)?;

    let root_hex = if let Some(value) = root {
        value
    } else if let Some(value) = legacy.clone() {
        set_metadata_value(conn, META_ROOT_PRIVATE_KEY_HEX, &value)?;
        value
    } else {
        let generated = Identity::generate().private_key_hex();
        set_metadata_value(conn, META_ROOT_PRIVATE_KEY_HEX, &generated)?;
        generated
    };

    let rgb_hex = if let Some(value) = rgb {
        value
    } else if let Some(value) = legacy {
        set_metadata_value(conn, META_RGB_PRIVATE_KEY_HEX, &value)?;
        value
    } else {
        let root_key = decode_fixed_32_hex(&root_hex, "root private key")?;
        let derived = derive_child_key_hex(&root_key, HKDF_RGB_IDENTITY_V1)?;
        set_metadata_value(conn, META_RGB_PRIVATE_KEY_HEX, &derived)?;
        derived
    };

    // Keep legacy metadata key populated for backward compatibility.
    set_metadata_value(conn, META_PRIVATE_KEY_HEX, &rgb_hex)?;
    if metadata_value(conn, META_KEY_MODEL_VERSION)?.is_none() {
        set_metadata_value(conn, META_KEY_MODEL_VERSION, KEY_MODEL_VERSION_V2)?;
    }

    if metadata_value(conn, META_WALLET_LABEL)?.is_none() {
        set_metadata_value(conn, META_WALLET_LABEL, "default")?;
    }

    Ok(())
}

fn ensure_default_pgp_identity(conn: &Connection) -> Result<()> {
    let mut count_stmt = conn.prepare("SELECT COUNT(*) FROM pgp_identities")?;
    let count: i64 = count_stmt.query_row([], |row| row.get(0))?;
    if count > 0 {
        // Ensure at least one active identity exists.
        let mut active_stmt =
            conn.prepare("SELECT COUNT(*) FROM pgp_identities WHERE is_active = 1")?;
        let active: i64 = active_stmt.query_row([], |row| row.get(0))?;
        if active == 0 {
            conn.execute(
                "UPDATE pgp_identities SET is_active = 1 WHERE key_index = (
                    SELECT MIN(key_index) FROM pgp_identities
                )",
                [],
            )?;
        }
        return Ok(());
    }

    let wallet_label =
        metadata_value(conn, META_WALLET_LABEL)?.unwrap_or_else(|| "default".to_string());
    let root_hex = metadata_value(conn, META_ROOT_PRIVATE_KEY_HEX)?
        .ok_or_else(|| Error::Other(anyhow::anyhow!("missing root private key")))?;

    let root_key = decode_fixed_32_hex(&root_hex, "root private key")?;
    let legacy = metadata_value(conn, META_PRIVATE_KEY_HEX)?;
    let rgb = metadata_value(conn, META_RGB_PRIVATE_KEY_HEX)?;
    let private_key_hex = match (legacy, rgb) {
        (Some(legacy), Some(rgb)) if legacy == rgb && legacy == root_hex => {
            // Legacy wallet where root==RGB identity. Preserve server-visible identity.
            legacy
        }
        _ => derive_pgp_private_key_hex(&root_key, 0)?,
    };

    let identity = Identity::from_hex(&private_key_hex)?;
    conn.execute(
        "INSERT INTO pgp_identities (label, key_index, private_key_hex, public_key_hex, created_at, is_active)
         VALUES (?1, 0, ?2, ?3, ?4, 1)",
        params![
            canonical_label(&wallet_label)?,
            private_key_hex,
            identity.public_key_hex(),
            chrono::Utc::now().to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn set_metadata_value(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO wallet_metadata (key, value) VALUES (?1, ?2)",
        params![key, value],
    )?;
    Ok(())
}

fn metadata_value(conn: &Connection, key: &str) -> Result<Option<String>> {
    let mut stmt = conn.prepare("SELECT value FROM wallet_metadata WHERE key = ?1")?;
    let mut rows = stmt.query(params![key])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    Ok(Some(row.get(0)?))
}

fn derive_child_key_hex(root: &[u8; 32], info: &[u8]) -> Result<String> {
    let hk = Hkdf::<Sha256>::new(None, root);
    let mut output = [0u8; 32];
    hk.expand(info, &mut output)
        .map_err(|_| Error::Other(anyhow::anyhow!("HKDF expansion failed")))?;
    Ok(hex::encode(output))
}

fn derive_pgp_private_key_hex(root: &[u8; 32], key_index: u32) -> Result<String> {
    if key_index >= MAX_PGP_KEYS {
        return Err(Error::Other(anyhow::anyhow!(
            "PGP key index out of range (max {})",
            MAX_PGP_KEYS - 1
        )));
    }
    let info = format!("harmoniis/hrmw/pgp/{key_index}/v1");
    derive_child_key_hex(root, info.as_bytes())
}

fn decode_fixed_32_hex(hex_value: &str, what: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_value)
        .map_err(|e| Error::Other(anyhow::anyhow!("invalid {what} hex: {e}")))?;
    let len = bytes.len();
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        Error::Other(anyhow::anyhow!(
            "invalid {what}: expected 32 bytes, got {}",
            len
        ))
    })?;
    Ok(arr)
}

fn canonical_label(label: &str) -> Result<String> {
    let canonical = label.trim();
    if canonical.is_empty() {
        return Err(Error::Other(anyhow::anyhow!("label cannot be empty")));
    }
    if canonical.len() > 64 {
        return Err(Error::Other(anyhow::anyhow!(
            "label too long (max 64 chars)"
        )));
    }
    Ok(canonical.to_string())
}

fn ensure_columns(conn: &Connection, table: &str, required: &[(&str, &str)]) -> Result<()> {
    let existing = current_columns(conn, table)?;
    for (name, ddl) in required {
        if existing.contains(*name) {
            continue;
        }
        let sql = format!("ALTER TABLE {table} ADD COLUMN {name} {ddl}");
        conn.execute(&sql, [])?;
    }
    Ok(())
}

fn current_columns(conn: &Connection, table: &str) -> Result<HashSet<String>> {
    let mut columns = HashSet::new();
    let sql = format!("PRAGMA table_info({table})");
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        columns.insert(name);
    }
    Ok(columns)
}

fn row_to_contract(row: &rusqlite::Row<'_>) -> Result<Contract> {
    let amount_units_i: i64 = row.get(5)?;
    Ok(Contract {
        contract_id: row.get(0)?,
        contract_type: ContractType::parse(&row.get::<_, String>(1)?)?,
        status: ContractStatus::parse(&row.get::<_, String>(2)?)?,
        witness_secret: row.get(3)?,
        witness_proof: row.get(4)?,
        amount_units: amount_units_i as u64,
        work_spec: row.get(6)?,
        buyer_fingerprint: row.get(7)?,
        seller_fingerprint: row.get(8)?,
        reference_post: row.get(9)?,
        delivery_deadline: row.get(10)?,
        role: Role::parse(&row.get::<_, String>(11)?)?,
        delivered_text: row.get(12)?,
        certificate_id: row.get(13)?,
        created_at: row.get(14)?,
        updated_at: row.get(15)?,
    })
}
