use std::collections::HashSet;
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    identity::Identity,
    keychain::{HdKeychain, KEY_MODEL_VERSION_V3},
    types::{Certificate, Contract, ContractStatus, ContractType, Role},
};

const META_RGB_PRIVATE_KEY_HEX: &str = "rgb_private_key_hex";
const META_ROOT_PRIVATE_KEY_HEX: &str = "root_private_key_hex";
const META_ROOT_MNEMONIC: &str = "root_mnemonic";
const META_NICKNAME: &str = "nickname";
const META_WALLET_LABEL: &str = "wallet_label";
const META_KEY_MODEL_VERSION: &str = "key_model_version";

pub const MAX_PGP_KEYS: u32 = 1_000;
const MASTER_DB_FILENAME: &str = "master.db";
const RGB_DB_FILENAME: &str = "rgb.db";
const WALLET_DB_FILENAME: &str = "wallet.db";
const RGB_SHARD_DIR: &str = "identities";

/// SQLite-backed Harmoniis wallet.
pub struct RgbWallet {
    master_conn: Connection,
    rgb_conn: Connection,
}

struct WalletDiskPaths {
    base_dir: PathBuf,
    master_path: PathBuf,
    rgb_path: PathBuf,
    wallet_migration_path: PathBuf,
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
    pub root_mnemonic: Option<String>,
    #[serde(default)]
    pub wallet_label: Option<String>,
    #[serde(default)]
    pub pgp_identities: Vec<PgpIdentitySnapshot>,
    pub nickname: Option<String>,
    pub contracts: Vec<Contract>,
    pub certificates: Vec<Certificate>,
}

impl RgbWallet {
    fn resolve_disk_paths(path: &Path) -> Result<WalletDiskPaths> {
        let normalized = if path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .is_empty()
        {
            PathBuf::from(MASTER_DB_FILENAME)
        } else {
            path.to_path_buf()
        };
        let file_name = normalized
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(MASTER_DB_FILENAME);
        let base_dir = normalized
            .parent()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| PathBuf::from("."));
        let master_path = if file_name.eq_ignore_ascii_case(MASTER_DB_FILENAME) {
            normalized.clone()
        } else if file_name.eq_ignore_ascii_case(RGB_DB_FILENAME)
            || file_name.eq_ignore_ascii_case(WALLET_DB_FILENAME)
        {
            base_dir.join(MASTER_DB_FILENAME)
        } else {
            normalized.clone()
        };
        Ok(WalletDiskPaths {
            base_dir: base_dir.clone(),
            master_path,
            rgb_path: base_dir.join(RGB_DB_FILENAME),
            wallet_migration_path: base_dir.join(WALLET_DB_FILENAME),
        })
    }

    fn derive_wallet_label(path: &Path) -> String {
        let stem = path
            .file_stem()
            .and_then(|x| x.to_str())
            .unwrap_or("wallet");
        if stem.eq_ignore_ascii_case("master")
            || stem.eq_ignore_ascii_case("rgb")
            || stem.eq_ignore_ascii_case("wallet")
        {
            path.parent()
                .and_then(|p| p.file_name())
                .and_then(|x| x.to_str())
                .map(ToString::to_string)
                .unwrap_or_else(|| "wallet".to_string())
        } else {
            stem.to_string()
        }
    }

    fn init_master_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;

            CREATE TABLE IF NOT EXISTS wallet_metadata (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pgp_identities (
                label           TEXT PRIMARY KEY,
                key_index       INTEGER NOT NULL UNIQUE,
                private_key_hex TEXT NOT NULL,
                public_key_hex  TEXT NOT NULL,
                created_at      TEXT NOT NULL,
                is_active       INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS wallet_slots (
                family      TEXT NOT NULL,
                slot_index  INTEGER NOT NULL,
                descriptor  TEXT NOT NULL,
                db_rel_path TEXT,
                label       TEXT,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL,
                PRIMARY KEY (family, slot_index)
            );
            ",
        )?;
        ensure_root_and_identity_materialized(conn)?;
        ensure_default_pgp_identity(conn)?;
        Ok(())
    }

    fn init_identity_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;

            CREATE TABLE IF NOT EXISTS contracts (
                contract_id        TEXT PRIMARY KEY,
                contract_type      TEXT NOT NULL DEFAULT 'service',
                status             TEXT NOT NULL DEFAULT 'issued',
                witness_secret     TEXT,
                witness_proof      TEXT,
                amount_units       INTEGER NOT NULL DEFAULT 0,
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
                certificate_id  TEXT PRIMARY KEY,
                contract_id     TEXT,
                witness_secret  TEXT,
                witness_proof   TEXT,
                created_at      TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS timeline_posts (
                post_id      TEXT PRIMARY KEY,
                created_at   TEXT NOT NULL,
                updated_at   TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS timeline_comments (
                comment_id    TEXT PRIMARY KEY,
                post_id       TEXT NOT NULL DEFAULT '',
                created_at    TEXT NOT NULL,
                updated_at    TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS timeline_bids (
                bid_post_id    TEXT PRIMARY KEY,
                contract_id    TEXT NOT NULL DEFAULT '',
                service_post_id TEXT NOT NULL DEFAULT '',
                created_at     TEXT NOT NULL,
                metadata_json  TEXT NOT NULL DEFAULT '{}'
            );
            ",
        )?;
        migrate_identity_schema(conn)?;
        Ok(())
    }

    fn with_identity_conn<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        f(&self.rgb_conn)
    }

    fn refresh_slot_registry(&self) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let root_hex = self.derive_slot_hex("root", 0)?;
        let rgb_hex = self.derive_slot_hex("rgb", 0)?;
        let webcash_hex = self.derive_slot_hex("webcash", 0)?;
        let bitcoin_hex = self.derive_slot_hex("bitcoin", 0)?;

        self.master_conn.execute(
            "INSERT OR REPLACE INTO wallet_slots (family, slot_index, descriptor, db_rel_path, label, created_at, updated_at)
             VALUES ('rgb', 0, ?1, NULL, NULL, COALESCE((SELECT created_at FROM wallet_slots WHERE family='rgb' AND slot_index=0), ?2), ?2)",
            params![rgb_hex, now],
        )?;
        self.master_conn.execute(
            "INSERT OR REPLACE INTO wallet_slots (family, slot_index, descriptor, db_rel_path, label, created_at, updated_at)
             VALUES ('webcash', 0, ?1, NULL, NULL, COALESCE((SELECT created_at FROM wallet_slots WHERE family='webcash' AND slot_index=0), ?2), ?2)",
            params![webcash_hex, now],
        )?;
        self.master_conn.execute(
            "INSERT OR REPLACE INTO wallet_slots (family, slot_index, descriptor, db_rel_path, label, created_at, updated_at)
             VALUES ('bitcoin', 0, ?1, NULL, NULL, COALESCE((SELECT created_at FROM wallet_slots WHERE family='bitcoin' AND slot_index=0), ?2), ?2)",
            params![bitcoin_hex, now],
        )?;
        self.master_conn.execute(
            "INSERT OR REPLACE INTO wallet_slots (family, slot_index, descriptor, db_rel_path, label, created_at, updated_at)
             VALUES ('root', 0, ?1, NULL, NULL, COALESCE((SELECT created_at FROM wallet_slots WHERE family='root' AND slot_index=0), ?2), ?2)",
            params![root_hex, now],
        )?;

        let mut stmt = self.master_conn.prepare(
            "SELECT key_index, public_key_hex, label FROM pgp_identities ORDER BY key_index ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let key_index_i: i64 = row.get(0)?;
            let key_index = u32::try_from(key_index_i)
                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, key_index_i))?;
            let public_key_hex: String = row.get(1)?;
            let label: String = row.get(2)?;
            Ok((key_index, public_key_hex, label))
        })?;
        for row in rows {
            let (key_index, public_key_hex, label) = row?;
            self.master_conn.execute(
                "INSERT OR REPLACE INTO wallet_slots (family, slot_index, descriptor, db_rel_path, label, created_at, updated_at)
                 VALUES ('pgp', ?1, ?2, ?3, ?4, COALESCE((SELECT created_at FROM wallet_slots WHERE family='pgp' AND slot_index=?1), ?5), ?5)",
                params![
                    i64::from(key_index),
                    public_key_hex,
                    Some(RGB_DB_FILENAME.to_string()),
                    label,
                    now
                ],
            )?;
        }
        Ok(())
    }

    fn import_previous_layout(paths: &WalletDiskPaths) -> Result<()> {
        let source_path = if paths.rgb_path.exists() {
            paths.rgb_path.clone()
        } else if paths.wallet_migration_path.exists() {
            paths.wallet_migration_path.clone()
        } else {
            return Err(Error::NotFound("no wallet data source found".to_string()));
        };

        let source_conn = Connection::open(&source_path)?;
        migrate_identity_schema_if_present(&source_conn)?;

        let master_conn = Connection::open(&paths.master_path)?;
        Self::init_master_schema(&master_conn)?;

        if table_exists(&source_conn, "wallet_metadata")? {
            let mut stmt = source_conn.prepare("SELECT key, value FROM wallet_metadata")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (key, value) = row?;
                master_conn.execute(
                    "INSERT OR REPLACE INTO wallet_metadata (key, value) VALUES (?1, ?2)",
                    params![key, value],
                )?;
            }
        }

        if table_exists(&source_conn, "pgp_identities")? {
            let mut stmt = source_conn.prepare(
                "SELECT label, key_index, private_key_hex, public_key_hex, created_at, is_active
                 FROM pgp_identities",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })?;
            master_conn.execute("DELETE FROM pgp_identities", [])?;
            for row in rows {
                let (label, key_index, private_key_hex, public_key_hex, created_at, is_active) =
                    row?;
                master_conn.execute(
                    "INSERT OR REPLACE INTO pgp_identities
                     (label, key_index, private_key_hex, public_key_hex, created_at, is_active)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        label,
                        key_index,
                        private_key_hex,
                        public_key_hex,
                        created_at,
                        is_active
                    ],
                )?;
            }
        }
        ensure_root_and_identity_materialized(&master_conn)?;
        ensure_default_pgp_identity(&master_conn)?;
        drop(master_conn);

        let rgb_conn = Connection::open(&paths.rgb_path)?;
        Self::init_identity_schema(&rgb_conn)?;
        if !same_path(&source_path, &paths.rgb_path) {
            migrate_rgb_state(&source_conn, &rgb_conn)?;
        }
        Self::merge_sharded_rgb_data(&paths.base_dir, &rgb_conn)?;
        Ok(())
    }

    fn merge_sharded_rgb_data(base_dir: &Path, rgb_conn: &Connection) -> Result<()> {
        let shard_dir = base_dir.join(RGB_SHARD_DIR);
        if !shard_dir.exists() {
            return Ok(());
        }
        for entry in std::fs::read_dir(&shard_dir)
            .map_err(|e| Error::Other(anyhow::anyhow!("cannot read rgb shard dir: {e}")))?
        {
            let entry =
                entry.map_err(|e| Error::Other(anyhow::anyhow!("cannot read rgb shard entry: {e}")))?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.starts_with("identity-") || !name.ends_with(".db") {
                continue;
            }
            let shard_conn = Connection::open(&path)?;
            migrate_identity_schema_if_present(&shard_conn)?;
            migrate_rgb_state(&shard_conn, rgb_conn)?;
        }
        Ok(())
    }

    fn open_from_disk(path: &Path, allow_create: bool) -> Result<Self> {
        let paths = Self::resolve_disk_paths(path)?;
        std::fs::create_dir_all(&paths.base_dir)
            .map_err(|e| Error::Other(anyhow::anyhow!("cannot create wallet dir: {e}")))?;

        if !paths.master_path.exists() {
            if paths.rgb_path.exists() || paths.wallet_migration_path.exists() {
                Self::import_previous_layout(&paths)?;
            } else if !allow_create {
                return Err(Error::NotFound(format!(
                    "master wallet database not found at {}",
                    paths.master_path.display()
                )));
            }
        }

        let master_conn = Connection::open(&paths.master_path)?;
        Self::init_master_schema(&master_conn)?;
        let rgb_conn = Connection::open(&paths.rgb_path)?;
        Self::init_identity_schema(&rgb_conn)?;
        Self::merge_sharded_rgb_data(&paths.base_dir, &rgb_conn)?;
        let wallet = Self {
            master_conn,
            rgb_conn,
        };
        wallet.refresh_slot_registry()?;

        if wallet.wallet_label()?.as_deref().unwrap_or("default") == "default" {
            let derived = Self::derive_wallet_label(path);
            wallet.set_wallet_label(&derived)?;
            let _ = wallet.rename_pgp_label("default", &derived);
            wallet.refresh_slot_registry()?;
        }
        Ok(wallet)
    }

    /// Create a new wallet at the given path, generating a fresh root key.
    pub fn create(path: &Path) -> Result<Self> {
        Self::open_from_disk(path, true)
    }

    /// Open an existing wallet at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_from_disk(path, false)
    }

    /// Open an in-memory wallet (for tests).
    pub fn open_memory() -> Result<Self> {
        let master_conn = Connection::open_in_memory()?;
        Self::init_master_schema(&master_conn)?;
        let rgb_conn = Connection::open_in_memory()?;
        Self::init_identity_schema(&rgb_conn)?;
        let wallet = Self {
            master_conn,
            rgb_conn,
        };
        if wallet.wallet_label()?.as_deref().unwrap_or("default") == "default" {
            wallet.set_wallet_label("memory-wallet")?;
            let _ = wallet.rename_pgp_label("default", "memory-wallet");
        }
        wallet.refresh_slot_registry()?;
        Ok(wallet)
    }

    // ── Identity material ────────────────────────────────────────────────────

    pub fn root_private_key_hex(&self) -> Result<String> {
        metadata_value(&self.master_conn, META_ROOT_PRIVATE_KEY_HEX)?
            .ok_or_else(|| Error::Other(anyhow::anyhow!("missing master entropy hex")))
    }

    fn keychain(&self) -> Result<HdKeychain> {
        if let Some(words) = metadata_value(&self.master_conn, META_ROOT_MNEMONIC)? {
            return HdKeychain::from_mnemonic_words(&words);
        }
        let entropy_hex = self.root_private_key_hex()?;
        HdKeychain::from_entropy_hex(&entropy_hex)
    }

    fn set_master_keychain_material(&self, keychain: &HdKeychain) -> Result<()> {
        set_metadata_value(
            &self.master_conn,
            META_ROOT_PRIVATE_KEY_HEX,
            &keychain.entropy_hex(),
        )?;
        set_metadata_value(
            &self.master_conn,
            META_ROOT_MNEMONIC,
            &keychain.mnemonic_words(),
        )?;
        set_metadata_value(
            &self.master_conn,
            META_RGB_PRIVATE_KEY_HEX,
            &keychain.derive_slot_hex("rgb", 0)?,
        )?;
        set_metadata_value(
            &self.master_conn,
            META_KEY_MODEL_VERSION,
            KEY_MODEL_VERSION_V3,
        )?;
        Ok(())
    }

    pub fn identity(&self) -> Result<Identity> {
        self.rgb_identity()
    }

    pub fn rgb_identity(&self) -> Result<Identity> {
        let hex = self.derive_slot_hex("rgb", 0)?;
        Identity::from_hex(&hex)
    }

    pub fn derive_webcash_master_secret_hex(&self) -> Result<String> {
        self.derive_slot_hex("webcash", 0)
    }

    pub fn derive_bitcoin_master_key_hex(&self) -> Result<String> {
        self.derive_slot_hex("bitcoin", 0)
    }

    pub fn derive_slot_hex(&self, family: &str, index: u32) -> Result<String> {
        self.keychain()?.derive_slot_hex(family, index)
    }

    pub fn export_master_key_hex(&self) -> Result<String> {
        self.root_private_key_hex()
    }

    pub fn export_master_key_mnemonic(&self) -> Result<String> {
        self.keychain().map(|k| k.mnemonic_words())
    }

    /// Export the canonical recovery phrase stored in wallet metadata.
    ///
    /// New wallets store a 12-word BIP39 phrase at creation time. Existing wallets
    /// may fall back to the reversible 24-word representation of the root key.
    pub fn export_recovery_mnemonic(&self) -> Result<String> {
        if let Some(mnemonic) = metadata_value(&self.master_conn, META_ROOT_MNEMONIC)? {
            return Ok(mnemonic);
        }
        self.export_master_key_mnemonic()
    }

    pub fn apply_master_key_hex(&self, root_private_key_hex: &str) -> Result<()> {
        let keychain = HdKeychain::from_entropy_hex(root_private_key_hex)?;
        self.set_master_keychain_material(&keychain)?;

        let wallet_label = self
            .wallet_label()?
            .unwrap_or_else(|| "default".to_string());
        let label = canonical_label(&wallet_label)?;
        let pgp0_hex = keychain.derive_slot_hex("pgp", 0)?;
        let pgp0 = Identity::from_hex(&pgp0_hex)?;
        let tx = self.master_conn.unchecked_transaction()?;
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
        self.refresh_slot_registry()?;
        Ok(())
    }

    pub fn apply_master_key_mnemonic(&self, mnemonic: &str) -> Result<()> {
        let keychain = HdKeychain::from_mnemonic_words(mnemonic)?;
        self.apply_master_key_hex(&keychain.entropy_hex())
    }

    pub fn has_local_state(&self) -> Result<bool> {
        let (contracts, certs) = self.with_identity_conn(|conn| {
            let mut stmt = conn.prepare("SELECT COUNT(*) FROM contracts")?;
            let contracts: i64 = stmt.query_row([], |row| row.get(0))?;
            let mut stmt = conn.prepare("SELECT COUNT(*) FROM certificates")?;
            let certs: i64 = stmt.query_row([], |row| row.get(0))?;
            Ok((contracts, certs))
        })?;
        Ok(contracts > 0 || certs > 0)
    }

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

    // ── Wallet metadata ──────────────────────────────────────────────────────

    pub fn fingerprint(&self) -> Result<String> {
        Ok(self.rgb_identity()?.fingerprint())
    }

    pub fn nickname(&self) -> Result<Option<String>> {
        metadata_value(&self.master_conn, META_NICKNAME)
    }

    pub fn set_nickname(&self, nick: &str) -> Result<()> {
        set_metadata_value(&self.master_conn, META_NICKNAME, nick)
    }

    pub fn wallet_label(&self) -> Result<Option<String>> {
        metadata_value(&self.master_conn, META_WALLET_LABEL)
    }

    pub fn set_wallet_label(&self, label: &str) -> Result<()> {
        let canonical = canonical_label(label)?;
        let out = set_metadata_value(&self.master_conn, META_WALLET_LABEL, &canonical);
        if out.is_ok() {
            let _ = self.refresh_slot_registry();
        }
        out
    }

    // ── Contracts ─────────────────────────────────────────────────────────────

    pub fn store_contract(&self, c: &Contract) -> Result<()> {
        self.with_identity_conn(|conn| {
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
            Ok(())
        })
    }

    pub fn update_contract(&self, c: &Contract) -> Result<()> {
        self.store_contract(c)
    }

    pub fn get_contract(&self, id: &str) -> Result<Option<Contract>> {
        self.with_identity_conn(|conn| {
            let mut stmt = conn.prepare(
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
        })
    }

    pub fn list_contracts(&self) -> Result<Vec<Contract>> {
        self.with_identity_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT contract_id, contract_type, status, witness_secret, witness_proof,
                    amount_units, work_spec, buyer_fingerprint, seller_fingerprint,
                    reference_post, delivery_deadline, role, delivered_text,
                    certificate_id, created_at, updated_at
                 FROM contracts ORDER BY created_at DESC",
            )?;
            let rows = stmt.query_map([], |row| {
                row_to_contract(row)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
            })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(Error::Storage)
        })
    }

    // ── Certificates ──────────────────────────────────────────────────────────

    pub fn store_certificate(&self, cert: &Certificate) -> Result<()> {
        self.with_identity_conn(|conn| {
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
            Ok(())
        })
    }

    pub fn list_certificates(&self) -> Result<Vec<Certificate>> {
        self.with_identity_conn(|conn| {
            let mut stmt = conn.prepare(
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
        })
    }

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

fn same_path(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(left), Ok(right)) => left == right,
        _ => a == b,
    }
}

fn migrate_rgb_state(source_conn: &Connection, target_conn: &Connection) -> Result<()> {
    if table_exists(source_conn, "contracts")? {
        let mut stmt = source_conn.prepare(
            "SELECT contract_id, contract_type, status, witness_secret, witness_proof,
                    amount_units, work_spec, buyer_fingerprint, seller_fingerprint,
                    reference_post, delivery_deadline, role, delivered_text,
                    certificate_id, created_at, updated_at
             FROM contracts",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Contract {
                contract_id: row.get(0)?,
                contract_type: ContractType::parse(&row.get::<_, String>(1)?)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
                status: ContractStatus::parse(&row.get::<_, String>(2)?)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
                witness_secret: row.get(3)?,
                witness_proof: row.get(4)?,
                amount_units: row.get::<_, i64>(5)? as u64,
                work_spec: row.get(6)?,
                buyer_fingerprint: row.get(7)?,
                seller_fingerprint: row.get(8)?,
                reference_post: row.get(9)?,
                delivery_deadline: row.get(10)?,
                role: Role::parse(&row.get::<_, String>(11)?)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
                delivered_text: row.get(12)?,
                certificate_id: row.get(13)?,
                created_at: row.get(14)?,
                updated_at: row.get(15)?,
            })
        })?;
        for row in rows {
            let c = row?;
            target_conn.execute(
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
    }

    if table_exists(source_conn, "certificates")? {
        let mut stmt = source_conn.prepare(
            "SELECT certificate_id, contract_id, witness_secret, witness_proof, created_at
             FROM certificates",
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
        for row in rows {
            let cert = row?;
            target_conn.execute(
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
    }

    if table_exists(source_conn, "timeline_posts")? {
        let mut stmt = source_conn.prepare(
            "SELECT post_id, created_at, updated_at, metadata_json FROM timeline_posts",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        for row in rows {
            let (post_id, created_at, updated_at, metadata_json) = row?;
            target_conn.execute(
                "INSERT OR REPLACE INTO timeline_posts (post_id, created_at, updated_at, metadata_json)
                 VALUES (?1, ?2, ?3, ?4)",
                params![post_id, created_at, updated_at, metadata_json],
            )?;
        }
    }

    if table_exists(source_conn, "timeline_comments")? {
        let mut stmt = source_conn.prepare(
            "SELECT comment_id, post_id, created_at, updated_at, metadata_json FROM timeline_comments",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        for row in rows {
            let (comment_id, post_id, created_at, updated_at, metadata_json) = row?;
            target_conn.execute(
                "INSERT OR REPLACE INTO timeline_comments (comment_id, post_id, created_at, updated_at, metadata_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![comment_id, post_id, created_at, updated_at, metadata_json],
            )?;
        }
    }

    if table_exists(source_conn, "timeline_bids")? {
        let mut stmt = source_conn.prepare(
            "SELECT bid_post_id, contract_id, service_post_id, created_at, metadata_json FROM timeline_bids",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        for row in rows {
            let (bid_post_id, contract_id, service_post_id, created_at, metadata_json) = row?;
            target_conn.execute(
                "INSERT OR REPLACE INTO timeline_bids (bid_post_id, contract_id, service_post_id, created_at, metadata_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    bid_post_id,
                    contract_id,
                    service_post_id,
                    created_at,
                    metadata_json
                ],
            )?;
        }
    }
    Ok(())
}

fn migrate_identity_schema(conn: &Connection) -> Result<()> {
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

fn migrate_identity_schema_if_present(conn: &Connection) -> Result<()> {
    if table_exists(conn, "contracts")? {
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
    }
    if table_exists(conn, "certificates")? {
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
    }
    Ok(())
}

fn ensure_root_and_identity_materialized(conn: &Connection) -> Result<()> {
    let mnemonic = metadata_value(conn, META_ROOT_MNEMONIC)?
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let entropy_hex = metadata_value(conn, META_ROOT_PRIVATE_KEY_HEX)?
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let keychain = if let Some(words) = mnemonic.as_deref() {
        HdKeychain::from_mnemonic_words(words)?
    } else if let Some(root_hex) = entropy_hex.as_deref() {
        HdKeychain::from_entropy_hex(root_hex)?
    } else {
        HdKeychain::generate_new()?
    };

    set_metadata_value(conn, META_ROOT_PRIVATE_KEY_HEX, &keychain.entropy_hex())?;
    set_metadata_value(conn, META_ROOT_MNEMONIC, &keychain.mnemonic_words())?;
    set_metadata_value(
        conn,
        META_RGB_PRIVATE_KEY_HEX,
        &keychain.derive_slot_hex("rgb", 0)?,
    )?;
    set_metadata_value(conn, META_KEY_MODEL_VERSION, KEY_MODEL_VERSION_V3)?;

    if metadata_value(conn, META_WALLET_LABEL)?.is_none() {
        set_metadata_value(conn, META_WALLET_LABEL, "default")?;
    }

    Ok(())
}

fn ensure_default_pgp_identity(conn: &Connection) -> Result<()> {
    let keychain = keychain_from_metadata(conn)?;
    let mut count_stmt = conn.prepare("SELECT COUNT(*) FROM pgp_identities")?;
    let count: i64 = count_stmt.query_row([], |row| row.get(0))?;
    if count > 0 {
        // Canonicalize all PGP private/public keys from deterministic BIP32 slots.
        let mut stmt = conn.prepare(
            "SELECT label, key_index, created_at, is_active
             FROM pgp_identities
             ORDER BY key_index ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        let mut entries = Vec::new();
        for row in rows {
            let (label, key_index, created_at, is_active) = row?;
            let private_key_hex = keychain.derive_slot_hex("pgp", key_index)?;
            let identity = Identity::from_hex(&private_key_hex)?;
            entries.push((
                canonical_label(&label)?,
                key_index,
                private_key_hex,
                identity.public_key_hex(),
                created_at,
                is_active,
            ));
        }
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM pgp_identities", [])?;
        let mut saw_active = false;
        for (label, key_index, private_key_hex, public_key_hex, created_at, was_active) in entries {
            let is_active = if was_active == 1 && !saw_active {
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
                    i64::from(key_index),
                    private_key_hex,
                    public_key_hex,
                    created_at,
                    is_active,
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
        tx.commit()?;
        return Ok(());
    }

    let wallet_label =
        metadata_value(conn, META_WALLET_LABEL)?.unwrap_or_else(|| "default".to_string());
    let private_key_hex = keychain.derive_slot_hex("pgp", 0)?;

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

fn keychain_from_metadata(conn: &Connection) -> Result<HdKeychain> {
    if let Some(words) = metadata_value(conn, META_ROOT_MNEMONIC)? {
        return HdKeychain::from_mnemonic_words(&words);
    }
    let entropy_hex = metadata_value(conn, META_ROOT_PRIVATE_KEY_HEX)?.ok_or_else(|| {
        Error::Other(anyhow::anyhow!("missing master entropy in wallet metadata"))
    })?;
    HdKeychain::from_entropy_hex(&entropy_hex)
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

fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    let mut stmt = conn
        .prepare("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = ?1 LIMIT 1")?;
    let count: i64 = stmt.query_row(params![table], |row| row.get(0))?;
    Ok(count > 0)
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
