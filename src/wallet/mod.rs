pub mod schema;
pub mod identities;
pub mod labeled_wallets;
pub mod payments;
pub mod contracts;
pub mod snapshots;
pub mod storage;
pub mod webcash;

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    identity::Identity,
    keychain::{
        HdKeychain, KEY_MODEL_VERSION_V3, MAX_VAULT_KEYS, SLOT_FAMILY_HARMONIA_VAULT,
        SLOT_FAMILY_VAULT,
    },
};

use schema::{
    canonical_label, ensure_root_and_identity_materialized, ensure_default_pgp_identity,
    metadata_value, migrate_identity_schema_if_present, migrate_rgb_state, same_path,
    set_metadata_value, table_exists,
    META_KEY_MODEL_VERSION, META_RGB_PRIVATE_KEY_HEX, META_ROOT_MNEMONIC,
    META_ROOT_PRIVATE_KEY_HEX, META_WALLET_LABEL,
};

// Re-export submodule types for backward compatibility.
pub use identities::PgpIdentityRecord;
pub use payments::{
    NewPaymentAttempt, NewPaymentTransaction, NewPaymentTransactionEvent, PaymentAttemptRecord,
    PaymentAttemptUpdate, PaymentBlacklistRecord, PaymentLossRecord,
    PaymentTransactionEventRecord, PaymentTransactionRecord, PaymentTransactionUpdate,
};
pub use snapshots::{PgpIdentitySnapshot, WalletSnapshot};

const META_NICKNAME: &str = "nickname";

pub const MAX_PGP_KEYS: u32 = 1_000;
const MASTER_DB_FILENAME: &str = "master.db";
const RGB_DB_FILENAME: &str = "rgb.db";
const VOUCHER_DB_FILENAME: &str = "voucher.db";
const WALLET_DB_FILENAME: &str = "wallet.db";
const RGB_SHARD_DIR: &str = "identities";

/// SQLite-backed Harmoniis wallet.
pub struct WalletCore {
    pub(crate) master_conn: Connection,
    pub(crate) rgb_conn: Connection,
}

/// Backward-compatible type alias.
pub type RgbWallet = WalletCore;

struct WalletDiskPaths {
    base_dir: PathBuf,
    master_path: PathBuf,
    rgb_path: PathBuf,
    wallet_migration_path: PathBuf,
}

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

impl WalletCore {
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

            CREATE TABLE IF NOT EXISTS payment_attempts (
                attempt_id        TEXT PRIMARY KEY,
                created_at        TEXT NOT NULL,
                updated_at        TEXT NOT NULL,
                service_origin    TEXT NOT NULL,
                endpoint_path     TEXT NOT NULL,
                method            TEXT NOT NULL,
                rail              TEXT NOT NULL,
                action_hint       TEXT NOT NULL,
                required_amount   TEXT NOT NULL,
                payment_unit      TEXT NOT NULL,
                payment_reference TEXT,
                request_hash      TEXT NOT NULL,
                response_status   INTEGER,
                response_code     TEXT,
                response_body     TEXT,
                recovery_state    TEXT NOT NULL,
                final_state       TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS payment_losses (
                loss_id            TEXT PRIMARY KEY,
                attempt_id         TEXT NOT NULL,
                created_at         TEXT NOT NULL,
                service_origin     TEXT NOT NULL,
                endpoint_path      TEXT NOT NULL,
                method             TEXT NOT NULL,
                rail               TEXT NOT NULL,
                amount             TEXT NOT NULL,
                payment_reference  TEXT,
                failure_stage      TEXT NOT NULL,
                response_status    INTEGER,
                response_code      TEXT,
                response_body      TEXT
            );

            CREATE TABLE IF NOT EXISTS payment_blacklist (
                service_origin      TEXT NOT NULL,
                endpoint_path       TEXT NOT NULL,
                method              TEXT NOT NULL,
                rail                TEXT NOT NULL,
                blacklisted_until   TEXT,
                reason              TEXT NOT NULL,
                triggered_by_loss_id TEXT,
                created_at          TEXT NOT NULL,
                updated_at          TEXT NOT NULL,
                PRIMARY KEY (service_origin, endpoint_path, method, rail)
            );

            CREATE TABLE IF NOT EXISTS payment_transactions (
                txn_id          TEXT PRIMARY KEY,
                attempt_id      TEXT,
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL,
                occurred_at     TEXT NOT NULL,
                direction       TEXT NOT NULL,
                role            TEXT NOT NULL,
                source_system   TEXT NOT NULL,
                service_origin  TEXT,
                frontend_kind   TEXT,
                transport_kind  TEXT,
                endpoint_path   TEXT,
                method          TEXT,
                session_id      TEXT,
                action_kind     TEXT NOT NULL,
                resource_ref    TEXT,
                contract_ref    TEXT,
                invoice_ref     TEXT,
                challenge_id    TEXT,
                rail            TEXT NOT NULL,
                payment_unit    TEXT NOT NULL,
                quoted_amount   TEXT,
                settled_amount  TEXT,
                fee_amount      TEXT,
                proof_ref       TEXT,
                proof_kind      TEXT,
                payer_ref       TEXT,
                payee_ref       TEXT,
                request_hash    TEXT,
                response_code   TEXT,
                status          TEXT NOT NULL,
                metadata_json   TEXT
            );

            CREATE TABLE IF NOT EXISTS payment_transaction_events (
                event_id       TEXT PRIMARY KEY,
                txn_id         TEXT NOT NULL,
                created_at     TEXT NOT NULL,
                event_type     TEXT NOT NULL,
                status         TEXT NOT NULL,
                actor          TEXT NOT NULL,
                details_json   TEXT NOT NULL DEFAULT '{}'
            );

            CREATE INDEX IF NOT EXISTS idx_payment_transactions_created_at
                ON payment_transactions(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_payment_transactions_status
                ON payment_transactions(status, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_payment_transactions_direction
                ON payment_transactions(direction, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_payment_transactions_action_kind
                ON payment_transactions(action_kind, created_at DESC);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_transactions_proof_ref
                ON payment_transactions(direction, rail, proof_ref)
                WHERE proof_ref IS NOT NULL AND proof_ref != '';
            CREATE INDEX IF NOT EXISTS idx_payment_transaction_events_txn_id
                ON payment_transaction_events(txn_id, created_at ASC);
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
        schema::migrate_identity_schema(conn)?;
        Ok(())
    }

    pub(crate) fn with_identity_conn<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        f(&self.rgb_conn)
    }

    pub(crate) fn refresh_slot_registry(&self) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let root_hex = self.derive_slot_hex("root", 0)?;
        let rgb_hex = self.derive_slot_hex("rgb", 0)?;
        let webcash_hex = self.derive_slot_hex("webcash", 0)?;
        let voucher_hex = self.derive_slot_hex("voucher", 0)?;
        let bitcoin_hex = self.derive_slot_hex("bitcoin", 0)?;
        let vault_hex = self.derive_slot_hex(SLOT_FAMILY_VAULT, 0)?;

        self.master_conn.execute(
            "INSERT OR REPLACE INTO wallet_slots (family, slot_index, descriptor, db_rel_path, label, created_at, updated_at)
             VALUES ('rgb', 0, ?1, NULL, (SELECT label FROM wallet_slots WHERE family='rgb' AND slot_index=0), COALESCE((SELECT created_at FROM wallet_slots WHERE family='rgb' AND slot_index=0), ?2), ?2)",
            params![rgb_hex, now],
        )?;
        self.master_conn.execute(
            "INSERT OR REPLACE INTO wallet_slots (family, slot_index, descriptor, db_rel_path, label, created_at, updated_at)
             VALUES ('webcash', 0, ?1, NULL, (SELECT label FROM wallet_slots WHERE family='webcash' AND slot_index=0), COALESCE((SELECT created_at FROM wallet_slots WHERE family='webcash' AND slot_index=0), ?2), ?2)",
            params![webcash_hex, now],
        )?;
        self.master_conn.execute(
            "INSERT OR REPLACE INTO wallet_slots (family, slot_index, descriptor, db_rel_path, label, created_at, updated_at)
             VALUES ('bitcoin', 0, ?1, NULL, (SELECT label FROM wallet_slots WHERE family='bitcoin' AND slot_index=0), COALESCE((SELECT created_at FROM wallet_slots WHERE family='bitcoin' AND slot_index=0), ?2), ?2)",
            params![bitcoin_hex, now],
        )?;
        self.master_conn.execute(
            "INSERT OR REPLACE INTO wallet_slots (family, slot_index, descriptor, db_rel_path, label, created_at, updated_at)
             VALUES ('voucher', 0, ?1, ?2, (SELECT label FROM wallet_slots WHERE family='voucher' AND slot_index=0), COALESCE((SELECT created_at FROM wallet_slots WHERE family='voucher' AND slot_index=0), ?3), ?3)",
            params![voucher_hex, Some(VOUCHER_DB_FILENAME.to_string()), now],
        )?;
        self.master_conn.execute(
            "INSERT OR REPLACE INTO wallet_slots (family, slot_index, descriptor, db_rel_path, label, created_at, updated_at)
             VALUES ('root', 0, ?1, NULL, (SELECT label FROM wallet_slots WHERE family='root' AND slot_index=0), COALESCE((SELECT created_at FROM wallet_slots WHERE family='root' AND slot_index=0), ?2), ?2)",
            params![root_hex, now],
        )?;
        self.master_conn.execute(
            "INSERT OR REPLACE INTO wallet_slots (family, slot_index, descriptor, db_rel_path, label, created_at, updated_at)
             VALUES (?1, 0, ?2, NULL, (SELECT label FROM wallet_slots WHERE family=?1 AND slot_index=0), COALESCE((SELECT created_at FROM wallet_slots WHERE family=?1 AND slot_index=0), ?3), ?3)",
            params![SLOT_FAMILY_VAULT, vault_hex, now],
        )?;

        let mut vault_stmt = self.master_conn.prepare(
            "SELECT slot_index, label, created_at
             FROM wallet_slots
             WHERE family = ?1 AND slot_index > 0
             ORDER BY slot_index ASC",
        )?;
        let vault_rows = vault_stmt.query_map(params![SLOT_FAMILY_VAULT], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let vault_rows = vault_rows.collect::<std::result::Result<Vec<_>, _>>()?;
        drop(vault_stmt);
        for row in vault_rows {
            let (slot_index, label, created_at) = row;
            let public_key_hex = self
                .derive_vault_identity_for_index(slot_index)?
                .public_key_hex();
            self.master_conn.execute(
                "INSERT OR REPLACE INTO wallet_slots (family, slot_index, descriptor, db_rel_path, label, created_at, updated_at)
                 VALUES (?1, ?2, ?3, NULL, ?4, ?5, ?6)",
                params![
                    SLOT_FAMILY_VAULT,
                    i64::from(slot_index),
                    public_key_hex,
                    label,
                    created_at,
                    now
                ],
            )?;
        }

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
            let entry = entry
                .map_err(|e| Error::Other(anyhow::anyhow!("cannot read rgb shard entry: {e}")))?;
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

    pub(crate) fn keychain(&self) -> Result<HdKeychain> {
        if let Some(words) = metadata_value(&self.master_conn, META_ROOT_MNEMONIC)? {
            return HdKeychain::from_mnemonic_words(&words);
        }
        let entropy_hex = self.root_private_key_hex()?;
        HdKeychain::from_entropy_hex(&entropy_hex)
    }

    pub(crate) fn set_master_keychain_material(&self, keychain: &HdKeychain) -> Result<()> {
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

    pub fn derive_voucher_master_secret_hex(&self) -> Result<String> {
        self.derive_slot_hex("voucher", 0)
    }

    pub fn derive_bitcoin_master_key_hex(&self) -> Result<String> {
        self.derive_slot_hex("bitcoin", 0)
    }

    pub fn derive_vault_master_key_hex(&self) -> Result<String> {
        self.derive_slot_hex(SLOT_FAMILY_VAULT, 0)
    }

    /// Backward-compatible alias retained for Harmonia integration naming.
    pub fn derive_harmonia_vault_master_key_hex(&self) -> Result<String> {
        self.derive_slot_hex(SLOT_FAMILY_HARMONIA_VAULT, 0)
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

    // ── Vault identities ────────────────────────────────────────────────────

    pub fn derive_vault_identity_for_index(&self, key_index: u32) -> Result<Identity> {
        if key_index == 0 {
            return Err(Error::Other(anyhow::anyhow!(
                "vault key index 0 is reserved for the vault root"
            )));
        }
        let private_key_hex = self.derive_slot_hex(SLOT_FAMILY_VAULT, key_index)?;
        Identity::from_hex(&private_key_hex)
    }

    pub fn create_vault_identity(&self, label: Option<&str>) -> Result<WalletSlotRecord> {
        let key_index = self.next_vault_key_index()?;
        self.ensure_vault_identity_index(key_index, label)
    }

    pub fn ensure_vault_identity_index(
        &self,
        key_index: u32,
        preferred_label: Option<&str>,
    ) -> Result<WalletSlotRecord> {
        if key_index == 0 || key_index >= MAX_VAULT_KEYS {
            return Err(Error::Other(anyhow::anyhow!(
                "vault key index out of range (valid: 1..{})",
                MAX_VAULT_KEYS - 1
            )));
        }

        let fallback_label = format!("vault-{key_index}-key-pairs");
        let desired_raw = preferred_label.unwrap_or(fallback_label.as_str());
        let desired = canonical_label(desired_raw)?;
        let label = self.unique_vault_label(&desired, key_index)?;
        let identity = self.derive_vault_identity_for_index(key_index)?;
        let public_key_hex = identity.public_key_hex();

        let tx = self.master_conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM wallet_slots WHERE family = ?1 AND slot_index = ?2",
            params![SLOT_FAMILY_VAULT, i64::from(key_index)],
        )?;
        tx.execute(
            "DELETE FROM wallet_slots WHERE family = ?1 AND label = ?2",
            params![SLOT_FAMILY_VAULT, label.clone()],
        )?;
        tx.execute(
            "INSERT INTO wallet_slots (family, slot_index, descriptor, db_rel_path, label, created_at, updated_at)
             VALUES (?1, ?2, ?3, NULL, ?4, ?5, ?5)",
            params![
                SLOT_FAMILY_VAULT,
                i64::from(key_index),
                public_key_hex,
                label,
                chrono::Utc::now().to_rfc3339(),
            ],
        )?;
        tx.commit()?;
        self.refresh_slot_registry()?;
        self.vault_identity_by_index(key_index)
    }

    pub fn list_vault_identities(&self) -> Result<Vec<WalletSlotRecord>> {
        self.list_wallet_slots(Some(SLOT_FAMILY_VAULT))
            .map(|items| {
                items
                    .into_iter()
                    .filter(|item| item.slot_index > 0)
                    .collect()
            })
    }

    pub fn vault_identity_by_label(&self, label: &str) -> Result<WalletSlotRecord> {
        let canonical = canonical_label(label)?;
        self.list_vault_identities()?
            .into_iter()
            .find(|item| item.label.as_deref() == Some(canonical.as_str()))
            .ok_or_else(|| Error::NotFound(format!("vault identity label '{canonical}' not found")))
    }

    pub fn vault_identity_by_index(&self, key_index: u32) -> Result<WalletSlotRecord> {
        self.list_vault_identities()?
            .into_iter()
            .find(|item| item.slot_index == key_index)
            .ok_or_else(|| Error::NotFound(format!("vault identity index '{key_index}' not found")))
    }

    fn next_vault_key_index(&self) -> Result<u32> {
        let mut stmt = self
            .master_conn
            .prepare("SELECT COALESCE(MAX(slot_index), 0) FROM wallet_slots WHERE family = ?1")?;
        let max_idx: i64 = stmt.query_row(params![SLOT_FAMILY_VAULT], |row| row.get(0))?;
        let next = max_idx.saturating_add(1);
        let next = u32::try_from(next)
            .map_err(|_| Error::Other(anyhow::anyhow!("too many vault identities in wallet")))?;
        if next >= MAX_VAULT_KEYS {
            return Err(Error::Other(anyhow::anyhow!(
                "vault key index out of range (max {})",
                MAX_VAULT_KEYS - 1
            )));
        }
        Ok(next)
    }

    fn unique_vault_label(&self, desired: &str, key_index: u32) -> Result<String> {
        let mut candidate = desired.to_string();
        let mut suffix = 1u32;
        loop {
            let mut stmt = self.master_conn.prepare(
                "SELECT slot_index FROM wallet_slots
                 WHERE family = ?1 AND label = ?2
                 LIMIT 1",
            )?;
            let mut rows = stmt.query(params![SLOT_FAMILY_VAULT, candidate.clone()])?;
            let Some(row) = rows.next()? else {
                return Ok(candidate);
            };
            let existing_i: i64 = row.get(0)?;
            let existing = u32::try_from(existing_i).map_err(|_| {
                Error::Other(anyhow::anyhow!("invalid vault key index in wallet_slots"))
            })?;
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

    pub fn list_wallet_slots(&self, family: Option<&str>) -> Result<Vec<WalletSlotRecord>> {
        let sql = if family.is_some() {
            "SELECT family, slot_index, descriptor, db_rel_path, label, created_at, updated_at
             FROM wallet_slots
             WHERE family = ?1
             ORDER BY family ASC, slot_index ASC"
        } else {
            "SELECT family, slot_index, descriptor, db_rel_path, label, created_at, updated_at
             FROM wallet_slots
             ORDER BY family ASC, slot_index ASC"
        };
        let mut stmt = self.master_conn.prepare(sql)?;
        let mapper = |row: &rusqlite::Row<'_>| -> rusqlite::Result<WalletSlotRecord> {
            Ok(WalletSlotRecord {
                family: row.get(0)?,
                slot_index: row.get(1)?,
                descriptor: row.get(2)?,
                db_rel_path: row.get(3)?,
                label: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        };
        let rows = match family {
            Some(name) => stmt.query_map(params![name], mapper)?,
            None => stmt.query_map([], mapper)?,
        };
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Error::Storage)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        payments::{NewPaymentTransaction, NewPaymentTransactionEvent, PaymentTransactionUpdate},
        WalletCore,
    };

    #[test]
    fn payment_transactions_round_trip_in_memory_wallet() {
        let wallet = WalletCore::open_memory().expect("memory wallet");
        let txn_id = wallet
            .record_payment_transaction(&NewPaymentTransaction {
                attempt_id: Some("pay_123"),
                occurred_at: Some("2026-03-17T10:00:00Z"),
                direction: "inbound",
                role: "payee",
                source_system: "harmonia",
                service_origin: Some("https://node.example"),
                frontend_kind: Some("http2"),
                transport_kind: Some("http2"),
                endpoint_path: Some("/v1/session"),
                method: Some("POST"),
                session_id: Some("session-1"),
                action_kind: "identity-claim",
                resource_ref: Some("identity:alice"),
                contract_ref: None,
                invoice_ref: None,
                challenge_id: Some("challenge-1"),
                rail: "webcash",
                payment_unit: "wats",
                quoted_amount: Some("42"),
                settled_amount: None,
                fee_amount: None,
                proof_ref: None,
                proof_kind: None,
                payer_ref: Some("payer:alice"),
                payee_ref: Some("payee:harmonia"),
                request_hash: Some("hash-1"),
                response_code: Some("payment_required"),
                status: "challenge_received",
                metadata_json: Some("{\"carrier\":\"http2\"}"),
            })
            .expect("record transaction");
        wallet
            .append_payment_transaction_event(&NewPaymentTransactionEvent {
                txn_id: &txn_id,
                event_type: "challenge_received",
                status: "challenge_received",
                actor: "gateway",
                details_json: Some("{\"price\":\"42\"}"),
            })
            .expect("append event");
        wallet
            .update_payment_transaction(
                &txn_id,
                &PaymentTransactionUpdate {
                    occurred_at: None,
                    service_origin: None,
                    frontend_kind: None,
                    transport_kind: None,
                    endpoint_path: None,
                    method: None,
                    session_id: None,
                    action_kind: None,
                    resource_ref: None,
                    contract_ref: None,
                    invoice_ref: None,
                    challenge_id: Some("challenge-1"),
                    quoted_amount: None,
                    settled_amount: Some("42"),
                    fee_amount: Some("1"),
                    proof_ref: Some("proof-hash-1"),
                    proof_kind: Some("webcash_secret_hash"),
                    payer_ref: None,
                    payee_ref: None,
                    request_hash: None,
                    response_code: Some("accepted"),
                    status: "succeeded",
                    metadata_json: Some("{\"settled\":true}"),
                },
            )
            .expect("update transaction");

        let txns = wallet
            .list_payment_transactions()
            .expect("list transactions");
        assert_eq!(txns.len(), 1);
        let txn = &txns[0];
        assert_eq!(txn.txn_id, txn_id);
        assert_eq!(txn.direction, "inbound");
        assert_eq!(txn.role, "payee");
        assert_eq!(txn.action_kind, "identity-claim");
        assert_eq!(txn.challenge_id.as_deref(), Some("challenge-1"));
        assert_eq!(txn.settled_amount.as_deref(), Some("42"));
        assert_eq!(txn.fee_amount.as_deref(), Some("1"));
        assert_eq!(txn.proof_kind.as_deref(), Some("webcash_secret_hash"));
        assert_eq!(txn.proof_ref.as_deref(), Some("proof-hash-1"));
        assert_eq!(txn.status, "succeeded");

        let events = wallet
            .list_payment_transaction_events(Some(&txn_id))
            .expect("list txn events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "challenge_received");
        assert_eq!(events[0].status, "challenge_received");
        assert_eq!(events[0].actor, "gateway");
    }

    #[test]
    fn payment_transactions_enforce_unique_proof_refs_per_direction_and_rail() {
        let wallet = WalletCore::open_memory().expect("memory wallet");
        wallet
            .record_payment_transaction(&NewPaymentTransaction {
                attempt_id: None,
                occurred_at: None,
                direction: "inbound",
                role: "payee",
                source_system: "harmonia",
                service_origin: Some("https://node.example"),
                frontend_kind: Some("http2"),
                transport_kind: Some("http2"),
                endpoint_path: Some("/v1/session"),
                method: Some("POST"),
                session_id: Some("session-1"),
                action_kind: "post",
                resource_ref: None,
                contract_ref: None,
                invoice_ref: None,
                challenge_id: None,
                rail: "voucher",
                payment_unit: "credits",
                quoted_amount: Some("10"),
                settled_amount: Some("10"),
                fee_amount: None,
                proof_ref: Some("proof-ref-1"),
                proof_kind: Some("voucher_public_hash"),
                payer_ref: None,
                payee_ref: None,
                request_hash: None,
                response_code: None,
                status: "succeeded",
                metadata_json: None,
            })
            .expect("insert first proof ref");

        let duplicate = wallet.record_payment_transaction(&NewPaymentTransaction {
            attempt_id: None,
            occurred_at: None,
            direction: "inbound",
            role: "payee",
            source_system: "harmonia",
            service_origin: Some("https://node.example"),
            frontend_kind: Some("mqtt"),
            transport_kind: Some("mqtt"),
            endpoint_path: Some("/topic/posts"),
            method: Some("PUBLISH"),
            session_id: Some("session-2"),
            action_kind: "comment",
            resource_ref: None,
            contract_ref: None,
            invoice_ref: None,
            challenge_id: None,
            rail: "voucher",
            payment_unit: "credits",
            quoted_amount: Some("5"),
            settled_amount: Some("5"),
            fee_amount: None,
            proof_ref: Some("proof-ref-1"),
            proof_kind: Some("voucher_public_hash"),
            payer_ref: None,
            payee_ref: None,
            request_hash: None,
            response_code: None,
            status: "succeeded",
            metadata_json: None,
        });
        assert!(
            duplicate.is_err(),
            "should reject duplicate proof_ref on same direction+rail"
        );

        wallet
            .record_payment_transaction(&NewPaymentTransaction {
                attempt_id: None,
                occurred_at: None,
                direction: "outbound",
                role: "payer",
                source_system: "harmonia",
                service_origin: Some("https://other.example"),
                frontend_kind: None,
                transport_kind: None,
                endpoint_path: None,
                method: None,
                session_id: None,
                action_kind: "refund",
                resource_ref: None,
                contract_ref: None,
                invoice_ref: None,
                challenge_id: None,
                rail: "voucher",
                payment_unit: "credits",
                quoted_amount: Some("10"),
                settled_amount: Some("10"),
                fee_amount: None,
                proof_ref: Some("proof-ref-1"),
                proof_kind: Some("voucher_public_hash"),
                payer_ref: None,
                payee_ref: None,
                request_hash: None,
                response_code: None,
                status: "succeeded",
                metadata_json: None,
            })
            .expect("same proof_ref on different direction should succeed");
    }
}
