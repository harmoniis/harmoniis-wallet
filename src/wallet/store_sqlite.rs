//! SQLite implementation of [`HarmoniiStore`].
//!
//! Uses two connections: `master_conn` for metadata, PGP identities,
//! wallet slots, and payment audit tables; `rgb_conn` for contracts
//! and certificates (identity store).

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};

use super::schema::{
    ensure_default_pgp_identity, ensure_root_and_identity_materialized, migrate_identity_schema,
    migrate_identity_schema_if_present, migrate_rgb_state, row_to_contract, same_path,
    table_exists,
};
use super::store::*;
use crate::error::{Error, Result};
use crate::types::{Certificate, Contract};

const MASTER_DB_FILENAME: &str = "master.db";
const LEGACY_RGB_DB: &str = "rgb.db";
const LEGACY_WALLET_DB: &str = "wallet.db";
const RGB_SHARD_DIR: &str = "identities";

struct WalletDiskPaths {
    base_dir: PathBuf,
    master_path: PathBuf,
    rgb_path: PathBuf,
    wallet_migration_path: PathBuf,
}

/// SQLite-backed storage for the Harmoniis wallet engine.
pub struct SqliteHarmoniiStore {
    master_conn: Connection,
    rgb_conn: Connection,
}

// ── Constructors + schema init ──────────────────────────────────

impl SqliteHarmoniiStore {
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
        } else if file_name.eq_ignore_ascii_case(LEGACY_RGB_DB)
            || file_name.eq_ignore_ascii_case("main_rgb.db")
            || file_name.eq_ignore_ascii_case(LEGACY_WALLET_DB)
        {
            base_dir.join(MASTER_DB_FILENAME)
        } else {
            normalized.clone()
        };
        let canonical_rgb = base_dir.join("main_rgb.db");
        let legacy_rgb = base_dir.join(LEGACY_RGB_DB);
        let rgb_path = if canonical_rgb.exists() {
            canonical_rgb
        } else if legacy_rgb.exists() {
            legacy_rgb
        } else {
            canonical_rgb
        };
        Ok(WalletDiskPaths {
            base_dir: base_dir.clone(),
            master_path,
            rgb_path,
            wallet_migration_path: base_dir.join(LEGACY_WALLET_DB),
        })
    }

    fn init_master_schema(conn: &Connection, allow_generate: bool) -> Result<()> {
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
        ensure_root_and_identity_materialized(conn, allow_generate)?;
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
        Self::init_master_schema(&master_conn, true)?;

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
                    params![label, key_index, private_key_hex, public_key_hex, created_at, is_active],
                )?;
            }
        }
        ensure_root_and_identity_materialized(&master_conn, true)?;
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
        Self::init_master_schema(&master_conn, allow_create)?;
        let rgb_conn = Connection::open(&paths.rgb_path)?;
        Self::init_identity_schema(&rgb_conn)?;
        Self::merge_sharded_rgb_data(&paths.base_dir, &rgb_conn)?;
        Ok(Self {
            master_conn,
            rgb_conn,
        })
    }

    /// Create a new store at the given path, generating fresh key material.
    pub fn create(path: &Path) -> Result<Self> {
        Self::open_from_disk(path, true)
    }

    /// Open an existing store at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_from_disk(path, false)
    }

    /// Open an in-memory store (for tests).
    pub fn open_memory() -> Result<Self> {
        let master_conn = Connection::open_in_memory()?;
        Self::init_master_schema(&master_conn, true)?;
        let rgb_conn = Connection::open_in_memory()?;
        Self::init_identity_schema(&rgb_conn)?;
        Ok(Self {
            master_conn,
            rgb_conn,
        })
    }

}

// ── HarmoniiStore implementation ────────────────────────────────

impl HarmoniiStore for SqliteHarmoniiStore {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    // ── Metadata ────────────────────────────────────────────────

    fn get_meta(&self, key: &str) -> Result<Option<String>> {
        let mut stmt = self
            .master_conn
            .prepare("SELECT value FROM wallet_metadata WHERE key = ?1")?;
        let mut rows = stmt.query(params![key])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        Ok(Some(row.get(0)?))
    }

    fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.master_conn.execute(
            "INSERT OR REPLACE INTO wallet_metadata (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    // ── PGP Identities ─────────────────────────────────────────

    fn list_pgp_raw(&self) -> Result<Vec<PgpIdentityRow>> {
        let mut stmt = self.master_conn.prepare(
            "SELECT label, key_index, private_key_hex, public_key_hex, created_at, is_active
             FROM pgp_identities
             ORDER BY key_index ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PgpIdentityRow {
                label: row.get(0)?,
                key_index: row.get(1)?,
                private_key_hex: row.get(2)?,
                public_key_hex: row.get(3)?,
                created_at: row.get(4)?,
                is_active: row.get::<_, i64>(5)? == 1,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Error::Storage)
    }

    fn insert_pgp(&self, row: &PgpIdentityRow) -> Result<()> {
        self.master_conn.execute(
            "INSERT INTO pgp_identities (label, key_index, private_key_hex, public_key_hex, created_at, is_active)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                row.label,
                i64::from(row.key_index),
                row.private_key_hex,
                row.public_key_hex,
                row.created_at,
                if row.is_active { 1i64 } else { 0i64 },
            ],
        )?;
        Ok(())
    }

    fn rename_pgp(&self, from: &str, to: &str) -> Result<u64> {
        let changed = self.master_conn.execute(
            "UPDATE pgp_identities SET label = ?1 WHERE label = ?2",
            params![to, from],
        )?;
        Ok(changed as u64)
    }

    fn count_pgp_by_label(&self, label: &str) -> Result<i64> {
        let mut stmt = self
            .master_conn
            .prepare("SELECT COUNT(*) FROM pgp_identities WHERE label = ?1")?;
        let count: i64 = stmt.query_row(params![label], |row| row.get(0))?;
        Ok(count)
    }

    fn max_pgp_key_index(&self) -> Result<i64> {
        let mut stmt = self
            .master_conn
            .prepare("SELECT COALESCE(MAX(key_index), -1) FROM pgp_identities")?;
        let max: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(max)
    }

    fn pgp_index_for_label(&self, label: &str) -> Result<Option<u32>> {
        let mut stmt = self
            .master_conn
            .prepare("SELECT key_index FROM pgp_identities WHERE label = ?1 LIMIT 1")?;
        let mut rows = stmt.query(params![label])?;
        if let Some(row) = rows.next()? {
            let idx: u32 = row.get(0)?;
            Ok(Some(idx))
        } else {
            Ok(None)
        }
    }

    fn replace_all_pgp(&self, rows: &[PgpIdentityRow]) -> Result<()> {
        let tx = self.master_conn.unchecked_transaction()?;
        tx.execute("DELETE FROM pgp_identities", [])?;
        for row in rows {
            tx.execute(
                "INSERT INTO pgp_identities (label, key_index, private_key_hex, public_key_hex, created_at, is_active)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    row.label,
                    i64::from(row.key_index),
                    row.private_key_hex,
                    row.public_key_hex,
                    row.created_at,
                    if row.is_active { 1i64 } else { 0i64 },
                ],
            )?;
        }
        if !rows.is_empty() && !rows.iter().any(|r| r.is_active) {
            tx.execute(
                "UPDATE pgp_identities SET is_active = 1 WHERE key_index = (
                    SELECT MIN(key_index) FROM pgp_identities
                )",
                [],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn replace_pgp_at(
        &self,
        key_index: u32,
        label: &str,
        row: &PgpIdentityRow,
        set_active: bool,
    ) -> Result<()> {
        let tx = self.master_conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM pgp_identities WHERE key_index = ?1",
            params![i64::from(key_index)],
        )?;
        tx.execute(
            "DELETE FROM pgp_identities WHERE label = ?1",
            params![label],
        )?;
        if set_active {
            tx.execute("UPDATE pgp_identities SET is_active = 0", [])?;
        }
        let active_flag = if set_active {
            1i64
        } else if row.is_active {
            1i64
        } else {
            0i64
        };
        tx.execute(
            "INSERT INTO pgp_identities (label, key_index, private_key_hex, public_key_hex, created_at, is_active)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                row.label,
                i64::from(row.key_index),
                row.private_key_hex,
                row.public_key_hex,
                row.created_at,
                active_flag,
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn activate_pgp_exclusive(&self, label: &str) -> Result<()> {
        let tx = self.master_conn.unchecked_transaction()?;
        tx.execute("UPDATE pgp_identities SET is_active = 0", [])?;
        let changed = tx.execute(
            "UPDATE pgp_identities SET is_active = 1 WHERE label = ?1",
            params![label],
        )?;
        if changed == 0 {
            return Err(Error::NotFound(format!(
                "PGP identity label '{label}' not found"
            )));
        }
        tx.commit()?;
        Ok(())
    }

    // ── Wallet Slots ────────────────────────────────────────────

    fn list_wallet_slots(&self, family: Option<&str>) -> Result<Vec<WalletSlotRecord>> {
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

    fn upsert_wallet_slot(&self, row: &WalletSlotRecord) -> Result<()> {
        self.master_conn.execute(
            "INSERT OR REPLACE INTO wallet_slots
                (family, slot_index, descriptor, db_rel_path, label, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5,
                COALESCE((SELECT created_at FROM wallet_slots WHERE family=?1 AND slot_index=?2), ?6), ?7)",
            params![
                row.family,
                i64::from(row.slot_index),
                row.descriptor,
                row.db_rel_path,
                row.label,
                row.created_at,
                row.updated_at,
            ],
        )?;
        Ok(())
    }

    fn get_slot_index_by_label(&self, family: &str, label: &str) -> Result<Option<u32>> {
        let mut stmt = self.master_conn.prepare(
            "SELECT slot_index FROM wallet_slots WHERE family = ?1 AND label = ?2 LIMIT 1",
        )?;
        let mut rows = stmt.query(params![family, label])?;
        if let Some(row) = rows.next()? {
            let idx: u32 = row.get(0)?;
            Ok(Some(idx))
        } else {
            Ok(None)
        }
    }

    fn max_slot_index(&self, family: &str) -> Result<i64> {
        let mut stmt = self
            .master_conn
            .prepare("SELECT COALESCE(MAX(slot_index), -1) FROM wallet_slots WHERE family = ?1")?;
        let max: i64 = stmt.query_row(params![family], |row| row.get(0))?;
        Ok(max)
    }

    fn replace_slot_at(
        &self,
        family: &str,
        slot_index: u32,
        label: &str,
        descriptor: &str,
        now: &str,
    ) -> Result<()> {
        let tx = self.master_conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM wallet_slots WHERE family = ?1 AND slot_index = ?2",
            params![family, i64::from(slot_index)],
        )?;
        tx.execute(
            "DELETE FROM wallet_slots WHERE family = ?1 AND label = ?2",
            params![family, label],
        )?;
        tx.execute(
            "INSERT INTO wallet_slots (family, slot_index, descriptor, db_rel_path, label, created_at, updated_at)
             VALUES (?1, ?2, ?3, NULL, ?4, ?5, ?5)",
            params![family, i64::from(slot_index), descriptor, label, now],
        )?;
        tx.commit()?;
        Ok(())
    }

    // ── Payment Attempts ────────────────────────────────────────

    fn insert_payment_attempt(&self, record: &PaymentAttemptRecord) -> Result<()> {
        self.master_conn.execute(
            "INSERT INTO payment_attempts (
                attempt_id, created_at, updated_at, service_origin, endpoint_path,
                method, rail, action_hint, required_amount, payment_unit,
                payment_reference, request_hash, response_status, response_code,
                response_body, recovery_state, final_state
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            params![
                record.attempt_id,
                record.created_at,
                record.updated_at,
                record.service_origin,
                record.endpoint_path,
                record.method,
                record.rail,
                record.action_hint,
                record.required_amount,
                record.payment_unit,
                record.payment_reference,
                record.request_hash,
                record.response_status.map(i64::from),
                record.response_code,
                record.response_body,
                record.recovery_state,
                record.final_state,
            ],
        )?;
        Ok(())
    }

    fn update_payment_attempt(
        &self,
        attempt_id: &str,
        now: &str,
        update: &PaymentAttemptUpdate<'_>,
    ) -> Result<()> {
        self.master_conn.execute(
            "UPDATE payment_attempts
             SET updated_at = ?2,
                 payment_reference = COALESCE(?3, payment_reference),
                 response_status = ?4,
                 response_code = ?5,
                 response_body = ?6,
                 recovery_state = ?7,
                 final_state = ?8
             WHERE attempt_id = ?1",
            params![
                attempt_id,
                now,
                update.payment_reference,
                update.response_status.map(i64::from),
                update.response_code,
                update.response_body,
                update.recovery_state,
                update.final_state,
            ],
        )?;
        Ok(())
    }

    // ── Payment Losses ──────────────────────────────────────────

    fn insert_payment_loss(&self, record: &PaymentLossRecord) -> Result<()> {
        self.master_conn.execute(
            "INSERT INTO payment_losses (
                loss_id, attempt_id, created_at, service_origin, endpoint_path,
                method, rail, amount, payment_reference, failure_stage,
                response_status, response_code, response_body
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                record.loss_id,
                record.attempt_id,
                record.created_at,
                record.service_origin,
                record.endpoint_path,
                record.method,
                record.rail,
                record.amount,
                record.payment_reference,
                record.failure_stage,
                record.response_status.map(i64::from),
                record.response_code,
                record.response_body,
            ],
        )?;
        Ok(())
    }

    fn list_payment_losses(&self) -> Result<Vec<PaymentLossRecord>> {
        let mut stmt = self.master_conn.prepare(
            "SELECT loss_id, attempt_id, created_at, service_origin, endpoint_path,
                    method, rail, amount, payment_reference, failure_stage,
                    response_status, response_code, response_body
             FROM payment_losses
             ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PaymentLossRecord {
                loss_id: row.get(0)?,
                attempt_id: row.get(1)?,
                created_at: row.get(2)?,
                service_origin: row.get(3)?,
                endpoint_path: row.get(4)?,
                method: row.get(5)?,
                rail: row.get(6)?,
                amount: row.get(7)?,
                payment_reference: row.get(8)?,
                failure_stage: row.get(9)?,
                response_status: row
                    .get::<_, Option<i64>>(10)?
                    .and_then(|v| u16::try_from(v).ok()),
                response_code: row.get(11)?,
                response_body: row.get(12)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Error::Storage)
    }

    fn count_recent_losses(
        &self,
        service_origin: &str,
        endpoint_path: &str,
        method: &str,
        rail: &str,
        cutoff: &str,
    ) -> Result<i64> {
        let mut stmt = self.master_conn.prepare(
            "SELECT COUNT(*)
             FROM payment_losses
             WHERE service_origin = ?1
               AND endpoint_path = ?2
               AND method = ?3
               AND rail = ?4
               AND created_at >= ?5",
        )?;
        let count: i64 = stmt.query_row(
            params![service_origin, endpoint_path, method, rail, cutoff],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    // ── Payment Blacklist ───────────────────────────────────────

    fn upsert_payment_blacklist(&self, record: &PaymentBlacklistRecord) -> Result<()> {
        self.master_conn.execute(
            "INSERT OR REPLACE INTO payment_blacklist (
                service_origin, endpoint_path, method, rail, blacklisted_until,
                reason, triggered_by_loss_id, created_at, updated_at
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7,
                COALESCE((SELECT created_at FROM payment_blacklist
                          WHERE service_origin = ?1 AND endpoint_path = ?2
                            AND method = ?3 AND rail = ?4), ?8),
                ?8
             )",
            params![
                record.service_origin,
                record.endpoint_path,
                record.method,
                record.rail,
                record.blacklisted_until,
                record.reason,
                record.triggered_by_loss_id,
                record.updated_at,
            ],
        )?;
        Ok(())
    }

    fn get_payment_blacklist_entry(
        &self,
        service_origin: &str,
        endpoint_path: &str,
        method: &str,
        rail: &str,
    ) -> Result<Option<PaymentBlacklistRecord>> {
        let mut stmt = self.master_conn.prepare(
            "SELECT service_origin, endpoint_path, method, rail,
                    blacklisted_until, reason, triggered_by_loss_id, created_at, updated_at
             FROM payment_blacklist
             WHERE service_origin = ?1 AND endpoint_path = ?2 AND method = ?3 AND rail = ?4",
        )?;
        let mut rows = stmt.query(params![service_origin, endpoint_path, method, rail])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        Ok(Some(PaymentBlacklistRecord {
            service_origin: row.get(0)?,
            endpoint_path: row.get(1)?,
            method: row.get(2)?,
            rail: row.get(3)?,
            blacklisted_until: row.get(4)?,
            reason: row.get(5)?,
            triggered_by_loss_id: row.get(6)?,
            created_at: row.get(7)?,
            updated_at: row.get(8)?,
        }))
    }

    fn list_payment_blacklist(&self) -> Result<Vec<PaymentBlacklistRecord>> {
        let mut stmt = self.master_conn.prepare(
            "SELECT service_origin, endpoint_path, method, rail,
                    blacklisted_until, reason, triggered_by_loss_id, created_at, updated_at
             FROM payment_blacklist
             ORDER BY updated_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PaymentBlacklistRecord {
                service_origin: row.get(0)?,
                endpoint_path: row.get(1)?,
                method: row.get(2)?,
                rail: row.get(3)?,
                blacklisted_until: row.get(4)?,
                reason: row.get(5)?,
                triggered_by_loss_id: row.get(6)?,
                created_at: row.get(7)?,
                updated_at: row.get(8)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Error::Storage)
    }

    fn delete_payment_blacklist(
        &self,
        service_origin: &str,
        endpoint_path: &str,
        method: &str,
        rail: &str,
    ) -> Result<bool> {
        let changed = self.master_conn.execute(
            "DELETE FROM payment_blacklist
             WHERE service_origin = ?1 AND endpoint_path = ?2 AND method = ?3 AND rail = ?4",
            params![service_origin, endpoint_path, method, rail],
        )?;
        Ok(changed > 0)
    }

    // ── Payment Transactions ────────────────────────────────────

    fn insert_payment_transaction(&self, record: &PaymentTransactionRecord) -> Result<()> {
        self.master_conn.execute(
            "INSERT INTO payment_transactions (
                txn_id, attempt_id, created_at, updated_at, occurred_at, direction, role,
                source_system, service_origin, frontend_kind, transport_kind, endpoint_path,
                method, session_id, action_kind, resource_ref, contract_ref, invoice_ref,
                challenge_id, rail, payment_unit, quoted_amount, settled_amount, fee_amount,
                proof_ref, proof_kind, payer_ref, payee_ref, request_hash, response_code,
                status, metadata_json
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7,
                ?8, ?9, ?10, ?11, ?12,
                ?13, ?14, ?15, ?16, ?17, ?18,
                ?19, ?20, ?21, ?22, ?23, ?24,
                ?25, ?26, ?27, ?28, ?29, ?30,
                ?31, ?32
             )",
            params![
                record.txn_id,
                record.attempt_id,
                record.created_at,
                record.updated_at,
                record.occurred_at,
                record.direction,
                record.role,
                record.source_system,
                record.service_origin,
                record.frontend_kind,
                record.transport_kind,
                record.endpoint_path,
                record.method,
                record.session_id,
                record.action_kind,
                record.resource_ref,
                record.contract_ref,
                record.invoice_ref,
                record.challenge_id,
                record.rail,
                record.payment_unit,
                record.quoted_amount,
                record.settled_amount,
                record.fee_amount,
                record.proof_ref,
                record.proof_kind,
                record.payer_ref,
                record.payee_ref,
                record.request_hash,
                record.response_code,
                record.status,
                record.metadata_json,
            ],
        )?;
        Ok(())
    }

    fn update_payment_transaction(
        &self,
        txn_id: &str,
        now: &str,
        update: &PaymentTransactionUpdate<'_>,
    ) -> Result<()> {
        self.master_conn.execute(
            "UPDATE payment_transactions
             SET updated_at = ?2,
                 occurred_at = COALESCE(?3, occurred_at),
                 service_origin = COALESCE(?4, service_origin),
                 frontend_kind = COALESCE(?5, frontend_kind),
                 transport_kind = COALESCE(?6, transport_kind),
                 endpoint_path = COALESCE(?7, endpoint_path),
                 method = COALESCE(?8, method),
                 session_id = COALESCE(?9, session_id),
                 action_kind = COALESCE(?10, action_kind),
                 resource_ref = COALESCE(?11, resource_ref),
                 contract_ref = COALESCE(?12, contract_ref),
                 invoice_ref = COALESCE(?13, invoice_ref),
                 challenge_id = COALESCE(?14, challenge_id),
                 quoted_amount = COALESCE(?15, quoted_amount),
                 settled_amount = COALESCE(?16, settled_amount),
                 fee_amount = COALESCE(?17, fee_amount),
                 proof_ref = COALESCE(?18, proof_ref),
                 proof_kind = COALESCE(?19, proof_kind),
                 payer_ref = COALESCE(?20, payer_ref),
                 payee_ref = COALESCE(?21, payee_ref),
                 request_hash = COALESCE(?22, request_hash),
                 response_code = COALESCE(?23, response_code),
                 status = ?24,
                 metadata_json = COALESCE(?25, metadata_json)
             WHERE txn_id = ?1",
            params![
                txn_id,
                now,
                update.occurred_at,
                update.service_origin,
                update.frontend_kind,
                update.transport_kind,
                update.endpoint_path,
                update.method,
                update.session_id,
                update.action_kind,
                update.resource_ref,
                update.contract_ref,
                update.invoice_ref,
                update.challenge_id,
                update.quoted_amount,
                update.settled_amount,
                update.fee_amount,
                update.proof_ref,
                update.proof_kind,
                update.payer_ref,
                update.payee_ref,
                update.request_hash,
                update.response_code,
                update.status,
                update.metadata_json,
            ],
        )?;
        Ok(())
    }

    fn list_payment_transactions(&self) -> Result<Vec<PaymentTransactionRecord>> {
        let mut stmt = self.master_conn.prepare(
            "SELECT txn_id, attempt_id, created_at, updated_at, occurred_at, direction, role,
                    source_system, service_origin, frontend_kind, transport_kind, endpoint_path,
                    method, session_id, action_kind, resource_ref, contract_ref, invoice_ref,
                    challenge_id, rail, payment_unit, quoted_amount, settled_amount, fee_amount,
                    proof_ref, proof_kind, payer_ref, payee_ref, request_hash, response_code,
                    status, metadata_json
             FROM payment_transactions
             ORDER BY occurred_at DESC, created_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PaymentTransactionRecord {
                txn_id: row.get(0)?,
                attempt_id: row.get(1)?,
                created_at: row.get(2)?,
                updated_at: row.get(3)?,
                occurred_at: row.get(4)?,
                direction: row.get(5)?,
                role: row.get(6)?,
                source_system: row.get(7)?,
                service_origin: row.get(8)?,
                frontend_kind: row.get(9)?,
                transport_kind: row.get(10)?,
                endpoint_path: row.get(11)?,
                method: row.get(12)?,
                session_id: row.get(13)?,
                action_kind: row.get(14)?,
                resource_ref: row.get(15)?,
                contract_ref: row.get(16)?,
                invoice_ref: row.get(17)?,
                challenge_id: row.get(18)?,
                rail: row.get(19)?,
                payment_unit: row.get(20)?,
                quoted_amount: row.get(21)?,
                settled_amount: row.get(22)?,
                fee_amount: row.get(23)?,
                proof_ref: row.get(24)?,
                proof_kind: row.get(25)?,
                payer_ref: row.get(26)?,
                payee_ref: row.get(27)?,
                request_hash: row.get(28)?,
                response_code: row.get(29)?,
                status: row.get(30)?,
                metadata_json: row.get(31)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Error::Storage)
    }

    // ── Payment Transaction Events ──────────────────────────────

    fn insert_payment_transaction_event(
        &self,
        record: &PaymentTransactionEventRecord,
    ) -> Result<()> {
        self.master_conn.execute(
            "INSERT INTO payment_transaction_events (
                event_id, txn_id, created_at, event_type, status, actor, details_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                record.event_id,
                record.txn_id,
                record.created_at,
                record.event_type,
                record.status,
                record.actor,
                record.details_json.as_deref().unwrap_or("{}"),
            ],
        )?;
        Ok(())
    }

    fn list_payment_transaction_events(
        &self,
        txn_id: Option<&str>,
    ) -> Result<Vec<PaymentTransactionEventRecord>> {
        let sql = if txn_id.is_some() {
            "SELECT event_id, txn_id, created_at, event_type, status, actor, details_json
             FROM payment_transaction_events
             WHERE txn_id = ?1
             ORDER BY created_at ASC"
        } else {
            "SELECT event_id, txn_id, created_at, event_type, status, actor, details_json
             FROM payment_transaction_events
             ORDER BY created_at ASC"
        };
        let mut stmt = self.master_conn.prepare(sql)?;
        let mapper = |row: &rusqlite::Row<'_>| {
            Ok(PaymentTransactionEventRecord {
                event_id: row.get(0)?,
                txn_id: row.get(1)?,
                created_at: row.get(2)?,
                event_type: row.get(3)?,
                status: row.get(4)?,
                actor: row.get(5)?,
                details_json: row
                    .get::<_, Option<String>>(6)?
                    .filter(|value| !value.is_empty() && value != "{}"),
            })
        };
        let rows = match txn_id {
            Some(id) => stmt.query_map(params![id], mapper)?,
            None => stmt.query_map([], mapper)?,
        };
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Error::Storage)
    }

    // ── Contracts (identity store / rgb_conn) ───────────────────

    fn store_contract(&self, c: &Contract) -> Result<()> {
        self.rgb_conn.execute(
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

    fn get_contract(&self, id: &str) -> Result<Option<Contract>> {
        let mut stmt = self.rgb_conn.prepare(
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

    fn list_contracts(&self) -> Result<Vec<Contract>> {
        let mut stmt = self.rgb_conn.prepare(
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
    }

    fn count_contracts(&self) -> Result<i64> {
        let mut stmt = self.rgb_conn.prepare("SELECT COUNT(*) FROM contracts")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count)
    }

    // ── Certificates (identity store / rgb_conn) ────────────────

    fn store_certificate(&self, cert: &Certificate) -> Result<()> {
        self.rgb_conn.execute(
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

    fn list_certificates(&self) -> Result<Vec<Certificate>> {
        let mut stmt = self.rgb_conn.prepare(
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

    fn count_certificates(&self) -> Result<i64> {
        let mut stmt = self
            .rgb_conn
            .prepare("SELECT COUNT(*) FROM certificates")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count)
    }

    // ── Bulk Operations ─────────────────────────────────────────

    fn replace_identity_data(
        &self,
        contracts: &[Contract],
        certificates: &[Certificate],
    ) -> Result<()> {
        let tx = self.rgb_conn.unchecked_transaction()?;
        tx.execute("DELETE FROM contracts", [])?;
        tx.execute("DELETE FROM certificates", [])?;
        for c in contracts {
            tx.execute(
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
        for cert in certificates {
            tx.execute(
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
        tx.commit()?;
        Ok(())
    }
}
