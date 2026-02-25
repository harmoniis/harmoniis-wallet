use std::collections::HashSet;
use std::path::Path;

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    identity::Identity,
    types::{Certificate, Contract, ContractStatus, ContractType, Role},
};

/// SQLite-backed RGB wallet.
pub struct RgbWallet {
    conn: Connection,
}

/// Serializable snapshot for backup/restore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSnapshot {
    pub private_key_hex: String,
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
            ",
        )?;
        migrate_legacy_schema(&conn)?;
        Ok(Self { conn })
    }

    /// Create a new wallet at the given path, generating a fresh identity.
    pub fn create(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Other(anyhow::anyhow!("cannot create wallet dir: {e}")))?;
        }
        let conn = Connection::open(path)?;
        let w = Self::init(conn)?;
        // Generate and persist a fresh identity
        let id = Identity::generate();
        w.conn.execute(
            "INSERT OR IGNORE INTO wallet_metadata (key, value) VALUES ('private_key_hex', ?1)",
            params![id.private_key_hex()],
        )?;
        Ok(w)
    }

    /// Open an existing wallet at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// Open an in-memory wallet (for tests).
    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let w = Self::init(conn)?;
        let id = Identity::generate();
        w.conn.execute(
            "INSERT OR IGNORE INTO wallet_metadata (key, value) VALUES ('private_key_hex', ?1)",
            params![id.private_key_hex()],
        )?;
        Ok(w)
    }

    // ── Identity ──────────────────────────────────────────────────────────────

    pub fn identity(&self) -> Result<Identity> {
        let hex: String = self.conn.query_row(
            "SELECT value FROM wallet_metadata WHERE key = 'private_key_hex'",
            [],
            |row| row.get(0),
        )?;
        Identity::from_hex(&hex)
    }

    pub fn fingerprint(&self) -> Result<String> {
        Ok(self.identity()?.fingerprint())
    }

    pub fn nickname(&self) -> Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM wallet_metadata WHERE key = 'nickname'")?;
        let mut rows = stmt.query([])?;
        Ok(rows.next()?.map(|r| r.get(0)).transpose()?)
    }

    pub fn set_nickname(&self, nick: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO wallet_metadata (key, value) VALUES ('nickname', ?1)",
            params![nick],
        )?;
        Ok(())
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
        let id = self.identity()?;
        Ok(WalletSnapshot {
            private_key_hex: id.private_key_hex(),
            nickname: self.nickname()?,
            contracts: self.list_contracts()?,
            certificates: self.list_certificates()?,
        })
    }

    pub fn import_snapshot(&self, snap: &WalletSnapshot) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO wallet_metadata (key, value) VALUES ('private_key_hex', ?1)",
            params![snap.private_key_hex],
        )?;
        if let Some(nick) = &snap.nickname {
            self.set_nickname(nick)?;
        }
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
