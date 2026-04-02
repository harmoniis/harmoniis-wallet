use std::collections::HashSet;
use std::path::Path;

use rusqlite::{params, Connection};

use crate::{
    error::{Error, Result},
    identity::Identity,
    keychain::{HdKeychain, KEY_MODEL_VERSION_V3},
    types::{Certificate, Contract, ContractStatus, ContractType, Role},
};

pub(crate) const META_RGB_PRIVATE_KEY_HEX: &str = "rgb_private_key_hex";
pub(crate) const META_ROOT_PRIVATE_KEY_HEX: &str = "root_private_key_hex";
pub(crate) const META_ROOT_MNEMONIC: &str = "root_mnemonic";
pub(crate) const META_WALLET_LABEL: &str = "wallet_label";
pub(crate) const META_KEY_MODEL_VERSION: &str = "key_model_version";

pub(crate) fn same_path(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(left), Ok(right)) => left == right,
        _ => a == b,
    }
}

pub(crate) fn migrate_rgb_state(source_conn: &Connection, target_conn: &Connection) -> Result<()> {
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
                arbitration_profit_wats: None,
                seller_value_wats: None,
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
        let mut stmt = source_conn
            .prepare("SELECT post_id, created_at, updated_at, metadata_json FROM timeline_posts")?;
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

pub(crate) fn migrate_identity_schema(conn: &Connection) -> Result<()> {
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

pub(crate) fn migrate_identity_schema_if_present(conn: &Connection) -> Result<()> {
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

pub(crate) fn ensure_root_and_identity_materialized(
    conn: &Connection,
    allow_generate: bool,
) -> Result<()> {
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
    } else if allow_generate {
        HdKeychain::generate_new()?
    } else {
        return Err(Error::KeyMaterialMissing(
            "root_mnemonic / root_private_key_hex missing; \
             refusing to generate new keys for an existing wallet \
             — restore from backup or re-import your mnemonic"
                .into(),
        ));
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

pub(crate) fn ensure_default_pgp_identity(conn: &Connection) -> Result<()> {
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

pub(crate) fn keychain_from_metadata(conn: &Connection) -> Result<HdKeychain> {
    if let Some(words) = metadata_value(conn, META_ROOT_MNEMONIC)? {
        return HdKeychain::from_mnemonic_words(&words);
    }
    let entropy_hex = metadata_value(conn, META_ROOT_PRIVATE_KEY_HEX)?.ok_or_else(|| {
        Error::Other(anyhow::anyhow!("missing master entropy in wallet metadata"))
    })?;
    HdKeychain::from_entropy_hex(&entropy_hex)
}

pub(crate) fn set_metadata_value(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO wallet_metadata (key, value) VALUES (?1, ?2)",
        params![key, value],
    )?;
    Ok(())
}

pub(crate) fn metadata_value(conn: &Connection, key: &str) -> Result<Option<String>> {
    let mut stmt = conn.prepare("SELECT value FROM wallet_metadata WHERE key = ?1")?;
    let mut rows = stmt.query(params![key])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    Ok(Some(row.get(0)?))
}

pub(crate) fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    let mut stmt = conn
        .prepare("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = ?1 LIMIT 1")?;
    let count: i64 = stmt.query_row(params![table], |row| row.get(0))?;
    Ok(count > 0)
}

pub(crate) fn canonical_label(label: &str) -> Result<String> {
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

pub(crate) fn ensure_columns(
    conn: &Connection,
    table: &str,
    required: &[(&str, &str)],
) -> Result<()> {
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

pub(crate) fn current_columns(conn: &Connection, table: &str) -> Result<HashSet<String>> {
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

pub(crate) fn row_to_contract(row: &rusqlite::Row<'_>) -> Result<Contract> {
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
        arbitration_profit_wats: None,
        seller_value_wats: None,
    })
}
