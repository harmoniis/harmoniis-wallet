use rusqlite::params;

use crate::error::{Error, Result};
use crate::types::{Certificate, Contract};

use super::WalletCore;
use super::schema::row_to_contract;

impl WalletCore {
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
}
