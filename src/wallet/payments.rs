use rusqlite::params;
use serde::{Deserialize, Serialize};

use super::WalletCore;
use crate::crypto::generate_secret_hex;
use crate::error::{Error, Result};

// ── Payment structs ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentAttemptRecord {
    pub attempt_id: String,
    pub created_at: String,
    pub updated_at: String,
    pub service_origin: String,
    pub endpoint_path: String,
    pub method: String,
    pub rail: String,
    pub action_hint: String,
    pub required_amount: String,
    pub payment_unit: String,
    pub payment_reference: Option<String>,
    pub request_hash: String,
    pub response_status: Option<u16>,
    pub response_code: Option<String>,
    pub response_body: Option<String>,
    pub recovery_state: String,
    pub final_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentLossRecord {
    pub loss_id: String,
    pub attempt_id: String,
    pub created_at: String,
    pub service_origin: String,
    pub endpoint_path: String,
    pub method: String,
    pub rail: String,
    pub amount: String,
    pub payment_reference: Option<String>,
    pub failure_stage: String,
    pub response_status: Option<u16>,
    pub response_code: Option<String>,
    pub response_body: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentBlacklistRecord {
    pub service_origin: String,
    pub endpoint_path: String,
    pub method: String,
    pub rail: String,
    pub blacklisted_until: Option<String>,
    pub reason: String,
    pub triggered_by_loss_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentTransactionRecord {
    pub txn_id: String,
    pub attempt_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub occurred_at: String,
    pub direction: String,
    pub role: String,
    pub source_system: String,
    pub service_origin: Option<String>,
    pub frontend_kind: Option<String>,
    pub transport_kind: Option<String>,
    pub endpoint_path: Option<String>,
    pub method: Option<String>,
    pub session_id: Option<String>,
    pub action_kind: String,
    pub resource_ref: Option<String>,
    pub contract_ref: Option<String>,
    pub invoice_ref: Option<String>,
    pub challenge_id: Option<String>,
    pub rail: String,
    pub payment_unit: String,
    pub quoted_amount: Option<String>,
    pub settled_amount: Option<String>,
    pub fee_amount: Option<String>,
    pub proof_ref: Option<String>,
    pub proof_kind: Option<String>,
    pub payer_ref: Option<String>,
    pub payee_ref: Option<String>,
    pub request_hash: Option<String>,
    pub response_code: Option<String>,
    pub status: String,
    pub metadata_json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentTransactionEventRecord {
    pub event_id: String,
    pub txn_id: String,
    pub created_at: String,
    pub event_type: String,
    pub status: String,
    pub actor: String,
    pub details_json: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewPaymentAttempt<'a> {
    pub service_origin: &'a str,
    pub endpoint_path: &'a str,
    pub method: &'a str,
    pub rail: &'a str,
    pub action_hint: &'a str,
    pub required_amount: &'a str,
    pub payment_unit: &'a str,
    pub payment_reference: Option<&'a str>,
    pub request_hash: &'a str,
}

#[derive(Debug, Clone)]
pub struct PaymentAttemptUpdate<'a> {
    pub payment_reference: Option<&'a str>,
    pub response_status: Option<u16>,
    pub response_code: Option<&'a str>,
    pub response_body: Option<&'a str>,
    pub recovery_state: &'a str,
    pub final_state: &'a str,
}

#[derive(Debug, Clone)]
pub struct NewPaymentTransaction<'a> {
    pub attempt_id: Option<&'a str>,
    pub occurred_at: Option<&'a str>,
    pub direction: &'a str,
    pub role: &'a str,
    pub source_system: &'a str,
    pub service_origin: Option<&'a str>,
    pub frontend_kind: Option<&'a str>,
    pub transport_kind: Option<&'a str>,
    pub endpoint_path: Option<&'a str>,
    pub method: Option<&'a str>,
    pub session_id: Option<&'a str>,
    pub action_kind: &'a str,
    pub resource_ref: Option<&'a str>,
    pub contract_ref: Option<&'a str>,
    pub invoice_ref: Option<&'a str>,
    pub challenge_id: Option<&'a str>,
    pub rail: &'a str,
    pub payment_unit: &'a str,
    pub quoted_amount: Option<&'a str>,
    pub settled_amount: Option<&'a str>,
    pub fee_amount: Option<&'a str>,
    pub proof_ref: Option<&'a str>,
    pub proof_kind: Option<&'a str>,
    pub payer_ref: Option<&'a str>,
    pub payee_ref: Option<&'a str>,
    pub request_hash: Option<&'a str>,
    pub response_code: Option<&'a str>,
    pub status: &'a str,
    pub metadata_json: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct PaymentTransactionUpdate<'a> {
    pub occurred_at: Option<&'a str>,
    pub service_origin: Option<&'a str>,
    pub frontend_kind: Option<&'a str>,
    pub transport_kind: Option<&'a str>,
    pub endpoint_path: Option<&'a str>,
    pub method: Option<&'a str>,
    pub session_id: Option<&'a str>,
    pub action_kind: Option<&'a str>,
    pub resource_ref: Option<&'a str>,
    pub contract_ref: Option<&'a str>,
    pub invoice_ref: Option<&'a str>,
    pub challenge_id: Option<&'a str>,
    pub quoted_amount: Option<&'a str>,
    pub settled_amount: Option<&'a str>,
    pub fee_amount: Option<&'a str>,
    pub proof_ref: Option<&'a str>,
    pub proof_kind: Option<&'a str>,
    pub payer_ref: Option<&'a str>,
    pub payee_ref: Option<&'a str>,
    pub request_hash: Option<&'a str>,
    pub response_code: Option<&'a str>,
    pub status: &'a str,
    pub metadata_json: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct NewPaymentTransactionEvent<'a> {
    pub txn_id: &'a str,
    pub event_type: &'a str,
    pub status: &'a str,
    pub actor: &'a str,
    pub details_json: Option<&'a str>,
}

// ── Payment audit ────────────────────────────────────────────────────────────

impl WalletCore {
    pub fn record_payment_attempt_start(&self, input: &NewPaymentAttempt<'_>) -> Result<String> {
        let attempt_id = format!("pay_{}", generate_secret_hex());
        let now = chrono::Utc::now().to_rfc3339();
        self.master_conn.execute(
            "INSERT INTO payment_attempts (
                attempt_id, created_at, updated_at, service_origin, endpoint_path,
                method, rail, action_hint, required_amount, payment_unit,
                payment_reference, request_hash, response_status, response_code,
                response_body, recovery_state, final_state
            ) VALUES (?1, ?2, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL, NULL, NULL, 'pending', 'pending')",
            params![
                attempt_id,
                now,
                input.service_origin,
                input.endpoint_path,
                input.method,
                input.rail,
                input.action_hint,
                input.required_amount,
                input.payment_unit,
                input.payment_reference,
                input.request_hash,
            ],
        )?;
        Ok(attempt_id)
    }

    pub fn update_payment_attempt(
        &self,
        attempt_id: &str,
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
                chrono::Utc::now().to_rfc3339(),
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

    #[allow(clippy::too_many_arguments)]
    pub fn store_payment_loss(
        &self,
        attempt_id: &str,
        service_origin: &str,
        endpoint_path: &str,
        method: &str,
        rail: &str,
        amount: &str,
        payment_reference: Option<&str>,
        failure_stage: &str,
        response_status: Option<u16>,
        response_code: Option<&str>,
        response_body: Option<&str>,
    ) -> Result<String> {
        let loss_id = format!("loss_{}", generate_secret_hex());
        let now = chrono::Utc::now().to_rfc3339();
        self.master_conn.execute(
            "INSERT INTO payment_losses (
                loss_id, attempt_id, created_at, service_origin, endpoint_path,
                method, rail, amount, payment_reference, failure_stage,
                response_status, response_code, response_body
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                loss_id,
                attempt_id,
                now,
                service_origin,
                endpoint_path,
                method,
                rail,
                amount,
                payment_reference,
                failure_stage,
                response_status.map(i64::from),
                response_code,
                response_body,
            ],
        )?;
        self.blacklist_if_needed(service_origin, endpoint_path, method, rail, &loss_id)?;
        Ok(loss_id)
    }

    pub fn list_payment_losses(&self) -> Result<Vec<PaymentLossRecord>> {
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

    pub fn list_payment_blacklist(&self) -> Result<Vec<PaymentBlacklistRecord>> {
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

    pub fn clear_payment_blacklist(
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

    pub fn payment_blacklist_entry(
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

    pub fn is_payment_blacklisted(
        &self,
        service_origin: &str,
        endpoint_path: &str,
        method: &str,
        rail: &str,
    ) -> Result<bool> {
        let Some(entry) =
            self.payment_blacklist_entry(service_origin, endpoint_path, method, rail)?
        else {
            return Ok(false);
        };
        Ok(match entry.blacklisted_until.as_deref() {
            Some(until) => until >= chrono::Utc::now().to_rfc3339().as_str(),
            None => true,
        })
    }

    fn blacklist_if_needed(
        &self,
        service_origin: &str,
        endpoint_path: &str,
        method: &str,
        rail: &str,
        loss_id: &str,
    ) -> Result<()> {
        let cutoff = (chrono::Utc::now() - chrono::TimeDelta::hours(24)).to_rfc3339();
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
        if count < 3 {
            return Ok(());
        }

        let now = chrono::Utc::now().to_rfc3339();
        self.master_conn.execute(
            "INSERT OR REPLACE INTO payment_blacklist (
                service_origin, endpoint_path, method, rail, blacklisted_until,
                reason, triggered_by_loss_id, created_at, updated_at
             ) VALUES (
                ?1, ?2, ?3, ?4, NULL,
                'service returned errors after consuming payment 3 times in the last 24 hours',
                ?5,
                COALESCE((SELECT created_at FROM payment_blacklist
                          WHERE service_origin = ?1 AND endpoint_path = ?2 AND method = ?3 AND rail = ?4), ?6),
                ?6
             )",
            params![service_origin, endpoint_path, method, rail, loss_id, now],
        )?;
        Ok(())
    }

    pub fn record_payment_transaction(&self, input: &NewPaymentTransaction<'_>) -> Result<String> {
        let txn_id = format!("txn_{}", generate_secret_hex());
        let now = chrono::Utc::now().to_rfc3339();
        self.master_conn.execute(
            "INSERT INTO payment_transactions (
                txn_id, attempt_id, created_at, updated_at, occurred_at, direction, role,
                source_system, service_origin, frontend_kind, transport_kind, endpoint_path,
                method, session_id, action_kind, resource_ref, contract_ref, invoice_ref,
                challenge_id, rail, payment_unit, quoted_amount, settled_amount, fee_amount,
                proof_ref, proof_kind, payer_ref, payee_ref, request_hash, response_code,
                status, metadata_json
             ) VALUES (
                ?1, ?2, ?3, ?3, ?4, ?5, ?6,
                ?7, ?8, ?9, ?10, ?11,
                ?12, ?13, ?14, ?15, ?16, ?17,
                ?18, ?19, ?20, ?21, ?22, ?23,
                ?24, ?25, ?26, ?27, ?28, ?29,
                ?30, ?31
             )",
            params![
                txn_id,
                input.attempt_id,
                now,
                input.occurred_at.unwrap_or(&now),
                input.direction,
                input.role,
                input.source_system,
                input.service_origin,
                input.frontend_kind,
                input.transport_kind,
                input.endpoint_path,
                input.method,
                input.session_id,
                input.action_kind,
                input.resource_ref,
                input.contract_ref,
                input.invoice_ref,
                input.challenge_id,
                input.rail,
                input.payment_unit,
                input.quoted_amount,
                input.settled_amount,
                input.fee_amount,
                input.proof_ref,
                input.proof_kind,
                input.payer_ref,
                input.payee_ref,
                input.request_hash,
                input.response_code,
                input.status,
                input.metadata_json,
            ],
        )?;
        Ok(txn_id)
    }

    pub fn update_payment_transaction(
        &self,
        txn_id: &str,
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
                chrono::Utc::now().to_rfc3339(),
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

    pub fn append_payment_transaction_event(
        &self,
        event: &NewPaymentTransactionEvent<'_>,
    ) -> Result<String> {
        let event_id = format!("txe_{}", generate_secret_hex());
        let now = chrono::Utc::now().to_rfc3339();
        self.master_conn.execute(
            "INSERT INTO payment_transaction_events (
                event_id, txn_id, created_at, event_type, status, actor, details_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                event_id,
                event.txn_id,
                now,
                event.event_type,
                event.status,
                event.actor,
                event.details_json.unwrap_or("{}"),
            ],
        )?;
        Ok(event_id)
    }

    pub fn list_payment_transactions(&self) -> Result<Vec<PaymentTransactionRecord>> {
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

    pub fn list_payment_transaction_events(
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
        let mapper = |row: &rusqlite::Row<'_>| -> std::result::Result<PaymentTransactionEventRecord, rusqlite::Error> {
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
}
