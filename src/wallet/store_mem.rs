//! In-memory implementation of [`HarmoniiStore`].
//!
//! Uses `RefCell<MemState>` for interior mutability. Serializable to JSON
//! for WASM persistence (IndexedDB / localStorage).

use std::cell::RefCell;

use serde::{Deserialize, Serialize};

use super::store::*;
use crate::error::{Error, Result};
use crate::types::{Certificate, Contract};

// ── Serializable state ──────────────────────────────────────────

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct MemState {
    pub meta: std::collections::HashMap<String, String>,
    pub pgp_identities: Vec<PgpIdentityRow>,
    pub wallet_slots: Vec<WalletSlotRecord>,
    pub payment_attempts: Vec<PaymentAttemptRecord>,
    pub payment_losses: Vec<PaymentLossRecord>,
    pub payment_blacklist: Vec<PaymentBlacklistRecord>,
    pub payment_transactions: Vec<PaymentTransactionRecord>,
    pub payment_transaction_events: Vec<PaymentTransactionEventRecord>,
    pub contracts: Vec<Contract>,
    pub certificates: Vec<Certificate>,
}

// ── MemHarmoniiStore ────────────────────────────────────────────

pub struct MemHarmoniiStore(pub RefCell<MemState>);

impl MemHarmoniiStore {
    pub fn new() -> Self {
        Self(RefCell::new(MemState::default()))
    }

    pub fn from_json(json: &str) -> Result<Self> {
        let state: MemState =
            serde_json::from_str(json).map_err(|e| Error::Other(anyhow::anyhow!(e)))?;
        Ok(Self(RefCell::new(state)))
    }

    pub fn to_json(&self) -> Result<String> {
        let state = self.0.borrow();
        serde_json::to_string(&*state).map_err(|e| Error::Other(anyhow::anyhow!(e)))
    }
}

impl Default for MemHarmoniiStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── HarmoniiStore implementation ────────────────────────────────

impl HarmoniiStore for MemHarmoniiStore {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    // ── Metadata ────────────────────────────────────────────────

    fn get_meta(&self, key: &str) -> Result<Option<String>> {
        Ok(self.0.borrow().meta.get(key).cloned())
    }

    fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.0
            .borrow_mut()
            .meta
            .insert(key.to_string(), value.to_string());
        Ok(())
    }

    // ── PGP Identities ─────────────────────────────────────────

    fn list_pgp_raw(&self) -> Result<Vec<PgpIdentityRow>> {
        let state = self.0.borrow();
        let mut rows = state.pgp_identities.clone();
        rows.sort_by_key(|r| r.key_index);
        Ok(rows)
    }

    fn insert_pgp(&self, row: &PgpIdentityRow) -> Result<()> {
        self.0.borrow_mut().pgp_identities.push(row.clone());
        Ok(())
    }

    fn rename_pgp(&self, from: &str, to: &str) -> Result<u64> {
        let mut state = self.0.borrow_mut();
        let mut count = 0u64;
        for row in &mut state.pgp_identities {
            if row.label == from {
                row.label = to.to_string();
                count += 1;
            }
        }
        Ok(count)
    }

    fn count_pgp_by_label(&self, label: &str) -> Result<i64> {
        let state = self.0.borrow();
        let count = state
            .pgp_identities
            .iter()
            .filter(|r| r.label == label)
            .count();
        Ok(count as i64)
    }

    fn max_pgp_key_index(&self) -> Result<i64> {
        let state = self.0.borrow();
        Ok(state
            .pgp_identities
            .iter()
            .map(|r| i64::from(r.key_index))
            .max()
            .unwrap_or(-1))
    }

    fn pgp_index_for_label(&self, label: &str) -> Result<Option<u32>> {
        let state = self.0.borrow();
        Ok(state
            .pgp_identities
            .iter()
            .find(|r| r.label == label)
            .map(|r| r.key_index))
    }

    fn replace_all_pgp(&self, rows: &[PgpIdentityRow]) -> Result<()> {
        let mut state = self.0.borrow_mut();
        state.pgp_identities.clear();
        state.pgp_identities.extend(rows.iter().cloned());
        if !rows.is_empty() && !rows.iter().any(|r| r.is_active) {
            if let Some(min_idx) = state.pgp_identities.iter().map(|r| r.key_index).min() {
                for row in &mut state.pgp_identities {
                    if row.key_index == min_idx {
                        row.is_active = true;
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    fn replace_pgp_at(
        &self,
        key_index: u32,
        label: &str,
        row: &PgpIdentityRow,
        set_active: bool,
    ) -> Result<()> {
        let mut state = self.0.borrow_mut();
        state
            .pgp_identities
            .retain(|r| r.key_index != key_index && r.label != label);
        if set_active {
            for r in &mut state.pgp_identities {
                r.is_active = false;
            }
        }
        let mut new_row = row.clone();
        if set_active {
            new_row.is_active = true;
        }
        state.pgp_identities.push(new_row);
        Ok(())
    }

    fn activate_pgp_exclusive(&self, label: &str) -> Result<()> {
        let mut state = self.0.borrow_mut();
        if !state.pgp_identities.iter().any(|r| r.label == label) {
            return Err(Error::NotFound(format!(
                "PGP identity label '{label}' not found"
            )));
        }
        for r in &mut state.pgp_identities {
            r.is_active = r.label == label;
        }
        Ok(())
    }

    // ── Wallet Slots ────────────────────────────────────────────

    fn list_wallet_slots(&self, family: Option<&str>) -> Result<Vec<WalletSlotRecord>> {
        let state = self.0.borrow();
        let mut rows: Vec<_> = state
            .wallet_slots
            .iter()
            .filter(|r| family.map_or(true, |f| r.family == f))
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.family.cmp(&b.family).then(a.slot_index.cmp(&b.slot_index)));
        Ok(rows)
    }

    fn upsert_wallet_slot(&self, row: &WalletSlotRecord) -> Result<()> {
        let mut state = self.0.borrow_mut();
        if let Some(existing) = state
            .wallet_slots
            .iter_mut()
            .find(|r| r.family == row.family && r.slot_index == row.slot_index)
        {
            // Preserve created_at on update
            let created_at = existing.created_at.clone();
            *existing = row.clone();
            existing.created_at = created_at;
        } else {
            state.wallet_slots.push(row.clone());
        }
        Ok(())
    }

    fn get_slot_index_by_label(&self, family: &str, label: &str) -> Result<Option<u32>> {
        let state = self.0.borrow();
        Ok(state
            .wallet_slots
            .iter()
            .find(|r| r.family == family && r.label.as_deref() == Some(label))
            .map(|r| r.slot_index))
    }

    fn max_slot_index(&self, family: &str) -> Result<i64> {
        let state = self.0.borrow();
        Ok(state
            .wallet_slots
            .iter()
            .filter(|r| r.family == family)
            .map(|r| i64::from(r.slot_index))
            .max()
            .unwrap_or(-1))
    }

    fn replace_slot_at(
        &self,
        family: &str,
        slot_index: u32,
        label: &str,
        descriptor: &str,
        now: &str,
    ) -> Result<()> {
        let mut state = self.0.borrow_mut();
        state.wallet_slots.retain(|r| {
            !(r.family == family && r.slot_index == slot_index)
                && !(r.family == family && r.label.as_deref() == Some(label))
        });
        state.wallet_slots.push(WalletSlotRecord {
            family: family.to_string(),
            slot_index,
            descriptor: descriptor.to_string(),
            db_rel_path: None,
            label: Some(label.to_string()),
            created_at: now.to_string(),
            updated_at: now.to_string(),
        });
        Ok(())
    }

    // ── Payment Attempts ────────────────────────────────────────

    fn insert_payment_attempt(&self, record: &PaymentAttemptRecord) -> Result<()> {
        self.0
            .borrow_mut()
            .payment_attempts
            .push(record.clone());
        Ok(())
    }

    fn update_payment_attempt(
        &self,
        attempt_id: &str,
        now: &str,
        update: &PaymentAttemptUpdate<'_>,
    ) -> Result<()> {
        let mut state = self.0.borrow_mut();
        if let Some(rec) = state
            .payment_attempts
            .iter_mut()
            .find(|r| r.attempt_id == attempt_id)
        {
            rec.updated_at = now.to_string();
            if let Some(pr) = update.payment_reference {
                rec.payment_reference = Some(pr.to_string());
            }
            rec.response_status = update.response_status;
            rec.response_code = update.response_code.map(|s| s.to_string());
            rec.response_body = update.response_body.map(|s| s.to_string());
            rec.recovery_state = update.recovery_state.to_string();
            rec.final_state = update.final_state.to_string();
        }
        Ok(())
    }

    // ── Payment Losses ──────────────────────────────────────────

    fn insert_payment_loss(&self, record: &PaymentLossRecord) -> Result<()> {
        self.0.borrow_mut().payment_losses.push(record.clone());
        Ok(())
    }

    fn list_payment_losses(&self) -> Result<Vec<PaymentLossRecord>> {
        let state = self.0.borrow();
        let mut rows = state.payment_losses.clone();
        rows.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(rows)
    }

    fn count_recent_losses(
        &self,
        service_origin: &str,
        endpoint_path: &str,
        method: &str,
        rail: &str,
        cutoff: &str,
    ) -> Result<i64> {
        let state = self.0.borrow();
        let count = state
            .payment_losses
            .iter()
            .filter(|r| {
                r.service_origin == service_origin
                    && r.endpoint_path == endpoint_path
                    && r.method == method
                    && r.rail == rail
                    && r.created_at.as_str() >= cutoff
            })
            .count();
        Ok(count as i64)
    }

    // ── Payment Blacklist ───────────────────────────────────────

    fn upsert_payment_blacklist(&self, record: &PaymentBlacklistRecord) -> Result<()> {
        let mut state = self.0.borrow_mut();
        if let Some(existing) = state.payment_blacklist.iter_mut().find(|r| {
            r.service_origin == record.service_origin
                && r.endpoint_path == record.endpoint_path
                && r.method == record.method
                && r.rail == record.rail
        }) {
            let created_at = existing.created_at.clone();
            *existing = record.clone();
            existing.created_at = created_at;
        } else {
            state.payment_blacklist.push(record.clone());
        }
        Ok(())
    }

    fn get_payment_blacklist_entry(
        &self,
        service_origin: &str,
        endpoint_path: &str,
        method: &str,
        rail: &str,
    ) -> Result<Option<PaymentBlacklistRecord>> {
        let state = self.0.borrow();
        Ok(state
            .payment_blacklist
            .iter()
            .find(|r| {
                r.service_origin == service_origin
                    && r.endpoint_path == endpoint_path
                    && r.method == method
                    && r.rail == rail
            })
            .cloned())
    }

    fn list_payment_blacklist(&self) -> Result<Vec<PaymentBlacklistRecord>> {
        let state = self.0.borrow();
        let mut rows = state.payment_blacklist.clone();
        rows.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        Ok(rows)
    }

    fn delete_payment_blacklist(
        &self,
        service_origin: &str,
        endpoint_path: &str,
        method: &str,
        rail: &str,
    ) -> Result<bool> {
        let mut state = self.0.borrow_mut();
        let before = state.payment_blacklist.len();
        state.payment_blacklist.retain(|r| {
            !(r.service_origin == service_origin
                && r.endpoint_path == endpoint_path
                && r.method == method
                && r.rail == rail)
        });
        Ok(state.payment_blacklist.len() < before)
    }

    // ── Payment Transactions ────────────────────────────────────

    fn insert_payment_transaction(&self, record: &PaymentTransactionRecord) -> Result<()> {
        self.0
            .borrow_mut()
            .payment_transactions
            .push(record.clone());
        Ok(())
    }

    fn update_payment_transaction(
        &self,
        txn_id: &str,
        now: &str,
        update: &PaymentTransactionUpdate<'_>,
    ) -> Result<()> {
        let mut state = self.0.borrow_mut();
        if let Some(rec) = state
            .payment_transactions
            .iter_mut()
            .find(|r| r.txn_id == txn_id)
        {
            rec.updated_at = now.to_string();
            macro_rules! coalesce {
                ($field:ident) => {
                    if let Some(v) = update.$field {
                        rec.$field = Some(v.to_string());
                    }
                };
                ($field:ident, required) => {
                    if let Some(v) = update.$field {
                        rec.$field = v.to_string();
                    }
                };
            }
            coalesce!(occurred_at, required);
            coalesce!(service_origin);
            coalesce!(frontend_kind);
            coalesce!(transport_kind);
            coalesce!(endpoint_path);
            coalesce!(method);
            coalesce!(session_id);
            coalesce!(action_kind, required);
            coalesce!(resource_ref);
            coalesce!(contract_ref);
            coalesce!(invoice_ref);
            coalesce!(challenge_id);
            coalesce!(quoted_amount);
            coalesce!(settled_amount);
            coalesce!(fee_amount);
            coalesce!(proof_ref);
            coalesce!(proof_kind);
            coalesce!(payer_ref);
            coalesce!(payee_ref);
            coalesce!(request_hash);
            coalesce!(response_code);
            rec.status = update.status.to_string();
            coalesce!(metadata_json);
        }
        Ok(())
    }

    fn list_payment_transactions(&self) -> Result<Vec<PaymentTransactionRecord>> {
        let state = self.0.borrow();
        let mut rows = state.payment_transactions.clone();
        rows.sort_by(|a, b| {
            b.occurred_at
                .cmp(&a.occurred_at)
                .then(b.created_at.cmp(&a.created_at))
        });
        Ok(rows)
    }

    // ── Payment Transaction Events ──────────────────────────────

    fn insert_payment_transaction_event(
        &self,
        record: &PaymentTransactionEventRecord,
    ) -> Result<()> {
        self.0
            .borrow_mut()
            .payment_transaction_events
            .push(record.clone());
        Ok(())
    }

    fn list_payment_transaction_events(
        &self,
        txn_id: Option<&str>,
    ) -> Result<Vec<PaymentTransactionEventRecord>> {
        let state = self.0.borrow();
        let mut rows: Vec<_> = state
            .payment_transaction_events
            .iter()
            .filter(|r| txn_id.map_or(true, |id| r.txn_id == id))
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        Ok(rows)
    }

    // ── Contracts ───────────────────────────────────────────────

    fn store_contract(&self, c: &Contract) -> Result<()> {
        let mut state = self.0.borrow_mut();
        state.contracts.retain(|r| r.contract_id != c.contract_id);
        state.contracts.push(c.clone());
        Ok(())
    }

    fn get_contract(&self, id: &str) -> Result<Option<Contract>> {
        let state = self.0.borrow();
        Ok(state
            .contracts
            .iter()
            .find(|r| r.contract_id == id)
            .cloned())
    }

    fn list_contracts(&self) -> Result<Vec<Contract>> {
        let state = self.0.borrow();
        let mut rows = state.contracts.clone();
        rows.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(rows)
    }

    fn count_contracts(&self) -> Result<i64> {
        Ok(self.0.borrow().contracts.len() as i64)
    }

    // ── Certificates ────────────────────────────────────────────

    fn store_certificate(&self, cert: &Certificate) -> Result<()> {
        let mut state = self.0.borrow_mut();
        state
            .certificates
            .retain(|r| r.certificate_id != cert.certificate_id);
        state.certificates.push(cert.clone());
        Ok(())
    }

    fn list_certificates(&self) -> Result<Vec<Certificate>> {
        let state = self.0.borrow();
        let mut rows = state.certificates.clone();
        rows.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(rows)
    }

    fn count_certificates(&self) -> Result<i64> {
        Ok(self.0.borrow().certificates.len() as i64)
    }

    // ── Bulk Operations ─────────────────────────────────────────

    fn replace_identity_data(
        &self,
        contracts: &[Contract],
        certificates: &[Certificate],
    ) -> Result<()> {
        let mut state = self.0.borrow_mut();
        state.contracts = contracts.to_vec();
        state.certificates = certificates.to_vec();
        Ok(())
    }
}
