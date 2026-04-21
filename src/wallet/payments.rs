use super::store::{
    NewPaymentAttempt, NewPaymentTransaction, NewPaymentTransactionEvent, PaymentAttemptRecord,
    PaymentAttemptUpdate, PaymentBlacklistRecord, PaymentLossRecord, PaymentTransactionEventRecord,
    PaymentTransactionRecord, PaymentTransactionUpdate,
};
use super::WalletCore;
use crate::crypto::generate_secret_hex;
use crate::error::Result;

// ── Payment audit ────────────────────────────────────────────────────────────

impl WalletCore {
    pub fn record_payment_attempt_start(&self, input: &NewPaymentAttempt<'_>) -> Result<String> {
        let attempt_id = format!("pay_{}", generate_secret_hex());
        let now = chrono::Utc::now().to_rfc3339();
        self.store().insert_payment_attempt(&PaymentAttemptRecord {
            attempt_id: attempt_id.clone(),
            created_at: now.clone(),
            updated_at: now,
            service_origin: input.service_origin.to_string(),
            endpoint_path: input.endpoint_path.to_string(),
            method: input.method.to_string(),
            rail: input.rail.to_string(),
            action_hint: input.action_hint.to_string(),
            required_amount: input.required_amount.to_string(),
            payment_unit: input.payment_unit.to_string(),
            payment_reference: input.payment_reference.map(ToString::to_string),
            request_hash: input.request_hash.to_string(),
            response_status: None,
            response_code: None,
            response_body: None,
            recovery_state: "pending".to_string(),
            final_state: "pending".to_string(),
        })?;
        Ok(attempt_id)
    }

    pub fn update_payment_attempt(
        &self,
        attempt_id: &str,
        update: &PaymentAttemptUpdate<'_>,
    ) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.store()
            .update_payment_attempt(attempt_id, &now, update)
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
        self.store().insert_payment_loss(&PaymentLossRecord {
            loss_id: loss_id.clone(),
            attempt_id: attempt_id.to_string(),
            created_at: now,
            service_origin: service_origin.to_string(),
            endpoint_path: endpoint_path.to_string(),
            method: method.to_string(),
            rail: rail.to_string(),
            amount: amount.to_string(),
            payment_reference: payment_reference.map(ToString::to_string),
            failure_stage: failure_stage.to_string(),
            response_status,
            response_code: response_code.map(ToString::to_string),
            response_body: response_body.map(ToString::to_string),
        })?;
        self.blacklist_if_needed(service_origin, endpoint_path, method, rail, &loss_id)?;
        Ok(loss_id)
    }

    pub fn list_payment_losses(&self) -> Result<Vec<PaymentLossRecord>> {
        self.store().list_payment_losses()
    }

    pub fn list_payment_blacklist(&self) -> Result<Vec<PaymentBlacklistRecord>> {
        self.store().list_payment_blacklist()
    }

    pub fn clear_payment_blacklist(
        &self,
        service_origin: &str,
        endpoint_path: &str,
        method: &str,
        rail: &str,
    ) -> Result<bool> {
        self.store()
            .delete_payment_blacklist(service_origin, endpoint_path, method, rail)
    }

    pub fn payment_blacklist_entry(
        &self,
        service_origin: &str,
        endpoint_path: &str,
        method: &str,
        rail: &str,
    ) -> Result<Option<PaymentBlacklistRecord>> {
        self.store()
            .get_payment_blacklist_entry(service_origin, endpoint_path, method, rail)
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
        let count = self.store().count_recent_losses(
            service_origin,
            endpoint_path,
            method,
            rail,
            &cutoff,
        )?;
        if count < 3 {
            return Ok(());
        }
        let now = chrono::Utc::now().to_rfc3339();
        self.store()
            .upsert_payment_blacklist(&PaymentBlacklistRecord {
                service_origin: service_origin.to_string(),
                endpoint_path: endpoint_path.to_string(),
                method: method.to_string(),
                rail: rail.to_string(),
                blacklisted_until: None,
                reason:
                    "service returned errors after consuming payment 3 times in the last 24 hours"
                        .to_string(),
                triggered_by_loss_id: Some(loss_id.to_string()),
                created_at: now.clone(),
                updated_at: now,
            })
    }

    pub fn record_payment_transaction(&self, input: &NewPaymentTransaction<'_>) -> Result<String> {
        let txn_id = format!("txn_{}", generate_secret_hex());
        let now = chrono::Utc::now().to_rfc3339();
        self.store()
            .insert_payment_transaction(&PaymentTransactionRecord {
                txn_id: txn_id.clone(),
                attempt_id: input.attempt_id.map(ToString::to_string),
                created_at: now.clone(),
                updated_at: now.clone(),
                occurred_at: input.occurred_at.unwrap_or(&now).to_string(),
                direction: input.direction.to_string(),
                role: input.role.to_string(),
                source_system: input.source_system.to_string(),
                service_origin: input.service_origin.map(ToString::to_string),
                frontend_kind: input.frontend_kind.map(ToString::to_string),
                transport_kind: input.transport_kind.map(ToString::to_string),
                endpoint_path: input.endpoint_path.map(ToString::to_string),
                method: input.method.map(ToString::to_string),
                session_id: input.session_id.map(ToString::to_string),
                action_kind: input.action_kind.to_string(),
                resource_ref: input.resource_ref.map(ToString::to_string),
                contract_ref: input.contract_ref.map(ToString::to_string),
                invoice_ref: input.invoice_ref.map(ToString::to_string),
                challenge_id: input.challenge_id.map(ToString::to_string),
                rail: input.rail.to_string(),
                payment_unit: input.payment_unit.to_string(),
                quoted_amount: input.quoted_amount.map(ToString::to_string),
                settled_amount: input.settled_amount.map(ToString::to_string),
                fee_amount: input.fee_amount.map(ToString::to_string),
                proof_ref: input.proof_ref.map(ToString::to_string),
                proof_kind: input.proof_kind.map(ToString::to_string),
                payer_ref: input.payer_ref.map(ToString::to_string),
                payee_ref: input.payee_ref.map(ToString::to_string),
                request_hash: input.request_hash.map(ToString::to_string),
                response_code: input.response_code.map(ToString::to_string),
                status: input.status.to_string(),
                metadata_json: input.metadata_json.map(ToString::to_string),
            })?;
        Ok(txn_id)
    }

    pub fn update_payment_transaction(
        &self,
        txn_id: &str,
        update: &PaymentTransactionUpdate<'_>,
    ) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.store()
            .update_payment_transaction(txn_id, &now, update)
    }

    pub fn append_payment_transaction_event(
        &self,
        event: &NewPaymentTransactionEvent<'_>,
    ) -> Result<String> {
        let event_id = format!("txe_{}", generate_secret_hex());
        let now = chrono::Utc::now().to_rfc3339();
        self.store()
            .insert_payment_transaction_event(&PaymentTransactionEventRecord {
                event_id: event_id.clone(),
                txn_id: event.txn_id.to_string(),
                created_at: now,
                event_type: event.event_type.to_string(),
                status: event.status.to_string(),
                actor: event.actor.to_string(),
                details_json: event
                    .details_json
                    .map(ToString::to_string)
                    .filter(|v| !v.is_empty() && v != "{}"),
            })?;
        Ok(event_id)
    }

    pub fn list_payment_transactions(&self) -> Result<Vec<PaymentTransactionRecord>> {
        self.store().list_payment_transactions()
    }

    pub fn list_payment_transaction_events(
        &self,
        txn_id: Option<&str>,
    ) -> Result<Vec<PaymentTransactionEventRecord>> {
        self.store().list_payment_transaction_events(txn_id)
    }
}
