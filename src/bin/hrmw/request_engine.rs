use anyhow::Context;
use bdk_wallet::bitcoin::Network;
use reqwest::{Method, Url};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use harmoniis_wallet::{
    ark::{ArkPaymentWallet, SqliteArkDb},
    bitcoin::DeterministicBitcoinWallet,
    client::HarmoniisClient,
    wallet::{
        NewPaymentAttempt, NewPaymentTransaction, NewPaymentTransactionEvent, PaymentAttemptUpdate,
        PaymentTransactionUpdate, RgbWallet,
    },
    VoucherSecret,
};
use webylib::SecretWebcash;

use crate::cli_support::{
    open_or_create_wallet, open_voucher_wallet, open_webcash_wallet, pay_from_wallet,
    pay_voucher_from_wallet,
};
use crate::PaymentRail;

#[derive(Clone, Debug)]
pub enum RequestBodySpec {
    None,
    Json(Value),
    Raw {
        bytes: Vec<u8>,
        content_type: String,
    },
}

#[derive(Clone, Debug)]
pub struct RequestSpec {
    pub base_url: String,
    pub endpoint: String,
    pub method: Method,
    pub headers: Vec<(String, String)>,
    pub query: Vec<(String, String)>,
    pub body: RequestBodySpec,
    pub action_hint: String,
    pub desired_rail: Option<PaymentRail>,
}

#[derive(Debug, Clone)]
pub struct RequestResponse {
    pub url: String,
    pub status: u16,
    pub content_type: Option<String>,
    pub body_text: String,
    pub body_json: Option<Value>,
}

#[derive(Debug, Clone)]
struct PaymentDirective {
    rail: PaymentRail,
    rail_name: String,
    header_name: String,
    required_amount: String,
    payment_unit: String,
    challenge_id: Option<String>,
    response_code: Option<String>,
    response_body: String,
    rail_details: Value,
}

#[derive(Debug, Clone)]
enum AcquiredPayment {
    Webcash {
        header_name: String,
        header_value: String,
        payment_reference: String,
    },
    Voucher {
        header_name: String,
        secret: VoucherSecret,
        payment_reference: String,
    },
    BitcoinArk {
        header_name: String,
        proof: String,
        payment_reference: String,
    },
}

impl AcquiredPayment {
    fn header_name(&self) -> &str {
        match self {
            Self::Webcash { header_name, .. }
            | Self::Voucher { header_name, .. }
            | Self::BitcoinArk { header_name, .. } => header_name,
        }
    }

    fn header_value(&self) -> String {
        match self {
            Self::Webcash { header_value, .. } => header_value.clone(),
            Self::Voucher { secret, .. } => secret.display(),
            Self::BitcoinArk { proof, .. } => proof.clone(),
        }
    }

    fn payment_reference(&self) -> &str {
        match self {
            Self::Webcash {
                payment_reference, ..
            }
            | Self::Voucher {
                payment_reference, ..
            }
            | Self::BitcoinArk {
                payment_reference, ..
            } => payment_reference,
        }
    }
}

pub async fn execute_paid_request(
    wallet_path: &Path,
    request: &RequestSpec,
) -> anyhow::Result<RequestResponse> {
    let http = build_http_client()?;
    let url = build_request_url(&request.base_url, &request.endpoint)?;
    let first = send_request(&http, request, &url, None, None, None).await?;
    if first.status != 402 {
        return Ok(first);
    }

    let directive = load_payment_directive(&http, &url, &first, request.desired_rail).await?;
    let wallet = open_or_create_wallet(wallet_path)?;
    let service_origin = origin_string(&url);
    let endpoint_path = url.path().to_string();
    let method_upper = request.method.as_str().to_ascii_uppercase();
    let rail_token = directive.rail_name.to_ascii_lowercase();
    let request_hash_value = request_hash(request);

    if wallet.is_payment_blacklisted(&service_origin, &endpoint_path, &method_upper, &rail_token)? {
        anyhow::bail!(
            "Refusing to pay {} {}{}: this service returned errors after consuming payment 3 times in the last 24 hours. Endpoint is blacklisted pending human attention.",
            method_upper,
            service_origin,
            endpoint_path
        );
    }

    let attempt_id = wallet.record_payment_attempt_start(&NewPaymentAttempt {
        service_origin: &service_origin,
        endpoint_path: &endpoint_path,
        method: &method_upper,
        rail: &rail_token,
        action_hint: &request.action_hint,
        required_amount: &directive.required_amount,
        payment_unit: &directive.payment_unit,
        payment_reference: None,
        request_hash: &request_hash_value,
    })?;
    let challenge_metadata = serde_json::json!({
        "url": url.as_str(),
        "header_name": &directive.header_name,
        "response_status": first.status,
    })
    .to_string();
    let txn_id = wallet.record_payment_transaction(&NewPaymentTransaction {
        attempt_id: Some(&attempt_id),
        occurred_at: None,
        direction: "outbound",
        role: "payer",
        source_system: "hrmw",
        service_origin: Some(&service_origin),
        frontend_kind: Some("hrmw"),
        transport_kind: Some("http"),
        endpoint_path: Some(&endpoint_path),
        method: Some(&method_upper),
        session_id: None,
        action_kind: &request.action_hint,
        resource_ref: None,
        contract_ref: None,
        invoice_ref: None,
        challenge_id: directive.challenge_id.as_deref(),
        rail: &rail_token,
        payment_unit: &directive.payment_unit,
        quoted_amount: Some(&directive.required_amount),
        settled_amount: None,
        fee_amount: None,
        proof_ref: None,
        proof_kind: None,
        payer_ref: None,
        payee_ref: Some(&service_origin),
        request_hash: Some(&request_hash_value),
        response_code: directive.response_code.as_deref(),
        status: "challenge_received",
        metadata_json: Some(&challenge_metadata),
    })?;
    let challenge_event_details = serde_json::json!({
        "rail": &rail_token,
        "required_amount": &directive.required_amount,
        "payment_unit": &directive.payment_unit,
        "response_code": &directive.response_code,
    })
    .to_string();
    wallet.append_payment_transaction_event(&NewPaymentTransactionEvent {
        txn_id: &txn_id,
        event_type: "challenge_received",
        status: "challenge_received",
        actor: "hrmw",
        details_json: Some(&challenge_event_details),
    })?;

    let payment = acquire_payment(
        wallet_path,
        &wallet,
        &directive,
        &service_origin,
        &request.action_hint,
    )
    .await?;
    let (proof_kind, proof_ref) = payment_transaction_proof(&payment);
    let payment_acquired_details = serde_json::json!({
        "proof_kind": proof_kind,
        "proof_ref": &proof_ref,
    })
    .to_string();
    wallet.update_payment_attempt(
        &attempt_id,
        &PaymentAttemptUpdate {
            payment_reference: Some(payment.payment_reference()),
            response_status: Some(first.status),
            response_code: directive.response_code.as_deref(),
            response_body: Some(&directive.response_body),
            recovery_state: "paid",
            final_state: "paid",
        },
    )?;
    wallet.update_payment_transaction(
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
            challenge_id: directive.challenge_id.as_deref(),
            quoted_amount: Some(&directive.required_amount),
            settled_amount: Some(&directive.required_amount),
            fee_amount: None,
            proof_ref: Some(&proof_ref),
            proof_kind: Some(proof_kind),
            payer_ref: None,
            payee_ref: Some(&service_origin),
            request_hash: None,
            response_code: directive.response_code.as_deref(),
            status: "payment_acquired",
            metadata_json: None,
        },
    )?;
    wallet.append_payment_transaction_event(&NewPaymentTransactionEvent {
        txn_id: &txn_id,
        event_type: "payment_acquired",
        status: "payment_acquired",
        actor: "hrmw",
        details_json: Some(&payment_acquired_details),
    })?;

    let second = send_request(
        &http,
        request,
        &url,
        Some((payment.header_name(), &payment.header_value())),
        directive.challenge_id.as_deref(),
        Some(directive.rail),
    )
    .await;
    match second {
        Ok(resp) if (200..300).contains(&resp.status) => {
            let success_metadata = serde_json::json!({
                "status": resp.status,
                "content_type": &resp.content_type,
            })
            .to_string();
            let success_event_details = serde_json::json!({
                "status": resp.status,
                "response_code": parse_response_code(resp.body_json.as_ref()),
            })
            .to_string();
            wallet.update_payment_attempt(
                &attempt_id,
                &PaymentAttemptUpdate {
                    payment_reference: Some(payment.payment_reference()),
                    response_status: Some(resp.status),
                    response_code: None,
                    response_body: Some(&resp.body_text),
                    recovery_state: "not_needed",
                    final_state: "succeeded",
                },
            )?;
            wallet.update_payment_transaction(
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
                    challenge_id: directive.challenge_id.as_deref(),
                    quoted_amount: None,
                    settled_amount: Some(&directive.required_amount),
                    fee_amount: None,
                    proof_ref: Some(&proof_ref),
                    proof_kind: Some(proof_kind),
                    payer_ref: None,
                    payee_ref: Some(&service_origin),
                    request_hash: None,
                    response_code: None,
                    status: "succeeded",
                    metadata_json: Some(&success_metadata),
                },
            )?;
            wallet.append_payment_transaction_event(&NewPaymentTransactionEvent {
                txn_id: &txn_id,
                event_type: "service_completed",
                status: "succeeded",
                actor: "service",
                details_json: Some(&success_event_details),
            })?;
            Ok(resp)
        }
        Ok(resp) => {
            recover_or_log_loss(
                wallet_path,
                &wallet,
                &directive,
                &payment,
                &attempt_id,
                &txn_id,
                &service_origin,
                &endpoint_path,
                &method_upper,
                Some(resp.status),
                parse_response_code(resp.body_json.as_ref()),
                Some(resp.body_text.as_str()),
                &service_origin,
            )
            .await?;
            Err(anyhow::anyhow!(
                "paid request failed with status {}: {}",
                resp.status,
                resp.body_text
            ))
        }
        Err(err) => {
            recover_or_log_loss(
                wallet_path,
                &wallet,
                &directive,
                &payment,
                &attempt_id,
                &txn_id,
                &service_origin,
                &endpoint_path,
                &method_upper,
                None,
                Some("request_send_failed".to_string()),
                Some(&err.to_string()),
                &service_origin,
            )
            .await?;
            Err(err)
        }
    }
}

async fn recover_or_log_loss(
    wallet_path: &Path,
    wallet: &RgbWallet,
    directive: &PaymentDirective,
    payment: &AcquiredPayment,
    attempt_id: &str,
    txn_id: &str,
    service_origin: &str,
    endpoint_path: &str,
    method_upper: &str,
    response_status: Option<u16>,
    response_code: Option<String>,
    response_body: Option<&str>,
    service_base_url: &str,
) -> anyhow::Result<()> {
    let rail_token = directive.rail_name.to_ascii_lowercase();
    let (proof_kind, proof_ref) = payment_transaction_proof(payment);
    match payment {
        AcquiredPayment::Webcash { header_value, .. } => {
            let webcash_wallet = open_webcash_wallet(wallet_path, wallet).await?;
            let secret = SecretWebcash::parse(header_value)
                .map_err(|e| anyhow::anyhow!("invalid paid webcash token: {e}"))?;
            match webcash_wallet.insert(secret).await {
                Ok(()) => {
                    let recovered_details = serde_json::json!({
                        "recovery_state": "reinserted",
                        "proof_kind": proof_kind,
                        "proof_ref": &proof_ref,
                        "response_status": response_status,
                        "response_code": &response_code,
                    })
                    .to_string();
                    wallet.update_payment_attempt(
                        attempt_id,
                        &PaymentAttemptUpdate {
                            payment_reference: Some(payment.payment_reference()),
                            response_status,
                            response_code: response_code.as_deref(),
                            response_body,
                            recovery_state: "reinserted",
                            final_state: "recovered",
                        },
                    )?;
                    wallet.update_payment_transaction(
                        txn_id,
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
                            challenge_id: directive.challenge_id.as_deref(),
                            quoted_amount: None,
                            settled_amount: Some(&directive.required_amount),
                            fee_amount: None,
                            proof_ref: Some(&proof_ref),
                            proof_kind: Some(proof_kind),
                            payer_ref: None,
                            payee_ref: Some(service_origin),
                            request_hash: None,
                            response_code: response_code.as_deref(),
                            status: "recovered",
                            metadata_json: None,
                        },
                    )?;
                    wallet.append_payment_transaction_event(&NewPaymentTransactionEvent {
                        txn_id,
                        event_type: "payment_recovered",
                        status: "recovered",
                        actor: "wallet",
                        details_json: Some(&recovered_details),
                    })?;
                }
                Err(err) if is_duplicate_wallet_row_error(&err.to_string()) => {
                    let recovered_details = serde_json::json!({
                        "recovery_state": "duplicate_present",
                        "proof_kind": proof_kind,
                        "proof_ref": &proof_ref,
                        "response_status": response_status,
                        "response_code": &response_code,
                    })
                    .to_string();
                    wallet.update_payment_attempt(
                        attempt_id,
                        &PaymentAttemptUpdate {
                            payment_reference: Some(payment.payment_reference()),
                            response_status,
                            response_code: response_code.as_deref(),
                            response_body,
                            recovery_state: "duplicate_present",
                            final_state: "recovered",
                        },
                    )?;
                    wallet.update_payment_transaction(
                        txn_id,
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
                            challenge_id: directive.challenge_id.as_deref(),
                            quoted_amount: None,
                            settled_amount: Some(&directive.required_amount),
                            fee_amount: None,
                            proof_ref: Some(&proof_ref),
                            proof_kind: Some(proof_kind),
                            payer_ref: None,
                            payee_ref: Some(service_origin),
                            request_hash: None,
                            response_code: response_code.as_deref(),
                            status: "recovered",
                            metadata_json: None,
                        },
                    )?;
                    wallet.append_payment_transaction_event(&NewPaymentTransactionEvent {
                        txn_id,
                        event_type: "payment_recovered",
                        status: "recovered",
                        actor: "wallet",
                        details_json: Some(&recovered_details),
                    })?;
                }
                Err(_) => {
                    let loss_id = wallet.store_payment_loss(
                        attempt_id,
                        service_origin,
                        endpoint_path,
                        method_upper,
                        &rail_token,
                        &directive.required_amount,
                        Some(payment.payment_reference()),
                        "post_payment_response_error",
                        response_status,
                        response_code.as_deref(),
                        response_body,
                    )?;
                    let loss_details = serde_json::json!({
                        "loss_id": &loss_id,
                        "failure_stage": "post_payment_response_error",
                        "recovery_state": "reinsert_failed",
                        "proof_kind": proof_kind,
                        "proof_ref": &proof_ref,
                        "response_status": response_status,
                        "response_code": &response_code,
                    })
                    .to_string();
                    wallet.update_payment_attempt(
                        attempt_id,
                        &PaymentAttemptUpdate {
                            payment_reference: Some(payment.payment_reference()),
                            response_status,
                            response_code: response_code.as_deref(),
                            response_body,
                            recovery_state: "reinsert_failed",
                            final_state: &format!("lost_pending_reclaim:{loss_id}"),
                        },
                    )?;
                    wallet.update_payment_transaction(
                        txn_id,
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
                            challenge_id: directive.challenge_id.as_deref(),
                            quoted_amount: None,
                            settled_amount: Some(&directive.required_amount),
                            fee_amount: None,
                            proof_ref: Some(&proof_ref),
                            proof_kind: Some(proof_kind),
                            payer_ref: None,
                            payee_ref: Some(service_origin),
                            request_hash: None,
                            response_code: response_code.as_deref(),
                            status: "lost",
                            metadata_json: None,
                        },
                    )?;
                    wallet.append_payment_transaction_event(&NewPaymentTransactionEvent {
                        txn_id,
                        event_type: "payment_lost",
                        status: "lost",
                        actor: "wallet",
                        details_json: Some(&loss_details),
                    })?;
                }
            }
        }
        AcquiredPayment::Voucher { secret, .. } => {
            let voucher_client = HarmoniisClient::new(service_base_url);
            let voucher_wallet = open_voucher_wallet(wallet_path, wallet)?;
            if voucher_wallet
                .reinsert_if_live(&voucher_client, secret)
                .await?
            {
                let recovered_details = serde_json::json!({
                    "recovery_state": "reinserted",
                    "proof_kind": proof_kind,
                    "proof_ref": &proof_ref,
                    "response_status": response_status,
                    "response_code": &response_code,
                })
                .to_string();
                wallet.update_payment_attempt(
                    attempt_id,
                    &PaymentAttemptUpdate {
                        payment_reference: Some(payment.payment_reference()),
                        response_status,
                        response_code: response_code.as_deref(),
                        response_body,
                        recovery_state: "reinserted",
                        final_state: "recovered",
                    },
                )?;
                wallet.update_payment_transaction(
                    txn_id,
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
                        challenge_id: directive.challenge_id.as_deref(),
                        quoted_amount: None,
                        settled_amount: Some(&directive.required_amount),
                        fee_amount: None,
                        proof_ref: Some(&proof_ref),
                        proof_kind: Some(proof_kind),
                        payer_ref: None,
                        payee_ref: Some(service_origin),
                        request_hash: None,
                        response_code: response_code.as_deref(),
                        status: "recovered",
                        metadata_json: None,
                    },
                )?;
                wallet.append_payment_transaction_event(&NewPaymentTransactionEvent {
                    txn_id,
                    event_type: "payment_recovered",
                    status: "recovered",
                    actor: "wallet",
                    details_json: Some(&recovered_details),
                })?;
            } else {
                let loss_id = wallet.store_payment_loss(
                    attempt_id,
                    service_origin,
                    endpoint_path,
                    method_upper,
                    &rail_token,
                    &directive.required_amount,
                    Some(payment.payment_reference()),
                    "post_payment_response_error",
                    response_status,
                    response_code.as_deref(),
                    response_body,
                )?;
                let loss_details = serde_json::json!({
                    "loss_id": &loss_id,
                    "failure_stage": "post_payment_response_error",
                    "recovery_state": "not_live",
                    "proof_kind": proof_kind,
                    "proof_ref": &proof_ref,
                    "response_status": response_status,
                    "response_code": &response_code,
                })
                .to_string();
                wallet.update_payment_attempt(
                    attempt_id,
                    &PaymentAttemptUpdate {
                        payment_reference: Some(payment.payment_reference()),
                        response_status,
                        response_code: response_code.as_deref(),
                        response_body,
                        recovery_state: "not_live",
                        final_state: &format!("lost_pending_reclaim:{loss_id}"),
                    },
                )?;
                wallet.update_payment_transaction(
                    txn_id,
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
                        challenge_id: directive.challenge_id.as_deref(),
                        quoted_amount: None,
                        settled_amount: Some(&directive.required_amount),
                        fee_amount: None,
                        proof_ref: Some(&proof_ref),
                        proof_kind: Some(proof_kind),
                        payer_ref: None,
                        payee_ref: Some(service_origin),
                        request_hash: None,
                        response_code: response_code.as_deref(),
                        status: "lost",
                        metadata_json: None,
                    },
                )?;
                wallet.append_payment_transaction_event(&NewPaymentTransactionEvent {
                    txn_id,
                    event_type: "payment_lost",
                    status: "lost",
                    actor: "wallet",
                    details_json: Some(&loss_details),
                })?;
            }
        }
        AcquiredPayment::BitcoinArk { .. } => {
            let loss_id = wallet.store_payment_loss(
                attempt_id,
                service_origin,
                endpoint_path,
                method_upper,
                &rail_token,
                &directive.required_amount,
                Some(payment.payment_reference()),
                "post_payment_response_error",
                response_status,
                response_code.as_deref(),
                response_body,
            )?;
            let loss_details = serde_json::json!({
                "loss_id": &loss_id,
                "failure_stage": "post_payment_response_error",
                "recovery_state": "irrecoverable_ark_transfer",
                "proof_kind": proof_kind,
                "proof_ref": &proof_ref,
                "response_status": response_status,
                "response_code": &response_code,
            })
            .to_string();
            wallet.update_payment_attempt(
                attempt_id,
                &PaymentAttemptUpdate {
                    payment_reference: Some(payment.payment_reference()),
                    response_status,
                    response_code: response_code.as_deref(),
                    response_body,
                    recovery_state: "irrecoverable_ark_transfer",
                    final_state: &format!("lost_pending_reclaim:{loss_id}"),
                },
            )?;
            wallet.update_payment_transaction(
                txn_id,
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
                    challenge_id: directive.challenge_id.as_deref(),
                    quoted_amount: None,
                    settled_amount: Some(&directive.required_amount),
                    fee_amount: None,
                    proof_ref: Some(&proof_ref),
                    proof_kind: Some(proof_kind),
                    payer_ref: None,
                    payee_ref: Some(service_origin),
                    request_hash: None,
                    response_code: response_code.as_deref(),
                    status: "lost",
                    metadata_json: None,
                },
            )?;
            wallet.append_payment_transaction_event(&NewPaymentTransactionEvent {
                txn_id,
                event_type: "payment_lost",
                status: "lost",
                actor: "wallet",
                details_json: Some(&loss_details),
            })?;
        }
    }
    Ok(())
}

async fn acquire_payment(
    wallet_path: &Path,
    wallet: &RgbWallet,
    directive: &PaymentDirective,
    service_base_url: &str,
    action_hint: &str,
) -> anyhow::Result<AcquiredPayment> {
    match directive.rail {
        PaymentRail::Webcash => {
            let token =
                pay_from_wallet(wallet_path, wallet, &directive.required_amount, action_hint)
                    .await?;
            Ok(AcquiredPayment::Webcash {
                header_name: directive.header_name.clone(),
                payment_reference: hashed_reference(&token),
                header_value: token,
            })
        }
        PaymentRail::Voucher => {
            let client = HarmoniisClient::new(service_base_url);
            let amount_units = directive.required_amount.parse::<u64>().with_context(|| {
                format!("invalid voucher amount '{}'", directive.required_amount)
            })?;
            let secret =
                pay_voucher_from_wallet(wallet_path, wallet, &client, amount_units, action_hint)
                    .await?;
            Ok(AcquiredPayment::Voucher {
                header_name: directive.header_name.clone(),
                payment_reference: secret.public_proof().public_hash.clone(),
                secret,
            })
        }
        PaymentRail::Bitcoin => {
            let (network, asp_url, offchain_receive_address) =
                bitcoin_ark_payment_target(&directive.rail_details)?;
            let btc = DeterministicBitcoinWallet::from_master_wallet(
                wallet,
                network,
                Some(crate::bitcoin_db_path(wallet_path)),
            )
            .map_err(anyhow::Error::from)?;
            let db = SqliteArkDb::open(&crate::bitcoin_db_path(wallet_path))
                .map_err(anyhow::Error::from)?;
            let ark = ArkPaymentWallet::connect(&btc, &asp_url, db).await?;
            let amount_sats = directive.required_amount.parse::<u64>().with_context(|| {
                format!("invalid bitcoin amount '{}'", directive.required_amount)
            })?;
            let proof = ark
                .send_payment(&offchain_receive_address, amount_sats)
                .await?
                .to_proof_string();
            let payment_reference = proof
                .strip_prefix("ark:")
                .and_then(|rest| rest.split(':').next())
                .unwrap_or(&proof)
                .to_string();
            Ok(AcquiredPayment::BitcoinArk {
                header_name: directive.header_name.clone(),
                payment_reference,
                proof,
            })
        }
    }
}

fn build_http_client() -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .no_proxy();
    if let Ok(overrides) = std::env::var("HRMW_RESOLVE") {
        for entry in overrides.split(',') {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Some((host, ip_raw)) = trimmed.split_once('=') else {
                continue;
            };
            let Ok(ip) = ip_raw.trim().parse::<IpAddr>() else {
                continue;
            };
            builder = builder.resolve(host.trim(), SocketAddr::new(ip, 443));
        }
    }
    builder.build().context("failed to build HTTP client")
}

fn build_request_url(base_url: &str, endpoint: &str) -> anyhow::Result<Url> {
    if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        return Url::parse(endpoint).context("invalid absolute endpoint url");
    }
    let mut base = Url::parse(base_url).context("invalid base url")?;
    if endpoint.is_empty() {
        return Ok(base);
    }
    let endpoint = endpoint.trim_start_matches('/');
    if endpoint.is_empty() {
        return Ok(base);
    }
    if !base.path().ends_with('/') {
        let current = base.path().to_string();
        base.set_path(&format!("{current}/"));
    }
    base.join(endpoint)
        .with_context(|| format!("failed to join endpoint '{endpoint}'"))
}

async fn send_request(
    http: &reqwest::Client,
    request: &RequestSpec,
    url: &Url,
    payment_header: Option<(&str, &str)>,
    payment_challenge: Option<&str>,
    settled_rail: Option<PaymentRail>,
) -> anyhow::Result<RequestResponse> {
    let mut builder = http.request(request.method.clone(), url.clone());
    for (name, value) in &request.headers {
        builder = builder.header(name, value);
    }
    if let Some(rail) = request.desired_rail {
        if !request
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("x-payment-rail"))
        {
            builder = builder.header(
                "X-Payment-Rail",
                match rail {
                    PaymentRail::Webcash => "webcash",
                    PaymentRail::Voucher => "voucher",
                    PaymentRail::Bitcoin => "bitcoin",
                },
            );
        }
        if !request
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("x-harmoniis-payment-rail"))
        {
            builder = builder.header("X-Harmoniis-Payment-Rail", rail_name(rail));
        }
    }
    if let Some((name, value)) = payment_header {
        builder = builder.header(name, value);
    }
    if let Some(challenge_id) = payment_challenge {
        builder = builder.header("X-Harmoniis-Payment-Challenge", challenge_id);
    }
    if let Some(rail) = settled_rail {
        builder = builder.header("X-Harmoniis-Payment-Rail", rail_name(rail));
    }
    if !request.query.is_empty() {
        builder = builder.query(&request.query);
    }
    builder = match &request.body {
        RequestBodySpec::None => builder,
        RequestBodySpec::Json(value) => builder.json(value),
        RequestBodySpec::Raw {
            bytes,
            content_type,
        } => builder
            .header("content-type", content_type)
            .body(bytes.clone()),
    };
    let response = builder.send().await?;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let body_text = response.text().await.unwrap_or_default();
    let body_json = serde_json::from_str::<Value>(&body_text).ok();
    Ok(RequestResponse {
        url: url.as_str().to_string(),
        status,
        content_type,
        body_text,
        body_json,
    })
}

async fn load_payment_directive(
    http: &reqwest::Client,
    request_url: &Url,
    first_response: &RequestResponse,
    preferred_rail: Option<PaymentRail>,
) -> anyhow::Result<PaymentDirective> {
    let body = first_response
        .body_json
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("402 response body is not valid JSON"))?;
    let payment = body
        .get("payment")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("402 response missing payment object"))?;
    let rail_details = payment.get("rail_details").cloned().unwrap_or(Value::Null);
    let rail = select_payment_rail(payment, preferred_rail)?;
    let rail_name = rail_name(rail).to_string();
    let header_name = payment_header_name(payment, rail, &rail_details);
    let required_amount = payment
        .get("price")
        .or_else(|| payment.get("required_amount"))
        .or_else(|| body.get("required_amount"))
        .map(value_to_string)
        .transpose()?
        .unwrap_or_default();
    let payment_unit = payment
        .get("payment_unit")
        .and_then(Value::as_str)
        .unwrap_or_else(|| match rail {
            PaymentRail::Webcash => "wats",
            PaymentRail::Voucher => "credits",
            PaymentRail::Bitcoin => "sats",
        })
        .to_string();
    let mut effective_rail_details = rail_details;
    if !effective_rail_details.is_object() {
        effective_rail_details = fetch_fee_schedule(
            http,
            request_url,
            payment.get("fee_schedule_url").and_then(Value::as_str),
        )
        .await
        .unwrap_or(Value::Null);
    }
    Ok(PaymentDirective {
        rail,
        rail_name,
        header_name,
        required_amount,
        payment_unit,
        challenge_id: payment
            .get("challenge_id")
            .and_then(Value::as_str)
            .or_else(|| body.get("challenge_id").and_then(Value::as_str))
            .map(ToString::to_string),
        response_code: parse_response_code(first_response.body_json.as_ref()),
        response_body: first_response.body_text.clone(),
        rail_details: effective_rail_details,
    })
}

async fn fetch_fee_schedule(
    http: &reqwest::Client,
    request_url: &Url,
    fee_schedule_url: Option<&str>,
) -> Option<Value> {
    let target = if let Some(raw) = fee_schedule_url {
        if raw.starts_with("http://") || raw.starts_with("https://") {
            Url::parse(raw).ok()
        } else {
            request_url.join(raw).ok().or_else(|| {
                let origin = Url::parse(&origin_string(request_url)).ok()?;
                origin.join(raw).ok()
            })
        }
    } else {
        Url::parse(&origin_string(request_url))
            .ok()
            .and_then(|origin| origin.join("/api/info").ok())
    }?;
    let response = http.get(target).send().await.ok()?;
    let body = response.json::<Value>().await.ok()?;
    body.get("payment_rails").cloned()
}

fn parse_response_code(body: Option<&Value>) -> Option<String> {
    body.and_then(|value| value.get("code").and_then(Value::as_str))
        .map(ToString::to_string)
}

fn bitcoin_ark_payment_target(rail_details: &Value) -> anyhow::Result<(Network, String, String)> {
    let bitcoin = rail_details
        .get("bitcoin")
        .ok_or_else(|| anyhow::anyhow!("402/info metadata missing bitcoin rail details"))?;
    let mode = bitcoin
        .get("mode")
        .and_then(Value::as_str)
        .or_else(|| {
            bitcoin
                .get("ark")
                .and_then(|v| v.get("mode"))
                .and_then(Value::as_str)
        })
        .unwrap_or("ark");
    if !mode.eq_ignore_ascii_case("ark") {
        anyhow::bail!("bitcoin rail is not ARK mode");
    }
    let asp_url = bitcoin
        .get("asp_url")
        .and_then(Value::as_str)
        .or_else(|| {
            bitcoin
                .get("ark")
                .and_then(|v| v.get("asp_url"))
                .and_then(Value::as_str)
        })
        .ok_or_else(|| anyhow::anyhow!("bitcoin rail metadata missing asp_url"))?
        .to_string();
    let offchain_receive_address = bitcoin
        .get("offchain_receive_address")
        .and_then(Value::as_str)
        .or_else(|| {
            bitcoin
                .get("ark")
                .and_then(|v| v.get("offchain_receive_address"))
                .and_then(Value::as_str)
        })
        .ok_or_else(|| anyhow::anyhow!("bitcoin rail metadata missing offchain_receive_address"))?
        .to_string();
    let network = bitcoin
        .get("network")
        .and_then(Value::as_str)
        .map(parse_network)
        .transpose()?
        .unwrap_or(Network::Bitcoin);
    Ok((network, asp_url, offchain_receive_address))
}

fn parse_network(raw: &str) -> anyhow::Result<Network> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "bitcoin" | "mainnet" => Ok(Network::Bitcoin),
        "testnet" => Ok(Network::Testnet),
        "testnet4" => Ok(Network::Testnet4),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        other => anyhow::bail!("unsupported bitcoin network '{other}'"),
    }
}

fn parse_rail(raw: &str) -> anyhow::Result<PaymentRail> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "webcash" => Ok(PaymentRail::Webcash),
        "voucher" => Ok(PaymentRail::Voucher),
        "bitcoin" => Ok(PaymentRail::Bitcoin),
        other => anyhow::bail!("unsupported payment rail '{other}'"),
    }
}

fn rail_name(rail: PaymentRail) -> &'static str {
    match rail {
        PaymentRail::Webcash => "webcash",
        PaymentRail::Voucher => "voucher",
        PaymentRail::Bitcoin => "bitcoin",
    }
}

fn default_payment_header(rail: PaymentRail) -> &'static str {
    match rail {
        PaymentRail::Webcash => "X-Webcash-Secret",
        PaymentRail::Voucher => "X-Voucher-Secret",
        PaymentRail::Bitcoin => "X-Bitcoin-Secret",
    }
}

fn select_payment_rail(
    payment: &serde_json::Map<String, Value>,
    preferred_rail: Option<PaymentRail>,
) -> anyhow::Result<PaymentRail> {
    let allowed = payment
        .get("allowed_rails")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter_map(|raw| parse_rail(raw).ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if let Some(preferred) = preferred_rail {
        if allowed.is_empty() || allowed.contains(&preferred) {
            return Ok(preferred);
        }
    }

    if let Some(raw) = payment
        .get("currency")
        .and_then(Value::as_str)
        .or_else(|| payment.get("expected_payment_rail").and_then(Value::as_str))
    {
        let parsed = parse_rail(raw)?;
        if allowed.is_empty() || allowed.contains(&parsed) {
            return Ok(parsed);
        }
    }

    if let Some(first) = allowed.first().copied() {
        return Ok(first);
    }

    Ok(PaymentRail::Webcash)
}

fn payment_header_name(
    payment: &serde_json::Map<String, Value>,
    rail: PaymentRail,
    rail_details: &Value,
) -> String {
    rail_details
        .get(rail_name(rail))
        .and_then(|value| value.get("header"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            payment
                .get("header")
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| default_payment_header(rail).to_string())
}

fn origin_string(url: &Url) -> String {
    let mut origin = format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default());
    if let Some(port) = url.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    origin
}

fn request_hash(request: &RequestSpec) -> String {
    let mut hasher = Sha256::new();
    hasher.update(request.base_url.as_bytes());
    hasher.update(request.endpoint.as_bytes());
    hasher.update(request.method.as_str().as_bytes());
    for (key, value) in &request.query {
        hasher.update(key.as_bytes());
        hasher.update(b"=");
        hasher.update(value.as_bytes());
    }
    for (key, value) in &request.headers {
        hasher.update(key.as_bytes());
        hasher.update(b":");
        hasher.update(value.as_bytes());
    }
    match &request.body {
        RequestBodySpec::None => {}
        RequestBodySpec::Json(value) => hasher.update(value.to_string().as_bytes()),
        RequestBodySpec::Raw {
            bytes,
            content_type,
        } => {
            hasher.update(content_type.as_bytes());
            hasher.update(bytes);
        }
    }
    hex::encode(hasher.finalize())
}

fn hashed_reference(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

fn payment_transaction_proof(payment: &AcquiredPayment) -> (&'static str, String) {
    match payment {
        AcquiredPayment::Webcash { header_value, .. } => {
            ("webcash_secret_hash", hashed_reference(header_value))
        }
        AcquiredPayment::Voucher {
            payment_reference, ..
        } => ("voucher_public_hash", payment_reference.clone()),
        AcquiredPayment::BitcoinArk {
            payment_reference, ..
        } => ("ark_vtxo_txid", payment_reference.clone()),
    }
}

fn value_to_string(value: &Value) -> anyhow::Result<String> {
    match value {
        Value::String(text) => Ok(text.trim().to_string()),
        Value::Number(number) => Ok(number.to_string()),
        other => anyhow::bail!("expected payment amount string/number, got {other}"),
    }
}

fn is_duplicate_wallet_row_error(err: &str) -> bool {
    err.contains("UNIQUE constraint") || err.contains("already exists")
}

#[cfg(test)]
mod tests {
    use super::{build_request_url, payment_header_name, select_payment_rail, PaymentRail};
    use serde_json::json;

    #[test]
    fn selects_preferred_allowed_rail() {
        let payment = json!({
            "allowed_rails": ["webcash", "voucher", "bitcoin"],
            "currency": "webcash",
        });
        let payment = payment.as_object().expect("object");
        assert_eq!(
            select_payment_rail(payment, Some(PaymentRail::Voucher)).expect("selected rail"),
            PaymentRail::Voucher
        );
    }

    #[test]
    fn prefers_selected_rail_header_over_top_level_default() {
        let payment = json!({
            "header": "X-Webcash-Secret",
            "rail_details": {
                "voucher": { "header": "X-Voucher-Secret" }
            }
        });
        let payment_obj = payment.as_object().expect("object");
        let rail_details = payment_obj.get("rail_details").expect("rail details");
        assert_eq!(
            payment_header_name(payment_obj, PaymentRail::Voucher, rail_details),
            "X-Voucher-Secret"
        );
    }

    #[test]
    fn request_url_keeps_base_path_for_leading_slash_endpoints() {
        let url = build_request_url("https://example.com/api/v1", "/posts").expect("url");
        assert_eq!(url.as_str(), "https://example.com/api/v1/posts");
    }

    #[test]
    fn request_url_accepts_absolute_endpoint_override() {
        let url = build_request_url(
            "https://example.com/api/v1",
            "https://payments.example.net/custom",
        )
        .expect("url");
        assert_eq!(url.as_str(), "https://payments.example.net/custom");
    }
}
