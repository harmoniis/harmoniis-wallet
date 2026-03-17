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
    wallet::{NewPaymentAttempt, PaymentAttemptUpdate, RgbWallet},
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
    let first = send_request(&http, request, &url, None).await?;
    if first.status != 402 {
        return Ok(first);
    }

    let directive = load_payment_directive(&http, &url, &first).await?;
    let wallet = open_or_create_wallet(wallet_path)?;
    let service_origin = origin_string(&url);
    let endpoint_path = url.path().to_string();
    let method_upper = request.method.as_str().to_ascii_uppercase();
    let rail_token = directive.rail_name.to_ascii_lowercase();

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
        request_hash: &request_hash(request),
    })?;

    let payment = acquire_payment(
        wallet_path,
        &wallet,
        &directive,
        &request.base_url,
        &request.action_hint,
    )
    .await?;
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

    let second = send_request(
        &http,
        request,
        &url,
        Some((payment.header_name(), &payment.header_value())),
    )
    .await;
    match second {
        Ok(resp) if (200..300).contains(&resp.status) => {
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
            Ok(resp)
        }
        Ok(resp) => {
            recover_or_log_loss(
                wallet_path,
                &wallet,
                &directive,
                &payment,
                &attempt_id,
                &service_origin,
                &endpoint_path,
                &method_upper,
                Some(resp.status),
                parse_response_code(resp.body_json.as_ref()),
                Some(resp.body_text.as_str()),
                &request.base_url,
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
                &service_origin,
                &endpoint_path,
                &method_upper,
                None,
                Some("request_send_failed".to_string()),
                Some(&err.to_string()),
                &request.base_url,
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
    service_origin: &str,
    endpoint_path: &str,
    method_upper: &str,
    response_status: Option<u16>,
    response_code: Option<String>,
    response_body: Option<&str>,
    service_base_url: &str,
) -> anyhow::Result<()> {
    let rail_token = directive.rail_name.to_ascii_lowercase();
    match payment {
        AcquiredPayment::Webcash { header_value, .. } => {
            let webcash_wallet = open_webcash_wallet(wallet_path, wallet).await?;
            let secret = SecretWebcash::parse(header_value)
                .map_err(|e| anyhow::anyhow!("invalid paid webcash token: {e}"))?;
            match webcash_wallet.insert(secret).await {
                Ok(()) => {
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
                }
                Err(err) if is_duplicate_wallet_row_error(&err.to_string()) => {
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
            let btc = DeterministicBitcoinWallet::from_master_wallet(wallet, network)
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
    }
    if let Some((name, value)) = payment_header {
        builder = builder.header(name, value);
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
) -> anyhow::Result<PaymentDirective> {
    let body = first_response
        .body_json
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("402 response body is not valid JSON"))?;
    let payment = body
        .get("payment")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("402 response missing payment object"))?;
    let rail_name = payment
        .get("currency")
        .and_then(Value::as_str)
        .or_else(|| payment.get("expected_payment_rail").and_then(Value::as_str))
        .unwrap_or("webcash")
        .trim()
        .to_ascii_lowercase();
    let rail = parse_rail(&rail_name)?;
    let header_name = payment
        .get("header")
        .and_then(Value::as_str)
        .unwrap_or_else(|| match rail {
            PaymentRail::Webcash => "X-Webcash-Secret",
            PaymentRail::Voucher => "X-Voucher-Secret",
            PaymentRail::Bitcoin => "X-Bitcoin-Secret",
        })
        .to_string();
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
    let mut rail_details = payment.get("rail_details").cloned().unwrap_or(Value::Null);
    if !rail_details.is_object() {
        rail_details = fetch_fee_schedule(
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
        response_code: parse_response_code(first_response.body_json.as_ref()),
        response_body: first_response.body_text.clone(),
        rail_details,
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
