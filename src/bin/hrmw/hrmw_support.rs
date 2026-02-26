use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::Context;
use harmoniis_wallet::{
    client::{
        timeline::{PostActivityMetadata, PostAttachment},
        HarmoniisClient,
    },
    wallet::RgbWallet,
};
use rand::Rng;
use webylib::{Amount as WebcashAmount, Wallet as WebcashWallet};

pub fn default_wallet_path() -> PathBuf {
    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".harmoniis").join("rgb.db")
}

fn legacy_wallet_path() -> PathBuf {
    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".harmoniis").join("wallet.db")
}

pub fn resolve_wallet_path(cli_wallet: Option<PathBuf>) -> PathBuf {
    if let Some(path) = cli_wallet {
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.eq_ignore_ascii_case("webcash.db"))
            .unwrap_or(false)
        {
            let rgb_path = path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."))
                .join("rgb.db");
            eprintln!(
                "Note: --wallet points to webcash.db; using RGB wallet {}",
                rgb_path.display()
            );
            return rgb_path;
        }
        return path;
    }
    let preferred = default_wallet_path();
    if preferred.exists() {
        return preferred;
    }
    let legacy = legacy_wallet_path();
    if legacy.exists() {
        return legacy;
    }
    preferred
}

pub fn open_or_create_wallet(path: &Path) -> anyhow::Result<RgbWallet> {
    if path.exists() {
        RgbWallet::open(path).context("failed to open wallet")
    } else {
        RgbWallet::create(path).context("failed to create wallet")
    }
}

pub fn default_webcash_wallet_path(rgb_wallet_path: &Path) -> PathBuf {
    let base_dir = rgb_wallet_path
        .parent()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| PathBuf::from("."));
    base_dir.join("webcash.db")
}

pub async fn open_webcash_wallet(
    rgb_wallet_path: &Path,
    wallet: &RgbWallet,
) -> anyhow::Result<WebcashWallet> {
    let webcash_path = default_webcash_wallet_path(rgb_wallet_path);
    let webcash_wallet = WebcashWallet::open(&webcash_path).await.with_context(|| {
        format!(
            "failed to open webcash wallet at {}",
            webcash_path.display()
        )
    })?;
    let master_secret = wallet
        .derive_webcash_master_secret_hex()
        .context("failed to derive wallet webcash master secret")?;
    webcash_wallet
        .store_master_secret(&master_secret)
        .await
        .context("failed to store deterministic webcash master secret")?;
    Ok(webcash_wallet)
}

pub fn extract_webcash_token(payment_output: &str) -> anyhow::Result<String> {
    let trimmed = payment_output.trim();
    if trimmed.starts_with('e') && trimmed.contains(":secret:") {
        return Ok(trimmed.to_string());
    }
    if let Some((_, right)) = trimmed.rsplit_once("recipient:") {
        let token = right.trim();
        if token.starts_with('e') && token.contains(":secret:") {
            return Ok(token.to_string());
        }
    }
    anyhow::bail!("failed to extract webcash token from payment output: {trimmed}");
}

pub fn is_payment_required_error(err: &anyhow::Error) -> bool {
    if let Some(herr) = err.downcast_ref::<harmoniis_wallet::error::Error>() {
        return matches!(herr, harmoniis_wallet::error::Error::Api { status, .. } if *status == 402);
    }
    false
}

pub fn required_amount_from_api_error(err: &anyhow::Error) -> Option<String> {
    fn amount_to_string(v: &serde_json::Value) -> Option<String> {
        match v {
            serde_json::Value::String(s) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            }
            serde_json::Value::Number(n) => n
                .as_f64()
                .map(|f| {
                    if (f.fract() - 0.0).abs() < f64::EPSILON {
                        format!("{}", f as u64)
                    } else {
                        let units = (f * 100_000_000.0).round() as u64;
                        let whole = units / 100_000_000;
                        let frac = units % 100_000_000;
                        if frac == 0 {
                            format!("{whole}")
                        } else {
                            format!("{whole}.{}", format!("{frac:08}").trim_end_matches('0'))
                        }
                    }
                })
                .filter(|s| !s.is_empty()),
            _ => None,
        }
    }

    if let Some(herr) = err.downcast_ref::<harmoniis_wallet::error::Error>() {
        if let harmoniis_wallet::error::Error::Api { status, body } = herr {
            if *status == 402 {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
                    if let Some(req) = v.get("required_amount").and_then(amount_to_string) {
                        return Some(req);
                    }
                    if let Some(req) = v.get("amount").and_then(amount_to_string) {
                        return Some(req);
                    }
                    if let Some(req) = v
                        .get("payment")
                        .and_then(|p| p.get("price"))
                        .and_then(amount_to_string)
                    {
                        return Some(req);
                    }
                }
            }
        }
    }
    None
}

pub fn required_amount_for_payment_retry(err: &anyhow::Error, fallback: &str) -> Option<String> {
    if !is_payment_required_error(err) {
        return None;
    }
    Some(required_amount_from_api_error(err).unwrap_or_else(|| fallback.to_string()))
}

pub async fn pay_from_wallet(
    rgb_wallet_path: &Path,
    wallet: &RgbWallet,
    amount: &str,
    memo: &str,
) -> anyhow::Result<String> {
    let webcash_wallet = open_webcash_wallet(rgb_wallet_path, wallet).await?;
    let parsed_amount = WebcashAmount::from_str(amount)
        .with_context(|| format!("invalid webcash amount '{amount}'"))?;
    let payment_output = webcash_wallet
        .pay(parsed_amount, memo)
        .await
        .with_context(|| format!("failed to create wallet payment for {memo}"))?;
    extract_webcash_token(&payment_output)
}

pub fn make_client(api: &str, direct: bool) -> HarmoniisClient {
    if direct {
        HarmoniisClient::new_direct(api)
    } else {
        HarmoniisClient::new(api)
    }
}

pub fn now_utc() -> String {
    chrono::Utc::now().to_rfc3339()
}

pub fn parse_amount_to_units(amount: &str) -> u64 {
    match amount.trim().parse::<f64>() {
        Ok(f) => (f * 1e8).round() as u64,
        Err(_) => 0,
    }
}

pub fn format_units_to_amount(units: u64) -> String {
    let whole = units / 100_000_000;
    let frac = units % 100_000_000;
    if frac == 0 {
        return whole.to_string();
    }
    let frac_str = format!("{frac:08}");
    format!("{whole}.{}", frac_str.trim_end_matches('0'))
}

pub fn parse_keywords_csv(input: Option<&str>) -> Vec<String> {
    input
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn normalize_token(input: Option<String>) -> Option<String> {
    input
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty())
}

fn normalize_list(values: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for value in values {
        let token = value.trim().to_lowercase();
        if token.is_empty() {
            continue;
        }
        if !out.iter().any(|v| v == &token) {
            out.push(token);
        }
    }
    out
}

fn normalize_optional_decimal(input: Option<String>) -> anyhow::Result<Option<String>> {
    let Some(raw) = input else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let parsed = trimmed
        .parse::<f64>()
        .with_context(|| format!("invalid decimal amount '{trimmed}'"))?;
    if parsed <= 0.0 {
        anyhow::bail!("amount must be > 0, got {trimmed}");
    }
    let units = (parsed * 100_000_000.0).round() as u64;
    let whole = units / 100_000_000;
    let frac = units % 100_000_000;
    if frac == 0 {
        Ok(Some(format!("{whole}")))
    } else {
        Ok(Some(format!(
            "{whole}.{}",
            format!("{frac:08}").trim_end_matches('0')
        )))
    }
}

fn attachment_type_for(path: &Path) -> String {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    if ext == "md" {
        "text/markdown".to_string()
    } else {
        "text/plain".to_string()
    }
}

fn read_attachment(path: &Path) -> anyhow::Result<PostAttachment> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed reading attachment file {}", path.display()))?;
    let filename = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid attachment filename: {}", path.display()))?
        .to_string();
    Ok(PostAttachment {
        filename,
        content: Some(content),
        attachment_type: attachment_type_for(path),
        s3_key: None,
        url: None,
        is_public: false,
    })
}

pub fn build_activity_metadata(
    post_type: &str,
    category: Option<String>,
    location: Option<String>,
    location_country: Option<String>,
    remote_ok: bool,
    service_terms: Vec<String>,
    tags_csv: Option<String>,
    price_min: Option<String>,
    price_max: Option<String>,
    currency: Option<String>,
    billing_model: Option<String>,
    billing_cycle: Option<String>,
    invoice_rule: Option<String>,
    unit_label: Option<String>,
) -> anyhow::Result<Option<PostActivityMetadata>> {
    let mut meta = PostActivityMetadata::default();
    meta.category = normalize_token(category);
    meta.location = normalize_token(location);
    meta.location_country = normalize_token(location_country);
    meta.remote_ok = if remote_ok { Some(true) } else { None };
    meta.service_terms = normalize_list(service_terms);
    meta.tags = parse_keywords_csv(tags_csv.as_deref());
    meta.price_min = normalize_optional_decimal(price_min)?;
    meta.price_max = normalize_optional_decimal(price_max)?;
    meta.currency = normalize_token(currency);
    meta.billing_model = normalize_token(billing_model);
    meta.billing_cycle = normalize_token(billing_cycle);
    meta.invoice_rule = normalize_token(invoice_rule);
    meta.unit_label = normalize_token(unit_label);
    meta.intent = if post_type == "general" {
        None
    } else {
        Some(post_type.to_string())
    };

    if meta.category.is_none() {
        meta.category = match post_type {
            "service_offer" | "service_request" => Some("services".to_string()),
            "product_listing" | "goods_offer" => Some("products".to_string()),
            "job_request" => Some("jobs".to_string()),
            "bid" => Some("contracts".to_string()),
            "provision" => Some("provisioning".to_string()),
            _ => None,
        };
    }
    if meta.currency.is_none() && (meta.price_min.is_some() || meta.price_max.is_some()) {
        meta.currency = Some("webcash".to_string());
    }
    if meta.billing_model.is_none() && is_commercial_listing_post_type(post_type) {
        meta.billing_model = Some("one_time".to_string());
    }
    if meta.billing_model.as_deref() == Some("subscription") {
        if meta.billing_cycle.is_none() {
            meta.billing_cycle = Some("monthly".to_string());
        }
        if meta.invoice_rule.is_none() {
            meta.invoice_rule = Some("monthly_pickup".to_string());
        }
    }

    let has_any = meta.intent.is_some()
        || meta.category.is_some()
        || meta.subcategory.is_some()
        || meta.location.is_some()
        || meta.location_country.is_some()
        || meta.remote_ok.is_some()
        || !meta.delivery_modes.is_empty()
        || !meta.service_terms.is_empty()
        || !meta.tags.is_empty()
        || meta.price_min.is_some()
        || meta.price_max.is_some()
        || meta.currency.is_some()
        || meta.exchange_type.is_some()
        || meta.market_model.is_some()
        || meta.participant_source.is_some()
        || meta.fulfillment_mode.is_some()
        || meta.execution_urgency.is_some()
        || meta.geo_scope.is_some()
        || meta.compliance_domain.is_some()
        || meta.billing_model.is_some()
        || meta.billing_cycle.is_some()
        || meta.invoice_rule.is_some()
        || meta.unit_label.is_some()
        || !meta.extra.is_empty();

    Ok(if has_any { Some(meta) } else { None })
}

pub fn build_post_attachments(
    post_type: &str,
    content: &str,
    terms_file: Option<PathBuf>,
    descriptor_file: Option<PathBuf>,
    attachment_files: Vec<PathBuf>,
) -> anyhow::Result<Vec<PostAttachment>> {
    let mut attachments = Vec::new();
    if let Some(path) = terms_file {
        let mut att = read_attachment(&path)?;
        let lower = att.filename.to_lowercase();
        att.filename = if lower.ends_with(".txt") {
            "terms.txt".to_string()
        } else {
            "terms.md".to_string()
        };
        attachments.push(att);
    }
    if let Some(path) = descriptor_file {
        let mut att = read_attachment(&path)?;
        let default_name = listing_descriptor_filename(post_type);
        let lower = att.filename.to_lowercase();
        att.filename = if lower.ends_with(".txt") {
            default_name.replacen(".md", ".txt", 1)
        } else {
            default_name.to_string()
        };
        attachments.push(att);
    }
    for path in attachment_files {
        attachments.push(read_attachment(&path)?);
    }

    if !attachments.is_empty() {
        return Ok(attachments);
    }

    if is_commercial_listing_post_type(post_type) {
        let descriptor_name = listing_descriptor_filename(post_type);
        let descriptor_title = descriptor_name
            .trim_end_matches(".md")
            .replace(['_', '-'], " ");
        Ok(vec![
            PostAttachment {
                filename: "terms.md".to_string(),
                content: Some(default_terms_markdown()),
                attachment_type: "text/markdown".to_string(),
                s3_key: None,
                url: None,
                is_public: false,
            },
            PostAttachment {
                filename: descriptor_name.to_string(),
                content: Some(format!("# {}\n\n{}", descriptor_title, content)),
                attachment_type: "text/markdown".to_string(),
                s3_key: None,
                url: None,
                is_public: false,
            },
        ])
    } else {
        Ok(vec![PostAttachment {
            filename: "description.md".to_string(),
            content: Some(format!("# Listing\n\n{}", content)),
            attachment_type: "text/markdown".to_string(),
            s3_key: None,
            url: None,
            is_public: false,
        }])
    }
}

pub fn is_commercial_listing_post_type(post_type: &str) -> bool {
    matches!(
        post_type,
        "service_offer"
            | "service_request"
            | "product_listing"
            | "job_request"
            | "provision"
            | "goods_offer"
    )
}

fn listing_descriptor_filename(post_type: &str) -> &'static str {
    match post_type {
        "service_offer" | "service_request" | "job_request" | "provision" => "service.md",
        "product_listing" | "goods_offer" => "product.md",
        _ => "description.md",
    }
}

fn default_terms_markdown() -> String {
    [
        "# Terms",
        "",
        "1. Scope is exactly what is written in the listing descriptor attachment.",
        "2. Buyer and seller must agree on delivery details through contract and bid flow.",
        "3. Payment, pickup fee, and dispute/refund rules follow Harmoniis contract endpoints.",
    ]
    .join("\n")
}

pub fn next_contract_id() -> String {
    let n: u32 = rand::thread_rng().gen_range(1..999_999);
    format!("CTR_{}_{:06}", chrono::Utc::now().format("%Y"), n)
}
