//! `hrmw` — Harmoniis RGB wallet CLI.
//!
//! Manages RGB21 bearer contracts and certificates via the Harmoniis Witness.
//!
//! Mental model (mirrors Webcash):
//!   insert  → take custody of a contract you received (like `webyc insert`)
//!   replace → transfer a contract to another party  (like `webyc pay`)
//!   list    → show all contracts/certificates in wallet
//!   check   → verify a contract is still live with the Witness

use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::Context;
use clap::{Parser, Subcommand};
use harmoniis_wallet::{
    client::{
        arbitration::{build_witness_commitment, BuyRequest},
        timeline::{
            DonationClaimRequest, PostActivityMetadata, PostAttachment, PublishPostRequest,
            RatePostRequest,
            RegisterRequest,
        },
        HarmoniisClient,
    },
    types::{Certificate, Contract, ContractStatus, ContractType, Role, WitnessSecret},
    wallet::RgbWallet,
    Identity,
};
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;
use webylib::{Amount as WebcashAmount, SecretWebcash, Wallet as WebcashWallet};

const DEFAULT_API_URL: &str = "https://harmoniis.com/api";

// ── Helpers ───────────────────────────────────────────────────────────────────

fn default_wallet_path() -> PathBuf {
    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".harmoniis").join("rgb.db")
}

fn legacy_wallet_path() -> PathBuf {
    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".harmoniis").join("wallet.db")
}

fn resolve_wallet_path(cli_wallet: Option<PathBuf>) -> PathBuf {
    if let Some(path) = cli_wallet {
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

fn open_or_create_wallet(path: &std::path::Path) -> anyhow::Result<RgbWallet> {
    if path.exists() {
        RgbWallet::open(path).context("failed to open wallet")
    } else {
        RgbWallet::create(path).context("failed to create wallet")
    }
}

fn default_webcash_wallet_path(rgb_wallet_path: &std::path::Path) -> PathBuf {
    let base_dir = rgb_wallet_path
        .parent()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| PathBuf::from("."));
    base_dir.join("webcash.db")
}

fn derive_webcash_master_secret_hex(identity: &Identity) -> anyhow::Result<String> {
    let root_key =
        hex::decode(identity.private_key_hex()).context("invalid root private key hex")?;
    let hk = Hkdf::<Sha256>::new(None, &root_key);
    let mut output = [0u8; 32];
    hk.expand(b"harmoniis/hrmw/webcash/master/v1|chain:3", &mut output)
        .map_err(|_| anyhow::anyhow!("failed to derive webcash master secret"))?;
    Ok(hex::encode(output))
}

async fn open_webcash_wallet(
    rgb_wallet_path: &std::path::Path,
    identity: &Identity,
) -> anyhow::Result<WebcashWallet> {
    let webcash_path = default_webcash_wallet_path(rgb_wallet_path);
    let webcash_wallet = WebcashWallet::open(&webcash_path).await.with_context(|| {
        format!(
            "failed to open webcash wallet at {}",
            webcash_path.display()
        )
    })?;
    let master_secret = derive_webcash_master_secret_hex(identity)?;
    webcash_wallet
        .store_master_secret(&master_secret)
        .await
        .context("failed to store deterministic webcash master secret")?;
    Ok(webcash_wallet)
}

fn extract_webcash_secret(payment_output: &str) -> anyhow::Result<String> {
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
    anyhow::bail!("failed to extract webcash secret from payment output: {trimmed}");
}

fn required_amount_from_api_error(err: &anyhow::Error) -> Option<String> {
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
                    if let Some(req) = v
                        .get("payment")
                        .and_then(|p| p.get("normal_price"))
                        .and_then(amount_to_string)
                    {
                        return Some(req);
                    }
                    if let Some(req) = v
                        .get("payment")
                        .and_then(|p| p.get("sale"))
                        .and_then(|s| s.get("sale_price"))
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

async fn pay_from_wallet(
    rgb_wallet_path: &std::path::Path,
    identity: &Identity,
    amount: &str,
    memo: &str,
) -> anyhow::Result<String> {
    let webcash_wallet = open_webcash_wallet(rgb_wallet_path, identity).await?;
    let parsed_amount = WebcashAmount::from_str(amount)
        .with_context(|| format!("invalid webcash amount '{amount}'"))?;
    let payment_output = webcash_wallet
        .pay(parsed_amount, memo)
        .await
        .with_context(|| format!("failed to create wallet payment for {memo}"))?;
    extract_webcash_secret(&payment_output)
}

fn make_client(api: &str, direct: bool) -> HarmoniisClient {
    if direct {
        HarmoniisClient::new_direct(api)
    } else {
        HarmoniisClient::new(api)
    }
}

fn now_utc() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn parse_amount_to_units(amount: &str) -> u64 {
    match amount.trim().parse::<f64>() {
        Ok(f) => (f * 1e8).round() as u64,
        Err(_) => 0,
    }
}

fn parse_keywords_csv(input: Option<&str>) -> Vec<String> {
    input
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn normalize_token(input: Option<String>) -> Option<String> {
    input.map(|v| v.trim().to_lowercase()).filter(|v| !v.is_empty())
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
        Ok(Some(
            format!("{whole}.{}", format!("{frac:08}").trim_end_matches('0'))
        ))
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
        content,
        attachment_type: attachment_type_for(path),
    })
}

fn build_activity_metadata(
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

fn build_post_attachments(
    post_type: &str,
    content: &str,
    terms_file: Option<PathBuf>,
    descriptor_file: Option<PathBuf>,
    attachment_files: Vec<PathBuf>,
) -> anyhow::Result<Vec<PostAttachment>> {
    let mut attachments = Vec::new();
    if let Some(path) = terms_file {
        attachments.push(read_attachment(&path)?);
    }
    if let Some(path) = descriptor_file {
        attachments.push(read_attachment(&path)?);
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
                content: default_terms_markdown(),
                attachment_type: "text/markdown".to_string(),
            },
            PostAttachment {
                filename: descriptor_name.to_string(),
                content: format!("# {}\n\n{}", descriptor_title, content),
                attachment_type: "text/markdown".to_string(),
            },
        ])
    } else {
        Ok(vec![PostAttachment {
            filename: "description.md".to_string(),
            content: format!("# Listing\n\n{}", content),
            attachment_type: "text/markdown".to_string(),
        }])
    }
}

fn is_commercial_listing_post_type(post_type: &str) -> bool {
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

fn next_contract_id() -> String {
    let n: u32 = rand::thread_rng().gen_range(1..999_999);
    format!("CTR_{}_{:06}", chrono::Utc::now().format("%Y"), n)
}

// ── CLI structure ─────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "hrmw",
    version,
    author = "Harmoniis Contributors",
    about = "Harmoniis bearer wallet — RGB21 contracts and certificates via Witness",
    long_about = "\
hrmw is the reference CLI wallet for the Harmoniis decentralised marketplace.\n\
It manages Ed25519 identities and RGB21 bearer contracts (Witness secrets).\n\
\n\
Bearer model — like Webcash but for contracts:\n\
  insert  <secret>   — take custody of a contract you received out-of-band\n\
  replace --id <id>  — transfer a contract; prints new secret for out-of-band delivery\n\
  list               — show all contracts (marks which ones you hold the secret for)\n\
  check   --id <id>  — verify contract is still live with the Witness\n\
\n\
By default connects to https://harmoniis.com/api via the Cloudflare edge proxy.\n\
Use --api for non-production targets. Use --direct to speak to a backend URL directly (local dev or Lambda URL).\n\
\n\
Wallet database: ~/.harmoniis/rgb.db (override with --wallet)\n\
\n\
Examples:\n\
  hrmw setup\n\
  hrmw webcash info\n\
  hrmw webcash insert 'e1.0:secret:<hex>'\n\
  hrmw identity register --nick alice\n\
  hrmw contract buy --post POST_xyz --amount 1.0 --type service\n\
  hrmw contract insert 'n:CTR_2026_001:secret:<hex>'\n\
  hrmw contract replace --id CTR_2026_001\n\
  hrmw contract list\n\
  hrmw --api http://localhost:9001 --direct info"
)]
struct Cli {
    #[arg(long, global = true)]
    wallet: Option<PathBuf>,

    #[arg(long, global = true, default_value = DEFAULT_API_URL)]
    api: String,

    /// Bypass the Cloudflare proxy; speak directly to the backend URL
    #[arg(long, global = true, default_value_t = false)]
    direct: bool,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Initialise or import a wallet (creates ~/.harmoniis/rgb.db)
    Setup {
        /// Import an existing 64-char Ed25519 private key hex
        #[arg(long)]
        secret: Option<String>,
    },

    /// Show wallet summary (fingerprint, nickname, counts)
    Info,

    /// Donation faucet operations
    #[command(subcommand)]
    Donation(DonationCmd),

    /// Webcash wallet operations
    #[command(subcommand)]
    Webcash(WebcashCmd),

    /// Identity operations
    #[command(subcommand)]
    Identity(IdentityCmd),

    /// Timeline operations (post/comment/rate)
    #[command(subcommand)]
    Timeline(TimelineCmd),

    /// Contract lifecycle
    #[command(subcommand)]
    Contract(ContractCmd),

    /// Certificate operations
    #[command(subcommand)]
    Certificate(CertCmd),
}

// ── Identity ──────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum DonationCmd {
    /// Claim one donation token for this wallet fingerprint (one per key)
    Claim,
}

#[derive(Subcommand)]
enum WebcashCmd {
    /// Show Webcash balance and output counts
    Info,
    /// Insert a secret webcash token into the local wallet
    Insert {
        /// Webcash secret token: e<amount>:secret:<hex>
        secret: String,
    },
    /// Create a spend token from the local wallet
    Pay {
        /// Amount in webcash decimal (e.g. 0.3)
        #[arg(long)]
        amount: String,
        /// Optional memo
        #[arg(long, default_value = "hrmw payment")]
        memo: String,
    },
    /// Verify unspent outputs against the Webcash server
    Check,
    /// Recover wallet outputs from deterministic master secret
    Recover {
        #[arg(long, default_value_t = 20)]
        gap_limit: usize,
    },
    /// Consolidate many outputs into fewer outputs
    Merge {
        #[arg(long, default_value_t = 20)]
        group: usize,
    },
}

#[derive(Subcommand)]
enum IdentityCmd {
    /// Register this wallet's identity on the Harmoniis network
    Register {
        #[arg(long)]
        nick: String,
        #[arg(long)]
        about: Option<String>,
    },
}

#[derive(Subcommand)]
enum TimelineCmd {
    /// Publish a public timeline post
    Post {
        /// Post content
        #[arg(long)]
        content: String,
        /// Post type (e.g. general, service_offer)
        #[arg(long, default_value = "general")]
        post_type: String,
        /// Optional comma-separated keywords
        #[arg(long)]
        keywords: Option<String>,
        /// Optional comma-separated tags for activity metadata
        #[arg(long)]
        tags: Option<String>,
        /// Optional repeated service terms (e.g. --service-term same-day)
        #[arg(long = "service-term")]
        service_terms: Vec<String>,
        /// Optional minimum listing price in Webcash decimal format
        #[arg(long)]
        price_min: Option<String>,
        /// Optional maximum listing price in Webcash decimal format
        #[arg(long)]
        price_max: Option<String>,
        /// Optional currency (defaults to webcash when price is set)
        #[arg(long)]
        currency: Option<String>,
        /// Optional category override
        #[arg(long)]
        category: Option<String>,
        /// Optional location
        #[arg(long)]
        location: Option<String>,
        /// Optional location country
        #[arg(long)]
        location_country: Option<String>,
        /// Mark listing as remotely fulfillable
        #[arg(long, default_value_t = false)]
        remote_ok: bool,
        /// Billing model: one_time | subscription
        #[arg(long)]
        billing_model: Option<String>,
        /// Billing cycle for subscriptions: monthly | weekly | quarterly | yearly
        #[arg(long)]
        billing_cycle: Option<String>,
        /// Invoice rule for subscriptions: monthly_pickup | milestone_pickup
        #[arg(long)]
        invoice_rule: Option<String>,
        /// Optional unit label for display (example: per_month_per_location)
        #[arg(long)]
        unit_label: Option<String>,
        /// Optional terms markdown file path
        #[arg(long)]
        terms_file: Option<PathBuf>,
        /// Optional descriptor markdown file path (service/product/skill/description)
        #[arg(long)]
        descriptor_file: Option<PathBuf>,
        /// Optional extra attachment file path (repeatable)
        #[arg(long = "attachment")]
        attachment_files: Vec<PathBuf>,
    },

    /// Publish a public comment under an existing post
    Comment {
        /// Parent post ID
        #[arg(long)]
        post: String,
        /// Comment content
        #[arg(long)]
        content: String,
    },

    /// Rate a post/comment (up/down)
    Rate {
        /// Target post ID
        #[arg(long)]
        post: String,
        /// Vote: up|down
        #[arg(long, default_value = "up")]
        vote: String,
    },
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum ContractCmd {
    /// List all contracts in the local wallet
    ///
    /// Columns: id | status | role | held | description
    /// 'held' = ✓ if you hold the current witness secret; '·' if tracking proof only
    List,

    /// Print one contract as JSON
    Get { id: String },

    /// Add a received contract to the wallet by its witness secret.
    ///
    /// Verifies the secret is live with the Witness before storing it.
    /// Use this when someone transfers a contract to you out-of-band.
    ///
    /// Example:
    ///   hrmw contract insert 'n:CTR_2026_001:secret:<hex64>'
    Insert {
        /// Witness secret string: `n:{contract_id}:secret:{hex64}`
        secret: String,
        /// Optional description / work spec for your records
        #[arg(long, default_value = "")]
        desc: String,
        /// Your role in this contract
        #[arg(long, default_value = "seller")]
        role: String,
    },

    /// Buy a new contract (buyer pays webcash to Arbitration Service).
    ///
    /// Calls POST /api/arbitration/contracts/buy.
    #[command(alias = "issue")]
    Buy {
        /// Post ID of the seller's service offer on the timeline
        #[arg(long)]
        post: String,
        /// Contract value in decimal webcash units (e.g. "1.5")
        #[arg(long)]
        amount: String,
        /// Contract type: service | product_digital | product_physical
        #[arg(long, default_value = "service")]
        r#type: String,
        /// Optional explicit contract id (defaults to generated CTR_<year>_<seq>)
        #[arg(long)]
        contract_id: Option<String>,
    },

    /// Publish a bid on a service offer (buyer, proves ownership of contract via witness proof).
    ///
    /// Only the public hash (proof) is published — the secret stays in your wallet.
    Bid {
        /// Seller's service offer post ID
        #[arg(long)]
        post: String,
        /// Contract ID (must be in wallet)
        #[arg(long)]
        contract: String,
        /// Bid message (default: "Bid on contract {id}")
        #[arg(long, default_value = "")]
        content: String,
    },

    /// Accept a bid on your service offer (seller).
    Accept {
        #[arg(long)]
        id: String,
    },

    /// Transfer contract control to another party (buyer → seller handover).
    ///
    /// This is the RGB21 bearer transfer step:
    ///   1. Generates a fresh new secret for the contract
    ///   2. Calls witness/replace (old secret → new secret becomes valid)
    ///   3. Prints the new secret to stdout — deliver it to the seller out-of-band
    ///   4. Clears the secret from your wallet (you no longer hold it)
    ///
    /// The seller then runs:  hrmw contract insert '<printed_secret>'
    ///
    /// ⚠ Never post the secret on the timeline or any public channel.
    Replace {
        /// Contract ID (must be in wallet with the current witness secret)
        #[arg(long)]
        id: String,
    },

    /// Deliver work to the Arbitration Service (seller).
    Deliver {
        #[arg(long)]
        id: String,
        /// Delivered work text
        #[arg(long)]
        text: String,
    },

    /// Pick up verified work and receive certificate (buyer, pays 3% fee).
    Pickup {
        #[arg(long)]
        id: String,
    },

    /// Request a refund (buyer, before acceptance or after expiry).
    Refund {
        #[arg(long)]
        id: String,
    },

    /// Verify a contract's witness proof is live (not spent/burned).
    Check {
        #[arg(long)]
        id: String,
    },
}

// ── Certificate ───────────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum CertCmd {
    /// List all certificates in the wallet
    List,
    /// Print one certificate as JSON
    Get { id: String },
    /// Insert a received certificate by its witness secret
    Insert {
        /// Witness secret: `n:{cert_id}:secret:{hex64}`
        secret: String,
    },
    /// Verify a certificate's witness proof is live
    Check { id: String },
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let wallet_path = resolve_wallet_path(cli.wallet.clone());
    let api = cli.api.as_str();
    let direct = cli.direct;

    match cli.command {
        // ── setup ─────────────────────────────────────────────────────────────
        Cmd::Setup { secret } => {
            if wallet_path.exists() {
                println!("Wallet already exists at {}", wallet_path.display());
                return Ok(());
            }
            let wallet = RgbWallet::create(&wallet_path).context("failed to create wallet")?;
            if let Some(hex) = secret {
                let id = Identity::from_hex(&hex).context("invalid private key hex")?;
                wallet.import_snapshot(&harmoniis_wallet::wallet::WalletSnapshot {
                    private_key_hex: id.private_key_hex(),
                    nickname: None,
                    contracts: vec![],
                    certificates: vec![],
                })?;
                println!("Wallet imported from key.");
                println!("Fingerprint: {}", id.fingerprint());
            } else {
                println!("Wallet created at {}", wallet_path.display());
                println!("Fingerprint: {}", wallet.fingerprint()?);
            }
        }

        // ── info ──────────────────────────────────────────────────────────────
        Cmd::Info => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let identity = wallet.identity()?;
            let webcash_wallet = open_webcash_wallet(&wallet_path, &identity).await?;
            let webcash_balance = webcash_wallet
                .balance()
                .await
                .unwrap_or_else(|_| "0".to_string());
            let webcash_stats = webcash_wallet.stats().await.ok();
            println!("Fingerprint:   {}", wallet.fingerprint()?);
            match wallet.nickname()? {
                Some(nick) => println!("Nickname:      {nick}"),
                None => println!("Nickname:      (not registered)"),
            }
            let contracts = wallet.list_contracts()?;
            let held = contracts
                .iter()
                .filter(|c| c.witness_secret.is_some())
                .count();
            println!("Contracts:     {} ({} held)", contracts.len(), held);
            println!("Certificates:  {}", wallet.list_certificates()?.len());
            if let Some(stats) = webcash_stats {
                println!(
                    "Webcash:       {} ({} outputs)",
                    webcash_balance, stats.unspent_webcash
                );
            } else {
                println!("Webcash:       {webcash_balance}");
            }
            println!(
                "API:           {} ({})",
                api,
                if direct { "direct" } else { "proxy" }
            );
        }

        // ── donation claim ────────────────────────────────────────────────────
        Cmd::Donation(DonationCmd::Claim) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let id = wallet.identity()?;
            let resp = make_client(api, direct)
                .claim_donation(&DonationClaimRequest {
                    pgp_public_key: id.public_key_hex(),
                    signature: id.sign("donation-request"),
                })
                .await?;
            match resp.status.as_str() {
                "donated" => {
                    if let Some(secret) = resp.webcash_secret {
                        let webcash_wallet = open_webcash_wallet(&wallet_path, &id).await?;
                        let parsed = SecretWebcash::parse(&secret)
                            .map_err(|e| anyhow::anyhow!("invalid donated webcash format: {e}"))?;
                        webcash_wallet
                            .insert(parsed)
                            .await
                            .context("failed to insert donated webcash into wallet")?;
                        println!("Donation claimed.");
                        println!(
                            "Inserted into wallet: {}",
                            default_webcash_wallet_path(&wallet_path).display()
                        );
                    } else {
                        anyhow::bail!("donation response missing webcash_secret");
                    }
                }
                "no_donation" => {
                    println!(
                        "{}",
                        resp.message
                            .unwrap_or_else(|| "No donation available yet.".to_string())
                    );
                }
                other => {
                    anyhow::bail!(
                        "unexpected donation status '{other}': {}",
                        serde_json::to_string(&resp)?
                    );
                }
            }
        }

        // ── webcash ───────────────────────────────────────────────────────────
        Cmd::Webcash(WebcashCmd::Info) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let identity = wallet.identity()?;
            let webcash_wallet = open_webcash_wallet(&wallet_path, &identity).await?;
            let balance = webcash_wallet.balance().await?;
            let stats = webcash_wallet.stats().await?;
            println!(
                "Webcash wallet: {}",
                default_webcash_wallet_path(&wallet_path).display()
            );
            println!("Balance:        {}", balance);
            println!("Unspent:        {}", stats.unspent_webcash);
            println!("Total outputs:  {}", stats.total_webcash);
            println!("Spent outputs:  {}", stats.spent_webcash);
        }

        Cmd::Webcash(WebcashCmd::Insert { secret }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let identity = wallet.identity()?;
            let webcash_wallet = open_webcash_wallet(&wallet_path, &identity).await?;
            let parsed = SecretWebcash::parse(&secret)
                .map_err(|e| anyhow::anyhow!("invalid webcash secret format: {e}"))?;
            webcash_wallet
                .insert(parsed)
                .await
                .context("failed to insert webcash")?;
            let balance = webcash_wallet.balance().await?;
            println!(
                "Inserted webcash into {}",
                default_webcash_wallet_path(&wallet_path).display()
            );
            println!("Balance: {balance}");
        }

        Cmd::Webcash(WebcashCmd::Pay { amount, memo }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let identity = wallet.identity()?;
            let webcash_wallet = open_webcash_wallet(&wallet_path, &identity).await?;
            let parsed_amount = WebcashAmount::from_str(&amount)
                .with_context(|| format!("invalid webcash amount '{amount}'"))?;
            let output = webcash_wallet
                .pay(parsed_amount, &memo)
                .await
                .context("failed to create payment")?;
            let token = extract_webcash_secret(&output)?;
            println!("Payment token:");
            println!("{token}");
        }

        Cmd::Webcash(WebcashCmd::Check) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let identity = wallet.identity()?;
            let webcash_wallet = open_webcash_wallet(&wallet_path, &identity).await?;
            webcash_wallet
                .check()
                .await
                .context("webcash check failed")?;
            println!("Webcash check passed.");
        }

        Cmd::Webcash(WebcashCmd::Recover { gap_limit }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let identity = wallet.identity()?;
            let webcash_wallet = open_webcash_wallet(&wallet_path, &identity).await?;
            let summary = webcash_wallet
                .recover_from_wallet(gap_limit)
                .await
                .context("webcash recovery failed")?;
            println!("{summary}");
        }

        Cmd::Webcash(WebcashCmd::Merge { group }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let identity = wallet.identity()?;
            let webcash_wallet = open_webcash_wallet(&wallet_path, &identity).await?;
            let summary = webcash_wallet
                .merge(group)
                .await
                .context("webcash merge failed")?;
            println!("{summary}");
        }

        // ── identity register ─────────────────────────────────────────────────
        Cmd::Identity(IdentityCmd::Register { nick, about }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let id = wallet.identity()?;
            let client = make_client(api, direct);
            let req = RegisterRequest {
                nickname: nick.clone(),
                pgp_public_key: id.public_key_hex(),
                signature: id.sign(&format!("register:{nick}")),
                about,
            };
            let preflight = client.register_identity(&req, "").await;
            let fp = match preflight {
                Ok(fp) => fp,
                Err(err) => {
                    let err = anyhow::Error::from(err);
                    let required =
                        required_amount_from_api_error(&err).unwrap_or_else(|| "0.6".to_string());
                    let payment =
                        pay_from_wallet(&wallet_path, &id, &required, "identity register").await?;
                    client
                        .register_identity(&req, &payment)
                        .await
                        .map_err(anyhow::Error::from)?
                }
            };
            wallet.set_nickname(&nick)?;
            println!("Registered as '{nick}'. Fingerprint: {fp}");
        }

        // ── timeline post ─────────────────────────────────────────────────────
        Cmd::Timeline(TimelineCmd::Post {
            content,
            post_type,
            keywords,
            tags,
            service_terms,
            price_min,
            price_max,
            currency,
            category,
            location,
            location_country,
            remote_ok,
            billing_model,
            billing_cycle,
            invoice_rule,
            unit_label,
            terms_file,
            descriptor_file,
            attachment_files,
        }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let id = wallet.identity()?;
            let fp = id.fingerprint();
            let nick = wallet.nickname()?.ok_or_else(|| {
                anyhow::anyhow!("nickname not set; run 'hrmw identity register' first")
            })?;
            let normalized_post_type = post_type.to_lowercase();
            let attachments = build_post_attachments(
                &normalized_post_type,
                &content,
                terms_file,
                descriptor_file,
                attachment_files,
            )?;
            let activity_metadata = build_activity_metadata(
                &normalized_post_type,
                category,
                location,
                location_country,
                remote_ok,
                service_terms,
                tags,
                price_min,
                price_max,
                currency,
                billing_model,
                billing_cycle,
                invoice_rule,
                unit_label,
            )?;
            let client = make_client(api, direct);
            let req = PublishPostRequest {
                author_fingerprint: fp,
                author_nick: nick,
                content: content.clone(),
                post_type: normalized_post_type,
                witness_proof: None,
                contract_id: None,
                parent_id: None,
                keywords: parse_keywords_csv(keywords.as_deref()),
                attachments,
                activity_metadata,
                signature: id.sign(&format!("post:{content}")),
            };
            let post_id = match client.publish_post(&req, "").await {
                Ok(post_id) => post_id,
                Err(err) => {
                    let err = anyhow::Error::from(err);
                    let required =
                        required_amount_from_api_error(&err).unwrap_or_else(|| "0.3".to_string());
                    let payment =
                        pay_from_wallet(&wallet_path, &id, &required, "timeline post").await?;
                    client
                        .publish_post(&req, &payment)
                        .await
                        .map_err(anyhow::Error::from)?
                }
            };
            println!("Post published: {post_id}");
        }

        // ── timeline comment ──────────────────────────────────────────────────
        Cmd::Timeline(TimelineCmd::Comment { post, content }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let id = wallet.identity()?;
            let fp = id.fingerprint();
            let nick = wallet.nickname()?.ok_or_else(|| {
                anyhow::anyhow!("nickname not set; run 'hrmw identity register' first")
            })?;
            let client = make_client(api, direct);
            let req = PublishPostRequest {
                author_fingerprint: fp,
                author_nick: nick,
                content: content.clone(),
                post_type: "comment".to_string(),
                witness_proof: None,
                contract_id: None,
                parent_id: Some(post),
                keywords: vec!["comment".to_string()],
                attachments: vec![PostAttachment {
                    filename: "comment.md".to_string(),
                    content: format!("# Comment\n\n{}", content),
                    attachment_type: "text/markdown".to_string(),
                }],
                activity_metadata: None,
                signature: id.sign(&format!("post:{content}")),
            };
            let comment_id = match client.publish_post(&req, "").await {
                Ok(comment_id) => comment_id,
                Err(err) => {
                    let err = anyhow::Error::from(err);
                    let required =
                        required_amount_from_api_error(&err).unwrap_or_else(|| "0.01".to_string());
                    let payment =
                        pay_from_wallet(&wallet_path, &id, &required, "timeline comment").await?;
                    client
                        .publish_post(&req, &payment)
                        .await
                        .map_err(anyhow::Error::from)?
                }
            };
            println!("Comment published: {comment_id}");
        }

        // ── timeline rate ─────────────────────────────────────────────────────
        Cmd::Timeline(TimelineCmd::Rate { post, vote }) => {
            let vote = vote.to_lowercase();
            if vote != "up" && vote != "down" {
                anyhow::bail!("vote must be 'up' or 'down'");
            }
            let wallet = open_or_create_wallet(&wallet_path)?;
            let id = wallet.identity()?;
            let client = make_client(api, direct);
            let req = RatePostRequest {
                post_id: post.clone(),
                actor_fingerprint: id.fingerprint(),
                vote: vote.clone(),
                signature: id.sign(&format!("vote:{post}:{vote}")),
            };
            if let Err(err) = client.rate_post(&req, "").await {
                let err = anyhow::Error::from(err);
                let required =
                    required_amount_from_api_error(&err).unwrap_or_else(|| "0.001".to_string());
                let payment =
                    pay_from_wallet(&wallet_path, &id, &required, "timeline rate").await?;
                client
                    .rate_post(&req, &payment)
                    .await
                    .map_err(anyhow::Error::from)?;
            }
            println!("Rated post {post}: {vote}");
        }

        // ── contract list ─────────────────────────────────────────────────────
        Cmd::Contract(ContractCmd::List) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let contracts = wallet.list_contracts()?;
            if contracts.is_empty() {
                println!("No contracts.");
            } else {
                println!(
                    "{:<26} {:>9} {:>6} {:>4}  {}",
                    "id", "status", "role", "held", "description"
                );
                println!("{}", "─".repeat(80));
                for c in &contracts {
                    let held = if c.witness_secret.is_some() {
                        "✓"
                    } else {
                        "·"
                    };
                    println!(
                        "{:<26} {:>9} {:>6} {:>4}  {}",
                        c.contract_id,
                        c.status.as_str(),
                        c.role.as_str(),
                        held,
                        c.work_spec.chars().take(40).collect::<String>(),
                    );
                }
            }
        }

        // ── contract get ──────────────────────────────────────────────────────
        Cmd::Contract(ContractCmd::Get { id }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            match wallet.get_contract(&id)? {
                Some(c) => println!("{}", serde_json::to_string_pretty(&c)?),
                None => println!("Contract not found: {id}"),
            }
        }

        // ── contract insert ───────────────────────────────────────────────────
        // The core "receive" command — seller (or buyer receiving a refunded contract)
        // uses this to take custody of a witness secret they received out-of-band.
        Cmd::Contract(ContractCmd::Insert { secret, desc, role }) => {
            let witness_secret = WitnessSecret::parse(&secret).context(
                "invalid witness secret format — expected n:{contract_id}:secret:{hex64}",
            )?;
            let contract_id = witness_secret.contract_id().to_string();
            let proof = witness_secret.public_proof();

            // Verify it's live with the Witness before storing
            let client = make_client(api, direct);
            let is_live = client
                .witness_is_live(&proof)
                .await
                .context("witness health check failed")?;
            if !is_live {
                anyhow::bail!(
                    "secret is not live — already spent or contract ended.\n\
                     Proof: {}",
                    proof.display()
                );
            }

            let wallet = open_or_create_wallet(&wallet_path)?;
            let fp = wallet.fingerprint()?;
            let parsed_role = Role::parse(&role).unwrap_or(Role::Seller);

            // If the contract already exists in the wallet, update it
            if let Some(mut existing) = wallet.get_contract(&contract_id)? {
                existing.witness_secret = Some(witness_secret.display());
                existing.witness_proof = Some(proof.display());
                existing.updated_at = now_utc();
                if !desc.is_empty() {
                    existing.work_spec = desc;
                }
                wallet.update_contract(&existing)?;
                println!("Updated existing contract: {contract_id}");
            } else {
                let mut c = Contract::new(
                    contract_id.clone(),
                    ContractType::Service,
                    0,
                    if desc.is_empty() {
                        contract_id.clone()
                    } else {
                        desc
                    },
                    fp.clone(),
                    parsed_role,
                );
                c.buyer_fingerprint = fp;
                c.witness_secret = Some(witness_secret.display());
                c.witness_proof = Some(proof.display());
                c.status = ContractStatus::Active;
                wallet.store_contract(&c)?;
                println!("Inserted contract: {contract_id}");
            }
            println!("Proof:    {}", proof.display());
            println!("Status:   live ✓");
        }

        // ── contract buy ──────────────────────────────────────────────────────
        Cmd::Contract(ContractCmd::Buy {
            post,
            amount,
            r#type,
            contract_id,
        }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let id = wallet.identity()?;
            let fp = id.fingerprint();
            let client = make_client(api, direct);

            let local_contract_id = contract_id.unwrap_or_else(next_contract_id);
            let witness_secret = WitnessSecret::generate(&local_contract_id);
            let witness_proof = witness_secret.public_proof();

            let seller_fingerprint = client.get_post(&post).await.ok().and_then(|v| {
                v.get("post")
                    .and_then(|p| p.get("author_fingerprint"))
                    .and_then(|s| s.as_str())
                    .map(ToString::to_string)
            });
            let seller_public_key = match seller_fingerprint.as_deref() {
                Some(seller_fp) => client.get_profile(seller_fp).await.ok().and_then(|v| {
                    v.get("profile")
                        .and_then(|p| p.get("pub_key"))
                        .and_then(|s| s.as_str())
                        .map(ToString::to_string)
                }),
                None => None,
            };

            let (encrypted_witness_secret, witness_zkp) = build_witness_commitment(
                &witness_secret,
                &witness_proof,
                &fp,
                seller_fingerprint.as_deref(),
                seller_public_key.as_deref(),
                |msg| id.sign(msg),
            );

            let sig = id.sign(&format!(
                "buy_contract:{}:{}:{}:{}",
                fp,
                post,
                local_contract_id,
                witness_proof.display()
            ));

            let req = BuyRequest {
                buyer_fingerprint: fp.clone(),
                buyer_public_key: id.public_key_hex(),
                contract_type: r#type.clone(),
                amount: amount.clone(),
                contract_id: local_contract_id.clone(),
                witness_proof: witness_proof.display(),
                encrypted_witness_secret,
                witness_zkp,
                reference_post: post.clone(),
                signature: sig,
            };
            let buy_response = match client.buy_contract(&req, "").await {
                Ok(v) => v,
                Err(err) => {
                    let err = anyhow::Error::from(err);
                    let required =
                        required_amount_from_api_error(&err).unwrap_or_else(|| "0.5".to_string());
                    let payment =
                        pay_from_wallet(&wallet_path, &id, &required, "contract buy").await?;
                    client
                        .buy_contract(&req, &payment)
                        .await
                        .map_err(anyhow::Error::from)?
                }
            };

            let contract_id = buy_response
                .get("contract_id")
                .and_then(|v| v.as_str())
                .map(ToString::to_string)
                .unwrap_or(local_contract_id);

            let contract_view = client.get_contract(&contract_id).await.unwrap_or_default();
            let amount_units = contract_view
                .get("amount")
                .and_then(|v| {
                    v.as_u64()
                        .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
                })
                .unwrap_or_else(|| parse_amount_to_units(&amount));
            let work_spec = contract_view
                .get("work_spec")
                .and_then(|v| v.as_str())
                .unwrap_or("Contract deliverable")
                .to_string();
            let final_contract_type = contract_view
                .get("contract_type")
                .and_then(|v| v.as_str())
                .unwrap_or(&r#type)
                .to_string();
            let final_deadline = contract_view
                .get("delivery_deadline")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let final_seller = buy_response
                .get("target_seller_fingerprint")
                .and_then(|v| v.as_str())
                .map(ToString::to_string)
                .or_else(|| {
                    contract_view
                        .get("target_seller_fingerprint")
                        .and_then(|v| v.as_str())
                        .map(ToString::to_string)
                });

            if let (Some(arbiter_sig), Some(deadline), Some(reference_post)) = (
                buy_response
                    .get("arbiter_signature")
                    .and_then(|v| v.as_str()),
                final_deadline.as_deref(),
                contract_view.get("reference_post").and_then(|v| v.as_str()),
            ) {
                let ok = client
                    .verify_contract_signature(
                        &contract_id,
                        &fp,
                        amount_units,
                        deadline,
                        &final_contract_type,
                        &work_spec,
                        reference_post,
                        &id.public_key_hex(),
                        arbiter_sig,
                    )
                    .await
                    .unwrap_or(false);
                if !ok {
                    anyhow::bail!(
                        "arbiter signature verification failed for bought contract {contract_id}"
                    );
                }
            }

            let mut contract = Contract::new(
                contract_id.clone(),
                ContractType::parse(&final_contract_type).unwrap_or(ContractType::Service),
                amount_units,
                work_spec,
                fp.clone(),
                Role::Buyer,
            );
            contract.witness_secret = Some(witness_secret.display());
            contract.witness_proof = Some(witness_proof.display());
            contract.reference_post = Some(post);
            contract.delivery_deadline = final_deadline;
            contract.seller_fingerprint = final_seller;
            wallet.store_contract(&contract)?;

            println!("Contract:  {contract_id}");
            println!("Proof:     {}", witness_proof.display());
            println!("(secret stored in wallet — use 'contract bid' to bid on seller's post)");
        }

        // ── contract bid ──────────────────────────────────────────────────────
        Cmd::Contract(ContractCmd::Bid {
            post,
            contract,
            content,
        }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let id = wallet.identity()?;
            let fp = id.fingerprint();
            let c = wallet
                .get_contract(&contract)?
                .ok_or_else(|| anyhow::anyhow!("contract {contract} not in wallet"))?;
            let proof_str = c
                .witness_proof
                .ok_or_else(|| anyhow::anyhow!("contract has no witness proof"))?;

            let bid_content = if content.is_empty() {
                format!("Bid on contract {contract}")
            } else {
                content
            };
            let sig = id.sign(&format!("post:{bid_content}"));
            let nick = wallet.nickname()?.unwrap_or_default();

            // Only the PUBLIC PROOF is published — the secret remains in wallet
            let req = PublishPostRequest {
                author_fingerprint: fp,
                author_nick: nick,
                content: bid_content,
                post_type: "bid".to_string(),
                witness_proof: Some(proof_str),
                contract_id: Some(contract),
                parent_id: Some(post),
                keywords: vec!["bid".to_string()],
                attachments: vec![PostAttachment {
                    filename: "bid.md".to_string(),
                    content: "Bid commitment details".to_string(),
                    attachment_type: "text/markdown".to_string(),
                }],
                activity_metadata: None,
                signature: sig,
            };
            let client = make_client(api, direct);
            let post_id = match client.publish_post(&req, "").await {
                Ok(post_id) => post_id,
                Err(err) => {
                    let err = anyhow::Error::from(err);
                    let required =
                        required_amount_from_api_error(&err).unwrap_or_else(|| "0.01".to_string());
                    let payment =
                        pay_from_wallet(&wallet_path, &id, &required, "contract bid").await?;
                    client
                        .publish_post(&req, &payment)
                        .await
                        .map_err(anyhow::Error::from)?
                }
            };
            println!("Bid posted: {post_id}");
        }

        // ── contract accept ───────────────────────────────────────────────────
        Cmd::Contract(ContractCmd::Accept { id }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let identity = wallet.identity()?;
            let fp = identity.fingerprint();
            let sig = identity.sign(&format!("accept:{id}:{fp}"));

            make_client(api, direct)
                .accept_contract(&id, &fp, &sig)
                .await?;

            if let Some(mut c) = wallet.get_contract(&id)? {
                c.status = ContractStatus::Active;
                c.updated_at = now_utc();
                wallet.update_contract(&c)?;
            }
            println!("Bid accepted. Contract {id} is now active.");
            println!("Buyer should now run:  hrmw contract replace --id {id}");
        }

        // ── contract replace ──────────────────────────────────────────────────
        // RGB21 bearer handover: buyer calls witness/replace, prints new secret
        // for out-of-band delivery to the seller.
        // Seller then runs: hrmw contract insert '<secret>'
        Cmd::Contract(ContractCmd::Replace { id }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let mut contract = wallet
                .get_contract(&id)?
                .ok_or_else(|| anyhow::anyhow!("contract {id} not in wallet"))?;

            let old_secret_str = contract.witness_secret.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "no witness secret in wallet for {id} — only the current holder can replace"
                )
            })?;
            let old_secret = WitnessSecret::parse(old_secret_str)?;

            // Generate a fresh secret the receiver will hold
            let new_secret = WitnessSecret::generate(&id);
            let new_proof = new_secret.public_proof();

            make_client(api, direct)
                .witness_replace(&old_secret, &new_secret)
                .await?;

            // Clear secret from wallet — we no longer hold it
            contract.witness_secret = None;
            contract.witness_proof = Some(new_proof.display());
            contract.updated_at = now_utc();
            wallet.update_contract(&contract)?;

            // Print the new secret for out-of-band delivery
            println!("Replaced. Deliver this secret to the receiver OUT-OF-BAND:");
            println!();
            println!("  {}", new_secret.display());
            println!();
            println!(
                "Receiver runs:  hrmw contract insert '{}'",
                new_secret.display()
            );
            println!();
            println!("⚠ Never post this secret on the timeline or any public channel.");
            println!("  Your wallet no longer holds the secret — proof updated.");
        }

        // ── contract deliver ──────────────────────────────────────────────────
        Cmd::Contract(ContractCmd::Deliver { id, text }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let identity = wallet.identity()?;
            let fp = identity.fingerprint();
            let contract = wallet
                .get_contract(&id)?
                .ok_or_else(|| anyhow::anyhow!("contract {id} not in wallet"))?;
            let secret_str = contract.witness_secret.ok_or_else(|| {
                anyhow::anyhow!(
                    "no witness secret in wallet for {id} — receive it with 'contract insert' first"
                )
            })?;

            let sig = identity.sign(&format!("deliver:{id}:{text}"));
            let resp = make_client(api, direct)
                .deliver(&id, &secret_str, &text, &fp, &sig)
                .await?;

            if let Some(mut c) = wallet.get_contract(&id)? {
                c.status = ContractStatus::Delivered;
                c.delivered_text = Some(text);
                c.updated_at = now_utc();
                wallet.update_contract(&c)?;
            }
            println!("Delivered. Arbitration verdict:");
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        // ── contract pickup ───────────────────────────────────────────────────
        Cmd::Contract(ContractCmd::Pickup { id }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let identity = wallet.identity()?;
            let fp = identity.fingerprint();
            let sig = identity.sign(&id);
            let client = make_client(api, direct);
            let resp = match client.pickup(&id, &fp, &sig, "").await {
                Ok(v) => v,
                Err(err) => {
                    let err = anyhow::Error::from(err);
                    let required =
                        required_amount_from_api_error(&err).unwrap_or_else(|| "0.015".to_string());
                    let payment =
                        pay_from_wallet(&wallet_path, &identity, &required, "contract pickup")
                            .await?;
                    client
                        .pickup(&id, &fp, &sig, &payment)
                        .await
                        .map_err(anyhow::Error::from)?
                }
            };

            if let Some(mut c) = wallet.get_contract(&id)? {
                c.status = ContractStatus::Burned;
                c.updated_at = now_utc();
                if let Some(cert_id) = resp.get("certificate_id").and_then(|v| v.as_str()) {
                    c.certificate_id = Some(cert_id.to_string());
                    wallet.store_certificate(&Certificate {
                        certificate_id: cert_id.to_string(),
                        contract_id: Some(id.clone()),
                        witness_secret: resp
                            .get("certificate_secret")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        witness_proof: resp
                            .get("certificate_proof")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        created_at: now_utc(),
                    })?;
                    println!("Certificate stored: {cert_id}");
                }
                wallet.update_contract(&c)?;
            }
            println!("Picked up. Contract ended.");
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        // ── contract refund ───────────────────────────────────────────────────
        Cmd::Contract(ContractCmd::Refund { id }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let identity = wallet.identity()?;
            let fp = identity.fingerprint();
            let contract = wallet
                .get_contract(&id)?
                .ok_or_else(|| anyhow::anyhow!("contract {id} not in wallet"))?;
            let secret_str = contract.witness_secret.ok_or_else(|| {
                anyhow::anyhow!(
                    "no witness secret in wallet for {id} — must hold current secret to refund"
                )
            })?;

            let sig = identity.sign(&format!("REFUND:{id}"));
            make_client(api, direct)
                .refund(&id, &fp, Some(&secret_str), &sig)
                .await?;

            if let Some(mut c) = wallet.get_contract(&id)? {
                c.status = ContractStatus::Refunded;
                c.witness_secret = None;
                c.updated_at = now_utc();
                wallet.update_contract(&c)?;
            }
            println!("Refund requested for: {id}");
        }

        // ── contract check ────────────────────────────────────────────────────
        Cmd::Contract(ContractCmd::Check { id }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let contract = wallet
                .get_contract(&id)?
                .ok_or_else(|| anyhow::anyhow!("contract {id} not in wallet"))?;
            let proof_str = contract
                .witness_proof
                .ok_or_else(|| anyhow::anyhow!("no witness proof in wallet for {id}"))?;
            let result = make_client(api, direct).witness_check(&[proof_str]).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }

        // ── certificate list ──────────────────────────────────────────────────
        Cmd::Certificate(CertCmd::List) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let certs = wallet.list_certificates()?;
            if certs.is_empty() {
                println!("No certificates.");
            } else {
                println!("{:<26} {:>4}  {}", "certificate_id", "held", "contract_id");
                println!("{}", "─".repeat(70));
                for cert in &certs {
                    let held = if cert.witness_secret.is_some() {
                        "✓"
                    } else {
                        "·"
                    };
                    println!(
                        "{:<26} {:>4}  {}",
                        cert.certificate_id,
                        held,
                        cert.contract_id.as_deref().unwrap_or("—"),
                    );
                }
            }
        }

        // ── certificate get ───────────────────────────────────────────────────
        Cmd::Certificate(CertCmd::Get { id }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let certs = wallet.list_certificates()?;
            match certs.iter().find(|c| c.certificate_id == id) {
                Some(c) => println!("{}", serde_json::to_string_pretty(c)?),
                None => println!("Certificate not found: {id}"),
            }
        }

        // ── certificate insert ────────────────────────────────────────────────
        Cmd::Certificate(CertCmd::Insert { secret }) => {
            let witness_secret = WitnessSecret::parse(&secret)
                .context("invalid witness secret — expected n:{cert_id}:secret:{hex64}")?;
            let cert_id = witness_secret.contract_id().to_string();
            let proof = witness_secret.public_proof();

            let client = make_client(api, direct);
            let is_live = client
                .witness_is_live(&proof)
                .await
                .context("witness health check failed")?;
            if !is_live {
                anyhow::bail!("certificate secret is not live — already spent or burned");
            }

            let wallet = open_or_create_wallet(&wallet_path)?;
            wallet.store_certificate(&Certificate {
                certificate_id: cert_id.clone(),
                contract_id: None,
                witness_secret: Some(witness_secret.display()),
                witness_proof: Some(proof.display()),
                created_at: now_utc(),
            })?;
            println!("Certificate inserted: {cert_id}");
            println!("Proof: {}", proof.display());
        }

        // ── certificate check ─────────────────────────────────────────────────
        Cmd::Certificate(CertCmd::Check { id }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let certs = wallet.list_certificates()?;
            let cert = certs
                .iter()
                .find(|c| c.certificate_id == id)
                .ok_or_else(|| anyhow::anyhow!("certificate {id} not in wallet"))?;
            let proof_str = cert
                .witness_proof
                .clone()
                .ok_or_else(|| anyhow::anyhow!("no proof for certificate {id}"))?;
            let result = make_client(api, direct).witness_check(&[proof_str]).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
    }

    Ok(())
}
