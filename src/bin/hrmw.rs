//! `hrmw` — Harmoniis RGB wallet CLI.
//!
//! Manages RGB21 bearer contracts and certificates via the Harmoniis Witness.
//!
//! Mental model (mirrors Webcash):
//!   insert  → take custody of a contract you received (like `webyc insert`)
//!   replace → transfer a contract to another party  (like `webyc pay`)
//!   list    → show all contracts/certificates in wallet
//!   check   → verify a contract is still live with the Witness

use std::path::PathBuf;
use std::str::FromStr;
use std::{fs, io::Write};

use anyhow::Context;
use bdk_wallet::bitcoin::Network;
use clap::{Parser, Subcommand, ValueEnum};
use harmoniis_wallet::{
    bitcoin::{BitcoinAddressKind, DeterministicBitcoinWallet},
    client::{
        arbitration::{build_witness_commitment, decrypt_witness_secret_envelope, BuyRequest},
        recovery::{RecoveryProbe, RecoveryScanRequest},
        timeline::{
            DeletePostRequest, DonationClaimRequest, PostAttachment, PublishPostRequest,
            RatePostRequest, RegisterRequest, StoragePresignRequest, UpdatePostRequest,
        },
        PaymentSecret,
    },
    types::{Certificate, Contract, ContractStatus, ContractType, Role, WitnessSecret},
    wallet::RgbWallet,
    Identity,
};
use rand::Rng;
use webylib::{Amount as WebcashAmount, SecretWebcash};

#[path = "hrmw/hrmw_support.rs"]
mod hrmw_support;
#[path = "hrmw/media.rs"]
mod media;
use hrmw_support::{
    build_activity_metadata, build_post_attachments, default_webcash_wallet_path,
    extract_webcash_token, format_units_to_amount, make_client, next_contract_id, now_utc,
    open_or_create_wallet, open_webcash_wallet, parse_amount_to_units, parse_keywords_csv,
    pay_from_wallet, required_amount_for_payment_retry, resolve_wallet_path,
};
use media::{prepare_avatar_image, prepare_post_image};

const DEFAULT_API_URL: &str = "https://harmoniis.com/api";

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum PaymentRail {
    Webcash,
    Bitcoin,
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

    /// Payment rail for paid API actions.
    #[arg(long, global = true, value_enum, default_value_t = PaymentRail::Webcash)]
    payment_rail: PaymentRail,

    /// Bitcoin/ARK secret header value used when --payment-rail bitcoin.
    #[arg(long, global = true)]
    bitcoin_secret: Option<String>,

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

    /// Deterministic Bitcoin/Taproot wallet operations
    #[command(subcommand)]
    Bitcoin(BitcoinCmd),

    /// Identity operations
    #[command(subcommand)]
    Identity(IdentityCmd),

    /// Profile operations
    #[command(subcommand)]
    Profile(ProfileCmd),

    /// Timeline operations (post/comment/rate)
    #[command(subcommand)]
    Timeline(TimelineCmd),

    /// Contract lifecycle
    #[command(subcommand)]
    Contract(ContractCmd),

    /// Certificate operations
    #[command(subcommand)]
    Certificate(CertCmd),

    /// Root key backup and restore
    #[command(subcommand)]
    Key(KeyCmd),

    /// Deterministic wallet reconstruction
    #[command(subcommand)]
    Recover(RecoverCmd),

    /// Webcash mining
    #[command(subcommand)]
    Webminer(WebminerCmd),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum BitcoinNetworkArg {
    Bitcoin,
    Testnet,
    Testnet4,
    Signet,
    Regtest,
}

impl From<BitcoinNetworkArg> for Network {
    fn from(value: BitcoinNetworkArg) -> Self {
        match value {
            BitcoinNetworkArg::Bitcoin => Network::Bitcoin,
            BitcoinNetworkArg::Testnet => Network::Testnet,
            BitcoinNetworkArg::Testnet4 => Network::Testnet4,
            BitcoinNetworkArg::Signet => Network::Signet,
            BitcoinNetworkArg::Regtest => Network::Regtest,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum BitcoinAddressKindArg {
    Taproot,
    Segwit,
}

impl From<BitcoinAddressKindArg> for BitcoinAddressKind {
    fn from(value: BitcoinAddressKindArg) -> Self {
        match value {
            BitcoinAddressKindArg::Taproot => BitcoinAddressKind::Taproot,
            BitcoinAddressKindArg::Segwit => BitcoinAddressKind::Segwit,
        }
    }
}

#[derive(Subcommand)]
enum BitcoinCmd {
    /// Show deterministic taproot/segwit wallet summary and optionally sync via Esplora
    Info {
        /// Bitcoin network
        #[arg(long, value_enum, default_value_t = BitcoinNetworkArg::Bitcoin)]
        network: BitcoinNetworkArg,
        /// Esplora base URL (defaults per network)
        #[arg(long)]
        esplora: Option<String>,
        /// Skip sync and only print deterministic descriptors/address
        #[arg(long, default_value_t = false)]
        no_sync: bool,
        /// Gap limit used for full scan
        #[arg(long, default_value_t = 20)]
        stop_gap: usize,
        /// Max parallel HTTP requests used during scan
        #[arg(long, default_value_t = 4)]
        parallel_requests: usize,
    },
    /// Show receive address at a deterministic index (`taproot` or `segwit`)
    Address {
        /// Bitcoin network
        #[arg(long, value_enum, default_value_t = BitcoinNetworkArg::Bitcoin)]
        network: BitcoinNetworkArg,
        /// Address kind (`taproot` preferred, `segwit` fallback)
        #[arg(long, value_enum, default_value_t = BitcoinAddressKindArg::Taproot)]
        kind: BitcoinAddressKindArg,
        /// Address index (external keychain)
        #[arg(long, default_value_t = 0)]
        index: u32,
    },
    /// Run explicit Esplora sync and print balances
    Sync {
        /// Bitcoin network
        #[arg(long, value_enum, default_value_t = BitcoinNetworkArg::Bitcoin)]
        network: BitcoinNetworkArg,
        /// Esplora base URL (defaults per network)
        #[arg(long)]
        esplora: Option<String>,
        /// Gap limit used for full scan
        #[arg(long, default_value_t = 20)]
        stop_gap: usize,
        /// Max parallel HTTP requests used during scan
        #[arg(long, default_value_t = 4)]
        parallel_requests: usize,
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
        /// Use a specific labeled PGP identity (defaults to active label)
        #[arg(long)]
        label: Option<String>,
    },
    /// Create a new labeled PGP identity derived from root key
    PgpNew {
        #[arg(long)]
        label: String,
        /// Set newly created identity as active
        #[arg(long, default_value_t = false)]
        active: bool,
    },
    /// List labeled PGP identities and active status
    PgpList,
    /// Set which PGP identity label is active
    PgpUse {
        #[arg(long)]
        label: String,
    },
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Export root master key
    Export {
        /// Output format: hex or mnemonic
        #[arg(long, default_value = "mnemonic")]
        format: KeyExportFormat,
        /// Optional file path to write the exported key
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Import root master key into this wallet
    Import {
        /// 64-char root key hex
        #[arg(long)]
        hex: Option<String>,
        /// BIP39 mnemonic phrase
        #[arg(long)]
        mnemonic: Option<String>,
        /// Allow import even when wallet has local contracts/certificates
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Show non-secret fingerprints for deterministic slots
    Fingerprint,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum KeyExportFormat {
    Hex,
    Mnemonic,
}

#[derive(Subcommand)]
enum RecoverCmd {
    /// Recover deterministic identities and contracts from root key + server scan
    Deterministic {
        /// First PGP slot index (inclusive)
        #[arg(long, default_value_t = 0)]
        pgp_start: u32,
        /// Last PGP slot index (inclusive, max 999)
        #[arg(long, default_value_t = 999)]
        pgp_end: u32,
        /// Harmoniis API batch size
        #[arg(long, default_value_t = 50)]
        batch_size: usize,
        /// Skip server scan and only ensure local deterministic slots
        #[arg(long, default_value_t = false)]
        no_server: bool,
    },
}

#[derive(Subcommand)]
enum ProfileCmd {
    /// Upload and set a profile picture (auto-cropped to square, max 1MB)
    SetPicture {
        /// Local image file path
        #[arg(long)]
        file: PathBuf,
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
        /// Optional image attachment path (repeatable). Images are resized/compressed to <= 1MB.
        #[arg(long = "image")]
        image_files: Vec<PathBuf>,
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

    /// Delete your own post/comment by signed author proof
    Delete {
        /// Target post ID
        #[arg(long)]
        post: String,
    },

    /// Update your own post/comment (author-signed)
    Update {
        /// Target post ID
        #[arg(long)]
        post: String,
        /// Updated content
        #[arg(long)]
        content: Option<String>,
        /// Optional comma-separated keywords replacement
        #[arg(long)]
        keywords: Option<String>,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum WebminerBackendArg {
    Auto,
    Gpu,
    Cpu,
}

impl From<WebminerBackendArg> for harmoniis_wallet::miner::BackendChoice {
    fn from(value: WebminerBackendArg) -> Self {
        use harmoniis_wallet::miner::BackendChoice;
        match value {
            WebminerBackendArg::Auto => BackendChoice::Auto,
            WebminerBackendArg::Gpu => BackendChoice::Gpu,
            WebminerBackendArg::Cpu => BackendChoice::Cpu,
        }
    }
}

#[derive(Subcommand)]
enum WebminerCmd {
    /// Start mining in the background
    Start {
        /// Webcash server URL
        #[arg(long, default_value = "https://webcash.tech")]
        server: String,
        /// Maximum difficulty to mine at
        #[arg(long, default_value_t = 80)]
        max_difficulty: u32,
        /// Mining backend policy
        #[arg(long, value_enum, default_value_t = WebminerBackendArg::Auto)]
        backend: WebminerBackendArg,
        /// Force CPU-only mining (skip GPU detection)
        #[arg(long)]
        cpu_only: bool,
        /// Limit CPU worker threads (used by CPU backend)
        #[arg(long)]
        cpu_threads: Option<usize>,
        /// Accept the Webcash terms of service
        #[arg(long)]
        accept_terms: bool,
    },
    /// Stop the running miner
    Stop,
    /// Show miner status and statistics
    Status,
    /// Benchmark local mining backends (CPU -> GPU)
    Bench {
        /// Limit CPU worker threads (used by CPU benchmark)
        #[arg(long)]
        cpu_threads: Option<usize>,
        /// Minimum expected CPU speed (Mh/s) for pass/fail reporting
        #[arg(long, default_value_t = 90.0)]
        cpu_target_mhs: f64,
        /// Minimum expected GPU speed (Mh/s) for pass/fail reporting
        #[arg(long, default_value_t = 320.0)]
        gpu_target_mhs: f64,
        /// Exit non-zero when a target is missed
        #[arg(long)]
        strict: bool,
    },
    /// Run miner in foreground with live logs
    Run {
        /// Webcash server URL
        #[arg(long, default_value = "https://webcash.tech")]
        server: String,
        /// Maximum difficulty to mine at
        #[arg(long, default_value_t = 80)]
        max_difficulty: u32,
        #[arg(long, value_enum, default_value_t = WebminerBackendArg::Auto)]
        backend: WebminerBackendArg,
        #[arg(long)]
        cpu_only: bool,
        #[arg(long)]
        cpu_threads: Option<usize>,
        #[arg(long)]
        accept_terms: bool,
        /// RGB wallet path (defaults to global --wallet / ~/.harmoniis/rgb.db)
        #[arg(long)]
        wallet: Option<PathBuf>,
        /// Webcash wallet path (defaults to sibling webcash wallet path)
        #[arg(long, name = "webcash-wallet")]
        webcash_wallet: Option<PathBuf>,
    },
}

fn benchmark_status_line(measured_mhs: f64, target_mhs: f64) -> &'static str {
    if measured_mhs >= target_mhs {
        "PASS"
    } else {
        "MISS"
    }
}

fn format_btc_from_sats(sats: u64) -> String {
    let whole = sats / 100_000_000;
    let frac = sats % 100_000_000;
    if frac == 0 {
        format!("{whole}")
    } else {
        format!("{whole}.{}", format!("{frac:08}").trim_end_matches('0'))
    }
}

fn resolved_esplora_url(network: Network, override_url: Option<String>) -> String {
    override_url
        .unwrap_or_else(|| DeterministicBitcoinWallet::default_esplora_url(network).to_string())
}

async fn run_webminer_benchmarks(
    cpu_threads: Option<usize>,
    cpu_target_mhs: f64,
    gpu_target_mhs: f64,
    strict: bool,
) -> anyhow::Result<()> {
    use harmoniis_wallet::miner::simd_cpu::SimdCpuMiner;
    use harmoniis_wallet::miner::MinerBackend;

    let mut failed = false;
    println!("Webminer benchmark plan: CPU -> GPU");
    println!("cpu_threads={:?}", cpu_threads);

    let cpu = SimdCpuMiner::from_option(cpu_threads);
    let cpu_mhs = cpu.benchmark().await? / 1_000_000.0;
    let cpu_status = benchmark_status_line(cpu_mhs, cpu_target_mhs);
    println!(
        "CPU: {:.2} Mh/s target={:.2} [{}]",
        cpu_mhs, cpu_target_mhs, cpu_status
    );
    for line in cpu.startup_summary() {
        println!("  {}", line);
    }
    if cpu_status == "MISS" {
        failed = true;
    }

    #[cfg(any(all(feature = "cuda", target_os = "linux"), feature = "gpu"))]
    {
        let mut gpu_reported = false;

        #[cfg(all(feature = "cuda", target_os = "linux"))]
        if !gpu_reported {
            use harmoniis_wallet::miner::multi_cuda::MultiCudaMiner;
            if let Some(cuda) = MultiCudaMiner::try_new().await {
                let gpu_hps = cuda.benchmark().await?;
                let gpu_mhs = gpu_hps / 1_000_000.0;
                let gpu_status = benchmark_status_line(gpu_mhs, gpu_target_mhs);
                println!(
                    "GPU: {:.2} Mh/s target={:.2} [{}] (CUDA)",
                    gpu_mhs, gpu_target_mhs, gpu_status
                );
                for line in cuda.startup_summary() {
                    println!("  {}", line);
                }
                if gpu_status == "MISS" {
                    failed = true;
                }
                gpu_reported = true;
            }
        }

        #[cfg(feature = "gpu")]
        if !gpu_reported {
            use harmoniis_wallet::miner::multi_gpu::MultiGpuMiner;
            if let Some(gpu) = MultiGpuMiner::try_new().await {
                let gpu_hps = gpu.benchmark().await?;
                let gpu_mhs = gpu_hps / 1_000_000.0;
                let gpu_status = benchmark_status_line(gpu_mhs, gpu_target_mhs);
                println!(
                    "GPU: {:.2} Mh/s target={:.2} [{}] (Vulkan/wgpu)",
                    gpu_mhs, gpu_target_mhs, gpu_status
                );
                for line in gpu.startup_summary() {
                    println!("  {}", line);
                }
                if gpu_status == "MISS" {
                    failed = true;
                }
                gpu_reported = true;
            }
        }

        if !gpu_reported {
            println!("GPU: unavailable [MISS]");
            failed = true;
        }
    }

    #[cfg(not(any(all(feature = "cuda", target_os = "linux"), feature = "gpu")))]
    {
        println!("GPU: feature-disabled [MISS]");
        failed = true;
    }

    if strict && failed {
        anyhow::bail!("benchmark targets not met");
    }
    Ok(())
}

async fn upload_post_images(
    client: &harmoniis_wallet::client::HarmoniisClient,
    identity: &Identity,
    fingerprint: &str,
    image_files: Vec<PathBuf>,
) -> anyhow::Result<Vec<PostAttachment>> {
    let mut out = Vec::new();
    for file in image_files {
        let prepared = prepare_post_image(&file)?;
        let now = chrono::Utc::now();
        let nonce: u16 = rand::thread_rng().gen_range(1000..9999);
        let storage_path = format!(
            "public/posts/{}-{}-{}",
            now.format("%Y%m%d%H%M%S"),
            nonce,
            prepared.filename
        );
        let signature = identity.sign(&format!("presign:{storage_path}"));
        let presign = client
            .storage_presign(&StoragePresignRequest {
                fingerprint: fingerprint.to_string(),
                file_path: storage_path,
                content_type: prepared.content_type.clone(),
                is_public: true,
                signature,
            })
            .await
            .map_err(anyhow::Error::from)?;
        client
            .upload_presigned_bytes(
                &presign.presigned_url,
                prepared.bytes,
                &prepared.content_type,
            )
            .await
            .map_err(anyhow::Error::from)?;
        out.push(PostAttachment {
            filename: prepared.filename,
            content: None,
            attachment_type: prepared.content_type,
            s3_key: Some(presign.s3_key),
            url: None,
            is_public: true,
        });
    }
    Ok(out)
}

async fn set_profile_picture(
    client: &harmoniis_wallet::client::HarmoniisClient,
    identity: &Identity,
    file: &PathBuf,
) -> anyhow::Result<String> {
    let prepared = prepare_avatar_image(file)?;
    let fingerprint = identity.fingerprint();
    let storage_path = format!(
        "profile/avatar-{}.jpg",
        chrono::Utc::now().format("%Y%m%d%H%M%S")
    );
    let signature = identity.sign(&format!("presign:{storage_path}"));
    let presign = client
        .storage_presign(&StoragePresignRequest {
            fingerprint: fingerprint.clone(),
            file_path: storage_path,
            content_type: prepared.content_type.clone(),
            is_public: true,
            signature,
        })
        .await
        .map_err(anyhow::Error::from)?;
    client
        .upload_presigned_bytes(
            &presign.presigned_url,
            prepared.bytes,
            &prepared.content_type,
        )
        .await
        .map_err(anyhow::Error::from)?;
    let update_signature = identity.sign(&format!("update_profile:{fingerprint}"));
    client
        .update_profile_picture(&fingerprint, &presign.s3_key, &update_signature)
        .await
        .map_err(anyhow::Error::from)?;
    if presign.s3_key.contains("/profile/") || presign.s3_key.contains("/public/") {
        Ok(format!("/api/storage/public/{}", presign.s3_key))
    } else {
        Ok(presign.s3_key)
    }
}

fn active_pgp_identity(wallet: &RgbWallet) -> anyhow::Result<(String, Identity)> {
    let (meta, identity) = wallet.active_pgp_identity()?;
    Ok((meta.label, identity))
}

fn pick_pgp_identity(
    wallet: &RgbWallet,
    label: Option<&str>,
) -> anyhow::Result<(String, Identity)> {
    match label {
        Some(name) => {
            let (meta, identity) = wallet.pgp_identity_by_label(name)?;
            Ok((meta.label, identity))
        }
        None => active_pgp_identity(wallet),
    }
}

fn payment_secret_for_rail<'a>(
    rail: PaymentRail,
    webcash_secret: Option<&'a str>,
    bitcoin_secret: Option<&'a str>,
) -> anyhow::Result<PaymentSecret<'a>> {
    match rail {
        PaymentRail::Webcash => Ok(PaymentSecret::Webcash(webcash_secret.unwrap_or_default())),
        PaymentRail::Bitcoin => {
            let secret = bitcoin_secret
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "--bitcoin-secret (or HRMW_BITCOIN_SECRET) is required when --payment-rail bitcoin"
                    )
                })?;
            Ok(PaymentSecret::Bitcoin(secret))
        }
    }
}

fn contract_from_recovery(
    rc: &harmoniis_wallet::client::recovery::RecoveryContract,
) -> Option<Contract> {
    let contract_type = rc
        .contract_type
        .as_deref()
        .and_then(|s| ContractType::parse(s).ok())
        .unwrap_or(ContractType::Service);
    let status = rc
        .status
        .as_deref()
        .and_then(|s| ContractStatus::parse(s).ok())
        .unwrap_or(ContractStatus::Issued);
    let amount_units = rc.amount.as_deref().map(parse_amount_to_units).unwrap_or(0);
    let buyer_fingerprint = rc.buyer_fingerprint.clone().unwrap_or_default();
    if rc.contract_id.trim().is_empty() {
        return None;
    }
    Some(Contract {
        contract_id: rc.contract_id.clone(),
        contract_type,
        status,
        witness_secret: None,
        witness_proof: rc.witness_proof.clone(),
        amount_units,
        work_spec: rc
            .reference_post
            .clone()
            .unwrap_or_else(|| "Recovered from server".to_string()),
        buyer_fingerprint,
        seller_fingerprint: rc.seller_fingerprint.clone(),
        reference_post: rc.reference_post.clone(),
        delivery_deadline: rc.delivery_deadline.clone(),
        role: Role::Buyer,
        delivered_text: None,
        certificate_id: None,
        created_at: rc.created_at.clone().unwrap_or_else(now_utc),
        updated_at: rc.updated_at.clone().unwrap_or_else(now_utc),
    })
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let wallet_path = resolve_wallet_path(cli.wallet.clone());
    let api = cli.api.as_str();
    let direct = cli.direct;
    let payment_rail = cli.payment_rail;
    let bitcoin_secret = cli
        .bitcoin_secret
        .clone()
        .or_else(|| std::env::var("HRMW_BITCOIN_SECRET").ok());

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
                    root_private_key_hex: Some(id.private_key_hex()),
                    wallet_label: wallet.wallet_label()?,
                    pgp_identities: vec![],
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
            if let Some(label) = wallet.wallet_label()? {
                println!("Wallet label: {label}");
            }
            let pgp = wallet.list_pgp_identities()?;
            println!("PGP identities: {}", pgp.len());
        }

        // ── info ──────────────────────────────────────────────────────────────
        Cmd::Info => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let (active_label, active_pgp) = active_pgp_identity(&wallet)?;
            let webcash_wallet = open_webcash_wallet(&wallet_path, &wallet).await?;
            let webcash_balance = webcash_wallet
                .balance()
                .await
                .unwrap_or_else(|_| "0".to_string());
            let webcash_stats = webcash_wallet.stats().await.ok();
            println!("RGB fingerprint: {}", wallet.fingerprint()?);
            println!("PGP fingerprint: {}", active_pgp.fingerprint());
            println!("PGP label:      {}", active_label);
            if let Some(label) = wallet.wallet_label()? {
                println!("Wallet label:   {label}");
            }
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
            let (_, id) = active_pgp_identity(&wallet)?;
            let resp = make_client(api, direct)
                .claim_donation(&DonationClaimRequest {
                    pgp_public_key: id.public_key_hex(),
                    signature: id.sign("donation-request"),
                })
                .await?;
            match resp.status.as_str() {
                "donated" => {
                    if let Some(secret) = resp.secret {
                        let webcash_wallet = open_webcash_wallet(&wallet_path, &wallet).await?;
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
                        anyhow::bail!("donation response missing secret");
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
            let webcash_wallet = open_webcash_wallet(&wallet_path, &wallet).await?;
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
            let webcash_wallet = open_webcash_wallet(&wallet_path, &wallet).await?;
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
            let webcash_wallet = open_webcash_wallet(&wallet_path, &wallet).await?;
            let parsed_amount = WebcashAmount::from_str(&amount)
                .with_context(|| format!("invalid webcash amount '{amount}'"))?;
            let output = webcash_wallet
                .pay(parsed_amount, &memo)
                .await
                .context("failed to create payment")?;
            let token = extract_webcash_token(&output)?;
            println!("Payment token:");
            println!("{token}");
        }

        Cmd::Webcash(WebcashCmd::Check) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let webcash_wallet = open_webcash_wallet(&wallet_path, &wallet).await?;
            webcash_wallet
                .check()
                .await
                .context("webcash check failed")?;
            println!("Webcash check passed.");
        }

        Cmd::Webcash(WebcashCmd::Recover { gap_limit }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let webcash_wallet = open_webcash_wallet(&wallet_path, &wallet).await?;
            let summary = webcash_wallet
                .recover_from_wallet(gap_limit)
                .await
                .context("webcash recovery failed")?;
            println!("{summary}");
        }

        Cmd::Webcash(WebcashCmd::Merge { group }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let webcash_wallet = open_webcash_wallet(&wallet_path, &wallet).await?;
            let summary = webcash_wallet
                .merge(group)
                .await
                .context("webcash merge failed")?;
            println!("{summary}");
        }

        // ── bitcoin deterministic wallet ───────────────────────────────────
        Cmd::Bitcoin(BitcoinCmd::Info {
            network,
            esplora,
            no_sync,
            stop_gap,
            parallel_requests,
        }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let network = Network::from(network);
            let btc = DeterministicBitcoinWallet::from_rgb_wallet(&wallet, network)?;
            let (taproot_external, taproot_internal) =
                btc.descriptor_strings_for(BitcoinAddressKind::Taproot)?;
            let (segwit_external, segwit_internal) =
                btc.descriptor_strings_for(BitcoinAddressKind::Segwit)?;
            println!("Bitcoin deterministic wallet");
            println!("Network:     {}", network);
            println!(
                "Esplora:     {}",
                resolved_esplora_url(network, esplora.clone())
            );
            println!("Taproot descriptor ext: {taproot_external}");
            println!("Taproot descriptor int: {taproot_internal}");
            println!(
                "Taproot address[0]: {}",
                btc.receive_address_at_kind(0, BitcoinAddressKind::Taproot)?
            );
            println!("SegWit descriptor ext:  {segwit_external}");
            println!("SegWit descriptor int:  {segwit_internal}");
            println!(
                "SegWit address[0]:  {}",
                btc.receive_address_at_kind(0, BitcoinAddressKind::Segwit)?
            );
            if !no_sync {
                let snapshot = btc.sync(
                    &resolved_esplora_url(network, esplora),
                    stop_gap,
                    parallel_requests,
                )?;
                println!(
                    "Confirmed:   {} BTC",
                    format_btc_from_sats(snapshot.confirmed_sats)
                );
                println!(
                    "Pending(tr): {} BTC",
                    format_btc_from_sats(snapshot.trusted_pending_sats)
                );
                println!(
                    "Pending(un): {} BTC",
                    format_btc_from_sats(snapshot.untrusted_pending_sats)
                );
                println!(
                    "Immature:    {} BTC",
                    format_btc_from_sats(snapshot.immature_sats)
                );
                println!(
                    "Total:       {} BTC",
                    format_btc_from_sats(snapshot.total_sats)
                );
                println!(
                    "Next receive (taproot): {} (index {})",
                    snapshot.taproot_receive_address, snapshot.taproot_receive_index
                );
                println!(
                    "Next receive (segwit):  {} (index {})",
                    snapshot.segwit_receive_address, snapshot.segwit_receive_index
                );
                println!("UTXOs(total): {}", snapshot.unspent_count);
            }
        }

        Cmd::Bitcoin(BitcoinCmd::Address {
            network,
            kind,
            index,
        }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let network = Network::from(network);
            let btc = DeterministicBitcoinWallet::from_rgb_wallet(&wallet, network)?;
            let addr = btc.receive_address_at_kind(index, kind.into())?;
            println!("{addr}");
        }

        Cmd::Bitcoin(BitcoinCmd::Sync {
            network,
            esplora,
            stop_gap,
            parallel_requests,
        }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let network = Network::from(network);
            let btc = DeterministicBitcoinWallet::from_rgb_wallet(&wallet, network)?;
            let esplora_url = resolved_esplora_url(network, esplora);
            let snapshot = btc.sync(&esplora_url, stop_gap, parallel_requests)?;
            println!("Network:       {}", snapshot.network);
            println!("Esplora:       {}", snapshot.esplora_url);
            println!(
                "Confirmed:     {} BTC",
                format_btc_from_sats(snapshot.confirmed_sats)
            );
            println!(
                "Trusted pend.: {} BTC",
                format_btc_from_sats(snapshot.trusted_pending_sats)
            );
            println!(
                "Untrusted pen: {} BTC",
                format_btc_from_sats(snapshot.untrusted_pending_sats)
            );
            println!(
                "Immature:      {} BTC",
                format_btc_from_sats(snapshot.immature_sats)
            );
            println!(
                "Total:         {} BTC",
                format_btc_from_sats(snapshot.total_sats)
            );
            println!(
                "Next taproot:  {} (index {})",
                snapshot.taproot_receive_address, snapshot.taproot_receive_index
            );
            println!(
                "Next segwit:   {} (index {})",
                snapshot.segwit_receive_address, snapshot.segwit_receive_index
            );
            println!("UTXOs(total):  {}", snapshot.unspent_count);
        }

        // ── key management ───────────────────────────────────────────────────
        Cmd::Key(KeyCmd::Export { format, output }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let payload = match format {
                KeyExportFormat::Hex => wallet.export_master_key_hex()?,
                KeyExportFormat::Mnemonic => wallet.export_master_key_mnemonic()?,
            };
            if let Some(path) = output {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).with_context(|| {
                        format!("failed creating export directory {}", parent.display())
                    })?;
                }
                let mut f = fs::File::create(&path)
                    .with_context(|| format!("failed creating {}", path.display()))?;
                writeln!(f, "{payload}")?;
                println!(
                    "Exported {} master key to {}",
                    format!("{:?}", format).to_lowercase(),
                    path.display()
                );
            } else {
                println!("{payload}");
            }
        }

        Cmd::Key(KeyCmd::Import {
            hex,
            mnemonic,
            force,
        }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            if wallet.has_local_state()? && !force {
                anyhow::bail!(
                    "wallet contains local contracts/certificates; rerun with --force to overwrite key material"
                );
            }
            match (hex, mnemonic) {
                (Some(h), None) => wallet.apply_master_key_hex(h.trim())?,
                (None, Some(m)) => wallet.apply_master_key_mnemonic(m.trim())?,
                (Some(_), Some(_)) => anyhow::bail!("provide either --hex or --mnemonic, not both"),
                (None, None) => anyhow::bail!("provide --hex or --mnemonic"),
            }
            let (label, pgp) = active_pgp_identity(&wallet)?;
            println!("Imported master key.");
            println!("RGB fingerprint: {}", wallet.fingerprint()?);
            println!("PGP fingerprint: {} ({})", pgp.fingerprint(), label);
        }

        Cmd::Key(KeyCmd::Fingerprint) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let root_hex = wallet.root_private_key_hex()?;
            let root_checksum = {
                use sha2::Digest;
                let digest = sha2::Sha256::digest(hex::decode(root_hex)?);
                hex::encode(digest)[..16].to_string()
            };
            let (label, pgp) = active_pgp_identity(&wallet)?;
            let webcash_slot = wallet.derive_webcash_master_secret_hex()?;
            let bitcoin_slot = wallet.derive_bitcoin_master_key_hex()?;
            println!("Root checksum:   {root_checksum}");
            println!("RGB fingerprint: {}", wallet.fingerprint()?);
            println!("PGP fingerprint: {} ({label})", pgp.fingerprint());
            println!("Webcash slot:    {}", &webcash_slot[..16]);
            println!("Bitcoin slot:    {}", &bitcoin_slot[..16]);
        }

        // ── deterministic recovery ───────────────────────────────────────────
        Cmd::Recover(RecoverCmd::Deterministic {
            pgp_start,
            pgp_end,
            batch_size,
            no_server,
        }) => {
            if pgp_start > pgp_end {
                anyhow::bail!("pgp_start must be <= pgp_end");
            }
            if pgp_end >= 1_000 {
                anyhow::bail!("pgp_end must be <= 999");
            }
            if batch_size == 0 {
                anyhow::bail!("batch_size must be > 0");
            }

            let wallet = open_or_create_wallet(&wallet_path)?;
            // Ensure deterministic base slots are reachable.
            let _ = wallet.derive_slot_hex("rgb", 0)?;
            let _ = wallet.derive_slot_hex("webcash", 0)?;
            let _ = wallet.derive_slot_hex("bitcoin", 0)?;

            let mut recovered_identities = 0usize;
            let mut recovered_contracts = 0usize;

            if !no_server {
                let challenge = format!("recover:{}:{}", wallet.fingerprint()?, now_utc());
                let client = make_client(api, direct);
                let mut index = pgp_start;
                while index <= pgp_end {
                    let end =
                        (index.saturating_add(batch_size as u32).saturating_sub(1)).min(pgp_end);
                    let mut probes = Vec::with_capacity((end - index + 1) as usize);
                    for key_index in index..=end {
                        let id = wallet.derive_pgp_identity_for_index(key_index)?;
                        probes.push(RecoveryProbe {
                            key_index,
                            fingerprint: id.fingerprint(),
                            signature: id.sign(&challenge),
                        });
                    }
                    let resp = client
                        .recovery_scan(&RecoveryScanRequest {
                            challenge: challenge.clone(),
                            probes,
                            include_contracts: true,
                            contract_limit: 500,
                        })
                        .await
                        .context("server recovery scan failed")?;

                    for item in resp.identities {
                        let label = item
                            .nickname
                            .as_deref()
                            .filter(|s| !s.trim().is_empty())
                            .map(|s| s.replace(' ', "-"))
                            .unwrap_or_else(|| format!("pgp-{}", item.key_index));
                        wallet.ensure_pgp_identity_index(item.key_index, Some(&label), false)?;
                        recovered_identities += 1;
                    }
                    for rc in resp.contracts {
                        if let Some(contract) = contract_from_recovery(&rc) {
                            wallet.store_contract(&contract)?;
                            recovered_contracts += 1;
                        }
                    }

                    if end == pgp_end {
                        break;
                    }
                    index = end.saturating_add(1);
                }
            }

            // Deterministic webcash reconstruction.
            let webcash_wallet = open_webcash_wallet(&wallet_path, &wallet).await?;
            let webcash_summary = webcash_wallet
                .recover_from_wallet(40)
                .await
                .unwrap_or_else(|e| format!("webcash recover skipped: {e}"));
            println!("Deterministic recovery complete.");
            println!("Recovered identities: {recovered_identities}");
            println!("Recovered contracts:  {recovered_contracts}");
            println!("{webcash_summary}");
        }

        // ── identity register ─────────────────────────────────────────────────
        Cmd::Identity(IdentityCmd::Register { nick, about, label }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let (selected_label, id) = pick_pgp_identity(&wallet, label.as_deref())?;
            let client = make_client(api, direct);
            let req = RegisterRequest {
                nickname: nick.clone(),
                pgp_public_key: id.public_key_hex(),
                signature: id.sign(&format!("register:{nick}")),
                about,
            };
            let fp = match payment_rail {
                PaymentRail::Webcash => {
                    let preflight = client
                        .register_identity_with_payment(
                            &req,
                            payment_secret_for_rail(
                                PaymentRail::Webcash,
                                Some(""),
                                bitcoin_secret.as_deref(),
                            )?,
                        )
                        .await;
                    match preflight {
                        Ok(fp) => fp,
                        Err(err) => {
                            let err = anyhow::Error::from(err);
                            let Some(required) = required_amount_for_payment_retry(&err, "0.6")
                            else {
                                return Err(err);
                            };
                            let payment = pay_from_wallet(
                                &wallet_path,
                                &wallet,
                                &required,
                                "identity register",
                            )
                            .await?;
                            client
                                .register_identity_with_payment(
                                    &req,
                                    payment_secret_for_rail(
                                        PaymentRail::Webcash,
                                        Some(&payment),
                                        bitcoin_secret.as_deref(),
                                    )?,
                                )
                                .await
                                .map_err(anyhow::Error::from)?
                        }
                    }
                }
                PaymentRail::Bitcoin => client
                    .register_identity_with_payment(
                        &req,
                        payment_secret_for_rail(
                            PaymentRail::Bitcoin,
                            None,
                            bitcoin_secret.as_deref(),
                        )?,
                    )
                    .await
                    .map_err(anyhow::Error::from)?,
            };
            wallet.set_nickname(&nick)?;
            println!("Registered as '{nick}'. Fingerprint: {fp} (pgp label: {selected_label})");
        }

        Cmd::Identity(IdentityCmd::PgpNew { label, active }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let created = wallet.create_pgp_identity(&label)?;
            if active {
                wallet.set_active_pgp_identity(&label)?;
            }
            let state = if active { "active" } else { "inactive" };
            println!(
                "Created PGP identity '{}' (index {}, {})",
                created.label, created.key_index, state
            );
            println!("Fingerprint: {}", created.public_key_hex);
        }

        Cmd::Identity(IdentityCmd::PgpList) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let ids = wallet.list_pgp_identities()?;
            if ids.is_empty() {
                println!("No PGP identities.");
            } else {
                println!(
                    "{:<20} {:>8} {:>8}  fingerprint",
                    "label", "index", "active"
                );
                println!("{}", "─".repeat(80));
                for rec in ids {
                    println!(
                        "{:<20} {:>8} {:>8}  {}",
                        rec.label,
                        rec.key_index,
                        if rec.is_active { "yes" } else { "no" },
                        rec.public_key_hex
                    );
                }
            }
        }

        Cmd::Identity(IdentityCmd::PgpUse { label }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            wallet.set_active_pgp_identity(&label)?;
            let (active, identity) = active_pgp_identity(&wallet)?;
            println!("Active PGP label: {active}");
            println!("Fingerprint: {}", identity.fingerprint());
        }

        // ── profile set-picture ───────────────────────────────────────────────
        Cmd::Profile(ProfileCmd::SetPicture { file }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let (_, identity) = active_pgp_identity(&wallet)?;
            let client = make_client(api, direct);
            let final_url = set_profile_picture(&client, &identity, &file).await?;
            println!("Profile picture updated.");
            println!("URL: {final_url}");
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
            image_files,
        }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let (_, id) = active_pgp_identity(&wallet)?;
            let fp = id.fingerprint();
            let nick = wallet.nickname()?.ok_or_else(|| {
                anyhow::anyhow!("nickname not set; run 'hrmw identity register' first")
            })?;
            let normalized_post_type = post_type.to_lowercase();
            let mut attachments = build_post_attachments(
                &normalized_post_type,
                &content,
                terms_file,
                descriptor_file,
                attachment_files,
            )?;
            if !image_files.is_empty() {
                let client = make_client(api, direct);
                let mut uploaded = upload_post_images(&client, &id, &fp, image_files).await?;
                attachments.append(&mut uploaded);
            }
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
            let client = make_client(api, direct);
            let post_id = match payment_rail {
                PaymentRail::Webcash => {
                    let preflight = client
                        .publish_post_with_payment(
                            &req,
                            payment_secret_for_rail(
                                PaymentRail::Webcash,
                                Some(""),
                                bitcoin_secret.as_deref(),
                            )?,
                        )
                        .await;
                    match preflight {
                        Ok(post_id) => post_id,
                        Err(err) => {
                            let err = anyhow::Error::from(err);
                            let Some(required) = required_amount_for_payment_retry(&err, "0.3")
                            else {
                                return Err(err);
                            };
                            let payment =
                                pay_from_wallet(&wallet_path, &wallet, &required, "timeline post")
                                    .await?;
                            client
                                .publish_post_with_payment(
                                    &req,
                                    payment_secret_for_rail(
                                        PaymentRail::Webcash,
                                        Some(&payment),
                                        bitcoin_secret.as_deref(),
                                    )?,
                                )
                                .await
                                .map_err(anyhow::Error::from)?
                        }
                    }
                }
                PaymentRail::Bitcoin => client
                    .publish_post_with_payment(
                        &req,
                        payment_secret_for_rail(
                            PaymentRail::Bitcoin,
                            None,
                            bitcoin_secret.as_deref(),
                        )?,
                    )
                    .await
                    .map_err(anyhow::Error::from)?,
            };
            println!("Post published: {post_id}");
        }

        // ── timeline comment ──────────────────────────────────────────────────
        Cmd::Timeline(TimelineCmd::Comment { post, content }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let (_, id) = active_pgp_identity(&wallet)?;
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
                    content: Some(format!("# Comment\n\n{}", content)),
                    attachment_type: "text/markdown".to_string(),
                    s3_key: None,
                    url: None,
                    is_public: false,
                }],
                activity_metadata: None,
                signature: id.sign(&format!("post:{content}")),
            };
            let comment_id = match payment_rail {
                PaymentRail::Webcash => {
                    let preflight = client
                        .publish_post_with_payment(
                            &req,
                            payment_secret_for_rail(
                                PaymentRail::Webcash,
                                Some(""),
                                bitcoin_secret.as_deref(),
                            )?,
                        )
                        .await;
                    match preflight {
                        Ok(comment_id) => comment_id,
                        Err(err) => {
                            let err = anyhow::Error::from(err);
                            let Some(required) = required_amount_for_payment_retry(&err, "0.01")
                            else {
                                return Err(err);
                            };
                            let payment = pay_from_wallet(
                                &wallet_path,
                                &wallet,
                                &required,
                                "timeline comment",
                            )
                            .await?;
                            client
                                .publish_post_with_payment(
                                    &req,
                                    payment_secret_for_rail(
                                        PaymentRail::Webcash,
                                        Some(&payment),
                                        bitcoin_secret.as_deref(),
                                    )?,
                                )
                                .await
                                .map_err(anyhow::Error::from)?
                        }
                    }
                }
                PaymentRail::Bitcoin => client
                    .publish_post_with_payment(
                        &req,
                        payment_secret_for_rail(
                            PaymentRail::Bitcoin,
                            None,
                            bitcoin_secret.as_deref(),
                        )?,
                    )
                    .await
                    .map_err(anyhow::Error::from)?,
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
            let (_, id) = active_pgp_identity(&wallet)?;
            let client = make_client(api, direct);
            let req = RatePostRequest {
                post_id: post.clone(),
                actor_fingerprint: id.fingerprint(),
                vote: vote.clone(),
                signature: id.sign(&format!("vote:{post}:{vote}")),
            };
            match payment_rail {
                PaymentRail::Webcash => {
                    if let Err(err) = client
                        .rate_post_with_payment(
                            &req,
                            payment_secret_for_rail(
                                PaymentRail::Webcash,
                                Some(""),
                                bitcoin_secret.as_deref(),
                            )?,
                        )
                        .await
                    {
                        let err = anyhow::Error::from(err);
                        let Some(required) = required_amount_for_payment_retry(&err, "0.001")
                        else {
                            return Err(err);
                        };
                        let payment =
                            pay_from_wallet(&wallet_path, &wallet, &required, "timeline rate")
                                .await?;
                        client
                            .rate_post_with_payment(
                                &req,
                                payment_secret_for_rail(
                                    PaymentRail::Webcash,
                                    Some(&payment),
                                    bitcoin_secret.as_deref(),
                                )?,
                            )
                            .await
                            .map_err(anyhow::Error::from)?;
                    }
                }
                PaymentRail::Bitcoin => {
                    client
                        .rate_post_with_payment(
                            &req,
                            payment_secret_for_rail(
                                PaymentRail::Bitcoin,
                                None,
                                bitcoin_secret.as_deref(),
                            )?,
                        )
                        .await
                        .map_err(anyhow::Error::from)?;
                }
            }
            println!("Rated post {post}: {vote}");
        }

        // ── timeline delete ───────────────────────────────────────────────────
        Cmd::Timeline(TimelineCmd::Delete { post }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let (_, id) = active_pgp_identity(&wallet)?;
            let req = DeletePostRequest {
                post_id: post.clone(),
                author_fingerprint: id.fingerprint(),
                signature: id.sign(&format!("delete_post:{post}")),
            };
            make_client(api, direct)
                .delete_post(&req)
                .await
                .map_err(anyhow::Error::from)?;
            println!("Deleted post: {post}");
        }

        // ── timeline update ───────────────────────────────────────────────────
        Cmd::Timeline(TimelineCmd::Update {
            post,
            content,
            keywords,
        }) => {
            if content
                .as_deref()
                .map(|v| v.trim().is_empty())
                .unwrap_or(true)
                && keywords
                    .as_deref()
                    .map(|v| v.trim().is_empty())
                    .unwrap_or(true)
            {
                anyhow::bail!("provide --content or --keywords");
            }
            let wallet = open_or_create_wallet(&wallet_path)?;
            let (_, id) = active_pgp_identity(&wallet)?;
            let req = UpdatePostRequest {
                post_id: post.clone(),
                author_fingerprint: id.fingerprint(),
                signature: id.sign(&format!("update_post:{post}")),
                content,
                keywords: keywords.as_deref().map(|csv| parse_keywords_csv(Some(csv))),
                attachments: None,
                activity_metadata: None,
            };
            make_client(api, direct)
                .update_post(&req)
                .await
                .map_err(anyhow::Error::from)?;
            println!("Updated post: {post}");
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
            let (_, id) = active_pgp_identity(&wallet)?;
            let fp = id.fingerprint();
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
            let (_, id) = active_pgp_identity(&wallet)?;
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
            let buy_response = match payment_rail {
                PaymentRail::Webcash => {
                    let preflight = client
                        .buy_contract_with_payment(
                            &req,
                            payment_secret_for_rail(
                                PaymentRail::Webcash,
                                Some(""),
                                bitcoin_secret.as_deref(),
                            )?,
                        )
                        .await;
                    match preflight {
                        Ok(v) => v,
                        Err(err) => {
                            let err = anyhow::Error::from(err);
                            if required_amount_for_payment_retry(&err, &amount).is_none() {
                                return Err(err);
                            }
                            // Contract buy should pay the explicit --amount requested by the buyer.
                            let required = amount.clone();
                            let payment =
                                pay_from_wallet(&wallet_path, &wallet, &required, "contract buy")
                                    .await?;
                            client
                                .buy_contract_with_payment(
                                    &req,
                                    payment_secret_for_rail(
                                        PaymentRail::Webcash,
                                        Some(&payment),
                                        bitcoin_secret.as_deref(),
                                    )?,
                                )
                                .await
                                .map_err(anyhow::Error::from)?
                        }
                    }
                }
                PaymentRail::Bitcoin => client
                    .buy_contract_with_payment(
                        &req,
                        payment_secret_for_rail(
                            PaymentRail::Bitcoin,
                            None,
                            bitcoin_secret.as_deref(),
                        )?,
                    )
                    .await
                    .map_err(anyhow::Error::from)?,
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
            let (_, id) = active_pgp_identity(&wallet)?;
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
                    content: Some("Bid commitment details".to_string()),
                    attachment_type: "text/markdown".to_string(),
                    s3_key: None,
                    url: None,
                    is_public: false,
                }],
                activity_metadata: None,
                signature: sig,
            };
            let client = make_client(api, direct);
            let post_id = match payment_rail {
                PaymentRail::Webcash => {
                    let preflight = client
                        .publish_post_with_payment(
                            &req,
                            payment_secret_for_rail(
                                PaymentRail::Webcash,
                                Some(""),
                                bitcoin_secret.as_deref(),
                            )?,
                        )
                        .await;
                    match preflight {
                        Ok(post_id) => post_id,
                        Err(err) => {
                            let err = anyhow::Error::from(err);
                            let Some(required) = required_amount_for_payment_retry(&err, "0.01")
                            else {
                                return Err(err);
                            };
                            let payment =
                                pay_from_wallet(&wallet_path, &wallet, &required, "contract bid")
                                    .await?;
                            client
                                .publish_post_with_payment(
                                    &req,
                                    payment_secret_for_rail(
                                        PaymentRail::Webcash,
                                        Some(&payment),
                                        bitcoin_secret.as_deref(),
                                    )?,
                                )
                                .await
                                .map_err(anyhow::Error::from)?
                        }
                    }
                }
                PaymentRail::Bitcoin => client
                    .publish_post_with_payment(
                        &req,
                        payment_secret_for_rail(
                            PaymentRail::Bitcoin,
                            None,
                            bitcoin_secret.as_deref(),
                        )?,
                    )
                    .await
                    .map_err(anyhow::Error::from)?,
            };
            println!("Bid posted: {post_id}");
        }

        // ── contract accept ───────────────────────────────────────────────────
        Cmd::Contract(ContractCmd::Accept { id }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let (_, identity) = active_pgp_identity(&wallet)?;
            let fp = identity.fingerprint();
            let sig = identity.sign(&format!("accept:{id}:{fp}"));
            let client = make_client(api, direct);

            let accept_response = client.accept_contract(&id, &fp, &sig).await?;
            let mut rotated_secret: Option<WitnessSecret> = None;
            let mut rotated_proof: Option<String> = accept_response
                .get("witness_proof")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);

            if let Some(envelope) = accept_response
                .get("witness_secret_encrypted_for_seller")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            {
                let decrypted = decrypt_witness_secret_envelope(envelope, &identity)?;
                let received_secret = WitnessSecret::parse(&decrypted)
                    .context("accept returned malformed witness secret envelope")?;
                let new_secret = WitnessSecret::generate(&id);
                let new_proof = new_secret.public_proof();
                client
                    .witness_replace(&received_secret, &new_secret)
                    .await?;
                rotated_proof = Some(new_proof.display());
                rotated_secret = Some(new_secret);
            }

            let contract_view = client.get_contract(&id).await.unwrap_or_default();
            let amount_units = contract_view
                .get("amount")
                .and_then(|v| {
                    v.as_u64()
                        .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
                })
                .unwrap_or(0);
            let work_spec = contract_view
                .get("work_spec")
                .and_then(|v| v.as_str())
                .unwrap_or("Contract deliverable")
                .to_string();
            let contract_type = contract_view
                .get("contract_type")
                .and_then(|v| v.as_str())
                .and_then(|s| ContractType::parse(s).ok())
                .unwrap_or(ContractType::Service);
            let buyer_fingerprint = contract_view
                .get("buyer_fingerprint")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let reference_post = contract_view
                .get("reference_post")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
            let delivery_deadline = contract_view
                .get("delivery_deadline")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);

            let mut local_contract = wallet.get_contract(&id)?.unwrap_or_else(|| {
                Contract::new(
                    id.clone(),
                    contract_type.clone(),
                    amount_units,
                    work_spec.clone(),
                    buyer_fingerprint.clone(),
                    Role::Seller,
                )
            });
            local_contract.contract_type = contract_type;
            local_contract.amount_units = amount_units;
            local_contract.work_spec = work_spec;
            local_contract.buyer_fingerprint = buyer_fingerprint;
            local_contract.seller_fingerprint = Some(fp.clone());
            local_contract.reference_post = reference_post;
            local_contract.delivery_deadline = delivery_deadline;
            local_contract.role = Role::Seller;
            local_contract.status = ContractStatus::Active;
            local_contract.witness_proof = rotated_proof;
            local_contract.witness_secret = rotated_secret.map(|s| s.display());
            local_contract.updated_at = now_utc();
            wallet.update_contract(&local_contract)?;

            println!("Bid accepted. Contract {id} is now active.");
            if local_contract.witness_secret.is_some() {
                println!("Seller custody rotated and witness secret stored locally.");
            } else {
                println!("No encrypted seller witness envelope was returned.");
            }
        }

        // ── contract replace ──────────────────────────────────────────────────
        // RGB21 bearer handover: current holder calls witness/replace and shares
        // the new secret out-of-band with the next holder.
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
            let (_, identity) = active_pgp_identity(&wallet)?;
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
            let (_, identity) = active_pgp_identity(&wallet)?;
            let fp = identity.fingerprint();
            let sig = identity.sign(&id);
            let client = make_client(api, direct);
            let resp = match payment_rail {
                PaymentRail::Webcash => {
                    let preflight = client
                        .pickup_with_payment(
                            &id,
                            &fp,
                            &sig,
                            payment_secret_for_rail(
                                PaymentRail::Webcash,
                                Some(""),
                                bitcoin_secret.as_deref(),
                            )?,
                        )
                        .await;
                    match preflight {
                        Ok(v) => v,
                        Err(err) => {
                            let err = anyhow::Error::from(err);
                            if required_amount_for_payment_retry(&err, "0.015").is_none() {
                                return Err(err);
                            }
                            let required = wallet
                                .get_contract(&id)?
                                .map(|c| format_units_to_amount((c.amount_units * 3) / 100))
                                .unwrap_or_else(|| "0.015".to_string());
                            let payment = pay_from_wallet(
                                &wallet_path,
                                &wallet,
                                &required,
                                "contract pickup",
                            )
                            .await?;
                            client
                                .pickup_with_payment(
                                    &id,
                                    &fp,
                                    &sig,
                                    payment_secret_for_rail(
                                        PaymentRail::Webcash,
                                        Some(&payment),
                                        bitcoin_secret.as_deref(),
                                    )?,
                                )
                                .await
                                .map_err(anyhow::Error::from)?
                        }
                    }
                }
                PaymentRail::Bitcoin => client
                    .pickup_with_payment(
                        &id,
                        &fp,
                        &sig,
                        payment_secret_for_rail(
                            PaymentRail::Bitcoin,
                            None,
                            bitcoin_secret.as_deref(),
                        )?,
                    )
                    .await
                    .map_err(anyhow::Error::from)?,
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
            let (_, identity) = active_pgp_identity(&wallet)?;
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

        // ── webminer ────────────────────────────────────────────────────────────
        Cmd::Webminer(WebminerCmd::Start {
            server,
            max_difficulty,
            backend,
            cpu_only,
            cpu_threads,
            accept_terms,
        }) => {
            use harmoniis_wallet::miner::{daemon, BackendChoice, MinerConfig};
            let webcash_wallet_path = default_webcash_wallet_path(&wallet_path);
            let backend_choice = if cpu_only {
                BackendChoice::Cpu
            } else {
                backend.into()
            };
            let config = MinerConfig {
                server_url: server,
                wallet_path: wallet_path.clone(),
                webcash_wallet_path,
                max_difficulty,
                backend: backend_choice,
                cpu_threads,
                accept_terms,
            };
            daemon::start(&config)?;
        }
        Cmd::Webminer(WebminerCmd::Stop) => {
            harmoniis_wallet::miner::daemon::stop()?;
        }
        Cmd::Webminer(WebminerCmd::Status) => {
            harmoniis_wallet::miner::daemon::status()?;
        }
        Cmd::Webminer(WebminerCmd::Bench {
            cpu_threads,
            cpu_target_mhs,
            gpu_target_mhs,
            strict,
        }) => {
            run_webminer_benchmarks(cpu_threads, cpu_target_mhs, gpu_target_mhs, strict).await?;
        }
        Cmd::Webminer(WebminerCmd::Run {
            server,
            max_difficulty,
            backend,
            cpu_only,
            cpu_threads,
            accept_terms,
            wallet: run_wallet,
            webcash_wallet,
        }) => {
            use harmoniis_wallet::miner::{daemon, BackendChoice, MinerConfig};
            let run_wallet = run_wallet.unwrap_or_else(|| wallet_path.clone());
            let run_webcash_wallet =
                webcash_wallet.unwrap_or_else(|| default_webcash_wallet_path(&run_wallet));
            let backend_choice = if cpu_only {
                BackendChoice::Cpu
            } else {
                backend.into()
            };
            let config = MinerConfig {
                server_url: server,
                wallet_path: run_wallet,
                webcash_wallet_path: run_webcash_wallet,
                max_difficulty,
                backend: backend_choice,
                cpu_threads,
                accept_terms,
            };
            daemon::run_mining_loop(config).await?;
        }
    }

    Ok(())
}
