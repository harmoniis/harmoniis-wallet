//! `hrmw` — Harmoniis wallet CLI.
//!
//! Manages RGB21 bearer contracts and certificates via the Harmoniis Witness.
//!
//! Mental model (mirrors Webcash):
//!   insert  → take custody of a contract you received (like `webyc insert`)
//!   replace → transfer a contract to another party  (like `webyc pay`)
//!   list    → show all contracts/certificates in wallet
//!   check   → verify a contract is still live with the Witness

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{fs, io::Write};

use anyhow::Context;
use bdk_wallet::bitcoin::Network;
use clap::{Args, Parser, Subcommand, ValueEnum};
use harmoniis_wallet::{
    ark::{parse_ark_proof, ArkPaymentWallet, SqliteArkDb},
    bitcoin::{BitcoinAddressKind, DeterministicBitcoinWallet},
    client::{
        arbitration::{build_witness_commitment, decrypt_witness_secret_envelope, BuyRequest},
        recovery::{RecoveryProbe, RecoveryScanRequest},
        timeline::{
            DeleteIdentityRequest, DeletePostRequest, DonationClaimRequest, PostAttachment,
            PublishPostRequest, RatePostRequest, RegisterRequest, StoragePresignRequest,
            UpdatePostRequest,
        },
    },
    types::{Certificate, Contract, ContractStatus, ContractType, Role, WitnessSecret},
    wallet::{RgbWallet, WalletSlotRecord},
    Identity,
};
use rand::Rng;
use reqwest::Method;
use serde::Serialize;
use serde_json::Value;
use webylib::{Amount as WebcashAmount, SecretWebcash};

#[path = "hrmw/cli_support.rs"]
mod cli_support;
#[path = "hrmw/media.rs"]
mod media;
#[path = "hrmw/request_engine.rs"]
mod request_engine;
use cli_support::{
    build_activity_metadata, build_post_attachments, check_master_in_password_manager,
    effective_label, extract_webcash_secret, labeled_wallet_display_path, make_client,
    next_contract_id, now_utc, open_or_create_wallet, parse_amount_to_units, parse_keywords_csv,
    remove_master_from_password_manager, resolve_bitcoin_db_path, resolve_voucher_wallet,
    resolve_wallet_path, resolve_webcash_wallet, store_master_in_password_manager,
    write_recovery_sidecar,
};
use media::{prepare_avatar_image, prepare_post_image};
use request_engine::{execute_paid_request, RequestBodySpec, RequestResponse, RequestSpec};

const DEFAULT_API_URL: &str = "https://harmoniis.com/api";

/// Derive the `bitcoin.db` path from the wallet path (sibling to `master.db`).
/// Used by ARK and other subsystems that always operate on the main bitcoin wallet.
fn bitcoin_db_path(wallet_path: &std::path::Path) -> std::path::PathBuf {
    resolve_bitcoin_db_path(wallet_path, None)
}

/// Open a labeled bitcoin wallet. Uses `--label` for HD derivation and DB path.
fn open_labeled_bitcoin_wallet(
    wallet: &harmoniis_wallet::wallet::RgbWallet,
    network: Network,
    wallet_path: &std::path::Path,
    label: Option<&str>,
) -> anyhow::Result<DeterministicBitcoinWallet> {
    let lbl = effective_label(label);
    let (slot_hex, _index) = wallet
        .derive_bitcoin_secret_for_label(lbl)
        .context("failed to derive labeled bitcoin wallet")?;
    let db_path = resolve_bitcoin_db_path(wallet_path, label);
    DeterministicBitcoinWallet::from_slot_seed_hex(&slot_hex, network, Some(db_path))
        .map_err(anyhow::Error::from)
}

/// Lazy CUDA-toolkit installer trigger. Called from `hrmw webminer start`
/// when GPU mining is in play. On Linux with an NVIDIA driver but no
/// `libnvrtc.so`, prompts the user (default Y) to install. On decline,
/// double-checks (the wgpu fallback works but at lower hashrate). On
/// non-apt distros, prints manual install steps and continues.
///
/// Always returns `Ok(())` — failures and refusals are non-fatal because
/// the wgpu Vulkan/DX12 backend is a real fallback.
#[cfg(all(feature = "cuda", target_os = "linux"))]
fn ensure_cuda_toolkit_if_needed(choice: CudaInstallChoice) -> anyhow::Result<()> {
    use harmoniis_wallet::miner::cuda_install;
    use std::io::{self, IsTerminal, Write};

    if matches!(choice, CudaInstallChoice::No) {
        return Ok(());
    }

    let Some(driver_major) = cuda_install::driver_cuda_major() else {
        return Ok(()); // No NVIDIA driver — nothing CUDA can do here.
    };
    if cuda_install::nvrtc_present() {
        return Ok(()); // Already installed.
    }

    let Some(distro) = cuda_install::detect_apt_distro() else {
        eprintln!(
            "NVIDIA driver detected (CUDA {driver_major}) but the CUDA toolkit \
             is not installed. Your distro is not apt-based, so hrmw cannot \
             install it for you — please install `cuda-nvrtc` (or the full \
             toolkit) for CUDA {driver_major}.x from \
             https://developer.nvidia.com/cuda-toolkit-archive"
        );
        eprintln!("Continuing with the wgpu Vulkan backend (slower hashrate).");
        return Ok(());
    };

    let proceed = match choice {
        CudaInstallChoice::Yes => true,
        CudaInstallChoice::No => false, // unreachable due to early return
        CudaInstallChoice::Auto => {
            if !io::stdin().is_terminal() {
                eprintln!(
                    "NVIDIA driver detected (CUDA {driver_major}) but CUDA toolkit \
                     is missing. Skipping interactive install (no TTY). Pass \
                     --cuda-install yes to install non-interactively, or run \
                     `hrmw webminer start` from a terminal."
                );
                false
            } else {
                eprintln!(
                    "NVIDIA driver detected (CUDA {driver_major}) but the CUDA toolkit \
                     is missing — the CUDA mining backend cannot run without it.\n\
                     hrmw can install it for you from NVIDIA's official apt repo \
                     (~300 MB, requires sudo)."
                );
                eprint!("Install the CUDA toolkit now? [Y/n] ");
                io::stderr().flush().ok();
                let mut buf = String::new();
                io::stdin().read_line(&mut buf)?;
                let first = buf.trim().to_ascii_lowercase();
                if first.is_empty() || first == "y" || first == "yes" {
                    true
                } else {
                    // Double-check — fallback works but is slower.
                    eprintln!(
                        "Without the CUDA toolkit, hrmw will fall back to the wgpu \
                         Vulkan backend. Mining will still work, but hashrate will \
                         be significantly lower than CUDA."
                    );
                    eprint!("Are you sure you want to skip the CUDA install? [y/N] ");
                    io::stderr().flush().ok();
                    let mut confirm = String::new();
                    io::stdin().read_line(&mut confirm)?;
                    let c = confirm.trim().to_ascii_lowercase();
                    !(c == "y" || c == "yes")
                }
            }
        }
    };

    if !proceed {
        eprintln!("Continuing with the wgpu Vulkan backend.");
        return Ok(());
    }

    eprintln!(
        "Installing CUDA NVRTC for driver CUDA {driver_major} on {}{}...",
        distro.id, distro.version_id
    );
    match cuda_install::install_nvrtc(&distro, driver_major) {
        Ok(()) => eprintln!("CUDA toolkit installed — CUDA backend will be used."),
        Err(e) => eprintln!("CUDA install failed: {e}\nContinuing with the wgpu Vulkan backend."),
    }
    Ok(())
}

/// No-op on non-Linux or builds without the cuda feature — the prompt is
/// irrelevant because the cudarc-backed CUDA miner isn't compiled in.
#[cfg(not(all(feature = "cuda", target_os = "linux")))]
fn ensure_cuda_toolkit_if_needed(_choice: CudaInstallChoice) -> anyhow::Result<()> {
    Ok(())
}

/// If `--accept-terms` was not passed on the CLI, prompt the user interactively.
/// Returns `true` if terms were accepted, or an error if declined.
fn prompt_accept_terms_if_needed(flag: bool) -> anyhow::Result<bool> {
    if flag {
        return Ok(true);
    }
    use std::io::{self, Write};
    eprint!(
        "By running the webcash miner you agree to the terms of service at https://webcash.org.\n\
         Accept? [y/N] "
    );
    io::stderr().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    if input.trim().eq_ignore_ascii_case("y") || input.trim().eq_ignore_ascii_case("yes") {
        Ok(true)
    } else {
        anyhow::bail!("Terms not accepted. Pass --accept-terms to skip this prompt.")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum PaymentRail {
    Webcash,
    Bitcoin,
    Voucher,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum PasswordManagerMode {
    Required,
    BestEffort,
    Off,
}

// ── CLI structure ─────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "hrmw",
    version,
    author = "Harmoniis Contributors",
    about = "Harmoniis bearer wallet — RGB21 contracts and certificates via Witness",
    long_about = "\
hrmw is the reference CLI wallet for the Harmoniis marketplace for agents and robots.\n\
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
Wallet database: ~/.harmoniis/wallet/master.db (override with --wallet)\n\
\n\
Sibling stores are derived from the wallet directory.\n\
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

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Initialise or import a wallet (fresh default: ~/.harmoniis/wallet/master.db)
    Setup {
        /// Import existing BIP39 entropy hex (16/20/24/28/32 bytes)
        #[arg(long)]
        secret: Option<String>,
        /// Password manager storage policy for master material
        #[arg(long, value_enum, default_value_t = PasswordManagerMode::Required)]
        password_manager: PasswordManagerMode,
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

    /// Voucher prepaid-credit wallet operations
    #[command(subcommand)]
    Voucher(VoucherCmd),

    /// Identity operations
    #[command(subcommand)]
    Identity(IdentityCmd),

    /// Profile operations
    #[command(subcommand)]
    Profile(ProfileCmd),

    /// Timeline operations (post/comment/rate)
    #[command(subcommand)]
    Timeline(TimelineCmd),

    /// Generic paid request executor and 402 audit inspection
    #[command(alias = "402")]
    Req(ReqArgs),

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

    /// Upgrade hrmw to the latest release from GitHub
    #[command(alias = "self-update")]
    Upgrade,

    /// Test if a GPU adapter can compile the mining shader (internal use).
    #[command(hide = true)]
    GpuProbe {
        /// GPU vendor ID (PCI)
        #[arg(long)]
        vendor: u32,
        /// GPU device ID (PCI)
        #[arg(long)]
        device: u32,
        /// Backend name: vulkan, dx12, metal
        #[arg(long)]
        backend: String,
        /// PCI bus address (e.g. "0000:01:00.0") — identifies the exact physical GPU
        #[arg(long, default_value = "")]
        pci_bus: String,
    },
}

// ── Identity ──────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum DonationCmd {
    /// Claim one donation allocation for this wallet fingerprint (one per key)
    Claim,
}

#[derive(Subcommand)]
enum WebcashCmd {
    /// Show Webcash balance and output counts
    Info {
        /// Use a labeled sub-wallet (e.g. "mining") instead of the default
        #[arg(long)]
        label: Option<String>,
    },
    /// Insert a bearer webcash secret (`e<amount>:secret:<hex>`) into the local wallet
    Insert {
        /// Full secret webcash string
        secret: String,
        /// Use a labeled sub-wallet (e.g. "mining") instead of the default
        #[arg(long)]
        label: Option<String>,
    },
    /// Pay: produce a secret webcash string for the recipient
    Pay {
        /// Amount in webcash decimal (e.g. 0.3, 1.5, 0.00000001)
        amount: String,
        /// Optional memo
        #[arg(long, default_value = "hrmw payment")]
        memo: String,
        /// Use a labeled sub-wallet (e.g. "mining") instead of the default
        #[arg(long)]
        label: Option<String>,
    },
    /// Verify unspent outputs against the Webcash server
    Check {
        /// Use a labeled sub-wallet (e.g. "mining") instead of the default
        #[arg(long)]
        label: Option<String>,
    },
    /// Recover wallet outputs from deterministic master secret
    Recover {
        #[arg(long, default_value_t = 20)]
        gap_limit: usize,
        /// Use a labeled sub-wallet (e.g. "mining") instead of the default
        #[arg(long)]
        label: Option<String>,
    },
    /// Consolidate many outputs into fewer outputs
    Merge {
        #[arg(long, default_value_t = 20)]
        group: usize,
        /// Use a labeled sub-wallet (e.g. "mining") instead of the default
        #[arg(long)]
        label: Option<String>,
    },
    /// List available labeled webcash wallets
    Labels,
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
        /// Use a labeled sub-wallet instead of the default "main"
        #[arg(long)]
        label: Option<String>,
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
        /// Use a labeled sub-wallet instead of the default "main"
        #[arg(long)]
        label: Option<String>,
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
        /// Use a labeled sub-wallet instead of the default "main"
        #[arg(long)]
        label: Option<String>,
    },
    /// Send sats on-chain from deterministic taproot wallet
    Send {
        /// Destination on-chain Bitcoin address
        address: String,
        /// Amount in satoshis
        amount: u64,
        /// Bitcoin network
        #[arg(long, value_enum, default_value_t = BitcoinNetworkArg::Bitcoin)]
        network: BitcoinNetworkArg,
        /// Esplora base URL (defaults per network)
        #[arg(long)]
        esplora: Option<String>,
        /// Target fee rate in sat/vB (default 10 for reasonable mainnet confirmation)
        #[arg(long, default_value_t = 10)]
        fee_rate_sat_vb: u64,
        /// Gap limit used for full scan
        #[arg(long, default_value_t = 20)]
        stop_gap: usize,
        /// Max parallel HTTP requests used during scan
        #[arg(long, default_value_t = 4)]
        parallel_requests: usize,
        /// Use a labeled sub-wallet instead of the default "main"
        #[arg(long)]
        label: Option<String>,
    },
    /// ARK protocol offchain Bitcoin operations (via Arkade ASP)
    #[command(subcommand)]
    Ark(BitcoinArkCmd),
    /// List available labeled bitcoin wallets
    Labels,
}

#[derive(Subcommand)]
enum BitcoinArkCmd {
    /// Show full ARK + on-chain wallet status (addresses and balances)
    Info {
        /// Bitcoin network
        #[arg(long, value_enum, default_value_t = BitcoinNetworkArg::Bitcoin)]
        network: BitcoinNetworkArg,
        /// Arkade ASP URL
        #[arg(long, default_value = harmoniis_wallet::ark::DEFAULT_ASP_URL)]
        asp_url: String,
    },
    /// Deposit: show ARK boarding address (send on-chain BTC here)
    Deposit {
        /// Bitcoin network
        #[arg(long, value_enum, default_value_t = BitcoinNetworkArg::Bitcoin)]
        network: BitcoinNetworkArg,
        /// Arkade ASP URL
        #[arg(long, default_value = harmoniis_wallet::ark::DEFAULT_ASP_URL)]
        asp_url: String,
    },
    /// Show a fresh ARK offchain receive address (VTXO receive)
    Offchain {
        /// Bitcoin network
        #[arg(long, value_enum, default_value_t = BitcoinNetworkArg::Bitcoin)]
        network: BitcoinNetworkArg,
        /// Arkade ASP URL
        #[arg(long, default_value = harmoniis_wallet::ark::DEFAULT_ASP_URL)]
        asp_url: String,
    },
    /// Show a fresh on-chain address controlled by this ARK wallet
    Onchain {
        /// Bitcoin network
        #[arg(long, value_enum, default_value_t = BitcoinNetworkArg::Bitcoin)]
        network: BitcoinNetworkArg,
        /// Arkade ASP URL
        #[arg(long, default_value = harmoniis_wallet::ark::DEFAULT_ASP_URL)]
        asp_url: String,
    },
    /// Show offchain ARK balance
    Balance {
        /// Bitcoin network
        #[arg(long, value_enum, default_value_t = BitcoinNetworkArg::Bitcoin)]
        network: BitcoinNetworkArg,
        /// Arkade ASP URL
        #[arg(long, default_value = harmoniis_wallet::ark::DEFAULT_ASP_URL)]
        asp_url: String,
    },
    /// Boarding: finalize deposited on-chain BTC into ARK offchain VTXOs
    Boarding {
        /// Bitcoin network
        #[arg(long, value_enum, default_value_t = BitcoinNetworkArg::Bitcoin)]
        network: BitcoinNetworkArg,
        /// Arkade ASP URL
        #[arg(long, default_value = harmoniis_wallet::ark::DEFAULT_ASP_URL)]
        asp_url: String,
    },
    /// Send a VTXO payment to another ARK address
    Send {
        /// Recipient ARK address
        address: String,
        /// Amount in satoshis
        amount: u64,
        /// Bitcoin network
        #[arg(long, value_enum, default_value_t = BitcoinNetworkArg::Bitcoin)]
        network: BitcoinNetworkArg,
        /// Arkade ASP URL
        #[arg(long, default_value = harmoniis_wallet::ark::DEFAULT_ASP_URL)]
        asp_url: String,
    },
    /// ARK settle-address: move ARK funds to an on-chain Bitcoin address
    SettleAddress {
        /// Destination on-chain Bitcoin address (must match selected network)
        address: String,
        /// Amount in satoshis
        amount: u64,
        /// Bitcoin network
        #[arg(long, value_enum, default_value_t = BitcoinNetworkArg::Bitcoin)]
        network: BitcoinNetworkArg,
        /// Arkade ASP URL
        #[arg(long, default_value = harmoniis_wallet::ark::DEFAULT_ASP_URL)]
        asp_url: String,
    },
    /// Settle ARK offchain to this wallet's deterministic taproot on-chain address
    Settle {
        /// Amount in satoshis
        amount: u64,
        /// Taproot external address index
        #[arg(long, default_value_t = 0)]
        index: u32,
        /// Bitcoin network
        #[arg(long, value_enum, default_value_t = BitcoinNetworkArg::Bitcoin)]
        network: BitcoinNetworkArg,
        /// Arkade ASP URL
        #[arg(long, default_value = harmoniis_wallet::ark::DEFAULT_ASP_URL)]
        asp_url: String,
    },
    /// Verify an ARK proof string against this wallet's offchain VTXO set
    VerifyProof {
        /// ARK proof: ark:<vtxo_txid>:<amount_sats>
        proof: String,
        /// Optional minimum sats required for verification
        #[arg(long)]
        min_amount_sats: Option<u64>,
        /// Bitcoin network
        #[arg(long, value_enum, default_value_t = BitcoinNetworkArg::Bitcoin)]
        network: BitcoinNetworkArg,
        /// Arkade ASP URL
        #[arg(long, default_value = harmoniis_wallet::ark::DEFAULT_ASP_URL)]
        asp_url: String,
    },
}

#[derive(Subcommand)]
enum VoucherCmd {
    /// Show Voucher balance and output counts
    Info {
        /// Use a labeled sub-wallet instead of the default "main"
        #[arg(long)]
        label: Option<String>,
    },
    /// Insert a voucher secret into the local wallet
    Insert {
        /// Full voucher secret string: v<amount>:secret:<hex>
        secret: String,
        /// Use a labeled sub-wallet instead of the default "main"
        #[arg(long)]
        label: Option<String>,
    },
    /// Pay: produce a voucher secret string for the recipient
    Pay {
        /// Amount in credits (e.g. 1, 0.5, 0.00000001)
        amount: String,
        /// Optional memo
        #[arg(long, default_value = "hrmw voucher payment")]
        memo: String,
        /// Use a labeled sub-wallet instead of the default "main"
        #[arg(long)]
        label: Option<String>,
    },
    /// Verify unspent outputs against the voucher service
    Check {
        /// Use a labeled sub-wallet instead of the default "main"
        #[arg(long)]
        label: Option<String>,
    },
    /// Recover wallet outputs from deterministic master secret
    Recover {
        #[arg(long, default_value_t = 20)]
        gap_limit: usize,
        /// Use a labeled sub-wallet instead of the default "main"
        #[arg(long)]
        label: Option<String>,
    },
    /// Consolidate many outputs into fewer outputs
    Merge {
        #[arg(long, default_value_t = 20)]
        group: usize,
        /// Use a labeled sub-wallet instead of the default "main"
        #[arg(long)]
        label: Option<String>,
    },
    /// List available labeled voucher wallets
    Labels,
}

#[derive(Subcommand)]
enum IdentityCmd {
    /// Register this wallet's identity on the Harmoniis network
    #[command(alias = "claim")]
    Register {
        #[arg(long)]
        nick: String,
        #[arg(long)]
        about: Option<String>,
        /// Use a specific labeled PGP identity (defaults to active label)
        #[arg(long)]
        label: Option<String>,
    },
    /// Delete an identity and all authored content (requires matching private key)
    Delete {
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
        /// BIP39 entropy hex (16/20/24/28/32 bytes)
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
    /// Create or materialize a labeled vault-derived identity for MQTT/TLS use
    VaultNew {
        /// Human label for the derived vault identity
        #[arg(long)]
        label: Option<String>,
        /// Explicit vault slot index to materialize (index 0 is reserved for the vault root)
        #[arg(long)]
        index: Option<u32>,
    },
    /// List labeled vault-derived identities
    VaultList,
    /// Export a vault-derived identity private key as PKCS#8 PEM
    VaultExport {
        /// Label of the vault-derived identity to export
        #[arg(long)]
        label: Option<String>,
        /// Explicit vault slot index to export
        #[arg(long)]
        index: Option<u32>,
        /// Optional file path to write the PEM private key
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Sign an arbitrary message with a vault-derived identity
    VaultSign {
        /// Label of the vault-derived identity to use
        #[arg(long)]
        label: Option<String>,
        /// Explicit vault slot index to use
        #[arg(long)]
        index: Option<u32>,
        /// Message to sign
        #[arg(long)]
        message: String,
    },
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

#[derive(Args)]
struct ReqArgs {
    #[command(subcommand)]
    action: Option<ReqAction>,

    /// Absolute service base URL (for example https://harmoniis.com/api or http://localhost:9001/api/v1)
    #[arg(long)]
    url: Option<String>,

    /// Relative endpoint path or absolute URL to call
    #[arg(long, default_value = "")]
    endpoint: String,

    /// HTTP request method (GET, POST, PUT, PATCH, DELETE, ...)
    #[arg(long, default_value = "GET")]
    method: String,

    /// Query parameter in key=value form (repeatable)
    #[arg(long = "query")]
    query_params: Vec<String>,

    /// Header in key=value form (repeatable)
    #[arg(long = "header")]
    headers: Vec<String>,

    /// Inline JSON body payload
    #[arg(long)]
    json: Option<String>,

    /// Read JSON body payload from file
    #[arg(long)]
    json_file: Option<PathBuf>,

    /// Inline raw body payload
    #[arg(long)]
    body: Option<String>,

    /// Read raw body payload from file
    #[arg(long)]
    body_file: Option<PathBuf>,

    /// Explicit content type for raw body payloads
    #[arg(long, default_value = "application/octet-stream")]
    content_type: String,
}

#[derive(Subcommand)]
enum ReqAction {
    /// Show paid requests that consumed value and were not recovered
    Losses,
    /// Manage the automatic payment blacklist
    #[command(subcommand)]
    Blacklist(ReqBlacklistCmd),
}

#[derive(Subcommand)]
enum ReqBlacklistCmd {
    /// List blacklisted paid endpoints
    List,
    /// Clear one blacklist entry
    Clear {
        #[arg(long)]
        url: String,
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        method: String,
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
        /// Optional minimum listing price in decimal format for --currency
        /// (defaults to webcash when --currency is omitted)
        #[arg(long)]
        price_min: Option<String>,
        /// Optional maximum listing price in decimal format for --currency
        /// (defaults to webcash when --currency is omitted)
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

    /// Buy a new contract (buyer pays using selected payment rail).
    ///
    /// Calls POST /api/arbitration/contracts/buy.
    #[command(alias = "issue")]
    Buy {
        /// Post ID of the seller's service offer on the timeline
        #[arg(long)]
        post: String,
        /// Contract value in decimal units of the listing rail
        /// (e.g. "1.5" for webcash, "0.000001" for bitcoin).
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

    /// Pick up verified work and receive certificate (buyer, free — 3% included in bid).
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
enum CudaInstallChoice {
    /// Prompt before installing if NVRTC is missing (default).
    Auto,
    /// Install without prompting (non-interactive).
    Yes,
    /// Never install — fall back to wgpu silently.
    No,
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
    /// List all available GPU mining devices
    ListDevices,
    /// Start mining (background by default, --foreground for live logs)
    Start {
        /// Webcash server URL (default: webcash.org from webylib)
        #[arg(long, default_value_t = webylib::NetworkMode::Production.base_url().to_string())]
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
        /// Comma-separated device IDs to mine on (from list-devices)
        #[arg(long, value_delimiter = ',')]
        device: Option<Vec<usize>>,
        /// Run in foreground with live logs (default: background daemon)
        #[arg(short = 'f', long)]
        foreground: bool,
        /// Master wallet path (defaults to global --wallet)
        #[arg(long)]
        wallet: Option<PathBuf>,
        /// Webcash wallet path (defaults to sibling webcash wallet path)
        #[arg(long, name = "webcash-wallet")]
        webcash_wallet: Option<PathBuf>,
        /// Auto-install the CUDA toolkit if a NVIDIA driver is detected
        /// but NVRTC is missing. Values: auto (prompt, default), yes
        /// (install without prompting), no (skip install, fall back to wgpu).
        #[arg(long, value_enum, default_value_t = CudaInstallChoice::Auto)]
        cuda_install: CudaInstallChoice,
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
    /// Submit pending mined solutions that weren't reported to the server
    Collect {
        /// Run in background (daemon mode — used automatically after cloud stop)
        #[arg(short = 'd', long)]
        daemon: bool,
    },
    /// Cloud mining on Vast.ai GPU instances
    Cloud {
        #[command(subcommand)]
        cmd: CloudCmd,
    },
    /// Internal: subprocess reporter (spawned by mining daemon, not for manual use)
    #[command(name = "report-worker")]
    ReportWorker {
        /// Server URL
        #[arg(long)]
        server: String,
        /// Pre-resolved server address (ip:port)
        #[arg(long)]
        resolved_addr: String,
        /// Number of independent HTTP clients (each = own TCP connection)
        #[arg(long, default_value = "60")]
        clients: usize,
        /// Path to webcash wallet database
        #[arg(long)]
        webcash_wallet: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum CloudCmd {
    /// Provision Vast.ai GPU instance(s) and start mining
    Start {
        /// Label for the mining wallet
        #[arg(long, default_value = "cloudminer")]
        label: String,
        /// Use a specific Vast.ai offer ID (from the # column or Vast.ai website)
        #[arg(long, alias = "machine")]
        offer: Option<u64>,
        /// Number of instances to provision
        #[arg(short = 'n', long, default_value = "1")]
        count: usize,
        /// Environment: 'dev' clones + builds from source for interactive testing
        #[arg(long)]
        env: Option<String>,
    },
    /// Stop miner(s), recover mined webcash, transfer to main wallet
    Stop {
        /// Instance number to stop (1-based). Omit to stop all.
        #[arg(short = 'n', long)]
        instance: Option<usize>,
    },
    /// Destroy Vast.ai instance(s) (stops charges)
    Destroy {
        /// Instance number to destroy (1-based). Omit to destroy all.
        #[arg(short = 'n', long)]
        instance: Option<usize>,
    },
    /// Show remote miner status
    Status {
        /// Instance number (1-based). Omit to show all.
        #[arg(short = 'n', long)]
        instance: Option<usize>,
    },
    /// Show mining wallet info
    Info {
        /// Label for the mining wallet
        #[arg(long, default_value = "cloudminer")]
        label: String,
    },
    /// Continuously sync + submit solutions from remote instances
    Watch {
        /// Seconds between sync cycles
        #[arg(long, default_value = "30")]
        interval: u64,
    },
    /// Set Vast.ai API key
    #[command(name = "set-api-key")]
    SetApiKey {
        /// Your Vast.ai API key
        key: String,
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

#[allow(unused_variables)]
async fn run_webminer_benchmarks(
    cpu_threads: Option<usize>,
    cpu_target_mhs: f64,
    gpu_target_mhs: f64,
    strict: bool,
) -> anyhow::Result<()> {
    use harmoniis_wallet::miner::simd_cpu::SimdCpuMiner;
    use harmoniis_wallet::miner::MinerBackend;

    #[allow(unused_assignments)]
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
            let wgpu_miners = harmoniis_wallet::miner::init_wgpu_miners_from_devices().await;
            if let Some(gpu) = MultiGpuMiner::from_miners(wgpu_miners).await {
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
        failed |= true;
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

fn pick_vault_identity(
    wallet: &RgbWallet,
    label: Option<&str>,
    index: Option<u32>,
) -> anyhow::Result<(WalletSlotRecord, Identity)> {
    match (label, index) {
        (Some(_), Some(_)) => anyhow::bail!("provide either --label or --index, not both"),
        (Some(name), None) => {
            let meta = wallet.vault_identity_by_label(name)?;
            let identity = wallet.derive_vault_identity_for_index(meta.slot_index)?;
            Ok((meta, identity))
        }
        (None, Some(slot_index)) => {
            let meta = wallet.vault_identity_by_index(slot_index)?;
            let identity = wallet.derive_vault_identity_for_index(meta.slot_index)?;
            Ok((meta, identity))
        }
        (None, None) => anyhow::bail!("provide --label or --index"),
    }
}

fn payment_rail_name(rail: PaymentRail) -> &'static str {
    match rail {
        PaymentRail::Webcash => "webcash",
        PaymentRail::Bitcoin => "bitcoin",
        PaymentRail::Voucher => "voucher",
    }
}

fn canonical_api_base(api: &str, direct: bool) -> String {
    let trimmed = api.trim_end_matches('/');
    if direct {
        if trimmed.ends_with("/api/v1") {
            trimmed.to_string()
        } else {
            format!("{trimmed}/api/v1")
        }
    } else if trimmed.ends_with("/api") || trimmed.ends_with("/api/v1") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/api")
    }
}

fn parse_key_value_arg(raw: &str, kind: &str) -> anyhow::Result<(String, String)> {
    let Some((key, value)) = raw.split_once('=') else {
        anyhow::bail!("{kind} must be in key=value form");
    };
    let key = key.trim();
    if key.is_empty() {
        anyhow::bail!("{kind} key must not be empty");
    }
    Ok((key.to_string(), value.to_string()))
}

fn resolve_request_url(base_url: &str, endpoint: &str) -> anyhow::Result<reqwest::Url> {
    if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        return reqwest::Url::parse(endpoint).context("invalid absolute endpoint url");
    }
    let mut base = reqwest::Url::parse(base_url).context("invalid base url")?;
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

fn request_body_from_json<T: Serialize>(payload: &T) -> anyhow::Result<RequestBodySpec> {
    Ok(RequestBodySpec::Json(
        serde_json::to_value(payload).context("failed to serialize request body")?,
    ))
}

fn build_marketplace_request<T: Serialize>(
    api: &str,
    direct: bool,
    payment_rail: PaymentRail,
    endpoint: &str,
    action_hint: &str,
    payload: &T,
) -> anyhow::Result<RequestSpec> {
    Ok(RequestSpec {
        base_url: canonical_api_base(api, direct),
        endpoint: endpoint.to_string(),
        method: Method::POST,
        headers: vec![],
        query: vec![],
        body: request_body_from_json(payload)?,
        action_hint: action_hint.to_string(),
        desired_rail: Some(payment_rail),
    })
}

fn ensure_success_json(response: RequestResponse) -> anyhow::Result<Value> {
    if !(200..300).contains(&response.status) {
        anyhow::bail!(
            "request failed with status {}: {}",
            response.status,
            response.body_text
        );
    }
    response
        .body_json
        .ok_or_else(|| anyhow::anyhow!("response was not valid JSON"))
}

fn ensure_success_status(response: RequestResponse) -> anyhow::Result<()> {
    if (200..300).contains(&response.status) {
        return Ok(());
    }
    anyhow::bail!(
        "request failed with status {}: {}",
        response.status,
        response.body_text
    );
}

async fn execute_marketplace_paid_json<T: Serialize>(
    wallet_path: &Path,
    api: &str,
    direct: bool,
    payment_rail: PaymentRail,
    endpoint: &str,
    action_hint: &str,
    payload: &T,
) -> anyhow::Result<Value> {
    let spec =
        build_marketplace_request(api, direct, payment_rail, endpoint, action_hint, payload)?;
    let response = execute_paid_request(wallet_path, &spec).await?;
    ensure_success_json(response)
}

async fn execute_marketplace_paid_status<T: Serialize>(
    wallet_path: &Path,
    api: &str,
    direct: bool,
    payment_rail: PaymentRail,
    endpoint: &str,
    action_hint: &str,
    payload: &T,
) -> anyhow::Result<()> {
    let spec =
        build_marketplace_request(api, direct, payment_rail, endpoint, action_hint, payload)?;
    let response = execute_paid_request(wallet_path, &spec).await?;
    ensure_success_status(response)
}

fn build_req_body(args: &ReqArgs) -> anyhow::Result<RequestBodySpec> {
    let json_count = args.json.is_some() as u8 + args.json_file.is_some() as u8;
    let raw_count = args.body.is_some() as u8 + args.body_file.is_some() as u8;
    if json_count > 1 {
        anyhow::bail!("provide only one of --json or --json-file");
    }
    if raw_count > 1 {
        anyhow::bail!("provide only one of --body or --body-file");
    }
    if json_count > 0 && raw_count > 0 {
        anyhow::bail!("choose JSON or raw body, not both");
    }

    if let Some(json_inline) = &args.json {
        let value = serde_json::from_str::<Value>(json_inline)
            .context("failed to parse inline JSON payload")?;
        return Ok(RequestBodySpec::Json(value));
    }
    if let Some(path) = &args.json_file {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read JSON file {}", path.display()))?;
        let value =
            serde_json::from_str::<Value>(&raw).context("failed to parse JSON body from file")?;
        return Ok(RequestBodySpec::Json(value));
    }
    if let Some(body) = &args.body {
        return Ok(RequestBodySpec::Raw {
            bytes: body.as_bytes().to_vec(),
            content_type: args.content_type.clone(),
        });
    }
    if let Some(path) = &args.body_file {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read body file {}", path.display()))?;
        return Ok(RequestBodySpec::Raw {
            bytes,
            content_type: args.content_type.clone(),
        });
    }
    Ok(RequestBodySpec::None)
}

fn print_request_response(response: &RequestResponse) -> anyhow::Result<()> {
    println!("Status: {}", response.status);
    println!("URL:    {}", response.url);
    if let Some(content_type) = &response.content_type {
        println!("Type:   {content_type}");
    }
    if let Some(body) = &response.body_json {
        println!("{}", serde_json::to_string_pretty(body)?);
    } else if !response.body_text.trim().is_empty() {
        println!("{}", response.body_text);
    }
    Ok(())
}

/// Offer to configure Vast.ai API key during setup.
/// If already configured, shows current status. Otherwise prompts.
fn setup_vast_api_key() -> anyhow::Result<()> {
    use harmoniis_wallet::miner::cloud::config as cloud_config;

    let cfg = cloud_config::load_config()?;
    if let Some(key) = &cfg.vast_api_key {
        if !key.is_empty() {
            println!();
            println!(
                "Vast.ai: configured (key ends in ...{})",
                &key[key.len().saturating_sub(8)..]
            );
            return Ok(());
        }
    }

    println!();
    println!("Cloud mining (optional):");
    println!("  Vast.ai GPU cloud for webcash mining.");
    println!("  Get an API key: https://cloud.vast.ai → Account → API Key");
    print!("Vast.ai API key (Enter to skip): ");
    use std::io::Write;
    std::io::stdout().flush()?;

    let mut key = String::new();
    std::io::stdin().read_line(&mut key)?;
    let key = key.trim().to_string();

    if key.is_empty() {
        println!("  Skipped. Configure later with: hrmw webminer cloud set-api-key <KEY>");
    } else {
        let mut cfg = cloud_config::load_config()?;
        cfg.vast_api_key = Some(key);
        cloud_config::save_config(&cfg)?;
        println!("  Vast.ai API key saved.");
    }

    Ok(())
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
        arbitration_profit_wats: None,
        seller_value_wats: None,
    })
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let wallet_path = resolve_wallet_path(cli.wallet.clone());
    if let Some(wallet_root) = wallet_path.parent() {
        std::env::set_var("HARMONIIS_WALLET_ROOT", wallet_root);
    }
    let api = cli.api.as_str();
    let direct = cli.direct;
    let payment_rail = cli.payment_rail;

    match cli.command {
        // ── setup ─────────────────────────────────────────────────────────────
        Cmd::Setup {
            secret,
            password_manager,
        } => {
            if wallet_path.exists() {
                // ── Re-run mode: open existing wallet, apply settings ────────
                let wallet =
                    RgbWallet::open(&wallet_path).context("failed to open existing wallet")?;
                println!("Wallet: {}", wallet_path.display());
                println!("Fingerprint: {}", wallet.fingerprint()?);
                if let Some(label) = wallet.wallet_label()? {
                    println!("Label: {label}");
                }
                let pgp = wallet.list_pgp_identities()?;
                println!("PGP identities: {}", pgp.len());
                match check_master_in_password_manager(&wallet_path, &wallet) {
                    Ok(true) => println!("Password manager: stored"),
                    Ok(false) => println!("Password manager: not stored"),
                    Err(_) => println!("Password manager: unknown"),
                }

                if secret.is_some() {
                    anyhow::bail!(
                        "cannot re-import key material via setup; \
                         use `hrmw key import --force` instead"
                    );
                }

                match password_manager {
                    PasswordManagerMode::Required => {
                        let backend = store_master_in_password_manager(&wallet_path, &wallet)?;
                        println!("Stored master material in {}.", backend.label());
                    }
                    PasswordManagerMode::BestEffort => {
                        match store_master_in_password_manager(&wallet_path, &wallet) {
                            Ok(b) => println!("Stored master material in {}.", b.label()),
                            Err(e) => eprintln!(
                                "Warning: could not store master material in password manager: {e}"
                            ),
                        }
                    }
                    PasswordManagerMode::Off => {
                        match remove_master_from_password_manager(&wallet_path, &wallet) {
                            Ok(b) => {
                                println!("Removed master material from {}.", b.label());
                                eprintln!();
                                eprintln!("Important: your master key is no longer in the OS credential store.");
                                eprintln!("Back up your wallet now:");
                                eprintln!("  hrmw key export --format mnemonic");
                                eprintln!("  (write down the 12 words and store them offline)");
                            }
                            Err(e) => eprintln!("Note: {e}"),
                        }
                    }
                }

                // Offer to configure Vast.ai API key for cloud mining
                setup_vast_api_key()?;

                return Ok(());
            }

            // ── First-run: create new wallet ─────────────────────────────────
            let wallet = RgbWallet::create(&wallet_path).context("failed to create wallet")?;
            if let Some(hex) = secret {
                wallet
                    .apply_master_key_hex(&hex)
                    .context("invalid BIP39 entropy hex")?;
                println!("Wallet imported from master key.");
                println!("Fingerprint: {}", wallet.fingerprint()?);
            } else {
                println!("Wallet created at {}", wallet_path.display());
                println!("Fingerprint: {}", wallet.fingerprint()?);
            }
            if let Some(label) = wallet.wallet_label()? {
                println!("Wallet label: {label}");
            }
            let pgp = wallet.list_pgp_identities()?;
            println!("PGP identities: {}", pgp.len());
            write_recovery_sidecar(&wallet_path, &wallet, true)?;
            match password_manager {
                PasswordManagerMode::Required => {
                    let backend = store_master_in_password_manager(&wallet_path, &wallet)?;
                    println!(
                        "Saved master material to password manager: {}.",
                        backend.label()
                    );
                }
                PasswordManagerMode::BestEffort => {
                    match store_master_in_password_manager(&wallet_path, &wallet) {
                        Ok(backend) => println!(
                            "Saved master material to password manager: {}.",
                            backend.label()
                        ),
                        Err(e) => eprintln!(
                            "Warning: could not store master material in password manager: {e}"
                        ),
                    }
                }
                PasswordManagerMode::Off => {}
            }

            // Offer to configure Vast.ai API key for cloud mining
            setup_vast_api_key()?;
        }

        // ── info ──────────────────────────────────────────────────────────────
        Cmd::Info => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let (active_label, active_pgp) = active_pgp_identity(&wallet)?;
            let webcash_wallet = resolve_webcash_wallet(&wallet_path, &wallet, None).await?;
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
                        let webcash_wallet =
                            resolve_webcash_wallet(&wallet_path, &wallet, None).await?;
                        let parsed = SecretWebcash::parse(&secret)
                            .map_err(|e| anyhow::anyhow!("invalid donated webcash format: {e}"))?;
                        webcash_wallet
                            .insert(parsed)
                            .await
                            .context("failed to insert donated webcash into wallet")?;
                        println!("Donation claimed.");
                        println!(
                            "Inserted into wallet: {}",
                            labeled_wallet_display_path(&wallet_path, "webcash", None).display()
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
        Cmd::Webcash(WebcashCmd::Labels) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let wallets = wallet.list_labeled_wallets("webcash")?;
            if wallets.is_empty() {
                println!("No labeled webcash wallets.");
            } else {
                println!("{:<24} {:>6}  db_filename", "label", "slot");
                for w in wallets {
                    println!("{:<24} {:>6}  {}", w.label, w.slot_index, w.db_filename);
                }
            }
        }

        Cmd::Webcash(WebcashCmd::Info { label }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let webcash_wallet =
                resolve_webcash_wallet(&wallet_path, &wallet, label.as_deref()).await?;
            let balance = webcash_wallet.balance().await?;
            let stats = webcash_wallet.stats().await?;
            let path = labeled_wallet_display_path(&wallet_path, "webcash", label.as_deref());
            println!("Webcash wallet: {}", path.display());
            println!("Balance:        {}", balance);
            println!("Unspent:        {}", stats.unspent_webcash);
            println!("Total outputs:  {}", stats.total_webcash);
            println!("Spent outputs:  {}", stats.spent_webcash);
        }

        Cmd::Webcash(WebcashCmd::Insert { secret, label }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let webcash_wallet =
                resolve_webcash_wallet(&wallet_path, &wallet, label.as_deref()).await?;
            let parsed = SecretWebcash::parse(&secret)
                .map_err(|e| anyhow::anyhow!("invalid webcash secret format: {e}"))?;
            webcash_wallet
                .insert(parsed)
                .await
                .context("failed to insert webcash")?;
            let balance = webcash_wallet.balance().await?;
            let path = labeled_wallet_display_path(&wallet_path, "webcash", label.as_deref());
            println!("Inserted webcash into {}", path.display());
            println!("Balance: {balance}");
        }

        Cmd::Webcash(WebcashCmd::Pay {
            amount,
            memo,
            label,
        }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let webcash_wallet =
                resolve_webcash_wallet(&wallet_path, &wallet, label.as_deref()).await?;
            let parsed_amount = WebcashAmount::from_str(&amount)
                .with_context(|| format!("invalid webcash amount '{amount}'"))?;
            let output = webcash_wallet
                .pay(parsed_amount, &memo)
                .await
                .context("failed to create payment")?;
            let secret = extract_webcash_secret(&output)?;
            println!("Payment secret (webcash):");
            println!("{secret}");
        }

        Cmd::Webcash(WebcashCmd::Check { label }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let webcash_wallet =
                resolve_webcash_wallet(&wallet_path, &wallet, label.as_deref()).await?;
            webcash_wallet
                .check()
                .await
                .context("webcash check failed")?;
            println!("Webcash check passed.");
        }

        Cmd::Webcash(WebcashCmd::Recover { gap_limit, label }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let webcash_wallet =
                resolve_webcash_wallet(&wallet_path, &wallet, label.as_deref()).await?;
            let summary = webcash_wallet
                .recover_from_wallet(gap_limit)
                .await
                .context("webcash recovery failed")?;
            println!("{summary}");
        }

        Cmd::Webcash(WebcashCmd::Merge { group, label }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let webcash_wallet =
                resolve_webcash_wallet(&wallet_path, &wallet, label.as_deref()).await?;
            let summary = webcash_wallet
                .merge(group)
                .await
                .context("webcash merge failed")?;
            println!("{summary}");
        }

        // ── voucher prepaid-credit wallet ────────────────────────────────────
        Cmd::Voucher(VoucherCmd::Labels) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let wallets = wallet.list_labeled_wallets("voucher")?;
            if wallets.is_empty() {
                println!("No labeled voucher wallets.");
            } else {
                println!("{:<24} {:>6}  db_filename", "label", "slot");
                for w in wallets {
                    println!("{:<24} {:>6}  {}", w.label, w.slot_index, w.db_filename);
                }
            }
        }
        Cmd::Voucher(cmd) => {
            let label = match &cmd {
                VoucherCmd::Info { label } => label.as_deref(),
                VoucherCmd::Insert { label, .. } => label.as_deref(),
                VoucherCmd::Pay { label, .. } => label.as_deref(),
                VoucherCmd::Check { label } => label.as_deref(),
                VoucherCmd::Recover { label, .. } => label.as_deref(),
                VoucherCmd::Merge { label, .. } => label.as_deref(),
                VoucherCmd::Labels => unreachable!(),
            };
            let wallet = open_or_create_wallet(&wallet_path)?;
            let client = make_client(api, direct);
            let voucher_wallet = resolve_voucher_wallet(&wallet_path, &wallet, label)?;
            let display_path = labeled_wallet_display_path(&wallet_path, "voucher", label);
            match cmd {
                VoucherCmd::Info { .. } => {
                    let stats = voucher_wallet.stats()?;
                    println!("Voucher wallet: {}", display_path.display());
                    let whole = stats.balance_units / 100_000_000;
                    let frac = stats.balance_units % 100_000_000;
                    if frac == 0 {
                        println!("Balance:        {} credits", whole);
                    } else {
                        let frac_str = format!("{:08}", frac).trim_end_matches('0').to_string();
                        println!("Balance:        {}.{} credits", whole, frac_str);
                    }
                    println!("Live outputs:   {}", stats.unspent_outputs);
                    println!("Total outputs:  {}", stats.total_outputs);
                    println!("Spent outputs:  {}", stats.spent_outputs);
                }
                VoucherCmd::Insert { secret, .. } => {
                    let parsed = harmoniis_wallet::VoucherSecret::parse(&secret)
                        .map_err(anyhow::Error::from)?;
                    voucher_wallet.insert(parsed)?;
                    let stats = voucher_wallet.stats()?;
                    println!("Inserted voucher into {}", display_path.display());
                    let w = stats.balance_units / 100_000_000;
                    let f = stats.balance_units % 100_000_000;
                    if f == 0 {
                        println!("Balance: {} credits", w);
                    } else {
                        println!(
                            "Balance: {}.{} credits",
                            w,
                            format!("{:08}", f).trim_end_matches('0')
                        );
                    }
                }
                VoucherCmd::Pay { amount, memo, .. } => {
                    let parsed: f64 = amount
                        .parse()
                        .map_err(|_| anyhow::anyhow!("invalid amount: '{amount}'"))?;
                    if parsed <= 0.0 {
                        anyhow::bail!("amount must be positive");
                    }
                    let amount_units = (parsed * 100_000_000.0).round() as u64;
                    if amount_units == 0 {
                        anyhow::bail!("amount too small — minimum 0.00000001 credits");
                    }
                    let output = voucher_wallet.pay(&client, amount_units, &memo).await?;
                    println!("Voucher payment:");
                    println!("{}", output.display());
                }
                VoucherCmd::Check { .. } => {
                    let refreshed = voucher_wallet.check(&client).await?;
                    println!(
                        "Voucher check complete. Live balance: {} credits",
                        refreshed.balance_units
                    );
                }
                VoucherCmd::Recover { gap_limit, .. } => {
                    let summary = voucher_wallet.recover_from_wallet(gap_limit)?;
                    println!("{summary}");
                }
                VoucherCmd::Merge { group, .. } => {
                    let summary = voucher_wallet.merge(&client, group).await?;
                    println!("{summary}");
                }
                VoucherCmd::Labels => unreachable!(),
            }
        }

        // ── bitcoin deterministic wallet ───────────────────────────────────
        Cmd::Bitcoin(BitcoinCmd::Labels) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let wallets = wallet.list_labeled_wallets("bitcoin")?;
            if wallets.is_empty() {
                println!("No labeled bitcoin wallets.");
            } else {
                println!("{:<24} {:>6}  db_filename", "label", "slot");
                for w in wallets {
                    println!("{:<24} {:>6}  {}", w.label, w.slot_index, w.db_filename);
                }
            }
        }
        Cmd::Bitcoin(BitcoinCmd::Info {
            network,
            esplora,
            no_sync,
            stop_gap,
            parallel_requests,
            label,
        }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let network = Network::from(network);
            let btc =
                open_labeled_bitcoin_wallet(&wallet, network, &wallet_path, label.as_deref())?;
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
            label,
        }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let network = Network::from(network);
            let btc =
                open_labeled_bitcoin_wallet(&wallet, network, &wallet_path, label.as_deref())?;
            let addr = btc.receive_address_at_kind(index, kind.into())?;
            println!("{addr}");
        }

        Cmd::Bitcoin(BitcoinCmd::Sync {
            network,
            esplora,
            stop_gap,
            parallel_requests,
            label,
        }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let network = Network::from(network);
            let btc =
                open_labeled_bitcoin_wallet(&wallet, network, &wallet_path, label.as_deref())?;
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

        Cmd::Bitcoin(BitcoinCmd::Send {
            address,
            amount,
            network,
            esplora,
            fee_rate_sat_vb,
            stop_gap,
            parallel_requests,
            label,
        }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let network = Network::from(network);
            let btc =
                open_labeled_bitcoin_wallet(&wallet, network, &wallet_path, label.as_deref())?;
            let esplora_url = resolved_esplora_url(network, esplora);
            let txid = btc.send_taproot_onchain(
                &esplora_url,
                &address,
                amount,
                fee_rate_sat_vb,
                stop_gap,
                parallel_requests,
            )?;
            println!("Sent {} sats on-chain", amount);
            println!("Destination: {address}");
            println!("Network:     {network}");
            println!("Esplora:     {esplora_url}");
            println!("TXID:        {txid}");
        }

        // ── ark ───────────────────────────────────────────────────────────────
        Cmd::Bitcoin(BitcoinCmd::Ark(BitcoinArkCmd::Info { network, asp_url })) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let network = Network::from(network);
            let btc = DeterministicBitcoinWallet::from_master_wallet(
                &wallet,
                network,
                Some(bitcoin_db_path(&wallet_path)),
            )?;
            let esplora_url = DeterministicBitcoinWallet::default_esplora_url(network);
            println!("Connecting to ARK ASP at {asp_url} ...");
            let ark = ArkPaymentWallet::connect(
                &btc,
                &asp_url,
                SqliteArkDb::open(&bitcoin_db_path(&wallet_path))?,
            )
            .await?;
            let boarding = ark.get_boarding_address()?;
            let offchain = ark.get_offchain_address()?;
            let onchain = ark.get_onchain_address()?;
            let onchain_sync = btc.sync(esplora_url, 20, 4);
            let balance = ark.offchain_balance().await?;
            println!("ARK wallet");
            println!("Status:         ok");
            println!("Network:        {network}");
            println!("ASP:            {asp_url}");
            println!("Boarding addr:  {boarding}");
            println!("Offchain addr:  {offchain}");
            println!("Onchain addr:   {onchain}");
            match onchain_sync {
                Ok(sync) => {
                    println!("Onchain confirmed:    {} sats", sync.confirmed_sats);
                    println!("Onchain trusted pend: {} sats", sync.trusted_pending_sats);
                    println!("Onchain untrusted:    {} sats", sync.untrusted_pending_sats);
                    println!("Onchain total:        {} sats", sync.total_sats);
                }
                Err(e) => {
                    println!("Onchain balance error: {e}");
                }
            }
            println!(
                "Offchain confirmed:   {} sats ({})",
                balance.confirmed_sats,
                format_btc_from_sats(balance.confirmed_sats)
            );
            println!(
                "Offchain pre-conf:    {} sats ({})",
                balance.pre_confirmed_sats,
                format_btc_from_sats(balance.pre_confirmed_sats)
            );
            println!(
                "Offchain total:       {} sats ({})",
                balance.total_sats,
                format_btc_from_sats(balance.total_sats)
            );
        }

        Cmd::Bitcoin(BitcoinCmd::Ark(BitcoinArkCmd::Deposit { network, asp_url })) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let network = Network::from(network);
            let btc = DeterministicBitcoinWallet::from_master_wallet(
                &wallet,
                network,
                Some(bitcoin_db_path(&wallet_path)),
            )?;
            let ark = ArkPaymentWallet::connect(
                &btc,
                &asp_url,
                SqliteArkDb::open(&bitcoin_db_path(&wallet_path))?,
            )
            .await?;
            let boarding = ark.get_boarding_address()?;
            println!("{boarding}");
        }

        Cmd::Bitcoin(BitcoinCmd::Ark(BitcoinArkCmd::Offchain { network, asp_url })) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let network = Network::from(network);
            let btc = DeterministicBitcoinWallet::from_master_wallet(
                &wallet,
                network,
                Some(bitcoin_db_path(&wallet_path)),
            )?;
            let ark = ArkPaymentWallet::connect(
                &btc,
                &asp_url,
                SqliteArkDb::open(&bitcoin_db_path(&wallet_path))?,
            )
            .await?;
            let offchain = ark.get_offchain_address()?;
            println!("{offchain}");
        }

        Cmd::Bitcoin(BitcoinCmd::Ark(BitcoinArkCmd::Onchain { network, asp_url })) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let network = Network::from(network);
            let btc = DeterministicBitcoinWallet::from_master_wallet(
                &wallet,
                network,
                Some(bitcoin_db_path(&wallet_path)),
            )?;
            let ark = ArkPaymentWallet::connect(
                &btc,
                &asp_url,
                SqliteArkDb::open(&bitcoin_db_path(&wallet_path))?,
            )
            .await?;
            let onchain = ark.get_onchain_address()?;
            println!("{onchain}");
        }

        Cmd::Bitcoin(BitcoinCmd::Ark(BitcoinArkCmd::Balance { network, asp_url })) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let network = Network::from(network);
            let btc = DeterministicBitcoinWallet::from_master_wallet(
                &wallet,
                network,
                Some(bitcoin_db_path(&wallet_path)),
            )?;
            let esplora_url = DeterministicBitcoinWallet::default_esplora_url(network);
            let ark = ArkPaymentWallet::connect(
                &btc,
                &asp_url,
                SqliteArkDb::open(&bitcoin_db_path(&wallet_path))?,
            )
            .await?;
            let onchain_sync = btc.sync(esplora_url, 20, 4);
            let balance = ark.offchain_balance().await?;
            match onchain_sync {
                Ok(sync) => {
                    println!("Onchain confirmed:    {} sats", sync.confirmed_sats);
                    println!("Onchain trusted pend: {} sats", sync.trusted_pending_sats);
                    println!("Onchain untrusted:    {} sats", sync.untrusted_pending_sats);
                    println!("Onchain total:        {} sats", sync.total_sats);
                }
                Err(e) => {
                    println!("Onchain balance error: {e}");
                }
            }
            println!(
                "Offchain confirmed:   {} BTC",
                format_btc_from_sats(balance.confirmed_sats)
            );
            println!(
                "Offchain pre-conf:    {} BTC",
                format_btc_from_sats(balance.pre_confirmed_sats)
            );
            println!(
                "Offchain total:       {} BTC",
                format_btc_from_sats(balance.total_sats)
            );
        }

        Cmd::Bitcoin(BitcoinCmd::Ark(BitcoinArkCmd::Boarding { network, asp_url })) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let network = Network::from(network);
            let btc = DeterministicBitcoinWallet::from_master_wallet(
                &wallet,
                network,
                Some(bitcoin_db_path(&wallet_path)),
            )?;
            let ark = ArkPaymentWallet::connect(
                &btc,
                &asp_url,
                SqliteArkDb::open(&bitcoin_db_path(&wallet_path))?,
            )
            .await?;
            println!("Boarding: confirming deposited on-chain funds into ARK offchain...");
            match ark.settle().await? {
                Some(txid) => println!("Settlement txid: {txid}"),
                None => println!("Nothing to board."),
            }
        }

        Cmd::Bitcoin(BitcoinCmd::Ark(BitcoinArkCmd::Send {
            address,
            amount,
            network,
            asp_url,
        })) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let network = Network::from(network);
            let btc = DeterministicBitcoinWallet::from_master_wallet(
                &wallet,
                network,
                Some(bitcoin_db_path(&wallet_path)),
            )?;
            let ark = ArkPaymentWallet::connect(
                &btc,
                &asp_url,
                SqliteArkDb::open(&bitcoin_db_path(&wallet_path))?,
            )
            .await?;
            let result = ark.send_payment(&address, amount).await?;
            println!("Sent {} sats via ARK", result.amount_sats);
            println!("VTXO txid: {}", result.vtxo_txid);
            println!("Proof: {}", result.to_proof_string());
        }

        Cmd::Bitcoin(BitcoinCmd::Ark(BitcoinArkCmd::SettleAddress {
            address,
            amount,
            network,
            asp_url,
        })) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let network = Network::from(network);
            let btc = DeterministicBitcoinWallet::from_master_wallet(
                &wallet,
                network,
                Some(bitcoin_db_path(&wallet_path)),
            )?;
            let ark = ArkPaymentWallet::connect(
                &btc,
                &asp_url,
                SqliteArkDb::open(&bitcoin_db_path(&wallet_path))?,
            )
            .await?;
            let txid = ark.send_onchain(&address, amount).await?;
            println!("ARK settle-address: {} sats", amount);
            println!("Destination: {address}");
            println!("On-chain txid: {txid}");
        }

        Cmd::Bitcoin(BitcoinCmd::Ark(BitcoinArkCmd::Settle {
            amount,
            index,
            network,
            asp_url,
        })) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let network = Network::from(network);
            let btc = DeterministicBitcoinWallet::from_master_wallet(
                &wallet,
                network,
                Some(bitcoin_db_path(&wallet_path)),
            )?;
            let destination = btc.receive_address_at_kind(index, BitcoinAddressKind::Taproot)?;
            let ark = ArkPaymentWallet::connect(
                &btc,
                &asp_url,
                SqliteArkDb::open(&bitcoin_db_path(&wallet_path))?,
            )
            .await?;
            let txid = ark.send_onchain(&destination, amount).await?;
            println!("ARK settle: {} sats", amount);
            println!("Taproot destination(index={}): {destination}", index);
            println!("On-chain txid: {txid}");
        }

        Cmd::Bitcoin(BitcoinCmd::Ark(BitcoinArkCmd::VerifyProof {
            proof,
            min_amount_sats,
            network,
            asp_url,
        })) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let network = Network::from(network);
            let btc = DeterministicBitcoinWallet::from_master_wallet(
                &wallet,
                network,
                Some(bitcoin_db_path(&wallet_path)),
            )?;
            let ark = ArkPaymentWallet::connect(
                &btc,
                &asp_url,
                SqliteArkDb::open(&bitcoin_db_path(&wallet_path))?,
            )
            .await?;
            let (vtxo_txid, declared_amount_sats) = parse_ark_proof(&proof).ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid proof format; expected ark:<64-hex-vtxo_txid>:<amount_sats>"
                )
            })?;
            let min_required = min_amount_sats.unwrap_or(declared_amount_sats);
            let verified = ark.verify_incoming_vtxo(&vtxo_txid, min_required).await?;
            println!("ARK proof verified");
            println!("Declared txid:      {vtxo_txid}");
            println!("Declared amount:    {declared_amount_sats} sats");
            println!("Minimum required:   {min_required} sats");
            println!("Verified txid:      {}", verified.txid);
            println!("Verified amount:    {} sats", verified.amount_sats);
            println!("Expires at (epoch): {}", verified.expires_at);
            println!(
                "Preconfirmed:       {}",
                if verified.is_preconfirmed {
                    "yes"
                } else {
                    "no"
                }
            );
        }

        // ── key management ───────────────────────────────────────────────────
        Cmd::Key(KeyCmd::Export { format, output }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let payload = match format {
                KeyExportFormat::Hex => wallet.export_master_key_hex()?,
                KeyExportFormat::Mnemonic => wallet.export_recovery_mnemonic()?,
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
            let vault_slot = wallet.derive_vault_master_key_hex()?;
            println!("Root checksum:   {root_checksum}");
            println!("RGB fingerprint: {}", wallet.fingerprint()?);
            println!("PGP fingerprint: {} ({label})", pgp.fingerprint());
            println!("Webcash slot:    {}", &webcash_slot[..16]);
            println!("Bitcoin slot:    {}", &bitcoin_slot[..16]);
            println!("Vault slot:      {}", &vault_slot[..16]);
        }
        Cmd::Key(KeyCmd::VaultNew { label, index }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let record = match index {
                Some(slot_index) => {
                    wallet.ensure_vault_identity_index(slot_index, label.as_deref())?
                }
                None => wallet.create_vault_identity(label.as_deref())?,
            };
            println!("Vault label:     {}", record.label.as_deref().unwrap_or(""));
            println!("Vault index:     {}", record.slot_index);
            println!("Vault public key: {}", record.descriptor);
        }
        Cmd::Key(KeyCmd::VaultList) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let items = wallet.list_vault_identities()?;
            if items.is_empty() {
                println!("No vault-derived identities.");
            } else {
                println!("{:<24} {:>8}  public_key", "label", "index");
                for item in items {
                    println!(
                        "{:<24} {:>8}  {}",
                        item.label.as_deref().unwrap_or(""),
                        item.slot_index,
                        item.descriptor
                    );
                }
            }
        }
        Cmd::Key(KeyCmd::VaultExport {
            label,
            index,
            output,
        }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let (record, identity) = pick_vault_identity(&wallet, label.as_deref(), index)?;
            let pem = identity.private_key_pkcs8_pem()?;
            if let Some(path) = output {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).with_context(|| {
                        format!("failed creating export directory {}", parent.display())
                    })?;
                }
                let mut f = fs::File::create(&path)
                    .with_context(|| format!("failed creating {}", path.display()))?;
                write!(f, "{pem}")?;
                println!(
                    "Exported vault-derived PKCS#8 private key ({}) to {}",
                    record.label.as_deref().unwrap_or(""),
                    path.display()
                );
            } else {
                print!("{pem}");
            }
            println!("Vault label:     {}", record.label.as_deref().unwrap_or(""));
            println!("Vault index:     {}", record.slot_index);
            println!("Vault public key: {}", record.descriptor);
        }
        Cmd::Key(KeyCmd::VaultSign {
            label,
            index,
            message,
        }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let (record, identity) = pick_vault_identity(&wallet, label.as_deref(), index)?;
            let signature = identity.sign(&message);
            println!("Vault label:     {}", record.label.as_deref().unwrap_or(""));
            println!("Vault index:     {}", record.slot_index);
            println!("Vault public key: {}", record.descriptor);
            println!("Signature:       {}", signature);
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
            let _ = wallet.derive_vault_master_key_hex()?;

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
            let webcash_wallet = resolve_webcash_wallet(&wallet_path, &wallet, None).await?;
            match webcash_wallet.recover_from_wallet(40).await {
                Ok(result) => {
                    println!("Deterministic recovery complete.");
                    println!("Recovered identities: {recovered_identities}");
                    println!("Recovered contracts:  {recovered_contracts}");
                    println!("{result}");
                }
                Err(e) => {
                    println!("Deterministic recovery complete.");
                    println!("Recovered identities: {recovered_identities}");
                    println!("Recovered contracts:  {recovered_contracts}");
                    println!("Webcash recover skipped: {e}");
                }
            }
        }

        // ── identity register ─────────────────────────────────────────────────
        Cmd::Identity(IdentityCmd::Register { nick, about, label }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let (selected_label, id) = pick_pgp_identity(&wallet, label.as_deref())?;
            let req = RegisterRequest {
                nickname: nick.clone(),
                pgp_public_key: id.public_key_hex(),
                signature: id.sign(&format!("register:{nick}")),
                about,
            };
            let fp = execute_marketplace_paid_json(
                &wallet_path,
                api,
                direct,
                payment_rail,
                "identity",
                "identity register",
                &req,
            )
            .await?
            .get("fingerprint")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing fingerprint in register response"))?
            .to_string();
            wallet.set_nickname(&nick)?;
            println!("Registered as '{nick}'. Fingerprint: {fp} (pgp label: {selected_label})");
        }

        Cmd::Identity(IdentityCmd::Delete { label }) => {
            let wallet = open_or_create_wallet(&wallet_path)?;
            let (selected_label, id) = pick_pgp_identity(&wallet, label.as_deref())?;
            let fingerprint = id.fingerprint();
            let req = DeleteIdentityRequest {
                signature: id.sign(&format!("delete_identity:{fingerprint}")),
                fingerprint,
            };
            make_client(api, direct)
                .delete_identity(&req)
                .await
                .map_err(anyhow::Error::from)?;
            println!(
                "Deleted identity {} (pgp label: {selected_label})",
                req.fingerprint
            );
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
            let is_commercial = matches!(
                normalized_post_type.as_str(),
                "service_offer" | "bid" | "bounty" | "gig"
            );
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
                accept_terms: if is_commercial { Some(true) } else { None },
            };
            let post_id = execute_marketplace_paid_json(
                &wallet_path,
                api,
                direct,
                payment_rail,
                "timeline",
                "timeline post",
                &req,
            )
            .await?
            .get("post_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing post_id in publish response"))?
            .to_string();
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
                accept_terms: None,
            };
            let comment_id = execute_marketplace_paid_json(
                &wallet_path,
                api,
                direct,
                payment_rail,
                "timeline",
                "timeline comment",
                &req,
            )
            .await?
            .get("post_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing post_id in publish response"))?
            .to_string();
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
            let req = RatePostRequest {
                post_id: post.clone(),
                actor_fingerprint: id.fingerprint(),
                vote: vote.clone(),
                signature: id.sign(&format!("vote:{post}:{vote}")),
            };
            execute_marketplace_paid_status(
                &wallet_path,
                api,
                direct,
                payment_rail,
                "profiles/rate",
                "timeline rate",
                &serde_json::json!({
                    "post_id": req.post_id,
                    "actor_fingerprint": req.actor_fingerprint,
                    "vote": req.vote,
                    "signature": req.signature,
                }),
            )
            .await?;
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

        Cmd::Req(args) => match args.action {
            Some(ReqAction::Losses) => {
                let wallet = open_or_create_wallet(&wallet_path)?;
                let losses = wallet.list_payment_losses()?;
                if losses.is_empty() {
                    println!("No unrecovered paid-request losses.");
                } else {
                    for loss in losses {
                        println!("{}", serde_json::to_string_pretty(&loss)?);
                    }
                }
            }
            Some(ReqAction::Blacklist(ReqBlacklistCmd::List)) => {
                let wallet = open_or_create_wallet(&wallet_path)?;
                let entries = wallet.list_payment_blacklist()?;
                if entries.is_empty() {
                    println!("Payment blacklist is empty.");
                } else {
                    for entry in entries {
                        println!("{}", serde_json::to_string_pretty(&entry)?);
                    }
                }
            }
            Some(ReqAction::Blacklist(ReqBlacklistCmd::Clear {
                url,
                endpoint,
                method,
            })) => {
                let wallet = open_or_create_wallet(&wallet_path)?;
                let resolved = resolve_request_url(&url, &endpoint)?;
                let service_origin = {
                    let mut origin = format!(
                        "{}://{}",
                        resolved.scheme(),
                        resolved.host_str().unwrap_or_default()
                    );
                    if let Some(port) = resolved.port() {
                        origin.push(':');
                        origin.push_str(&port.to_string());
                    }
                    origin
                };
                let endpoint_path = resolved.path().to_string();
                wallet.clear_payment_blacklist(
                    &service_origin,
                    &endpoint_path,
                    &method.to_ascii_uppercase(),
                    payment_rail_name(payment_rail),
                )?;
                println!(
                    "Cleared blacklist entry for {} {}{} ({})",
                    method.to_ascii_uppercase(),
                    service_origin,
                    endpoint_path,
                    payment_rail_name(payment_rail)
                );
            }
            None => {
                let base_url = args
                    .url
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("--url is required for `hrmw req`"))?;
                let method = Method::from_bytes(args.method.trim().to_ascii_uppercase().as_bytes())
                    .with_context(|| format!("invalid HTTP method '{}'", args.method))?;
                let query = args
                    .query_params
                    .iter()
                    .map(|item| parse_key_value_arg(item, "--query"))
                    .collect::<anyhow::Result<Vec<_>>>()?;
                let headers = args
                    .headers
                    .iter()
                    .map(|item| parse_key_value_arg(item, "--header"))
                    .collect::<anyhow::Result<Vec<_>>>()?;
                let spec = RequestSpec {
                    base_url: base_url.to_string(),
                    endpoint: args.endpoint.clone(),
                    method: method.clone(),
                    headers,
                    query,
                    body: build_req_body(&args)?,
                    action_hint: format!(
                        "{} {}",
                        method.as_str().to_ascii_uppercase(),
                        args.endpoint
                    ),
                    desired_rail: Some(payment_rail),
                };
                let response = execute_paid_request(&wallet_path, &spec).await?;
                print_request_response(&response)?;
            }
        },

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
                accept_terms: true,
            };
            let buy_response = execute_marketplace_paid_json(
                &wallet_path,
                api,
                direct,
                payment_rail,
                "arbitration/contracts/buy",
                "contract buy",
                &serde_json::json!({
                    "buyer_fingerprint": req.buyer_fingerprint,
                    "buyer_public_key": req.buyer_public_key,
                    "contract_type": req.contract_type,
                    "amount": req.amount,
                    "contract_id": req.contract_id,
                    "witness_proof": req.witness_proof,
                    "encrypted_witness_secret": req.encrypted_witness_secret,
                    "witness_zkp": req.witness_zkp,
                    "reference_post": req.reference_post,
                    "signature": req.signature,
                    "accept_terms": true,
                }),
            )
            .await?;

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
                accept_terms: Some(true),
            };
            let post_id = execute_marketplace_paid_json(
                &wallet_path,
                api,
                direct,
                payment_rail,
                "timeline",
                "contract bid",
                &req,
            )
            .await?
            .get("post_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing post_id in publish response"))?
            .to_string();
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
            // Pickup is free — no payment header required.
            let resp = client.pickup(&id, &fp, &sig).await?;

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
        Cmd::Webminer(WebminerCmd::ListDevices) => {
            let enumerated = harmoniis_wallet::miner::enumerate_all_devices().await;
            let devices = enumerated.devices;
            if devices.is_empty() {
                println!("No mining devices found.");
            } else {
                println!("Available mining devices:");
                for d in &devices {
                    println!("  {}: {}", d.id, d.label);
                }
                println!("\nUse --device 0,1 to select specific devices.");
            }
        }
        Cmd::Webminer(WebminerCmd::Start {
            server,
            max_difficulty,
            backend,
            cpu_only,
            cpu_threads,
            accept_terms,
            device,
            foreground,
            wallet: run_wallet,
            webcash_wallet,
            cuda_install,
        }) => {
            use harmoniis_wallet::miner::{daemon, BackendChoice, MinerConfig};
            let accept_terms = prompt_accept_terms_if_needed(accept_terms)?;
            if !cpu_only {
                ensure_cuda_toolkit_if_needed(cuda_install)?;
            }
            let run_wallet = run_wallet.unwrap_or_else(|| wallet_path.clone());
            let run_webcash_wallet = webcash_wallet
                .unwrap_or_else(|| labeled_wallet_display_path(&run_wallet, "webcash", None));
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
                devices: device,
            };
            if foreground {
                daemon::run_mining_loop(config).await?;
            } else {
                daemon::start(&config)?;
            }
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
        Cmd::Webminer(WebminerCmd::Collect { daemon }) => {
            if daemon {
                // Daemon mode: fork to background, write PID, run silently.
                let exe = std::env::current_exe().context("cannot find own executable")?;
                let child = std::process::Command::new(exe)
                    .args(["webminer", "collect"])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .context("failed to spawn collect daemon")?;
                println!("Collect daemon started (PID {}).", child.id());
                return Ok(());
            }
            // Foreground: verbose per-solution feedback.
            println!("Collecting pending mining solutions...");
            let r = harmoniis_wallet::miner::collect::run("https://webcash.org", true)?;
            println!();
            println!("Pending solutions: {}", r.pending);
            println!("Already accepted:  {}", r.already_accepted);
            println!("Submitted:         {}", r.submitted);
            println!("Failed:            {}", r.failed);
            if r.pending == 0 {
                println!("Nothing to collect.");
            } else if r.submitted > 0 {
                println!();
                println!("Run `hrmw webcash recover` to pick up newly accepted webcash.");
            }
        }
        Cmd::Webminer(WebminerCmd::ReportWorker {
            server,
            resolved_addr,
            clients,
            webcash_wallet,
        }) => {
            let addr: std::net::SocketAddr = resolved_addr
                .parse()
                .context("invalid --resolved-addr (expected ip:port)")?;
            let wallet_path = webcash_wallet.unwrap_or_else(|| {
                dirs_next::home_dir()
                    .unwrap_or_default()
                    .join(".harmoniis")
                    .join("wallet")
                    .join("main_webcash.db")
            });
            harmoniis_wallet::miner::collect::report_worker(&server, addr, clients, &wallet_path)?;
        }
        Cmd::Webminer(WebminerCmd::Cloud { cmd: cloud_cmd }) => {
            use harmoniis_wallet::miner::cloud::{
                config as cloud_config, config::InstanceState, provision,
            };

            // Open existing wallet — required for vault SSH key derivation.
            if !wallet_path.exists() {
                anyhow::bail!(
                    "Wallet not found at {}. Run `hrmw setup` first.",
                    wallet_path.display()
                );
            }
            let wallet = RgbWallet::open(&wallet_path)
                .context("Failed to open wallet. Run `hrmw setup` first.")?;

            // Derive SSH key from vault (deterministic, same key every time)
            let ssh_key = harmoniis_wallet::miner::cloud::ssh::derive_ssh_keypair(&wallet)?;

            match cloud_cmd {
                CloudCmd::Start {
                    label,
                    offer: machine,
                    count,
                    env,
                } => {
                    // Dev mode: clone + build from source, no auto-start
                    if env.as_deref() == Some("dev") {
                        let _lock = cloud_config::acquire_start_lock()
                            .context("Another cloud start is in progress")?;

                        let _wc =
                            resolve_webcash_wallet(&wallet_path, &wallet, Some(&label)).await?;
                        let db_path =
                            labeled_wallet_display_path(&wallet_path, "webcash", Some(&label));

                        let state =
                            provision::start_dev(&label, machine, &db_path, &ssh_key).await?;

                        // Write SSH key to persistent path for dev SSH access.
                        let key_dir = dirs_next::home_dir()
                            .unwrap_or_default()
                            .join(".harmoniis")
                            .join("cloud");
                        let _ = std::fs::create_dir_all(&key_dir);
                        let key_path = key_dir.join("id_ed25519");
                        let key_file =
                            harmoniis_wallet::miner::cloud::ssh::write_temp_key_file(&ssh_key)?;
                        let _ = std::fs::copy(&key_file, &key_path);
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ = std::fs::set_permissions(
                                &key_path,
                                std::fs::Permissions::from_mode(0o600),
                            );
                        }

                        println!();
                        println!("Dev instance ready. SSH in and test manually:");
                        println!(
                            "  ssh -i {} -p {} root@{}",
                            key_path.display(),
                            state.ssh_port,
                            state.ssh_host
                        );
                        println!();
                        println!("On the remote machine:");
                        println!(
                            "  cd /root/hw && /root/.local/bin/hrmw webminer start -f \
                             --accept-terms"
                        );
                        println!();
                        println!("Or rebuild after changes:");
                        println!(
                            "  cd /root/hw && CC=gcc-10 CXX=g++-10 cargo build --release && \
                             cp target/release/hrmw /root/.local/bin/hrmw"
                        );
                        return Ok(());
                    }

                    use harmoniis_wallet::miner::cloud::slots;

                    // Concurrency guard — prevents two terminals from racing.
                    let _lock = cloud_config::acquire_start_lock()
                        .context("Another cloud start is in progress")?;

                    // Check for existing instances.
                    let active = cloud_config::load_instances()?;
                    if !active.is_empty() {
                        provision::print_active_summary(&active);
                        print!("{} instance(s) running. Start more? [y/N] ", active.len());
                        use std::io::Write;
                        std::io::stdout().flush()?;
                        let mut input = String::new();
                        std::io::stdin().read_line(&mut input)?;
                        if !input.trim().eq_ignore_ascii_case("y") {
                            println!("Cancelled.");
                            return Ok(());
                        }
                    }

                    // Ask how many instances if not specified with -n.
                    let count = if count == 1 {
                        print!("How many instances? [1] ");
                        use std::io::Write;
                        std::io::stdout().flush()?;
                        let mut input = String::new();
                        std::io::stdin().read_line(&mut input)?;
                        let input = input.trim();
                        if input.is_empty() {
                            1
                        } else {
                            input.parse::<usize>().unwrap_or(1).max(1)
                        }
                    } else {
                        count
                    };

                    // Allocate slots (avoids label collision with active instances).
                    let slots = slots::allocate_slots(&wallet, &label, count, &active)?;

                    // Each instance gets its own offer selection (fresh search each time).
                    for (i, slot) in slots.iter().enumerate() {
                        if slots.len() > 1 {
                            println!(
                                "\n=== Instance {}/{} ({}) ===",
                                i + 1,
                                slots.len(),
                                slot.label
                            );
                        }

                        let _wc = resolve_webcash_wallet(&wallet_path, &wallet, Some(&slot.label))
                            .await?;
                        let db_path =
                            labeled_wallet_display_path(&wallet_path, "webcash", Some(&slot.label));

                        if let Err(e) =
                            provision::start(&slot.label, machine, &db_path, &ssh_key).await
                        {
                            eprintln!("Instance {}/{} failed: {e}", i + 1, slots.len());
                        }
                    }

                    // Auto-start solution dispatch daemon.
                    let exe = std::env::current_exe().context("cannot find own executable")?;
                    match std::process::Command::new(exe)
                        .args(["webminer", "cloud", "watch", "--interval", "30"])
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .spawn()
                    {
                        Ok(child) => println!(
                            "\nSolution dispatcher started in background (PID {}).\n\
                             Run `hrmw webminer cloud watch` for live output.",
                            child.id()
                        ),
                        Err(e) => eprintln!("Warning: could not start dispatcher: {e}"),
                    }
                }
                CloudCmd::Stop { instance } => {
                    let instances = cloud_config::load_instances()?;
                    if instances.is_empty() {
                        anyhow::bail!("No active instances.");
                    }

                    let targets: Vec<&InstanceState> = if let Some(n) = instance {
                        let idx = n.checked_sub(1).context("-n must be >= 1")?;
                        vec![instances.get(idx).ok_or_else(|| {
                            anyhow::anyhow!(
                                "Instance #{n} not found. Have {} instances.",
                                instances.len()
                            )
                        })?]
                    } else {
                        instances.iter().collect()
                    };

                    // Stop all miners and download solution files (fast — just SSH).
                    for state in &targets {
                        if let Err(e) = provision::stop(state, &ssh_key).await {
                            eprintln!(
                                "Warning: failed to stop instance {}: {e}",
                                state.instance_id
                            );
                        }
                    }

                    // Recover from each instance's labeled wallet and transfer to main.
                    let mut unique_labels: Vec<String> = targets
                        .iter()
                        .map(|s| s.label.clone())
                        .collect::<std::collections::HashSet<_>>()
                        .into_iter()
                        .collect();
                    unique_labels.sort();

                    println!();
                    let mut total_transferred = 0.0f64;
                    for label in &unique_labels {
                        println!("Recovering {label}...");
                        let labeled_wc =
                            resolve_webcash_wallet(&wallet_path, &wallet, Some(label)).await?;
                        let recovery = labeled_wc
                            .recover_from_wallet(50)
                            .await
                            .context("webcash recovery failed")?;
                        println!("{recovery}");

                        let labeled_balance = labeled_wc.balance().await?;
                        if labeled_balance != "0" && !labeled_balance.is_empty() {
                            println!("  Balance: {labeled_balance} — transferring to main...");
                            let payment = labeled_wc
                                .pay(
                                    WebcashAmount::from_str(&labeled_balance)?,
                                    "cloud-mining-collect",
                                )
                                .await
                                .context("failed to pay from mining wallet")?;
                            let secret_str = extract_webcash_secret(&payment)?;
                            let main_wc =
                                resolve_webcash_wallet(&wallet_path, &wallet, None).await?;
                            let parsed = SecretWebcash::parse(&secret_str)
                                .map_err(|e| anyhow::anyhow!("bad webcash secret: {e}"))?;
                            main_wc
                                .insert(parsed)
                                .await
                                .context("failed to insert into main wallet")?;
                            total_transferred += labeled_balance.parse::<f64>().unwrap_or(0.0);
                        }
                    }

                    let main_wc = resolve_webcash_wallet(&wallet_path, &wallet, None).await?;
                    let main_balance = main_wc.balance().await?;
                    if total_transferred > 0.0 {
                        println!();
                        println!("Total transferred: {total_transferred} webcash");
                    }
                    println!("Main wallet balance: {main_balance}");

                    // Auto-collect uncollected solutions in daemon mode.
                    // Singleton: skip if a daemon is already running.
                    let solutions_path = harmoniis_wallet::miner::daemon::pending_solutions_path();
                    if solutions_path.exists() {
                        let pending = std::fs::read_to_string(&solutions_path)
                            .unwrap_or_default()
                            .lines()
                            .filter(|l| !l.trim().is_empty())
                            .count();
                        if pending > 0 {
                            println!();
                            if let Err(e) = provision::ensure_collect_daemon(pending) {
                                eprintln!(
                                    "Warning: failed to ensure collect daemon: {e}"
                                );
                            }
                        }
                    }
                }
                CloudCmd::Destroy { instance } => {
                    let instances = cloud_config::load_instances()?;
                    if instances.is_empty() {
                        println!("No active instances.");
                    } else {
                        let targets: Vec<&InstanceState> = if let Some(n) = instance {
                            let idx = n.checked_sub(1).context("-n must be >= 1")?;
                            vec![instances
                                .get(idx)
                                .ok_or_else(|| anyhow::anyhow!("Instance #{n} not found."))?]
                        } else {
                            instances.iter().collect()
                        };

                        // Download solution files BEFORE destroying (fast SSH).
                        for state in &targets {
                            provision::backup_pending_files(state, &ssh_key);
                        }

                        // Destroy instances immediately (stops charges).
                        if let Some(_n) = instance {
                            let state = &targets[0];
                            provision::destroy(state).await?;
                        } else {
                            provision::destroy_all().await?;
                        }

                        // Recover locally after destroy (instances gone, but we have the files).
                        let mut unique_labels: Vec<String> = targets
                            .iter()
                            .map(|s| s.label.clone())
                            .collect::<std::collections::HashSet<_>>()
                            .into_iter()
                            .collect();
                        unique_labels.sort();

                        let mut total_transferred = 0.0f64;
                        for label in &unique_labels {
                            println!("Recovering {label}...");
                            let labeled_wc =
                                resolve_webcash_wallet(&wallet_path, &wallet, Some(label)).await?;
                            let recovery = labeled_wc
                                .recover_from_wallet(50)
                                .await
                                .context("recovery failed")?;
                            println!("{recovery}");

                            let balance = labeled_wc.balance().await?;
                            if balance != "0" && !balance.is_empty() {
                                println!("  Transferring {balance} to main...");
                                let payment = labeled_wc
                                    .pay(WebcashAmount::from_str(&balance)?, "cloud-mining-collect")
                                    .await?;
                                let secret_str = extract_webcash_secret(&payment)?;
                                let main_wc =
                                    resolve_webcash_wallet(&wallet_path, &wallet, None).await?;
                                let parsed = SecretWebcash::parse(&secret_str)
                                    .map_err(|e| anyhow::anyhow!("bad webcash secret: {e}"))?;
                                main_wc.insert(parsed).await?;
                                total_transferred += balance.parse::<f64>().unwrap_or(0.0);
                            }
                        }

                        if total_transferred > 0.0 {
                            let main_wc =
                                resolve_webcash_wallet(&wallet_path, &wallet, None).await?;
                            let main_balance = main_wc.balance().await?;
                            println!("Transferred: {total_transferred} webcash");
                            println!("Main wallet: {main_balance}");
                        }

                        // Auto-collect uncollected solutions in daemon mode —
                        // drains the in-flight queue downloaded from the
                        // (now-destroyed) cloud instance at home rate, no
                        // cloud cost. Singleton via collect_pid_file so a
                        // chain of stop+destroy doesn't spawn duplicates.
                        let solutions_path =
                            harmoniis_wallet::miner::daemon::pending_solutions_path();
                        if solutions_path.exists() {
                            let pending = std::fs::read_to_string(&solutions_path)
                                .unwrap_or_default()
                                .lines()
                                .filter(|l| !l.trim().is_empty())
                                .count();
                            if pending > 0 {
                                println!();
                                if let Err(e) = provision::ensure_collect_daemon(pending) {
                                    eprintln!(
                                        "Warning: failed to ensure collect daemon: {e}"
                                    );
                                }
                            }
                        }
                    }
                }
                CloudCmd::Status { instance } => {
                    let instances = cloud_config::load_instances()?;
                    if instances.is_empty() {
                        println!("No active instances.");
                    } else if let Some(n) = instance {
                        let idx = n.checked_sub(1).context("-n must be >= 1")?;
                        let state = instances
                            .get(idx)
                            .ok_or_else(|| anyhow::anyhow!("Instance #{n} not found."))?;
                        provision::status(state, &ssh_key).await?;
                    } else {
                        for (i, state) in instances.iter().enumerate() {
                            if instances.len() > 1 {
                                println!("\n=== Instance #{} ===", i + 1);
                            }
                            provision::status(state, &ssh_key).await?;
                        }
                    }
                    // Show local collect-daemon progress (drains the queue
                    // downloaded from cloud instances at home rate, no cost).
                    provision::print_local_collect_status();
                }
                CloudCmd::Info { label } => {
                    let instances = cloud_config::load_instances()?;
                    if instances.is_empty() {
                        provision::info(&label, &ssh_key, None);
                    } else {
                        for (i, state) in instances.iter().enumerate() {
                            if instances.len() > 1 {
                                println!("\n=== Instance #{} ===", i + 1);
                            }
                            provision::info(&state.label, &ssh_key, Some(state));
                        }
                    }
                }
                CloudCmd::Watch { interval } => {
                    use harmoniis_wallet::miner::cloud::dispatch;
                    dispatch::run(&ssh_key, "https://webcash.org", interval, true)?;
                }
                CloudCmd::SetApiKey { key } => {
                    let mut cfg = cloud_config::load_config()?;
                    cfg.vast_api_key = Some(key);
                    cloud_config::save_config(&cfg)?;
                    println!("Vast.ai API key saved.");
                }
            }
        }

        // ── upgrade / self-update ────────────────────────────────────────────
        Cmd::Upgrade => {
            self_update::run_upgrade().await?;
        }

        // ── gpu-probe (internal) ────────────────────────────────────────────
        #[allow(unused_variables)]
        Cmd::GpuProbe {
            vendor,
            device,
            backend,
            pci_bus,
        } => {
            #[cfg(feature = "gpu")]
            {
                let identity = harmoniis_wallet::miner::gpu::AdapterIdentity {
                    name: String::new(), // probe matches by pci_bus/vendor/device, not name
                    vendor,
                    device,
                    backend,
                    pci_bus,
                };
                harmoniis_wallet::miner::gpu::probe_adapter(&identity).await?;
            }
            #[cfg(not(feature = "gpu"))]
            {
                let _ = (vendor, device, backend);
                anyhow::bail!("GPU support not compiled");
            }
        }
    }

    Ok(())
}

// ── Self-update logic ─────────────────────────────────────────────────────────

mod self_update {
    use anyhow::{bail, Context};
    use std::process::Command;

    const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
    const RELEASES_URL: &str =
        "https://api.github.com/repos/harmoniis/harmoniis-wallet/releases/latest";

    /// Detect the platform label matching the release tarball naming convention.
    fn detect_platform() -> anyhow::Result<&'static str> {
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;
        match (os, arch) {
            ("linux", "x86_64") => Ok("linux-x86_64"),
            ("linux", "aarch64") => Ok("linux-aarch64"),
            ("macos", "x86_64") => Ok("macos-x86_64"),
            ("macos", "aarch64") => Ok("macos-aarch64"),
            ("windows", "x86_64") => Ok("windows-x86_64"),
            ("freebsd", "x86_64") => Ok("freebsd-x86_64"),
            ("freebsd", "aarch64") => Ok("freebsd-aarch64"),
            _ => bail!("unsupported platform: {os}-{arch}"),
        }
    }

    /// Shell out to curl and return stdout bytes.
    fn curl(args: &[&str]) -> anyhow::Result<Vec<u8>> {
        let output = Command::new("curl")
            .args(args)
            .output()
            .context("failed to run curl — is it installed?")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("curl failed: {stderr}");
        }
        Ok(output.stdout)
    }

    /// Extract a string value for `key` from a (flat) JSON object.
    /// Minimal parser — avoids pulling in serde_json just for two fields.
    fn json_str_value(json: &str, key: &str) -> Option<String> {
        let needle = format!("\"{}\"", key);
        let idx = json.find(&needle)?;
        let rest = &json[idx + needle.len()..];
        // skip optional whitespace and colon
        let rest = rest.trim_start();
        let rest = rest.strip_prefix(':')?;
        let rest = rest.trim_start();
        let rest = rest.strip_prefix('"')?;
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    }

    /// Path where we cache the installed tarball checksum.
    fn installed_checksum_path() -> std::path::PathBuf {
        dirs_next::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".harmoniis")
            .join("installed_checksum")
    }

    /// Remove stale `.old` / `.old.exe` left by a previous Windows upgrade.
    fn cleanup_old_binaries() {
        let Ok(current_exe) = std::env::current_exe() else {
            return;
        };
        for ext in &["old.exe", "old"] {
            let old_path = current_exe.with_extension(ext);
            if old_path.exists() {
                match std::fs::remove_file(&old_path) {
                    Ok(()) => println!(
                        "Cleaned up previous update artifact: {}",
                        old_path.display()
                    ),
                    Err(e) => eprintln!(
                        "Warning: could not remove {}: {} (non-fatal)",
                        old_path.display(),
                        e
                    ),
                }
            }
        }
    }

    pub async fn run_upgrade() -> anyhow::Result<()> {
        cleanup_old_binaries();

        let platform = detect_platform()?;
        println!("Current version : {CURRENT_VERSION}");
        println!("Platform        : {platform}");
        println!();

        // 1. Query latest release metadata
        println!("Checking latest release...");
        let body = curl(&[
            "-sSL",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "User-Agent: hrmw-self-update",
            RELEASES_URL,
        ])?;
        let json = String::from_utf8(body).context("GitHub API returned non-UTF-8")?;

        let tag = json_str_value(&json, "tag_name")
            .context("could not find `tag_name` in release JSON")?;
        let latest_version = tag.strip_prefix('v').unwrap_or(&tag);

        // 2. Same version? Download tarball checksum and compare with local binary.
        //    Detects rebuilt releases (same version tag, different binary).
        if latest_version == CURRENT_VERSION {
            let sha_name = format!("harmoniis-wallet-{latest_version}-{platform}.tar.gz.sha256");
            let sha_url = format!(
                "https://github.com/harmoniis/harmoniis-wallet/releases/download/{tag}/{sha_name}"
            );
            // Fetch remote tarball checksum.
            let remote_tarball_sha = curl(&["-sSL", &sha_url])
                .ok()
                .and_then(|b| {
                    String::from_utf8(b)
                        .ok()
                        .and_then(|s| s.split_whitespace().next().map(|h| h.to_lowercase()))
                })
                .unwrap_or_default();

            if remote_tarball_sha.is_empty() {
                println!("Already up to date (v{CURRENT_VERSION}).");
                return Ok(());
            }

            // Compare with checksum saved at install time.
            let local_cached_sha = std::fs::read_to_string(installed_checksum_path())
                .unwrap_or_default()
                .trim()
                .to_lowercase();

            if remote_tarball_sha == local_cached_sha {
                println!("Already up to date (v{CURRENT_VERSION}).");
                return Ok(());
            }

            if !local_cached_sha.is_empty() {
                println!("Release updated — downloading new build...");
            }
            // Fall through to download + install.
        }
        println!("Latest version  : {latest_version}");

        // 3. Build expected tarball name and find download URL
        let tarball_name = format!("harmoniis-wallet-{latest_version}-{platform}.tar.gz");

        // Search for the browser_download_url matching our tarball in the JSON.
        // The assets array contains objects with "name" and "browser_download_url".
        let download_url = {
            let mut url: Option<String> = None;
            // Walk through every browser_download_url and check the asset name.
            let search = "\"browser_download_url\"";
            let mut cursor = 0usize;
            while let Some(pos) = json[cursor..].find(search) {
                let abs = cursor + pos;
                // Extract URL value
                let after = &json[abs + search.len()..];
                let after = after.trim_start().strip_prefix(':').unwrap_or(after);
                let after = after.trim_start().strip_prefix('"').unwrap_or(after);
                if let Some(end) = after.find('"') {
                    let candidate = &after[..end];
                    if candidate.ends_with(&tarball_name) {
                        url = Some(candidate.to_string());
                        break;
                    }
                }
                cursor = abs + search.len();
            }
            url.with_context(|| {
                format!(
                    "release {tag} has no asset matching {tarball_name} — \
                     is there a build for {platform}?"
                )
            })?
        };
        println!("Downloading     : {download_url}");

        // 4. Download to a temp file
        let tmp_dir = std::env::temp_dir().join(format!("hrmw-upgrade-{}", std::process::id()));
        std::fs::create_dir_all(&tmp_dir).context("failed to create temp dir")?;
        let tarball_path = tmp_dir.join(&tarball_name);
        curl(&[
            "-sSL",
            "-o",
            tarball_path.to_str().context("non-UTF-8 temp path")?,
            &download_url,
        ])?;

        // 5. Extract — the tarball contains `harmoniis-wallet-{ver}/bin/hrmw`
        let status = Command::new("tar")
            .args([
                "xzf",
                tarball_path.to_str().unwrap(),
                "-C",
                tmp_dir.to_str().unwrap(),
            ])
            .status()
            .context("failed to run tar")?;
        if !status.success() {
            bail!("tar extraction failed");
        }

        let binary_name = if cfg!(windows) { "hrmw.exe" } else { "hrmw" };
        let extracted_bin = tmp_dir
            .join(format!("harmoniis-wallet-{latest_version}"))
            .join("bin")
            .join(binary_name);
        if !extracted_bin.exists() {
            bail!(
                "expected binary not found in tarball at {}",
                extracted_bin.display()
            );
        }

        // 6. Replace the running binary
        let current_exe =
            std::env::current_exe().context("could not determine path of running hrmw binary")?;

        // Canonicalize to resolve symlinks so we replace the actual file.
        let target_path = std::fs::canonicalize(&current_exe).unwrap_or(current_exe);

        // Copy the new binary next to the target before swapping.
        let staging_path = target_path.with_extension("new");
        std::fs::copy(&extracted_bin, &staging_path).with_context(|| {
            format!(
                "failed to copy new binary to {} — do you have write permission?",
                staging_path.display()
            )
        })?;

        // Preserve executable permission on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&target_path)
                .map(|m| m.permissions())
                .unwrap_or_else(|_| std::fs::Permissions::from_mode(0o755));
            std::fs::set_permissions(&staging_path, perms).ok();
        }

        // --- Platform-specific binary swap ---
        //
        // Unix: atomic rename over the running binary (works because Unix
        //       replaces the directory entry while the running process keeps
        //       its open file descriptor).
        //
        // Windows: the OS locks the running .exe, so we cannot overwrite it
        //          directly.  Instead we *rename* the running exe to .old.exe
        //          (Windows allows renaming a locked file) and then rename the
        //          staging binary into the now-free target name.
        #[cfg(unix)]
        {
            std::fs::rename(&staging_path, &target_path).with_context(|| {
                format!(
                    "failed to replace {} — check write permissions \
                     (sudo may be needed if hrmw is installed outside ~/.local/bin)",
                    target_path.display()
                )
            })?;
        }

        #[cfg(windows)]
        {
            let old_path = target_path.with_extension("old.exe");

            // Remove a leftover .old.exe from an earlier upgrade.
            if old_path.exists() {
                std::fs::remove_file(&old_path).with_context(|| {
                    format!(
                        "failed to remove previous backup {} — \
                         is another hrmw process running?",
                        old_path.display()
                    )
                })?;
            }

            // Step 1: rename the running exe out of the way.
            std::fs::rename(&target_path, &old_path).with_context(|| {
                format!(
                    "failed to rename running binary {} to {} — \
                     try closing other hrmw processes or run as Administrator",
                    target_path.display(),
                    old_path.display()
                )
            })?;

            // Step 2: move the new binary into place.
            if let Err(e) = std::fs::rename(&staging_path, &target_path) {
                // Best-effort rollback: restore the original binary.
                let _ = std::fs::rename(&old_path, &target_path);
                return Err(e).with_context(|| {
                    format!(
                        "failed to move new binary to {} — original binary restored",
                        target_path.display()
                    )
                });
            }

            println!(
                "Note: {} will be cleaned up on next upgrade.",
                old_path.display()
            );
        }

        #[cfg(not(any(unix, windows)))]
        {
            std::fs::rename(&staging_path, &target_path)
                .with_context(|| format!("failed to replace {}", target_path.display()))?;
        }

        // Clean up temp directory.
        let _ = std::fs::remove_dir_all(&tmp_dir);

        // Save the remote tarball checksum so future same-version checks work.
        let sha_name = format!("harmoniis-wallet-{latest_version}-{platform}.tar.gz.sha256");
        let sha_url = format!(
            "https://github.com/harmoniis/harmoniis-wallet/releases/download/{tag}/{sha_name}"
        );
        if let Ok(sha_bytes) = curl(&["-sSL", &sha_url]) {
            if let Some(sha) = String::from_utf8_lossy(&sha_bytes)
                .split_whitespace()
                .next()
            {
                let _ = std::fs::write(installed_checksum_path(), sha.to_lowercase());
            }
        }

        println!();
        println!("Upgraded hrmw: v{CURRENT_VERSION} -> v{latest_version}");
        println!("Binary path   : {}", target_path.display());

        Ok(())
    }
}
