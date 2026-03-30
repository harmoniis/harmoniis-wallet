//! Centralized configuration for the harmoniis-wallet crate.
//!
//! All configurable values (URLs, timeouts, network settings) flow through
//! [`WalletConfig`]. Construct via [`WalletConfig::from_env()`] or use
//! [`WalletConfig::default()`] for production defaults.

use std::time::Duration;

use bdk_wallet::bitcoin::Network;

/// Centralized configuration for harmoniis-wallet.
///
/// All hardcoded defaults are collected here. Consumers should construct
/// this once at startup and pass it through to wallet components.
#[derive(Debug, Clone)]
pub struct WalletConfig {
    // ── Harmoniis API ────────────────────────────────────────────────────
    /// Base URL for the Harmoniis API proxy (production: `https://harmoniis.com/api`).
    pub harmoniis_api_url: String,
    /// Optional direct backend URL, bypassing Cloudflare proxy.
    pub harmoniis_direct_url: Option<String>,
    /// HTTP request timeout.
    pub http_timeout: Duration,

    // ── Bitcoin ──────────────────────────────────────────────────────────
    /// Bitcoin network (mainnet, testnet, signet, regtest).
    pub bitcoin_network: Network,
    /// Esplora API URL. If `None`, uses the default for the configured network.
    pub esplora_url: Option<String>,

    // ── ARK ──────────────────────────────────────────────────────────────
    /// Arkade ASP URL.
    pub ark_asp_url: String,
    /// Boltz exchange API URL (for submarine swaps).
    pub ark_boltz_url: String,
    /// Timeout for ARK ASP connection.
    pub ark_connect_timeout: Duration,

    // ── Webcash ─────────────────────────────────────────────────────────
    /// Webcash server URL.
    pub webcash_server_url: String,

    // ── S3 storage (optional) ───────────────────────────────────────────
    /// S3 bucket for wallet database storage.
    pub s3_bucket: Option<String>,
    /// S3 key prefix (e.g. `"wallet/"`).
    pub s3_prefix: String,

    // ── Secret manager (optional) ───────────────────────────────────────
    /// AWS Secrets Manager ARN for the master mnemonic.
    pub secret_manager_arn: Option<String>,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            harmoniis_api_url: "https://harmoniis.com/api".to_string(),
            harmoniis_direct_url: None,
            http_timeout: Duration::from_secs(30),
            bitcoin_network: Network::Bitcoin,
            esplora_url: None,
            ark_asp_url: "https://arkade.computer".to_string(),
            ark_boltz_url: "https://api.boltz.exchange/v2".to_string(),
            ark_connect_timeout: Duration::from_secs(30),
            webcash_server_url: "https://webcash.org".to_string(),
            s3_bucket: None,
            s3_prefix: "wallet/".to_string(),
            secret_manager_arn: None,
        }
    }
}

impl WalletConfig {
    /// Build config from environment variables, falling back to defaults.
    ///
    /// Recognized env vars:
    /// - `HARMONIIS_API_URL` — API base URL
    /// - `HARMONIIS_DIRECT_URL` — direct backend URL
    /// - `HARMONIIS_HTTP_TIMEOUT_SECS` — HTTP timeout in seconds
    /// - `HARMONIIS_BITCOIN_NETWORK` — `bitcoin`, `testnet`, `signet`, `regtest`
    /// - `HARMONIIS_ESPLORA_URL` — Esplora API URL
    /// - `HARMONIIS_ARK_ASP_URL` — Arkade ASP URL
    /// - `HARMONIIS_ARK_BOLTZ_URL` — Boltz exchange API URL
    /// - `HARMONIIS_WEBCASH_SERVER_URL` — Webcash server URL
    /// - `HRMW_WALLET_S3_BUCKET` — S3 bucket
    /// - `HRMW_WALLET_S3_PREFIX` — S3 key prefix
    /// - `HARMONIIS_MASTER_MNEMONIC_ARN` — Secrets Manager ARN
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(v) = std::env::var("HARMONIIS_API_URL") {
            config.harmoniis_api_url = v;
        }
        if let Ok(v) = std::env::var("HARMONIIS_DIRECT_URL") {
            config.harmoniis_direct_url = Some(v);
        }
        if let Ok(v) = std::env::var("HARMONIIS_HTTP_TIMEOUT_SECS") {
            if let Ok(secs) = v.parse::<u64>() {
                config.http_timeout = Duration::from_secs(secs);
            }
        }
        if let Ok(v) = std::env::var("HARMONIIS_BITCOIN_NETWORK") {
            config.bitcoin_network = match v.to_lowercase().as_str() {
                "testnet" => Network::Testnet,
                "signet" => Network::Signet,
                "regtest" => Network::Regtest,
                _ => Network::Bitcoin,
            };
        }
        if let Ok(v) = std::env::var("HARMONIIS_ESPLORA_URL") {
            config.esplora_url = Some(v);
        }
        if let Ok(v) = std::env::var("HARMONIIS_ARK_ASP_URL") {
            config.ark_asp_url = v;
        }
        if let Ok(v) = std::env::var("HARMONIIS_ARK_BOLTZ_URL") {
            config.ark_boltz_url = v;
        }
        if let Ok(v) = std::env::var("HARMONIIS_WEBCASH_SERVER_URL") {
            config.webcash_server_url = v;
        }
        if let Ok(v) = std::env::var("HRMW_WALLET_S3_BUCKET") {
            config.s3_bucket = Some(v);
        }
        if let Ok(v) = std::env::var("HRMW_WALLET_S3_PREFIX") {
            config.s3_prefix = v;
        }
        if let Ok(v) = std::env::var("HARMONIIS_MASTER_MNEMONIC_ARN") {
            config.secret_manager_arn = Some(v);
        }

        config
    }

    /// Resolve the effective Esplora URL for the configured network.
    pub fn effective_esplora_url(&self) -> String {
        if let Some(url) = &self.esplora_url {
            return url.clone();
        }
        match self.bitcoin_network {
            Network::Bitcoin => "https://blockstream.info/api".to_string(),
            Network::Testnet | Network::Testnet4 => {
                "https://blockstream.info/testnet/api".to_string()
            }
            Network::Signet => "https://blockstream.info/signet/api".to_string(),
            Network::Regtest => "http://127.0.0.1:3002".to_string(),
        }
    }
}
