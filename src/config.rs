//! Centralized configuration for the harmoniis-wallet crate.
//!
//! All configurable values (URLs, timeouts, network settings) flow through
//! [`WalletConfig`]. Construct via [`WalletConfig::from_env()`] or use
//! [`WalletConfig::default()`] for production defaults.

use std::time::Duration;

/// Centralized configuration for harmoniis-wallet.
///
/// All hardcoded defaults are collected here. Consumers should construct
/// this once at startup and pass it through to wallet components.
#[derive(Debug, Clone)]
pub struct WalletConfig {
    // ── Harmoniis API ────────────────────────────────────────────────────
    pub harmoniis_api_url: String,
    pub harmoniis_direct_url: Option<String>,
    pub http_timeout: Duration,

    // ── Bitcoin ──────────────────────────────────────────────────────────
    /// Network name: "bitcoin", "testnet", "signet", "regtest".
    pub bitcoin_network: String,
    pub esplora_url: Option<String>,

    // ── ARK ──────────────────────────────────────────────────────────────
    pub ark_asp_url: String,
    pub ark_boltz_url: String,
    pub ark_connect_timeout: Duration,

    // ── Webcash ─────────────────────────────────────────────────────────
    pub webcash_server_url: String,

    // ── Storage ─────────────────────────────────────────────────────────
    pub s3_bucket: Option<String>,
    pub s3_prefix: String,
    pub secret_manager_arn: Option<String>,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            harmoniis_api_url: "https://harmoniis.com/api".to_string(),
            harmoniis_direct_url: None,
            http_timeout: Duration::from_secs(30),
            bitcoin_network: "bitcoin".to_string(),
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
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(v) = std::env::var("HARMONIIS_API_URL") { config.harmoniis_api_url = v; }
        if let Ok(v) = std::env::var("HARMONIIS_DIRECT_URL") { config.harmoniis_direct_url = Some(v); }
        if let Ok(v) = std::env::var("HARMONIIS_HTTP_TIMEOUT_SECS") {
            if let Ok(secs) = v.parse::<u64>() { config.http_timeout = Duration::from_secs(secs); }
        }
        if let Ok(v) = std::env::var("HARMONIIS_BITCOIN_NETWORK") { config.bitcoin_network = v.to_lowercase(); }
        if let Ok(v) = std::env::var("HARMONIIS_ESPLORA_URL") { config.esplora_url = Some(v); }
        if let Ok(v) = std::env::var("HARMONIIS_ARK_ASP_URL") { config.ark_asp_url = v; }
        if let Ok(v) = std::env::var("HARMONIIS_ARK_BOLTZ_URL") { config.ark_boltz_url = v; }
        if let Ok(v) = std::env::var("HARMONIIS_WEBCASH_SERVER_URL") { config.webcash_server_url = v; }
        if let Ok(v) = std::env::var("HRMW_WALLET_S3_BUCKET") { config.s3_bucket = Some(v); }
        if let Ok(v) = std::env::var("HRMW_WALLET_S3_PREFIX") { config.s3_prefix = v; }
        if let Ok(v) = std::env::var("HARMONIIS_MASTER_MNEMONIC_ARN") { config.secret_manager_arn = Some(v); }

        config
    }

    /// Resolve the effective Esplora URL for the configured network.
    pub fn effective_esplora_url(&self) -> String {
        if let Some(url) = &self.esplora_url {
            return url.clone();
        }
        match self.bitcoin_network.as_str() {
            "testnet" => "https://blockstream.info/testnet/api".to_string(),
            "signet" => "https://blockstream.info/signet/api".to_string(),
            "regtest" => "http://127.0.0.1:3002".to_string(),
            _ => "https://blockstream.info/api".to_string(),
        }
    }

    /// Parse the network string into a BDK Network enum (native only).
    #[cfg(feature = "bitcoin")]
    pub fn bdk_network(&self) -> bdk_wallet::bitcoin::Network {
        match self.bitcoin_network.as_str() {
            "testnet" => bdk_wallet::bitcoin::Network::Testnet,
            "signet" => bdk_wallet::bitcoin::Network::Signet,
            "regtest" => bdk_wallet::bitcoin::Network::Regtest,
            _ => bdk_wallet::bitcoin::Network::Bitcoin,
        }
    }
}
