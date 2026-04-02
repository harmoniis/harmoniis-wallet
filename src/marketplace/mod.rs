pub mod arbiter;
pub mod arbitration;
pub mod identities;
pub mod posts;
pub mod recovery;
pub mod storage;
pub mod timeline;
pub mod voucher;
pub mod witness;

use std::net::{IpAddr, SocketAddr};

use crate::config::WalletConfig;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy)]
pub enum PaymentSecret<'a> {
    Webcash(&'a str),
    Bitcoin(&'a str),
    Voucher(&'a str),
}

pub(crate) fn apply_payment_header(
    req: reqwest::RequestBuilder,
    payment: PaymentSecret<'_>,
) -> reqwest::RequestBuilder {
    match payment {
        PaymentSecret::Webcash(secret) => req.header("X-Webcash-Secret", secret),
        PaymentSecret::Bitcoin(secret) => req.header("X-Bitcoin-Secret", secret),
        PaymentSecret::Voucher(secret) => req.header("X-Voucher-Secret", secret),
    }
}

/// HTTP client for the Harmoniis backend API.
pub struct HarmoniisClient {
    api_base: String,
    pub(crate) http: reqwest::Client,
}

impl HarmoniisClient {
    /// Connect via the Harmoniis frontend proxy (production default).
    pub fn new(base_url: &str) -> Self {
        let trimmed = base_url.trim_end_matches('/');
        let api_base = if trimmed.ends_with("/api") || trimmed.ends_with("/api/v1") {
            trimmed.to_string()
        } else {
            format!("{trimmed}/api")
        };
        Self::with_base(api_base)
    }

    /// Connect directly to the backend, bypassing the Cloudflare proxy.
    pub fn new_direct(backend_url: &str) -> Self {
        let trimmed = backend_url.trim_end_matches('/');
        let api_base = if trimmed.ends_with("/api/v1") {
            trimmed.to_string()
        } else {
            format!("{trimmed}/api/v1")
        };
        Self::with_base(api_base)
    }

    fn with_base(api_base: String) -> Self {
        Self::with_base_and_timeout(api_base, std::time::Duration::from_secs(30))
    }

    /// Construct from a [`WalletConfig`].
    ///
    /// Uses `harmoniis_direct_url` if set, otherwise `harmoniis_api_url`.
    pub fn from_config(config: &WalletConfig) -> Self {
        if let Some(direct) = &config.harmoniis_direct_url {
            Self::new_direct_with_timeout(direct, config.http_timeout)
        } else {
            Self::new_with_timeout(&config.harmoniis_api_url, config.http_timeout)
        }
    }

    fn new_with_timeout(base_url: &str, timeout: std::time::Duration) -> Self {
        let trimmed = base_url.trim_end_matches('/');
        let api_base = if trimmed.ends_with("/api") || trimmed.ends_with("/api/v1") {
            trimmed.to_string()
        } else {
            format!("{trimmed}/api")
        };
        Self::with_base_and_timeout(api_base, timeout)
    }

    fn new_direct_with_timeout(backend_url: &str, timeout: std::time::Duration) -> Self {
        let trimmed = backend_url.trim_end_matches('/');
        let api_base = if trimmed.ends_with("/api/v1") {
            trimmed.to_string()
        } else {
            format!("{trimmed}/api/v1")
        };
        Self::with_base_and_timeout(api_base, timeout)
    }

    fn with_base_and_timeout(api_base: String, timeout: std::time::Duration) -> Self {
        let default_port = if api_base.starts_with("https://") {
            443
        } else {
            80
        };
        let mut builder = reqwest::Client::builder().timeout(timeout).no_proxy();
        if let Ok(overrides) = std::env::var("HRMW_RESOLVE") {
            for entry in overrides.split(',') {
                let e = entry.trim();
                if e.is_empty() {
                    continue;
                }
                let Some((host, ip_raw)) = e.split_once('=') else {
                    continue;
                };
                let host = host.trim();
                let Ok(ip) = ip_raw.trim().parse::<IpAddr>() else {
                    continue;
                };
                builder = builder.resolve(host, SocketAddr::new(ip, default_port));
            }
        }
        let http = builder.build().expect("failed to build HTTP client");
        Self { api_base, http }
    }

    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}/{}", self.api_base, path.trim_start_matches('/'))
    }

    pub(crate) async fn check_status(resp: reqwest::Response) -> Result<reqwest::Response> {
        let status = resp.status().as_u16();
        if (200..300).contains(&status) {
            Ok(resp)
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(Error::Api { status, body })
        }
    }
}
