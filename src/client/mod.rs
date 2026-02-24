pub mod arbiter;
pub mod arbitration;
pub mod witness;
pub mod timeline;

use crate::error::{Error, Result};

/// HTTP client for the Harmoniis backend API.
///
/// # URL modes
///
/// The Harmoniis frontend at `https://harmoniis.com` proxies API calls:
///
/// ```text
/// Browser/wallet  →  harmoniis.com/api/{path}
///                    └── Cloudflare edge proxy adds /api/v1/ prefix
///                        → backend Lambda /api/v1/{path}
/// ```
///
/// Two constructors handle this:
///
/// ```no_run
/// use harmoniis_wallet::client::HarmoniisClient;
///
/// // Production — via harmoniis.com Cloudflare proxy (default)
/// let client = HarmoniisClient::new("https://harmoniis.com/api");
///
/// // Development — talk directly to a local or Lambda backend
/// let client = HarmoniisClient::new_direct("http://localhost:9001");
/// ```
pub struct HarmoniisClient {
    /// Full base path: "https://harmoniis.com/api" or "http://localhost:9001/api/v1"
    api_base: String,
    pub(crate) http: reqwest::Client,
}

impl HarmoniisClient {
    /// Connect via the Harmoniis frontend proxy (production default).
    ///
    /// The proxy at `{base_url}/api/[path]` adds the `/v1/` prefix before
    /// forwarding to the backend, so the wallet must NOT include it.
    ///
    /// Default production URL: `https://harmoniis.com/api`
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
    ///
    /// Use this for local development or Lambda URL testing where the backend
    /// is directly reachable. Appends `/api/v1` to `backend_url`.
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
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");
        Self { api_base, http }
    }

    /// Build a full URL for a given API path segment.
    ///
    /// `path` is relative to the API base, e.g. `"witness/health_check"`.
    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}/{}", self.api_base, path.trim_start_matches('/'))
    }

    /// Check for non-2xx HTTP status and return [`Error::Api`].
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
