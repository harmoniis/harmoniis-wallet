//! Webcash mining server protocol: target fetching and report submission.
//!
//! Works on both native (reqwest + rustls) and WASM (reqwest + browser fetch).
//! On WASM, POST bodies are sent without Content-Type: application/json to
//! avoid CORS preflight — the webcash server parses JSON regardless.

use reqwest::Client;
use serde::Deserialize;
use std::time::SystemTime;
use webylib::Amount;

/// Mining target information from the server.
#[derive(Debug, Clone)]
pub struct TargetInfo {
    pub difficulty: u32,
    pub epoch: u32,
    pub mining_amount: Amount,
    pub subsidy_amount: Amount,
    pub ratio: f64,
    /// Server time parsed from the HTTP `Date:` response header. `None`
    /// when the server is behind a proxy that strips it (defensive).
    pub server_time: Option<SystemTime>,
}

/// Response from `/api/v1/target`.
#[derive(Debug, Deserialize)]
struct TargetResponse {
    difficulty_target_bits: u32,
    epoch: u32,
    mining_amount: String,
    mining_subsidy_amount: String,
    ratio: f64,
}

/// Response from `/api/v1/mining_report`.
#[derive(Debug, Deserialize)]
pub struct MiningReportResponse {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub difficulty_target: Option<u32>,
    #[serde(default)]
    pub error: Option<String>,
    /// Server time parsed from the response `Date:` header (set by
    /// `submit_report*` after deserialization; not part of the JSON
    /// payload).
    #[serde(skip)]
    pub server_time: Option<SystemTime>,
}

/// Try to parse the `Date:` header from a response into `SystemTime`.
/// Returns `None` if the header is missing or malformed.
fn parse_date_header(headers: &reqwest::header::HeaderMap) -> Option<SystemTime> {
    let raw = headers.get(reqwest::header::DATE)?.to_str().ok()?;
    httpdate::parse_http_date(raw).ok()
}

/// Mining protocol client.
pub struct MiningProtocol {
    server_url: String,
    http: Client,
    #[cfg(not(target_arch = "wasm32"))]
    http_blocking: reqwest::blocking::Client,
}

impl MiningProtocol {
    pub fn server_url(&self) -> &str {
        &self.server_url
    }
}

impl MiningProtocol {
    pub fn new(server_url: &str) -> anyhow::Result<Self> {
        #[cfg(not(target_arch = "wasm32"))]
        let builder = Client::builder().timeout(std::time::Duration::from_secs(60));
        #[cfg(target_arch = "wasm32")]
        let builder = Client::builder();
        let http = builder.build()?;

        #[cfg(not(target_arch = "wasm32"))]
        let http_blocking = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()?;

        Ok(MiningProtocol {
            server_url: server_url.trim_end_matches('/').to_string(),
            http,
            #[cfg(not(target_arch = "wasm32"))]
            http_blocking,
        })
    }

    /// Construct from a webylib NetworkMode.
    pub fn from_network(network: &webylib::NetworkMode) -> anyhow::Result<Self> {
        Self::new(network.base_url())
    }

    /// Fetch current mining target from the server.
    pub async fn get_target(&self) -> anyhow::Result<TargetInfo> {
        let url = format!("{}/api/v1/target", self.server_url);
        let resp = self.http.get(&url).send().await?;
        let server_time = parse_date_header(resp.headers());
        let parsed: TargetResponse = resp.json().await?;

        let mining_amount: Amount = parsed.mining_amount.parse().map_err(|e| {
            anyhow::anyhow!("invalid mining_amount '{}': {}", parsed.mining_amount, e)
        })?;
        let subsidy_amount: Amount = parsed.mining_subsidy_amount.parse().map_err(|e| {
            anyhow::anyhow!(
                "invalid mining_subsidy_amount '{}': {}",
                parsed.mining_subsidy_amount,
                e
            )
        })?;

        // Feed the global skew anchor when available.
        if let Some(t) = server_time {
            if let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) {
                let _ = super::clock_skew::observe_and_warn(d.as_secs_f64());
            }
        }

        Ok(TargetInfo {
            difficulty: parsed.difficulty_target_bits,
            epoch: parsed.epoch,
            mining_amount,
            subsidy_amount,
            ratio: parsed.ratio,
            server_time,
        })
    }

    /// Submit a mining report to the server.
    ///
    /// The `work` field is the SHA256 hash as a decimal integer (matching
    /// the C++ webminer's `BN_bn2dec` format).
    /// On WASM, body is sent without Content-Type header to avoid CORS preflight.
    pub async fn submit_report(
        &self,
        preimage: &str,
        hash: &[u8; 32],
    ) -> anyhow::Result<MiningReportResponse> {
        use num_bigint::BigUint;

        let url = format!("{}/api/v1/mining_report", self.server_url);
        let hash_decimal = BigUint::from_bytes_be(hash).to_string();
        let body_str = format!(
            r#"{{"preimage": "{}", "work": {}, "legalese": {{"terms": true}}}}"#,
            preimage, hash_decimal
        );

        #[cfg(not(target_arch = "wasm32"))]
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body_str)
            .send();
        #[cfg(target_arch = "wasm32")]
        let resp = self.http.post(&url).body(body_str).send();
        let resp = resp.await?;
        let status_code = resp.status();
        let server_time = parse_date_header(resp.headers());
        let body_text = resp.text().await?;

        let mut parsed: MiningReportResponse =
            serde_json::from_str(&body_text).unwrap_or(MiningReportResponse {
                status: None,
                difficulty_target: None,
                error: Some(body_text.clone()),
                server_time: None,
            });
        parsed.server_time = server_time;

        // Anchor skew on every successful response — submissions land
        // every 6-30s under normal load, much more often than the 15s
        // target poll, so this keeps the skew tight.
        if let Some(t) = server_time {
            if let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) {
                let _ = super::clock_skew::observe_and_warn(d.as_secs_f64());
            }
        }

        if let Some(ref err) = parsed.error {
            if err.contains("Didn't use a new secret") {
                anyhow::bail!("Didn't use a new secret value.");
            }
        }

        if status_code.is_success() {
            Ok(parsed)
        } else {
            anyhow::bail!(
                "mining report rejected (HTTP {}): {}",
                status_code,
                body_text
            )
        }
    }
}

// ── Native-only: blocking submission ────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
impl MiningProtocol {
    pub fn submit_report_blocking(
        &self,
        preimage: &str,
        hash: &[u8; 32],
    ) -> anyhow::Result<MiningReportResponse> {
        Self::submit_report_with_client(&self.http_blocking, &self.server_url, preimage, hash)
    }

    pub fn submit_report_with_client(
        client: &reqwest::blocking::Client,
        server_url: &str,
        preimage: &str,
        hash: &[u8; 32],
    ) -> anyhow::Result<MiningReportResponse> {
        use num_bigint::BigUint;

        let url = format!("{}/api/v1/mining_report", server_url);
        let hash_decimal = BigUint::from_bytes_be(hash).to_string();
        let body_str = format!(
            r#"{{"preimage": "{}", "work": {}, "legalese": {{"terms": true}}}}"#,
            preimage, hash_decimal
        );

        let resp = client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()?;

        let status_code = resp.status();
        let server_time = parse_date_header(resp.headers());
        let body_text = resp.text()?;

        let mut parsed: MiningReportResponse =
            serde_json::from_str(&body_text).unwrap_or(MiningReportResponse {
                status: None,
                difficulty_target: None,
                error: Some(body_text.clone()),
                server_time: None,
            });
        parsed.server_time = server_time;

        if let Some(t) = server_time {
            if let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) {
                let _ = super::clock_skew::observe_and_warn(d.as_secs_f64());
            }
        }

        if let Some(ref err) = parsed.error {
            if err.contains("Didn't use a new secret") {
                anyhow::bail!("Didn't use a new secret value.");
            }
        }

        if status_code.is_success() {
            Ok(parsed)
        } else {
            anyhow::bail!(
                "mining report rejected (HTTP {}): {}",
                status_code,
                body_text
            )
        }
    }
}
