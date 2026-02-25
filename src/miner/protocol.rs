//! Webcash mining server protocol: target fetching and report submission.

use num_bigint::BigUint;
use reqwest::Client;
use serde::Deserialize;
use webylib::Amount;

/// Mining target information from the server.
#[derive(Debug, Clone)]
pub struct TargetInfo {
    pub difficulty: u32,
    pub epoch: u32,
    pub mining_amount: Amount,
    pub subsidy_amount: Amount,
    pub ratio: f64,
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
}

/// Mining protocol client.
pub struct MiningProtocol {
    server_url: String,
    http: Client,
}

impl MiningProtocol {
    pub fn new(server_url: &str) -> anyhow::Result<Self> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()?;
        Ok(MiningProtocol {
            server_url: server_url.trim_end_matches('/').to_string(),
            http,
        })
    }

    /// Fetch current mining target from the server.
    pub async fn get_target(&self) -> anyhow::Result<TargetInfo> {
        let url = format!("{}/api/v1/target", self.server_url);
        let resp: TargetResponse = self.http.get(&url).send().await?.json().await?;

        let mining_amount = Amount::from_wats(
            resp.mining_amount
                .parse::<i64>()
                .map_err(|e| anyhow::anyhow!("invalid mining_amount: {}", e))?,
        );
        let subsidy_amount = Amount::from_wats(
            resp.mining_subsidy_amount
                .parse::<i64>()
                .map_err(|e| anyhow::anyhow!("invalid mining_subsidy_amount: {}", e))?,
        );

        Ok(TargetInfo {
            difficulty: resp.difficulty_target_bits,
            epoch: resp.epoch,
            mining_amount,
            subsidy_amount,
            ratio: resp.ratio,
        })
    }

    /// Submit a mining report to the server.
    ///
    /// The `work` field is the SHA256 hash expressed as a decimal integer (matching
    /// the C++ webminer's `BN_bn2dec` format). The webylib `MiningReportRequest`
    /// struct is missing this field, so we build the JSON manually.
    pub async fn submit_report(
        &self,
        preimage: &str,
        hash: &[u8; 32],
    ) -> anyhow::Result<MiningReportResponse> {
        let url = format!("{}/api/v1/mining_report", self.server_url);

        // Convert 32-byte hash to decimal integer string.
        // The C++ webminer uses BN_bn2dec for this — the server expects a plain decimal number.
        let hash_decimal = BigUint::from_bytes_be(hash).to_string();

        // Build raw JSON because serde_json::Number can't represent a 256-bit integer.
        // The work field must be a bare number (not a string), matching the C++ webminer.
        let body_str = format!(
            r#"{{"preimage": "{}", "work": {}, "legalese": {{"terms": true}}}}"#,
            preimage, hash_decimal
        );

        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body_str)
            .send()
            .await?;

        let status_code = resp.status();
        let body_text = resp.text().await?;

        if status_code.is_success() {
            let parsed: MiningReportResponse = serde_json::from_str(&body_text)?;
            Ok(parsed)
        } else {
            // Try to parse error response
            if let Ok(parsed) = serde_json::from_str::<MiningReportResponse>(&body_text) {
                if parsed.error.as_deref() == Some("Didn't use a new secret value.") {
                    // This is a known benign error (duplicate secret)
                    return Ok(parsed);
                }
            }
            anyhow::bail!(
                "mining report rejected (HTTP {}): {}",
                status_code,
                body_text
            )
        }
    }
}
