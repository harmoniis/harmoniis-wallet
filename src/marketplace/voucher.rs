//! Voucher API client — health_check and replace calls.

use crate::error::Result;
use crate::marketplace::HarmoniisClient;
use crate::types::{VoucherProof, VoucherSecret};

impl HarmoniisClient {
    /// POST /voucher/health_check — check liveness of voucher proofs.
    pub async fn voucher_check(&self, proofs: &[String]) -> Result<serde_json::Value> {
        let url = self.url("voucher/health_check");
        let resp = self
            .http
            .post(&url)
            .json(&serde_json::json!({ "secrets": proofs }))
            .send()
            .await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json().await?)
    }

    /// Check if a single voucher proof is live.
    pub async fn voucher_is_live(&self, proof: &VoucherProof) -> Result<bool> {
        let proof_str = proof.display();
        let result = self.voucher_check(&[proof_str.clone()]).await?;
        Ok(result["results"][&proof_str]["spent"]
            .as_bool()
            .map(|b| !b)
            .unwrap_or(false))
    }

    /// POST /voucher/replace — atomic split/combine.
    pub async fn voucher_replace(
        &self,
        inputs: &[VoucherSecret],
        outputs: &[VoucherSecret],
    ) -> Result<()> {
        let url = self.url("voucher/replace");
        let input_strs: Vec<String> = inputs.iter().map(|v| v.display()).collect();
        let output_strs: Vec<String> = outputs.iter().map(|v| v.display()).collect();
        let resp = self
            .http
            .post(&url)
            .json(&serde_json::json!({
                "secrets": input_strs,
                "new_secrets": output_strs,
            }))
            .send()
            .await?;
        Self::check_status(resp).await?;
        Ok(())
    }
}
