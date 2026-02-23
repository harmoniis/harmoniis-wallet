use serde_json::json;

use crate::{
    client::HarmoniisClient,
    error::Result,
    types::{WitnessProof, WitnessSecret, StablecashSecret},
};

impl HarmoniisClient {
    /// `POST /api/v1/witness/health_check`
    /// body: `["n:...:public:..."]`  (array of proof strings)
    ///
    /// Backend response:
    /// ```json
    /// { "status": "success", "results": { "<proof>": { "spent": bool, "contract_id": "...", ... } } }
    /// ```
    pub async fn witness_check(&self, proofs: &[String]) -> Result<serde_json::Value> {
        let resp = self
            .http
            .post(self.url("witness/health_check"))
            .json(proofs)
            .send()
            .await?;
        let resp = Self::check_status(resp).await?;
        let json: serde_json::Value = resp.json().await?;
        Ok(json)
    }

    /// Returns `true` if the given proof is live (not spent/burned).
    ///
    /// Parses `results[proof_str]["spent"]` — `spent: false` means live.
    pub async fn witness_is_live(&self, proof: &WitnessProof) -> Result<bool> {
        let proof_str = proof.display();
        let result = self.witness_check(&[proof_str.clone()]).await?;
        // { "results": { "<proof>": { "spent": false, ... } } }
        let entry = result
            .get("results")
            .and_then(|r| r.get(&proof_str));
        match entry {
            Some(e) => {
                // "spent": false means the record is live
                let spent = e.get("spent").and_then(|s| s.as_bool()).unwrap_or(true);
                let has_error = e.get("error").is_some();
                Ok(!spent && !has_error)
            }
            None => Ok(false),
        }
    }

    /// `POST /api/v1/witness/replace` — RGB21 (1-to-1)
    /// Transfers contract/certificate ownership: marks old secret spent, creates new.
    ///
    /// body: `{ "secrets": ["n:...:secret:..."], "new_secrets": ["n:...:secret:..."] }`
    pub async fn witness_replace(&self, old: &WitnessSecret, new: &WitnessSecret) -> Result<()> {
        let body = json!({
            "secrets": [old.display()],
            "new_secrets": [new.display()],
        });
        let resp = self
            .http
            .post(self.url("witness/replace"))
            .json(&body)
            .send()
            .await?;
        Self::check_status(resp).await?;
        Ok(())
    }

    /// `POST /api/v1/witness/replace` — RGB20 split/merge.
    /// Inputs and outputs are Stablecash secrets. Sum of input amounts must equal sum of outputs.
    ///
    /// body: `{ "secrets": ["u1000:USDH_MAIN:secret:..."], "new_secrets": [...] }`
    pub async fn witness_replace_rgb20(
        &self,
        inputs: &[StablecashSecret],
        outputs: &[StablecashSecret],
    ) -> Result<()> {
        let body = json!({
            "secrets":     inputs.iter().map(|s| s.display()).collect::<Vec<_>>(),
            "new_secrets": outputs.iter().map(|s| s.display()).collect::<Vec<_>>(),
        });
        let resp = self
            .http
            .post(self.url("witness/replace"))
            .json(&body)
            .send()
            .await?;
        Self::check_status(resp).await?;
        Ok(())
    }
}
