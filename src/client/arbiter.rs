//! Arbiter Service client methods.
//!
//! The wallet always fetches the arbiter public key from the configured server
//! (the one you're actually talking to), then verifies locally. This mirrors
//! how a browser checks TLS: trust the CA you know, not a cert someone hands you.

use crate::{arbiter, client::HarmoniisClient, error::{Error, Result}};

impl HarmoniisClient {
    /// Fetch the Arbiter Service Ed25519 public key (64-char hex) from this server.
    ///
    /// **Always call this** rather than trusting any pubkey embedded in a contract.
    /// The contract only contains `arbiter_signature`; the matching pubkey lives
    /// exclusively on the server that issued the contract.
    ///
    /// Uses GraphQL query `{ arbiterPubkey }`.
    pub async fn fetch_arbiter_pubkey(&self) -> Result<String> {
        let body = serde_json::json!({ "query": "{ arbiterPubkey }" });
        let resp = self
            .http
            .post(self.url("graphql"))
            .json(&body)
            .send()
            .await?;
        let resp = Self::check_status(resp).await?;
        let json: serde_json::Value = resp.json().await?;
        let pubkey = json
            .get("data")
            .and_then(|d| d.get("arbiterPubkey"))
            .and_then(|p| p.as_str())
            .ok_or_else(|| Error::Api {
                status: 0,
                body: "missing arbiterPubkey in GraphQL response".into(),
            })?
            .to_string();
        if pubkey.len() != 64 {
            return Err(Error::InvalidFormat(format!(
                "arbiterPubkey must be 64 hex chars, got {}",
                pubkey.len()
            )));
        }
        Ok(pubkey)
    }

    /// Verify a contract's arbiter signature by fetching the pubkey from THIS server.
    ///
    /// Pass all immutable contract fields as returned by `GET /api/arbitration/contracts/<id>`.
    /// The pubkey is fetched live from `{ arbiterPubkey }` and used for verification —
    /// a pubkey stored in the contract itself is never trusted.
    ///
    /// Returns `Ok(true)` if the signature is valid.
    pub async fn verify_contract_signature(
        &self,
        contract_id: &str,
        buyer_fp: &str,
        amount_units: u64,
        deadline: &str,
        contract_type: &str,
        work_spec: &str,
        reference_post: &str,
        buyer_pk: &str,
        arbiter_signature: &str,
    ) -> Result<bool> {
        let pubkey = self.fetch_arbiter_pubkey().await?;
        arbiter::verify_with_pubkey(
            &pubkey,
            contract_id, buyer_fp, amount_units, deadline,
            contract_type, work_spec, reference_post, buyer_pk,
            arbiter_signature,
        )
    }
}
