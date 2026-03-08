use serde::{Deserialize, Serialize};

use crate::error::Result;

use super::HarmoniisClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryProbe {
    pub key_index: u32,
    pub fingerprint: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryScanRequest {
    pub challenge: String,
    pub probes: Vec<RecoveryProbe>,
    pub include_contracts: bool,
    pub contract_limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryIdentity {
    pub key_index: u32,
    pub fingerprint: String,
    pub nickname: Option<String>,
    pub pub_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryContract {
    pub contract_id: String,
    pub contract_type: Option<String>,
    pub status: Option<String>,
    pub buyer_fingerprint: Option<String>,
    pub seller_fingerprint: Option<String>,
    pub amount: Option<String>,
    pub witness_proof: Option<String>,
    pub reference_post: Option<String>,
    pub delivery_deadline: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryScanResponse {
    pub challenge: String,
    pub identities: Vec<RecoveryIdentity>,
    pub contracts: Vec<RecoveryContract>,
}

impl HarmoniisClient {
    pub async fn recovery_scan(&self, req: &RecoveryScanRequest) -> Result<RecoveryScanResponse> {
        let resp = self
            .http
            .post(self.url("recovery/scan"))
            .json(req)
            .send()
            .await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json().await?)
    }
}
