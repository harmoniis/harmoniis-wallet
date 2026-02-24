use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    client::HarmoniisClient,
    error::{Error, Result},
};

// ── Request types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub nickname: String,
    pub pgp_public_key: String, // hex Ed25519 pubkey (backend accepts this field name)
    pub signature: String,      // sign("register:{nickname}")
    pub about: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DonationClaimRequest {
    pub pgp_public_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DonationClaimResponse {
    pub status: String,
    pub webcash_secret: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostAttachment {
    pub filename: String,
    pub content: String,
    pub attachment_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishPostRequest {
    pub author_fingerprint: String,
    pub author_nick: String,
    pub content: String,
    pub post_type: String,             // "bid" | "service_offer" | "general"
    pub witness_proof: Option<String>, // for bids
    pub contract_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    pub keywords: Vec<String>,
    #[serde(default)]
    pub attachments: Vec<PostAttachment>,
    pub signature: String, // sign("post:{content}")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatePostRequest {
    pub post_id: String,
    pub actor_fingerprint: String,
    pub vote: String,
    pub signature: String, // sign("vote:{post_id}:{vote}")
}

// ── Client methods ────────────────────────────────────────────────────────────

impl HarmoniisClient {
    /// `POST /api/v1/donations`
    /// Returns `{ status: donated|no_donation, webcash_secret?, message? }`.
    pub async fn claim_donation(
        &self,
        req: &DonationClaimRequest,
    ) -> Result<DonationClaimResponse> {
        let resp = self
            .http
            .post(self.url("donations"))
            .json(req)
            .send()
            .await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json().await?)
    }

    /// `POST /api/v1/identity`
    /// Requires `X-Webcash-Secret` header.
    /// Returns the fingerprint.
    pub async fn register_identity(&self, req: &RegisterRequest, webcash: &str) -> Result<String> {
        let resp = self
            .http
            .post(self.url("identity"))
            .header("X-Webcash-Secret", webcash)
            .json(req)
            .send()
            .await?;
        let resp = Self::check_status(resp).await?;
        let body: serde_json::Value = resp.json().await?;
        let fp = body
            .get("fingerprint")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InvalidFormat("missing fingerprint in register response".into()))?
            .to_string();
        Ok(fp)
    }

    /// `POST /api/v1/timeline`
    /// Requires `X-Webcash-Secret` header.
    /// Returns the post ID.
    pub async fn publish_post(&self, req: &PublishPostRequest, webcash: &str) -> Result<String> {
        let resp = self
            .http
            .post(self.url("timeline"))
            .header("X-Webcash-Secret", webcash)
            .json(req)
            .send()
            .await?;
        let resp = Self::check_status(resp).await?;
        let body: serde_json::Value = resp.json().await?;
        let post_id = body
            .get("post_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InvalidFormat("missing post_id in publish response".into()))?
            .to_string();
        Ok(post_id)
    }

    /// `POST /api/v1/profiles/rate`
    /// Requires `X-Webcash-Secret` header.
    pub async fn rate_post(&self, req: &RatePostRequest, webcash: &str) -> Result<()> {
        let body = json!({
            "post_id": req.post_id,
            "actor_fingerprint": req.actor_fingerprint,
            "vote": req.vote,
            "signature": req.signature,
        });
        let resp = self
            .http
            .post(self.url("profiles/rate"))
            .header("X-Webcash-Secret", webcash)
            .json(&body)
            .send()
            .await?;
        Self::check_status(resp).await?;
        Ok(())
    }

    /// `GET /api/v1/profile?fingerprint={fp}`
    /// Returns the profile JSON (includes `public_key` field).
    pub async fn get_profile(&self, fingerprint: &str) -> Result<serde_json::Value> {
        let resp = self
            .http
            .get(self.url("profile"))
            .query(&[("fingerprint", fingerprint)])
            .send()
            .await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json().await?)
    }

    /// `GET /api/v1/posts/{post_id}`
    /// Returns `{ post: {...}, author_profile: {...} }`.
    pub async fn get_post(&self, post_id: &str) -> Result<serde_json::Value> {
        let resp = self
            .http
            .get(self.url(&format!("posts/{post_id}")))
            .send()
            .await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json().await?)
    }

    /// `POST /api/v1/timeline` with an encrypted payload for private messaging.
    /// The `encrypted_payload` field carries the new witness secret for the seller.
    pub async fn publish_encrypted_reply(
        &self,
        author_fingerprint: &str,
        author_nick: &str,
        recipient_fingerprint: &str,
        parent_id: &str,
        encrypted_payload: &str,
        signature: &str,
        webcash: &str,
    ) -> Result<String> {
        let body = json!({
            "author_fingerprint": author_fingerprint,
            "author_nick": author_nick,
            "content": "",
            "post_type": "private_reply",
            "recipient_fingerprint": recipient_fingerprint,
            "parent_id": parent_id,
            "encrypted_payload": encrypted_payload,
            "keywords": [],
            "signature": signature,
        });
        let resp = self
            .http
            .post(self.url("timeline"))
            .header("X-Webcash-Secret", webcash)
            .json(&body)
            .send()
            .await?;
        let resp = Self::check_status(resp).await?;
        let response_body: serde_json::Value = resp.json().await?;
        let post_id = response_body
            .get("post_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                Error::InvalidFormat("missing post_id in publish reply response".into())
            })?
            .to_string();
        Ok(post_id)
    }
}
