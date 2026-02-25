use std::collections::HashMap;

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
    #[serde(default)]
    pub secret: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostAttachment {
    pub filename: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    pub attachment_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default)]
    pub is_public: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoragePresignRequest {
    pub fingerprint: String,
    pub file_path: String,
    pub content_type: String,
    pub is_public: bool,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoragePresignResponse {
    pub presigned_url: String,
    pub s3_key: String,
    pub public_url: Option<String>,
    pub expires_in: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileUpdateRequest {
    pub fingerprint: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skills: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_picture: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PostActivityMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subcategory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location_country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delivery_modes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_terms: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price_min: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price_max: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exchange_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub market_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub participant_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fulfillment_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_urgency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance_domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing_cycle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invoice_rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit_label: Option<String>,
    #[serde(flatten, default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, serde_json::Value>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity_metadata: Option<PostActivityMetadata>,
    pub signature: String, // sign("post:{content}")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatePostRequest {
    pub post_id: String,
    pub actor_fingerprint: String,
    pub vote: String,
    pub signature: String, // sign("vote:{post_id}:{vote}")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletePostRequest {
    pub post_id: String,
    pub author_fingerprint: String,
    pub signature: String, // sign("delete_post:{post_id}")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePostRequest {
    pub post_id: String,
    pub author_fingerprint: String,
    pub signature: String, // sign("update_post:{post_id}")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keywords: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<PostAttachment>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity_metadata: Option<PostActivityMetadata>,
}

// ── Client methods ────────────────────────────────────────────────────────────

impl HarmoniisClient {
    /// `POST /api/v1/donations`
    /// Returns `{ status: donated|no_donation, secret?, message? }`.
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

    /// `POST /api/v1/posts/delete`
    pub async fn delete_post(&self, req: &DeletePostRequest) -> Result<()> {
        let resp = self
            .http
            .post(self.url("posts/delete"))
            .json(req)
            .send()
            .await?;
        Self::check_status(resp).await?;
        Ok(())
    }

    /// `POST /api/v1/posts/update`
    pub async fn update_post(&self, req: &UpdatePostRequest) -> Result<()> {
        let resp = self
            .http
            .post(self.url("posts/update"))
            .json(req)
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

    /// `POST /api/v1/storage/presign`
    pub async fn storage_presign(
        &self,
        req: &StoragePresignRequest,
    ) -> Result<StoragePresignResponse> {
        let resp = self
            .http
            .post(self.url("storage/presign"))
            .json(req)
            .send()
            .await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json().await?)
    }

    /// Upload bytes to an S3 presigned PUT URL.
    pub async fn upload_presigned_bytes(
        &self,
        presigned_url: &str,
        bytes: Vec<u8>,
        content_type: &str,
    ) -> Result<()> {
        let resp = self
            .http
            .put(presigned_url)
            .header("Content-Type", content_type)
            .body(bytes)
            .send()
            .await?;
        let status = resp.status().as_u16();
        if (200..300).contains(&status) {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(Error::Api { status, body })
        }
    }

    /// `POST /api/v1/profile/update`
    pub async fn update_profile_picture(
        &self,
        fingerprint: &str,
        profile_picture: &str,
        signature: &str,
    ) -> Result<()> {
        let req = ProfileUpdateRequest {
            fingerprint: fingerprint.to_string(),
            signature: signature.to_string(),
            about: None,
            skills: None,
            profile_picture: Some(profile_picture.to_string()),
        };
        let resp = self
            .http
            .post(self.url("profile/update"))
            .json(&req)
            .send()
            .await?;
        Self::check_status(resp).await?;
        Ok(())
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
