use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::{Error, Result};

use super::{apply_payment_header, HarmoniisClient, PaymentSecret};

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
    pub post_type: String,
    pub witness_proof: Option<String>,
    pub contract_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    pub keywords: Vec<String>,
    #[serde(default)]
    pub attachments: Vec<PostAttachment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity_metadata: Option<PostActivityMetadata>,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_terms: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatePostRequest {
    pub post_id: String,
    pub actor_fingerprint: String,
    pub vote: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletePostRequest {
    pub post_id: String,
    pub author_fingerprint: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePostRequest {
    pub post_id: String,
    pub author_fingerprint: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keywords: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<PostAttachment>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity_metadata: Option<PostActivityMetadata>,
}

impl HarmoniisClient {
    pub async fn publish_post(&self, req: &PublishPostRequest, webcash: &str) -> Result<String> {
        self.publish_post_with_payment(req, PaymentSecret::Webcash(webcash))
            .await
    }

    /// `POST /api/v1/timeline`
    pub async fn publish_post_with_payment(
        &self,
        req: &PublishPostRequest,
        payment: PaymentSecret<'_>,
    ) -> Result<String> {
        let resp = self.http.post(self.url("timeline"));
        let resp = apply_payment_header(resp, payment).json(req).send().await?;
        let resp = Self::check_status(resp).await?;
        let body: serde_json::Value = resp.json().await?;
        let post_id = body
            .get("post_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InvalidFormat("missing post_id in publish response".into()))?
            .to_string();
        Ok(post_id)
    }

    pub async fn rate_post(&self, req: &RatePostRequest, webcash: &str) -> Result<()> {
        self.rate_post_with_payment(req, PaymentSecret::Webcash(webcash))
            .await
    }

    /// `POST /api/v1/profiles/rate`
    pub async fn rate_post_with_payment(
        &self,
        req: &RatePostRequest,
        payment: PaymentSecret<'_>,
    ) -> Result<()> {
        let body = json!({
            "post_id": req.post_id,
            "actor_fingerprint": req.actor_fingerprint,
            "vote": req.vote,
            "signature": req.signature,
        });
        let resp = self.http.post(self.url("profiles/rate"));
        let resp = apply_payment_header(resp, payment)
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

    /// `GET /api/v1/posts/{post_id}`
    pub async fn get_post(&self, post_id: &str) -> Result<serde_json::Value> {
        let resp = self
            .http
            .get(self.url(&format!("posts/{post_id}")))
            .send()
            .await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json().await?)
    }

    /// `POST /api/v1/timeline` with encrypted payload for private messaging.
    #[allow(clippy::too_many_arguments)]
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
        self.publish_encrypted_reply_with_payment(
            author_fingerprint,
            author_nick,
            recipient_fingerprint,
            parent_id,
            encrypted_payload,
            signature,
            PaymentSecret::Webcash(webcash),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn publish_encrypted_reply_with_payment(
        &self,
        author_fingerprint: &str,
        author_nick: &str,
        recipient_fingerprint: &str,
        parent_id: &str,
        encrypted_payload: &str,
        signature: &str,
        payment: PaymentSecret<'_>,
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
        let resp = self.http.post(self.url("timeline"));
        let resp = apply_payment_header(resp, payment)
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
