use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::{apply_payment_header, HarmoniisClient, PaymentSecret};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub nickname: String,
    pub pgp_public_key: String,
    pub signature: String,
    pub about: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteIdentityRequest {
    pub fingerprint: String,
    pub signature: String,
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

impl HarmoniisClient {
    /// `POST /api/v1/donations`
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

    pub async fn register_identity(&self, req: &RegisterRequest, webcash: &str) -> Result<String> {
        self.register_identity_with_payment(req, PaymentSecret::Webcash(webcash))
            .await
    }

    /// `POST /api/v1/identity`
    pub async fn register_identity_with_payment(
        &self,
        req: &RegisterRequest,
        payment: PaymentSecret<'_>,
    ) -> Result<String> {
        let resp = self.http.post(self.url("identity"));
        let resp = apply_payment_header(resp, payment).json(req).send().await?;
        let resp = Self::check_status(resp).await?;
        let body: serde_json::Value = resp.json().await?;
        let fp = body
            .get("fingerprint")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InvalidFormat("missing fingerprint in register response".into()))?
            .to_string();
        Ok(fp)
    }

    /// `POST /api/v1/identity/delete`
    pub async fn delete_identity(&self, req: &DeleteIdentityRequest) -> Result<()> {
        let resp = self
            .http
            .post(self.url("identity/delete"))
            .json(req)
            .send()
            .await?;
        Self::check_status(resp).await?;
        Ok(())
    }

    /// `GET /api/v1/profile?fingerprint={fp}`
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
}
