use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::HarmoniisClient;

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

impl HarmoniisClient {
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
}
