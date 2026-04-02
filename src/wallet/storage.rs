//! S3 storage for wallet database files.
//!
//! Provides upload/download of wallet SQLite databases to/from S3.
//! Requires the `s3-storage` feature flag.

#[cfg(feature = "s3-storage")]
mod s3_impl {
    use crate::error::{Error, Result};

    /// S3-backed wallet storage.
    ///
    /// Manages upload/download of wallet database files (master.db, rgb.db,
    /// webcash.db, bitcoin.db, voucher.db) to an S3 bucket.
    pub struct WalletStorage {
        s3_client: aws_sdk_s3::Client,
        bucket: String,
        prefix: String,
    }

    impl WalletStorage {
        pub fn new(s3_client: aws_sdk_s3::Client, bucket: String, prefix: String) -> Self {
            Self {
                s3_client,
                bucket,
                prefix,
            }
        }

        fn s3_key(&self, db_name: &str) -> String {
            format!("{}{}", self.prefix, db_name)
        }

        /// Upload a database file to S3.
        pub async fn upload_db(&self, db_name: &str, data: Vec<u8>) -> Result<()> {
            let key = self.s3_key(db_name);
            self.s3_client
                .put_object()
                .bucket(&self.bucket)
                .key(&key)
                .body(data.into())
                .send()
                .await
                .map_err(|e| Error::Other(anyhow::anyhow!("S3 upload failed for {key}: {e}")))?;
            Ok(())
        }

        /// Download a database file from S3. Returns `None` if the key doesn't exist.
        pub async fn download_db(&self, db_name: &str) -> Result<Option<Vec<u8>>> {
            let key = self.s3_key(db_name);
            match self
                .s3_client
                .get_object()
                .bucket(&self.bucket)
                .key(&key)
                .send()
                .await
            {
                Ok(output) => {
                    let bytes = output
                        .body
                        .collect()
                        .await
                        .map_err(|e| {
                            Error::Other(anyhow::anyhow!(
                                "S3 download body read failed for {key}: {e}"
                            ))
                        })?
                        .into_bytes();
                    Ok(Some(bytes.to_vec()))
                }
                Err(e) => {
                    let service_err = e.into_service_error();
                    if service_err.is_no_such_key() {
                        Ok(None)
                    } else {
                        Err(Error::Other(anyhow::anyhow!(
                            "S3 download failed for {key}: {service_err}"
                        )))
                    }
                }
            }
        }

        /// Upload a JSON snapshot (for webcash wallet snapshots).
        pub async fn upload_json<T: serde::Serialize>(
            &self,
            key_name: &str,
            value: &T,
        ) -> Result<()> {
            let json = serde_json::to_vec(value)
                .map_err(|e| Error::Other(anyhow::anyhow!("JSON serialize failed: {e}")))?;
            self.upload_db(key_name, json).await
        }

        /// Download and deserialize a JSON snapshot.
        pub async fn download_json<T: serde::de::DeserializeOwned>(
            &self,
            key_name: &str,
        ) -> Result<Option<T>> {
            match self.download_db(key_name).await? {
                Some(bytes) => {
                    let value = serde_json::from_slice(&bytes).map_err(|e| {
                        Error::Other(anyhow::anyhow!(
                            "JSON deserialize failed for {key_name}: {e}"
                        ))
                    })?;
                    Ok(Some(value))
                }
                None => Ok(None),
            }
        }

        /// Sync a local directory of wallet databases to S3.
        pub async fn sync_to_s3(&self, wallet_dir: &std::path::Path) -> Result<()> {
            let db_files = ["master.db", "rgb.db", "bitcoin.db", "voucher.db"];
            for db_name in &db_files {
                let local_path = wallet_dir.join(db_name);
                if local_path.exists() {
                    let data = std::fs::read(&local_path).map_err(|e| {
                        Error::Other(anyhow::anyhow!(
                            "failed to read {}: {e}",
                            local_path.display()
                        ))
                    })?;
                    self.upload_db(db_name, data).await?;
                }
            }
            Ok(())
        }

        /// Download wallet databases from S3 to a local directory.
        pub async fn sync_from_s3(&self, wallet_dir: &std::path::Path) -> Result<()> {
            std::fs::create_dir_all(wallet_dir).map_err(|e| {
                Error::Other(anyhow::anyhow!(
                    "failed to create wallet dir {}: {e}",
                    wallet_dir.display()
                ))
            })?;
            let db_files = ["master.db", "rgb.db", "bitcoin.db", "voucher.db"];
            for db_name in &db_files {
                if let Some(data) = self.download_db(db_name).await? {
                    let local_path = wallet_dir.join(db_name);
                    std::fs::write(&local_path, &data).map_err(|e| {
                        Error::Other(anyhow::anyhow!(
                            "failed to write {}: {e}",
                            local_path.display()
                        ))
                    })?;
                }
            }
            Ok(())
        }
    }
}

#[cfg(feature = "s3-storage")]
pub use s3_impl::WalletStorage;
