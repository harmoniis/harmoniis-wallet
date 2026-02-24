use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use curve25519_dalek::edwards::CompressedEdwardsY;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{
    client::HarmoniisClient,
    crypto::sha256_bytes,
    error::Result,
    types::{WitnessProof, WitnessSecret},
};

// ── Request types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuyRequest {
    pub buyer_fingerprint: String,
    pub buyer_public_key: String,
    pub contract_type: String,
    pub amount: String,
    pub contract_id: String,
    pub witness_proof: String,
    pub encrypted_witness_secret: String,
    pub witness_zkp: String,
    pub reference_post: String,
    pub signature: String, // sign("buy_contract:{fp}:{reference_post}:{contract_id}:{witness_proof}")
}

pub fn witness_commitment_message(
    buyer_fingerprint: &str,
    contract_id: &str,
    public_hash: &str,
    ciphertext_sha256: &str,
    seller_fingerprint: &str,
) -> String {
    format!(
        "witness_commitment:{}:{}:{}:{}:{}",
        buyer_fingerprint, contract_id, public_hash, ciphertext_sha256, seller_fingerprint
    )
}

fn encrypt_for_seller_envelope(
    seller_public_key: Option<&str>,
    witness_secret: &WitnessSecret,
) -> String {
    let Some(pk_hex) = seller_public_key.map(str::trim).filter(|s| !s.is_empty()) else {
        return format!(
            "sealed:v1:{}",
            hex::encode(witness_secret.display().as_bytes())
        );
    };

    let Ok(pk_bytes) = hex::decode(pk_hex) else {
        return format!(
            "sealed:v1:{}",
            hex::encode(witness_secret.display().as_bytes())
        );
    };
    if pk_bytes.len() != 32 {
        return format!(
            "sealed:v1:{}",
            hex::encode(witness_secret.display().as_bytes())
        );
    }

    let mut ed_arr = [0u8; 32];
    ed_arr.copy_from_slice(&pk_bytes);
    let Some(edwards_point) = CompressedEdwardsY(ed_arr).decompress() else {
        return format!(
            "sealed:v1:{}",
            hex::encode(witness_secret.display().as_bytes())
        );
    };
    let seller_x25519 = edwards_point.to_montgomery().to_bytes();

    let eph = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&PublicKey::from(seller_x25519));
    let key_material = Sha256::digest(shared.as_bytes());
    let cipher = ChaCha20Poly1305::new((&key_material).into());
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let Ok(ciphertext) = cipher.encrypt(nonce, witness_secret.display().as_bytes()) else {
        return format!(
            "sealed:v1:{}",
            hex::encode(witness_secret.display().as_bytes())
        );
    };

    json!({
        "scheme": "sealed_v2_x25519_chacha20poly1305",
        "ephemeral_pub": hex::encode(eph_pub.as_bytes()),
        "nonce": hex::encode(nonce_bytes),
        "ciphertext": hex::encode(ciphertext),
    })
    .to_string()
}

/// Build a witness commitment payload for `/arbitration/contracts/buy`.
///
/// This emits:
/// - `encrypted_witness_secret`: opaque envelope string carrying the buyer witness secret
/// - `witness_zkp`: JSON `commitment_v1` payload with buyer signature
///
/// The backend currently validates commitment consistency (`public_hash`, `seller_fingerprint`,
/// and `ciphertext_sha256`) and can enforce stricter formats via
/// `HARMONIIS_STRICT_WITNESS_ZKP=1`.
pub fn build_witness_commitment<F>(
    witness_secret: &WitnessSecret,
    witness_proof: &WitnessProof,
    buyer_fingerprint: &str,
    seller_fingerprint: Option<&str>,
    seller_public_key: Option<&str>,
    signer: F,
) -> (String, String)
where
    F: FnOnce(&str) -> String,
{
    let encrypted_witness_secret = encrypt_for_seller_envelope(seller_public_key, witness_secret);
    let ciphertext_sha256 = sha256_bytes(encrypted_witness_secret.as_bytes());
    let seller = seller_fingerprint
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_default();
    let signature = signer(&witness_commitment_message(
        buyer_fingerprint,
        witness_secret.contract_id(),
        &witness_proof.public_hash,
        &ciphertext_sha256,
        seller,
    ));

    let mut payload = serde_json::Map::new();
    payload.insert("scheme".to_string(), json!("commitment_v1"));
    payload.insert(
        "contract_id".to_string(),
        json!(witness_secret.contract_id()),
    );
    payload.insert("buyer_fingerprint".to_string(), json!(buyer_fingerprint));
    payload.insert("public_hash".to_string(), json!(witness_proof.public_hash));
    payload.insert("ciphertext_sha256".to_string(), json!(ciphertext_sha256));
    if !seller.is_empty() {
        payload.insert("seller_fingerprint".to_string(), json!(seller));
    }
    payload.insert("signature".to_string(), json!(signature));

    (
        encrypted_witness_secret,
        serde_json::Value::Object(payload).to_string(),
    )
}

// ── Client methods ────────────────────────────────────────────────────────────

impl HarmoniisClient {
    /// `POST /api/v1/arbitration/contracts/buy`
    /// Requires `X-Webcash-Secret` header.
    pub async fn buy_contract(&self, req: &BuyRequest, webcash: &str) -> Result<serde_json::Value> {
        let resp = self
            .http
            .post(self.url("arbitration/contracts/buy"))
            .header("X-Webcash-Secret", webcash)
            .json(req)
            .send()
            .await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json().await?)
    }

    /// `GET /api/v1/arbitration/contracts/{id}`
    pub async fn get_contract(&self, id: &str) -> Result<serde_json::Value> {
        let resp = self
            .http
            .get(self.url(&format!("arbitration/contracts/{id}")))
            .send()
            .await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json().await?)
    }

    /// `GET /api/v1/arbitration/contracts/{id}/status`
    pub async fn contract_status(&self, id: &str) -> Result<String> {
        let resp = self
            .http
            .get(self.url(&format!("arbitration/contracts/{id}/status")))
            .send()
            .await?;
        let resp = Self::check_status(resp).await?;
        let body: serde_json::Value = resp.json().await?;
        Ok(body
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("unknown")
            .to_string())
    }

    /// `POST /api/v1/arbitration/contracts/{id}/accept`
    pub async fn accept_contract(&self, id: &str, seller_fp: &str, sig: &str) -> Result<()> {
        let body = json!({
            "seller_fingerprint": seller_fp,
            "signature": sig,
        });
        let resp = self
            .http
            .post(self.url(&format!("arbitration/contracts/{id}/accept")))
            .json(&body)
            .send()
            .await?;
        Self::check_status(resp).await?;
        Ok(())
    }

    /// `POST /api/v1/arbitration/contracts/{id}/deliver`
    pub async fn deliver(
        &self,
        id: &str,
        witness_secret: &str,
        text: &str,
        actor_fingerprint: &str,
        signature: &str,
    ) -> Result<serde_json::Value> {
        let body = json!({
            "witness_secret": witness_secret,
            "delivered_text": text,
            "actor_fingerprint": actor_fingerprint,
            "signature": signature,
        });
        let resp = self
            .http
            .post(self.url(&format!("arbitration/contracts/{id}/deliver")))
            .json(&body)
            .send()
            .await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json().await?)
    }

    /// `POST /api/v1/arbitration/contracts/{id}/pickup`
    /// Requires `X-Webcash-Secret` header (first pickup only: 3% fee).
    pub async fn pickup(
        &self,
        id: &str,
        actor_fingerprint: &str,
        signature: &str,
        webcash: &str,
    ) -> Result<serde_json::Value> {
        let body = json!({
            "actor_fingerprint": actor_fingerprint,
            "signature": signature,
        });
        let resp = self
            .http
            .post(self.url(&format!("arbitration/contracts/{id}/pickup")))
            .header("X-Webcash-Secret", webcash)
            .json(&body)
            .send()
            .await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json().await?)
    }

    /// `POST /api/v1/arbitration/contracts/{id}/refund`
    pub async fn refund(
        &self,
        id: &str,
        actor_fingerprint: &str,
        witness_secret: Option<&str>,
        signature: &str,
    ) -> Result<serde_json::Value> {
        let body = match witness_secret {
            Some(secret) => json!({
                "actor_fingerprint": actor_fingerprint,
                "witness_secret": secret,
                "signature": signature,
            }),
            None => json!({
                "actor_fingerprint": actor_fingerprint,
                "signature": signature,
            }),
        };
        let resp = self
            .http
            .post(self.url(&format!("arbitration/contracts/{id}/refund")))
            .json(&body)
            .send()
            .await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json().await?)
    }

    /// `POST /api/v1/arbitration/contracts/{id}/release`
    pub async fn request_release(
        &self,
        id: &str,
        tracking_number: &str,
        tracking_carrier: Option<&str>,
        actor_fingerprint: &str,
        witness_secret: &str,
        signature: &str,
    ) -> Result<serde_json::Value> {
        let mut body = json!({
            "tracking_number": tracking_number,
            "actor_fingerprint": actor_fingerprint,
            "witness_secret": witness_secret,
            "signature": signature,
        });
        if let Some(carrier) = tracking_carrier {
            body["tracking_carrier"] = json!(carrier);
        }
        let resp = self
            .http
            .post(self.url(&format!("arbitration/contracts/{id}/release")))
            .json(&body)
            .send()
            .await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json().await?)
    }
}
