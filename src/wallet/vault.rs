use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::keychain::SLOT_FAMILY_VAULT;
#[cfg(feature = "native")]
use super::WalletCore;
use crate::error::{Error, Result};

const VAULT_HKDF_SALT: &[u8] = b"harmoniis-wallet:derived-vault:v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultPublicIdentity {
    pub slot_family: String,
    pub slot_index: u32,
    pub key_id: String,
    pub signing_public_key_hex: String,
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct VaultRootMaterial {
    slot_secret: [u8; 32],
}

impl VaultRootMaterial {
    #[cfg(feature = "native")]
    pub fn from_wallet(wallet: &WalletCore) -> Result<Self> {
        let slot_hex = wallet.derive_vault_master_key_hex()?;
        Self::from_slot_hex(&slot_hex)
    }

    pub fn from_slot_hex(slot_hex: &str) -> Result<Self> {
        let bytes = hex::decode(slot_hex.trim())
            .map_err(|e| Error::InvalidFormat(format!("invalid vault slot hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(Error::InvalidFormat(format!(
                "vault slot must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut slot_secret = [0u8; 32];
        slot_secret.copy_from_slice(&bytes);
        Ok(Self { slot_secret })
    }

    pub fn slot_fingerprint(&self) -> String {
        let digest = Sha256::digest(self.slot_secret);
        hex::encode(digest)[..16].to_string()
    }

    pub fn derive_key_bytes(&self, purpose: &str) -> Result<[u8; 32]> {
        let purpose = purpose.trim();
        if purpose.is_empty() {
            return Err(Error::InvalidFormat("purpose cannot be empty".to_string()));
        }
        let hk = Hkdf::<Sha256>::new(Some(VAULT_HKDF_SALT), &self.slot_secret);
        let mut out = [0u8; 32];
        let info = format!("vault/{purpose}");
        hk.expand(info.as_bytes(), &mut out)
            .map_err(|_| Error::Crypto("hkdf expand failed".to_string()))?;
        Ok(out)
    }

    pub fn derive_key_hex(&self, purpose: &str) -> Result<String> {
        Ok(hex::encode(self.derive_key_bytes(purpose)?))
    }

    pub fn derive_aead_key_bytes(&self, namespace: &str) -> Result<[u8; 32]> {
        self.derive_key_bytes(&format!("aead/{namespace}"))
    }

    pub fn derive_mqtt_tls_seed_bytes(&self, node: &str) -> Result<[u8; 32]> {
        self.derive_key_bytes(&format!("mqtt-tls/{node}"))
    }

    pub fn derive_signing_key(&self, namespace: &str) -> Result<SigningKey> {
        let bytes = self.derive_key_bytes(&format!("ed25519/{namespace}"))?;
        Ok(SigningKey::from_bytes(&bytes))
    }

    pub fn derive_public_identity(&self, namespace: &str) -> Result<VaultPublicIdentity> {
        let signing = self.derive_signing_key(namespace)?;
        let vk: VerifyingKey = signing.verifying_key();
        let pub_hex = hex::encode(vk.to_bytes());
        let key_id = {
            let digest = Sha256::digest(vk.to_bytes());
            hex::encode(digest)[..16].to_string()
        };
        Ok(VaultPublicIdentity {
            slot_family: SLOT_FAMILY_VAULT.to_string(),
            slot_index: 0,
            key_id,
            signing_public_key_hex: pub_hex,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::VaultRootMaterial;
    use crate::wallet::keychain::{HdKeychain, SLOT_FAMILY_VAULT};

    #[test]
    fn derives_domain_separated_material() {
        let keychain = HdKeychain::from_mnemonic_words(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .expect("valid mnemonic");

        let slot_hex = keychain
            .derive_slot_hex(SLOT_FAMILY_VAULT, 0)
            .expect("slot");
        let root = VaultRootMaterial::from_slot_hex(&slot_hex).expect("root");

        let aead = root.derive_aead_key_bytes("harmonia").expect("aead");
        let mqtt = root
            .derive_mqtt_tls_seed_bytes("default")
            .expect("mqtt seed");

        assert_ne!(aead, mqtt);
        assert_eq!(aead.len(), 32);
        assert_eq!(mqtt.len(), 32);
    }

    #[test]
    fn public_identity_is_stable_for_same_namespace() {
        let slot_hex = "dfbb7b8a4fc6e869a3449a580493d7b8df82926d049e9e9eaff345b274e6b368";
        let root = VaultRootMaterial::from_slot_hex(slot_hex).expect("root");
        let a = root.derive_public_identity("harmonia").expect("identity a");
        let b = root.derive_public_identity("harmonia").expect("identity b");
        assert_eq!(a.key_id, b.key_id);
        assert_eq!(a.signing_public_key_hex, b.signing_public_key_hex);
    }
}
