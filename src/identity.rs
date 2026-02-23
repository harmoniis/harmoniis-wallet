use crate::error::{Error, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use zeroize::ZeroizeOnDrop;

/// Ed25519 identity.
/// The 32-byte public key (hex-encoded, 64 chars) IS the fingerprint —
/// matching backend identity.rs line 182: `Ok(pub_key_str.to_string())`.
#[derive(ZeroizeOnDrop)]
pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    /// Generate a fresh Ed25519 identity.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Restore from 32-byte private key hex (64 chars).
    pub fn from_hex(private_key_hex: &str) -> Result<Self> {
        let bytes = hex::decode(private_key_hex).map_err(|e| {
            Error::InvalidFormat(format!("invalid private key hex: {e}"))
        })?;
        if bytes.len() != 32 {
            return Err(Error::InvalidFormat(format!(
                "private key must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let arr: [u8; 32] = bytes.try_into().expect("checked above");
        Ok(Self {
            signing_key: SigningKey::from_bytes(&arr),
        })
    }

    /// Return the 32-byte private key as 64-char hex (for storage).
    pub fn private_key_hex(&self) -> String {
        hex::encode(self.signing_key.to_bytes())
    }

    /// Return the 32-byte public key as 64-char hex.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    /// The fingerprint IS the public key hex (64 chars).
    pub fn fingerprint(&self) -> String {
        self.public_key_hex()
    }

    /// Sign a message, returning the 64-byte signature as 128-char hex.
    pub fn sign(&self, message: &str) -> String {
        use ed25519_dalek::Signer;
        let sig = self.signing_key.sign(message.as_bytes());
        hex::encode(sig.to_bytes())
    }

    /// Verify a hex-encoded Ed25519 signature against a public key hex.
    pub fn verify(public_key_hex: &str, message: &str, signature_hex: &str) -> Result<bool> {
        use ed25519_dalek::Verifier;

        let pub_bytes = hex::decode(public_key_hex)
            .map_err(|e| Error::InvalidFormat(format!("invalid public key hex: {e}")))?;
        let pub_arr: [u8; 32] = pub_bytes
            .try_into()
            .map_err(|_| Error::InvalidFormat("public key must be 32 bytes".into()))?;
        let verifying_key = VerifyingKey::from_bytes(&pub_arr)
            .map_err(|e| Error::Crypto(format!("invalid verifying key: {e}")))?;

        let sig_bytes = hex::decode(signature_hex)
            .map_err(|e| Error::InvalidFormat(format!("invalid signature hex: {e}")))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| Error::InvalidFormat("signature must be 64 bytes".into()))?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

        Ok(verifying_key.verify(message.as_bytes(), &signature).is_ok())
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}
