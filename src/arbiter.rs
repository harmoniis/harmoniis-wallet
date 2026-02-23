//! Arbiter contract signature verification for client-side use.
//!
//! ## Trust model
//!
//! The Arbiter Service signs every contract it issues with an Ed25519 key derived
//! from its master seed. The public key is served at:
//!
//! ```text
//! POST https://harmoniis.com/api/graphql
//! { "query": "{ arbiterPubkey }" }
//! ```
//!
//! **The pubkey is never stored in the contract itself.** Clients must always
//! fetch it from the legitimate Harmoniis server — the same server they are
//! transacting with. This mirrors how browsers verify TLS certificates against
//! trusted certificate authorities: you don't trust a cert just because someone
//! hands it to you; you trust it because a known authority signed it.
//!
//! ## What is signed
//!
//! The signature covers **all immutable contract fields** via a SHA256 hash:
//!
//! ```text
//! SHA256(
//!   len(contract_id)    || contract_id
//!   len(buyer_fp)       || buyer_fp
//!   len(amount_str)     || amount_str      (atomic units as integer string, e.g. "50000")
//!   len(deadline)       || deadline        (RFC 3339)
//!   len(contract_type)  || contract_type   ("service" | "product_digital" | "product_physical")
//!   len(work_spec)      || work_spec
//!   len(reference_post) || reference_post
//!   len(buyer_pk)       || buyer_pk        (armored PGP public key)
//! )
//! ```
//!
//! Length-prefix encoding ensures there is no ambiguity even when field values
//! contain special characters. If any field in DynamoDB is tampered with, the
//! Arbiter's own signature check fails on every subsequent contract operation.
//!
//! ## Usage
//!
//! ```no_run
//! use harmoniis_wallet::client::HarmoniisClient;
//! use harmoniis_wallet::arbiter;
//!
//! # async fn example() -> harmoniis_wallet::Result<()> {
//! let client = HarmoniisClient::new("https://harmoniis.com");
//!
//! // After receiving a contract from contracts/buy:
//! let ok = client.verify_contract_signature(
//!     "CTR_2026_001234",
//!     "buyer_fingerprint_hex",
//!     50_000_000,
//!     "2026-03-01T12:00:00Z",
//!     "service",
//!     "500-word technical article",
//!     "post_id_of_seller_listing",
//!     "-----BEGIN PGP PUBLIC KEY BLOCK-----...",
//!     "arbiter_signature_hex_from_issue_response",
//! ).await?;
//! assert!(ok, "reject contract if arbiter signature is invalid");
//! # Ok(())
//! # }
//! ```

use sha2::{Digest, Sha256};

use crate::error::Result;
use crate::identity::Identity;

/// Compute the canonical signed message for a contract issuance.
///
/// **Must match** `ArbiterKey::canonical_message` in the Harmoniis backend.
/// If you change the field list or encoding here, update both sides.
pub fn canonical_message(
    contract_id: &str,
    buyer_fp: &str,
    amount_units: u64,
    deadline: &str,
    contract_type: &str,
    work_spec: &str,
    reference_post: &str,
    buyer_pk: &str,
) -> String {
    let amount_str = amount_units.to_string();
    let fields: &[&str] = &[
        contract_id, buyer_fp, &amount_str, deadline,
        contract_type, work_spec, reference_post, buyer_pk,
    ];
    let mut hasher = Sha256::new();
    for field in fields {
        let bytes = field.as_bytes();
        // Length-prefix: prevents field-value injection via special characters.
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    format!("arbiter_issue:{}", hex::encode(hasher.finalize()))
}

/// Verify an arbiter signature given a trusted public key (64-char hex Ed25519).
///
/// Prefer [`HarmoniisClient::verify_contract_signature`] which fetches the
/// pubkey from the server automatically. Only use this directly if you have
/// already obtained and cached a trusted pubkey from the legitimate server.
pub fn verify_with_pubkey(
    arbiter_pubkey_hex: &str,
    contract_id: &str,
    buyer_fp: &str,
    amount_units: u64,
    deadline: &str,
    contract_type: &str,
    work_spec: &str,
    reference_post: &str,
    buyer_pk: &str,
    sig_hex: &str,
) -> Result<bool> {
    let msg = canonical_message(
        contract_id, buyer_fp, amount_units, deadline,
        contract_type, work_spec, reference_post, buyer_pk,
    );
    Identity::verify(arbiter_pubkey_hex, &msg, sig_hex)
}
