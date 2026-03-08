use crate::{
    crypto::{generate_secret_hex, sha256_bytes},
    error::{Error, Result},
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── WitnessSecret ─────────────────────────────────────────────────────────────

/// Format: `n:{contract_id}:secret:{hex64}`
/// Matches backend arbitration.rs and witness.rs exactly.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct WitnessSecret {
    contract_id: String,
    hex_value: String,
}

impl WitnessSecret {
    /// Generate a fresh random secret for the given contract.
    pub fn generate(contract_id: &str) -> Self {
        Self {
            contract_id: contract_id.to_string(),
            hex_value: generate_secret_hex(),
        }
    }

    /// Parse from `n:{contract_id}:secret:{hex64}` string.
    pub fn parse(s: &str) -> Result<Self> {
        // Format: n:<id>:secret:<hex64>
        // Split on ":secret:" to handle contract_ids that contain colons
        let prefix = "n:";
        let mid = ":secret:";
        if !s.starts_with(prefix) {
            return Err(Error::InvalidFormat(format!(
                "WitnessSecret must start with 'n:': {s}"
            )));
        }
        let without_prefix = &s[prefix.len()..];
        let sep_pos = without_prefix
            .rfind(mid)
            .ok_or_else(|| Error::InvalidFormat(format!("missing ':secret:' in: {s}")))?;
        let contract_id = &without_prefix[..sep_pos];
        let hex_value = &without_prefix[sep_pos + mid.len()..];
        if hex_value.len() != 64 {
            return Err(Error::InvalidFormat(format!(
                "hex_value must be 64 chars, got {}: {s}",
                hex_value.len()
            )));
        }
        if !hex_value.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::InvalidFormat(format!(
                "hex_value must be hex digits: {s}"
            )));
        }
        Ok(Self {
            contract_id: contract_id.to_string(),
            hex_value: hex_value.to_string(),
        })
    }

    /// Serialize to wire format: `n:{contract_id}:secret:{hex64}`
    pub fn display(&self) -> String {
        format!("n:{}:secret:{}", self.contract_id, self.hex_value)
    }

    /// Compute the public proof by SHA256-ing the 32 raw bytes of hex_value.
    pub fn public_proof(&self) -> WitnessProof {
        let raw = hex::decode(&self.hex_value)
            .expect("hex_value is always valid hex; generated/parsed that way");
        let public_hash = sha256_bytes(&raw);
        WitnessProof {
            contract_id: self.contract_id.clone(),
            public_hash,
        }
    }

    pub fn contract_id(&self) -> &str {
        &self.contract_id
    }

    pub fn hex_value(&self) -> &str {
        &self.hex_value
    }
}

impl std::fmt::Debug for WitnessSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WitnessSecret")
            .field("contract_id", &self.contract_id)
            .field("hex_value", &"[redacted]")
            .finish()
    }
}

// ── WitnessProof ───────────────────────────────────────────────────────────────

/// Format: `n:{contract_id}:public:{sha256_hex64}`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WitnessProof {
    pub contract_id: String,
    pub public_hash: String,
}

impl WitnessProof {
    /// Parse from `n:{contract_id}:public:{hash64}` string.
    pub fn parse(s: &str) -> Result<Self> {
        let prefix = "n:";
        let mid = ":public:";
        if !s.starts_with(prefix) {
            return Err(Error::InvalidFormat(format!(
                "WitnessProof must start with 'n:': {s}"
            )));
        }
        let without_prefix = &s[prefix.len()..];
        let sep_pos = without_prefix
            .rfind(mid)
            .ok_or_else(|| Error::InvalidFormat(format!("missing ':public:' in: {s}")))?;
        let contract_id = &without_prefix[..sep_pos];
        let public_hash = &without_prefix[sep_pos + mid.len()..];
        if public_hash.len() != 64 {
            return Err(Error::InvalidFormat(format!(
                "public_hash must be 64 chars, got {}: {s}",
                public_hash.len()
            )));
        }
        Ok(Self {
            contract_id: contract_id.to_string(),
            public_hash: public_hash.to_string(),
        })
    }

    /// Serialize to wire format: `n:{contract_id}:public:{hash64}`
    pub fn display(&self) -> String {
        format!("n:{}:public:{}", self.contract_id, self.public_hash)
    }
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContractStatus {
    Issued,
    Active,
    Delivered,
    Burned,
    Refunded,
}

impl ContractStatus {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Issued => "issued",
            Self::Active => "active",
            Self::Delivered => "delivered",
            Self::Burned => "burned",
            Self::Refunded => "refunded",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "issued" => Ok(Self::Issued),
            "active" => Ok(Self::Active),
            "delivered" => Ok(Self::Delivered),
            "burned" => Ok(Self::Burned),
            "refunded" => Ok(Self::Refunded),
            _ => Err(Error::InvalidFormat(format!("unknown status: {s}"))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContractType {
    Service,
    ProductDigital,
    ProductPhysical,
}

impl ContractType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Service => "service",
            Self::ProductDigital => "product_digital",
            Self::ProductPhysical => "product_physical",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "service" => Ok(Self::Service),
            "product_digital" => Ok(Self::ProductDigital),
            "product_physical" => Ok(Self::ProductPhysical),
            _ => Err(Error::InvalidFormat(format!("unknown contract type: {s}"))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Buyer,
    Seller,
}

impl Role {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Buyer => "buyer",
            Self::Seller => "seller",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "buyer" => Ok(Self::Buyer),
            "seller" => Ok(Self::Seller),
            _ => Err(Error::InvalidFormat(format!("unknown role: {s}"))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contract {
    pub contract_id: String,
    pub contract_type: ContractType,
    pub status: ContractStatus,
    /// Stored as display string: `n:{id}:secret:{hex64}`
    pub witness_secret: Option<String>,
    /// Stored as display string: `n:{id}:public:{hash64}`
    pub witness_proof: Option<String>,
    pub amount_units: u64,
    pub work_spec: String,
    pub buyer_fingerprint: String,
    pub seller_fingerprint: Option<String>,
    pub reference_post: Option<String>,
    pub delivery_deadline: Option<String>,
    pub role: Role,
    pub delivered_text: Option<String>,
    pub certificate_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl Contract {
    pub fn new(
        contract_id: String,
        contract_type: ContractType,
        amount_units: u64,
        work_spec: String,
        buyer_fingerprint: String,
        role: Role,
    ) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            contract_id,
            contract_type,
            status: ContractStatus::Issued,
            witness_secret: None,
            witness_proof: None,
            amount_units,
            work_spec,
            buyer_fingerprint,
            seller_fingerprint: None,
            reference_post: None,
            delivery_deadline: None,
            role,
            delivered_text: None,
            certificate_id: None,
            created_at: now.clone(),
            updated_at: now,
        }
    }
}

// ── StablecashSecret (RGB20) ──────────────────────────────────────────────────
//
// PHASE:  SANDBOX — not yet in production.
// Enable via the Exchange service once the BTC ↔ USDH bridge is live.
// RGB20 is the fungible layer; all production contracts remain RGB21.

/// RGB20 fungible bearer token — split/merge allowed, sum must balance.
///
/// **⚠ SANDBOX ONLY** — Stablecash (USDH) is not yet in production.
/// Use only against testnet or local backends with `--sandbox` flag.
///
/// Wire format: `u{amount_units}:{contract_id}:secret:{hex64}`
/// Proof format: `u{amount_units}:{contract_id}:public:{sha256_hex64}`
///
/// The canonical Stablecash contract_id is `USDH_MAIN`.
/// Amount is in integer atomic units (minimum unit is 0.00000001): 1 USDH = 100_000_000 units.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct StablecashSecret {
    pub amount_units: u64,
    pub contract_id: String,
    hex_value: String,
}

impl StablecashSecret {
    /// Generate a fresh random Stablecash secret.
    pub fn generate(amount_units: u64, contract_id: &str) -> Self {
        Self {
            amount_units,
            contract_id: contract_id.to_string(),
            hex_value: crate::crypto::generate_secret_hex(),
        }
    }

    /// Parse from `u{amount}:{contract_id}:secret:{hex64}`.
    pub fn parse(s: &str) -> Result<Self> {
        if !s.starts_with('u') {
            return Err(Error::InvalidFormat(format!(
                "StablecashSecret must start with 'u': {s}"
            )));
        }
        let rest = &s[1..];
        let colon1 = rest
            .find(':')
            .ok_or_else(|| Error::InvalidFormat(format!("missing first ':' in: {s}")))?;
        let amount_str = &rest[..colon1];
        let amount_units: u64 = amount_str
            .parse()
            .map_err(|_| Error::InvalidFormat(format!("invalid amount in: {s}")))?;
        let after_amount = &rest[colon1 + 1..];

        // Now split on ":secret:" (rfind to be robust)
        let mid = ":secret:";
        let sep = after_amount
            .rfind(mid)
            .ok_or_else(|| Error::InvalidFormat(format!("missing ':secret:' in: {s}")))?;
        let contract_id = &after_amount[..sep];
        let hex_value = &after_amount[sep + mid.len()..];

        if hex_value.len() != 64 || !hex_value.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::InvalidFormat(format!(
                "hex_value must be 64 lowercase hex chars in: {s}"
            )));
        }
        Ok(Self {
            amount_units,
            contract_id: contract_id.to_string(),
            hex_value: hex_value.to_string(),
        })
    }

    /// Serialize to wire format: `u{amount}:{contract_id}:secret:{hex64}`
    pub fn display(&self) -> String {
        format!(
            "u{}:{}:secret:{}",
            self.amount_units, self.contract_id, self.hex_value
        )
    }

    /// Compute the public proof.
    pub fn public_proof(&self) -> StablecashProof {
        let raw = hex::decode(&self.hex_value).expect("always valid hex");
        StablecashProof {
            amount_units: self.amount_units,
            contract_id: self.contract_id.clone(),
            public_hash: crate::crypto::sha256_bytes(&raw),
        }
    }

    pub fn hex_value(&self) -> &str {
        &self.hex_value
    }
}

impl std::fmt::Debug for StablecashSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StablecashSecret")
            .field("amount_units", &self.amount_units)
            .field("contract_id", &self.contract_id)
            .field("hex_value", &"[redacted]")
            .finish()
    }
}

/// RGB20 public proof — `u{amount}:{contract_id}:public:{sha256_hex64}`
///
/// **⚠ SANDBOX ONLY** — see [`StablecashSecret`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StablecashProof {
    pub amount_units: u64,
    pub contract_id: String,
    pub public_hash: String,
}

impl StablecashProof {
    pub fn parse(s: &str) -> Result<Self> {
        if !s.starts_with('u') {
            return Err(Error::InvalidFormat(format!(
                "StablecashProof must start with 'u': {s}"
            )));
        }
        let rest = &s[1..];
        let colon1 = rest
            .find(':')
            .ok_or_else(|| Error::InvalidFormat(format!("missing first ':' in: {s}")))?;
        let amount_units: u64 = rest[..colon1]
            .parse()
            .map_err(|_| Error::InvalidFormat(format!("invalid amount in: {s}")))?;
        let after_amount = &rest[colon1 + 1..];
        let mid = ":public:";
        let sep = after_amount
            .rfind(mid)
            .ok_or_else(|| Error::InvalidFormat(format!("missing ':public:' in: {s}")))?;
        let contract_id = &after_amount[..sep];
        let public_hash = &after_amount[sep + mid.len()..];
        if public_hash.len() != 64 {
            return Err(Error::InvalidFormat(format!(
                "public_hash must be 64 chars in: {s}"
            )));
        }
        Ok(Self {
            amount_units,
            contract_id: contract_id.to_string(),
            public_hash: public_hash.to_string(),
        })
    }

    pub fn display(&self) -> String {
        format!(
            "u{}:{}:public:{}",
            self.amount_units, self.contract_id, self.public_hash
        )
    }
}

// ── Certificate ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub certificate_id: String,
    pub contract_id: Option<String>,
    /// Stored as display string
    pub witness_secret: Option<String>,
    pub witness_proof: Option<String>,
    pub created_at: String,
}
