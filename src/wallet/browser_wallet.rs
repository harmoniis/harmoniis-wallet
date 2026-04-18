//! Browser wallet — webcash state management and operations for the PWA.
//!
//! Contains ALL webcash business logic previously split between wallet-wasm
//! and TypeScript. Operations needing server I/O return effect structs;
//! the calling code (WASM bridge or test) executes the I/O and feeds results back.
//!
//! Encryption lives in the JS layer (Web Crypto API) — this module handles
//! only plaintext state.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::wallet::keychain::HdKeychain;

// ── Constants ───────────────────────────────────────────────────

const UNIT: i64 = 100_000_000;
const CHAIN_RECEIVE: u32 = 0;
const CHAIN_PAY: u32 = 1;
const CHAIN_CHANGE: u32 = 2;
const CHAIN_MINING: u32 = 3;

// ── State Types ─────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
pub struct BrowserWallet {
    pub mnemonic: String,
    pub active_family: String,
    pub active_label: String,
    pub active_network: String,
    pub wallets: HashMap<String, WebcashFamily>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WebcashFamily {
    pub master_secret_hex: String,
    pub outputs: Vec<WebcashOutput>,
    pub spent_hashes: Vec<String>,
    pub depths: HashMap<String, u64>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WebcashOutput {
    pub secret: String,
    pub public_hash: String,
    pub amount: i64,
    pub spent: bool,
}

// ── Effect Types (returned to caller for server I/O) ────────────

#[derive(Serialize, Deserialize, Clone)]
pub struct ReplaceRequest {
    pub webcashes: Vec<String>,
    pub new_webcashes: Vec<String>,
    pub legalese: Legalese,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Legalese {
    pub terms: bool,
}

#[derive(Serialize, Deserialize)]
pub struct PaymentEffect {
    pub replace_request: ReplaceRequest,
    pub payment_webcash: String,
    pub mark_spent_secrets: Vec<String>,
    pub change_secret: Option<String>,
    pub change_amount: i64,
    pub depth_updates: HashMap<String, u64>,
}

#[derive(Serialize, Deserialize)]
pub struct InsertEffect {
    pub replace_request: ReplaceRequest,
    pub new_secret: String,
    pub new_amount: i64,
    pub receive_depth: u64,
}

#[derive(Serialize, Deserialize)]
pub struct MergeEffect {
    pub replace_request: ReplaceRequest,
    pub mark_spent_secrets: Vec<String>,
    pub merged_secret: String,
    pub merged_amount: i64,
    pub change_depth: u64,
}

#[derive(Serialize, Deserialize)]
pub struct MiningParams {
    pub secret: String,
    pub webcash_str: String,
    pub public_hash: String,
    pub difficulty: u32,
    pub mining_depth: u64,
}

#[derive(Serialize, Deserialize)]
pub struct RecoverBatch {
    pub public_webcash_strings: Vec<String>,
    pub secrets: Vec<String>,
    pub start_depth: u64,
    pub batch_size: u64,
}

#[derive(Serialize, Deserialize)]
pub struct RecoverResult {
    pub amount: i64,
    pub spent: bool,
}

#[derive(Serialize, Deserialize)]
pub struct WalletStats {
    pub total_webcash: usize,
    pub unspent_webcash: usize,
    pub spent_webcash: usize,
    pub total_balance: i64,
    pub mined_count: u64,
    pub received_count: u64,
    pub sent_count: u64,
}

#[derive(Serialize, Deserialize)]
pub struct ParsedWebcash {
    pub secret: String,
    pub amount_wats: i64,
    pub amount_display: String,
}

#[derive(Serialize, Deserialize)]
pub struct WebcashSnapshot {
    pub master_secret: String,
    pub unspent_outputs: Vec<SnapshotOutput>,
    pub spent_hashes: Vec<String>,
    pub depths: HashMap<String, u64>,
}

#[derive(Serialize, Deserialize)]
pub struct SnapshotOutput {
    pub secret: String,
    pub amount: i64,
}

// ── Utility Functions ───────────────────────────────────────────

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// GPU mining input: midstate + metadata for reconstructing the preimage on solution.
#[derive(Serialize, Deserialize)]
pub struct GpuMiningWork {
    pub secret: String,
    pub webcash_str: String,
    pub mining_depth: u64,
    pub difficulty: u32,
    /// Base64-encoded prefix (everything before the nonce).
    pub prefix_b64: String,
}

/// Tagged-SHA256 derivation: SHA256(tag||tag||master||chain_be64||depth_be64)
pub fn derive_output_secret(master_secret_hex: &str, chain_code: u32, depth: u64) -> Result<String> {
    let master =
        hex::decode(master_secret_hex).map_err(|_| Error::InvalidFormat("invalid master hex".into()))?;
    if master.len() != 32 {
        return Err(Error::InvalidFormat("master secret must be 32 bytes".into()));
    }
    let tag = sha256(b"webcashwalletv1");
    let mut input = Vec::with_capacity(32 + 32 + 32 + 8 + 8);
    input.extend_from_slice(&tag);
    input.extend_from_slice(&tag);
    input.extend_from_slice(&master);
    input.extend_from_slice(&(chain_code as u64).to_be_bytes());
    input.extend_from_slice(&depth.to_be_bytes());
    Ok(hex::encode(sha256(&input)))
}

/// Convert a 64-char hex entropy string to BIP39 mnemonic words.
pub fn mnemonic_from_hex(hex: &str) -> Result<String> {
    let keychain = HdKeychain::from_entropy_hex(hex)?;
    Ok(keychain.mnemonic_words())
}

pub fn secret_to_public_hash(secret: &str) -> String {
    hex::encode(sha256(secret.as_bytes()))
}

pub fn format_amount(wats: i64) -> String {
    if wats == 0 {
        return "0".into();
    }
    let integer = wats / UNIT;
    let frac = (wats % UNIT).abs();
    if frac == 0 {
        format!("{integer}")
    } else {
        let s = format!("{frac:08}");
        format!("{integer}.{}", s.trim_end_matches('0'))
    }
}

pub fn parse_amount(s: &str) -> Result<i64> {
    let s = s.trim().strip_prefix('e').unwrap_or(s);
    if s == "0" {
        return Ok(0);
    }
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() > 2 {
        return Err(Error::InvalidFormat("too many decimal points".into()));
    }
    let int_part: i64 = parts[0]
        .parse()
        .map_err(|_| Error::InvalidFormat("invalid integer".into()))?;
    if parts.len() == 1 {
        return Ok(int_part * UNIT);
    }
    let frac = parts[1];
    if frac.len() > 8 {
        return Err(Error::InvalidFormat("too many decimals".into()));
    }
    let frac_val: i64 = frac
        .parse()
        .map_err(|_| Error::InvalidFormat("invalid fraction".into()))?;
    let mult = 10_i64.pow(8 - frac.len() as u32);
    Ok(int_part * UNIT + frac_val * mult)
}

pub fn parse_webcash(s: &str) -> Result<ParsedWebcash> {
    let s = s.trim();
    if !s.starts_with('e') {
        return Err(Error::InvalidFormat("webcash must start with 'e'".into()));
    }
    let parts: Vec<&str> = s[1..].split(':').collect();
    if parts.len() < 3 || parts[1] != "secret" {
        return Err(Error::InvalidFormat("invalid webcash format".into()));
    }
    let wats = parse_amount(parts[0])?;
    let secret = parts[2..].join(":");
    if secret.len() != 64 {
        return Err(Error::InvalidFormat("secret must be 64 hex chars".into()));
    }
    Ok(ParsedWebcash {
        secret,
        amount_wats: wats,
        amount_display: format_amount(wats),
    })
}

pub fn format_webcash(secret: &str, amount_wats: i64) -> String {
    format!("e{}:secret:{}", format_amount(amount_wats), secret)
}

pub fn format_public_webcash(hash_hex: &str, amount_wats: i64) -> String {
    format!("e{}:public:{}", format_amount(amount_wats), hash_hex)
}

/// The three wallet families. Bitcoin and RGB are placeholders for now.
pub const FAMILIES: &[&str] = &["webcash", "bitcoin", "rgb"];

/// Info about a labeled wallet within a family.
#[derive(Serialize, Deserialize, Clone)]
pub struct WalletInfo {
    pub family: String,
    pub label: String,
    pub balance: i64,
    pub output_count: usize,
}

// ── BrowserWallet Lifecycle ─────────────────────────────────────

impl BrowserWallet {
    fn empty_family(master_secret_hex: String) -> WebcashFamily {
        WebcashFamily {
            master_secret_hex,
            outputs: Vec::new(),
            spent_hashes: Vec::new(),
            depths: [
                ("RECEIVE".into(), 0),
                ("PAY".into(), 0),
                ("CHANGE".into(), 0),
                ("MINING".into(), 0),
            ]
            .into(),
        }
    }

    /// Create a new master wallet. Initializes "main" wallet for each family.
    pub fn create(mnemonic_words: Option<&str>) -> Result<Self> {
        let keychain = match mnemonic_words {
            Some(words) => HdKeychain::from_mnemonic_words(words)?,
            None => HdKeychain::generate_new()?,
        };
        let mnemonic = keychain.mnemonic_words();

        let mut wallets = HashMap::new();
        for family in FAMILIES {
            let secret = keychain.derive_slot_hex(family, 0)?;
            wallets.insert(format!("{family}:main"), Self::empty_family(secret));
        }

        Ok(Self {
            mnemonic,
            active_family: "webcash".into(),
            active_label: "main".into(),
            active_network: "production".into(),
            wallets,
        })
    }

    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| Error::Other(anyhow::anyhow!(e)))
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| Error::Other(anyhow::anyhow!(e)))
    }

    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    pub fn active_family(&self) -> &str {
        &self.active_family
    }

    pub fn active_label(&self) -> &str {
        &self.active_label
    }

    pub fn active_network(&self) -> &str {
        &self.active_network
    }

    pub fn set_active_network(&mut self, network: &str) {
        self.active_network = network.to_string();
    }

    fn active_data(&self) -> Result<&WebcashFamily> {
        let key = format!("{}:{}", self.active_family, self.active_label);
        self.wallets
            .get(&key)
            .ok_or_else(|| Error::NotFound("active wallet not found".into()))
    }

    fn active_data_mut(&mut self) -> Result<&mut WebcashFamily> {
        let key = format!("{}:{}", self.active_family, self.active_label);
        self.wallets
            .get_mut(&key)
            .ok_or_else(|| Error::NotFound("active wallet not found".into()))
    }

    // ── Multi-wallet Management ─────────────────────────────────

    /// Switch active wallet to the given family + label.
    pub fn set_active(&mut self, family: &str, label: &str) -> Result<()> {
        let key = format!("{family}:{label}");
        if !self.wallets.contains_key(&key) {
            return Err(Error::NotFound(format!("wallet '{key}' not found")));
        }
        self.active_family = family.to_string();
        self.active_label = label.to_string();
        Ok(())
    }

    /// Add a new labeled wallet within a family.
    pub fn add_wallet(&mut self, family: &str, label: &str) -> Result<()> {
        let label = label.trim();
        if label.is_empty() {
            return Err(Error::InvalidFormat("label cannot be empty".into()));
        }
        let key = format!("{family}:{label}");
        if self.wallets.contains_key(&key) {
            return Err(Error::Other(anyhow::anyhow!(
                "wallet '{key}' already exists"
            )));
        }
        let slot_index = self
            .wallets
            .keys()
            .filter(|k| k.starts_with(&format!("{family}:")))
            .count() as u32;
        let secret = self.keychain()?.derive_slot_hex(family, slot_index)?;
        self.wallets
            .insert(key, Self::empty_family(secret));
        Ok(())
    }

    /// Remove a labeled wallet (cannot remove "main").
    pub fn remove_wallet(&mut self, family: &str, label: &str) -> Result<()> {
        if label == "main" {
            return Err(Error::Other(anyhow::anyhow!(
                "cannot remove the main wallet"
            )));
        }
        let key = format!("{family}:{label}");
        self.wallets
            .remove(&key)
            .ok_or_else(|| Error::NotFound(format!("wallet '{key}' not found")))?;
        if self.active_family == family && self.active_label == label {
            self.active_label = "main".to_string();
        }
        Ok(())
    }

    /// Rename a labeled wallet.
    pub fn rename_wallet(&mut self, family: &str, old_label: &str, new_label: &str) -> Result<()> {
        let new_label = new_label.trim();
        if new_label.is_empty() {
            return Err(Error::InvalidFormat("label cannot be empty".into()));
        }
        let old_key = format!("{family}:{old_label}");
        let new_key = format!("{family}:{new_label}");
        if self.wallets.contains_key(&new_key) {
            return Err(Error::Other(anyhow::anyhow!(
                "wallet '{new_key}' already exists"
            )));
        }
        let data = self
            .wallets
            .remove(&old_key)
            .ok_or_else(|| Error::NotFound(format!("wallet '{old_key}' not found")))?;
        self.wallets.insert(new_key, data);
        if self.active_family == family && self.active_label == old_label {
            self.active_label = new_label.to_string();
        }
        Ok(())
    }

    /// List all labeled wallets for a family (sorted by label).
    pub fn list_wallets(&self, family: &str) -> Vec<WalletInfo> {
        let prefix = format!("{family}:");
        let mut wallets: Vec<_> = self
            .wallets
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(k, data)| WalletInfo {
                family: family.to_string(),
                label: k[prefix.len()..].to_string(),
                balance: data.outputs.iter().filter(|o| !o.spent).map(|o| o.amount).sum(),
                output_count: data.outputs.iter().filter(|o| !o.spent).count(),
            })
            .collect();
        wallets.sort_by(|a, b| {
            if a.label == "main" { std::cmp::Ordering::Less }
            else if b.label == "main" { std::cmp::Ordering::Greater }
            else { a.label.cmp(&b.label) }
        });
        wallets
    }

    // ── Key Derivation Helpers ──────────────────────────────────

    pub fn keychain(&self) -> Result<HdKeychain> {
        HdKeychain::from_mnemonic_words(&self.mnemonic)
    }

    pub fn derive_webcash_secret(&self, label_index: u32) -> Result<String> {
        self.keychain()?.derive_slot_hex("webcash", label_index)
    }

    pub fn derive_vault_key(&self, purpose: &str) -> Result<String> {
        let keychain = self.keychain()?;
        let vault_hex = keychain.derive_slot_hex("vault", 0)?;
        let vault = crate::vault::VaultRootMaterial::from_slot_hex(&vault_hex)?;
        let key = vault.derive_aead_key_bytes(purpose)?;
        Ok(hex::encode(key))
    }

    pub fn derive_identity_public_key(&self) -> Result<String> {
        let keychain = self.keychain()?;
        let rgb_hex = keychain.derive_slot_hex("rgb", 0)?;
        let identity = crate::Identity::from_hex(&rgb_hex)?;
        Ok(identity.public_key_hex())
    }

    pub fn derive_pgp_key(&self, index: u32) -> Result<(String, String)> {
        let keychain = self.keychain()?;
        let pgp_hex = keychain.derive_slot_hex("pgp", index)?;
        let identity = crate::Identity::from_hex(&pgp_hex)?;
        Ok((pgp_hex, identity.public_key_hex()))
    }

    // ── Balance & State Queries ─────────────────────────────────

    pub fn balance(&self) -> Result<i64> {
        let data = self.active_data()?;
        Ok(data.outputs.iter().filter(|o| !o.spent).map(|o| o.amount).sum())
    }

    pub fn stats(&self) -> Result<WalletStats> {
        let data = self.active_data()?;
        let unspent: Vec<_> = data.outputs.iter().filter(|o| !o.spent).collect();
        Ok(WalletStats {
            total_webcash: data.outputs.len(),
            unspent_webcash: unspent.len(),
            spent_webcash: data.spent_hashes.len(),
            total_balance: unspent.iter().map(|o| o.amount).sum(),
            mined_count: data.depths.get("MINING").copied().unwrap_or(0),
            received_count: data.depths.get("RECEIVE").copied().unwrap_or(0),
            sent_count: data.depths.get("PAY").copied().unwrap_or(0),
        })
    }

    pub fn master_secret_hex(&self) -> Result<String> {
        Ok(self.active_data()?.master_secret_hex.clone())
    }

    // ── Payment ─────────────────────────────────────────────────

    pub fn prepare_payment(&self, amount_wats: i64) -> Result<PaymentEffect> {
        let data = self.active_data()?;
        let mut unspent: Vec<_> = data.outputs.iter().filter(|o| !o.spent).collect();
        unspent.sort_by(|a, b| b.amount.cmp(&a.amount));

        let mut selected = Vec::new();
        let mut total: i64 = 0;
        for o in &unspent {
            selected.push(o.secret.clone());
            total += o.amount;
            if total >= amount_wats {
                break;
            }
        }
        if total < amount_wats {
            return Err(Error::Other(anyhow::anyhow!("Insufficient funds")));
        }

        let change = total - amount_wats;
        let pay_depth = data.depths.get("PAY").copied().unwrap_or(0);
        let change_depth = data.depths.get("CHANGE").copied().unwrap_or(0);

        let pay_secret = derive_output_secret(&data.master_secret_hex, CHAIN_PAY, pay_depth)?;
        let pay_str = format_webcash(&pay_secret, amount_wats);
        let mut new_webcashes = vec![pay_str.clone()];
        let mut depth_updates: HashMap<String, u64> = [("PAY".into(), pay_depth + 1)].into();

        let mut change_secret = None;
        if change > 0 {
            let cs = derive_output_secret(&data.master_secret_hex, CHAIN_CHANGE, change_depth)?;
            new_webcashes.push(format_webcash(&cs, change));
            depth_updates.insert("CHANGE".into(), change_depth + 1);
            change_secret = Some(cs);
        }

        let webcashes: Vec<String> = selected
            .iter()
            .filter_map(|s| {
                data.outputs
                    .iter()
                    .find(|o| o.secret == *s)
                    .map(|o| format_webcash(s, o.amount))
            })
            .collect();

        Ok(PaymentEffect {
            replace_request: ReplaceRequest {
                webcashes,
                new_webcashes,
                legalese: Legalese { terms: true },
            },
            payment_webcash: pay_str,
            mark_spent_secrets: selected,
            change_secret,
            change_amount: change,
            depth_updates,
        })
    }

    pub fn apply_payment(&mut self, effect: &PaymentEffect) -> Result<()> {
        let data = self.active_data_mut()?;
        for secret in &effect.mark_spent_secrets {
            if let Some(o) = data.outputs.iter_mut().find(|o| o.secret == *secret) {
                o.spent = true;
            }
            let hash = secret_to_public_hash(secret);
            if !data.spent_hashes.contains(&hash) {
                data.spent_hashes.push(hash);
            }
        }
        if let Some(cs) = &effect.change_secret {
            data.outputs.push(WebcashOutput {
                secret: cs.clone(),
                public_hash: secret_to_public_hash(cs),
                amount: effect.change_amount,
                spent: false,
            });
        }
        for (chain, depth) in &effect.depth_updates {
            data.depths.insert(chain.clone(), *depth);
        }
        Ok(())
    }

    // ── Insert (import webcash via replace) ─────────────────────

    pub fn prepare_insert(&self, webcash_str: &str) -> Result<InsertEffect> {
        let parsed = parse_webcash(webcash_str)?;
        let data = self.active_data()?;
        let receive_depth = data.depths.get("RECEIVE").copied().unwrap_or(0);
        let new_secret =
            derive_output_secret(&data.master_secret_hex, CHAIN_RECEIVE, receive_depth)?;

        let input_str = format_webcash(&parsed.secret, parsed.amount_wats);
        let output_str = format_webcash(&new_secret, parsed.amount_wats);

        Ok(InsertEffect {
            replace_request: ReplaceRequest {
                webcashes: vec![input_str],
                new_webcashes: vec![output_str],
                legalese: Legalese { terms: true },
            },
            new_secret,
            new_amount: parsed.amount_wats,
            receive_depth: receive_depth + 1,
        })
    }

    pub fn apply_insert(&mut self, effect: &InsertEffect) -> Result<()> {
        let data = self.active_data_mut()?;
        data.outputs.push(WebcashOutput {
            secret: effect.new_secret.clone(),
            public_hash: secret_to_public_hash(&effect.new_secret),
            amount: effect.new_amount,
            spent: false,
        });
        data.depths.insert("RECEIVE".into(), effect.receive_depth);
        Ok(())
    }

    // ── Mining ──────────────────────────────────────────────────

    pub fn build_mining_params(&self, difficulty: u32, mining_amount: &str) -> Result<MiningParams> {
        let data = self.active_data()?;
        let depth = data.depths.get("MINING").copied().unwrap_or(0);
        let secret = derive_output_secret(&data.master_secret_hex, CHAIN_MINING, depth)?;
        let webcash_str = format!("e{}:secret:{}", mining_amount, secret);
        Ok(MiningParams {
            public_hash: secret_to_public_hash(&secret),
            secret,
            webcash_str,
            difficulty,
            mining_depth: depth,
        })
    }

    /// Build GPU mining work: derives secret, builds the base64 preimage prefix
    /// for SHA256 midstate computation. Used by the WebGPU miner.
    pub fn build_gpu_mining_work(&self, difficulty: u32, mining_amount: &str) -> Result<GpuMiningWork> {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let data = self.active_data()?;
        let depth = data.depths.get("MINING").copied().unwrap_or(0);
        let secret = derive_output_secret(&data.master_secret_hex, CHAIN_MINING, depth)?;
        let webcash_str = format!("e{}:secret:{}", mining_amount, secret);

        // Build the JSON preimage matching C++ webminer format.
        // The nonce field is padded to keep total length fixed.
        let raw_json = format!(
            "{{\"legalese\": {{\"terms\": true}}, \"webcash\": [\"{webcash_str}\"], \"subsidy\": [], \"difficulty\": {difficulty}, \"nonce\":      0}}"
        );

        // Pad raw JSON to a multiple of 48 bytes → 64 base64 bytes = one SHA256 block.
        let raw_bytes = raw_json.as_bytes();
        let pad_len = ((raw_bytes.len() + 47) / 48) * 48;
        let mut padded = vec![0u8; pad_len];
        padded[..raw_bytes.len()].copy_from_slice(raw_bytes);

        // Base64-encode the prefix (everything except closing "}").
        // The last 3 raw bytes "0}}" are replaced by nonce digits + "}".
        let prefix_raw = &padded[..pad_len - 3];
        let prefix_b64 = STANDARD.encode(prefix_raw);

        Ok(GpuMiningWork {
            secret,
            webcash_str,
            mining_depth: depth,
            difficulty,
            prefix_b64,
        })
    }

    pub fn store_mined_output(&mut self, secret: &str, amount_wats: i64) -> Result<()> {
        let data = self.active_data_mut()?;
        data.outputs.push(WebcashOutput {
            secret: secret.to_string(),
            public_hash: secret_to_public_hash(secret),
            amount: amount_wats,
            spent: false,
        });
        let depth = data.depths.get("MINING").copied().unwrap_or(0);
        data.depths.insert("MINING".into(), depth + 1);
        Ok(())
    }

    // ── Check (verify spent status) ─────────────────────────────

    /// Returns public webcash strings to send to health_check API.
    pub fn prepare_check(&self) -> Result<Vec<String>> {
        let data = self.active_data()?;
        Ok(data
            .outputs
            .iter()
            .filter(|o| !o.spent)
            .map(|o| format_public_webcash(&o.public_hash, o.amount))
            .collect())
    }

    /// Apply health_check results. Keys are public hash hex strings.
    pub fn apply_check(&mut self, results: &HashMap<String, bool>) -> Result<(usize, usize)> {
        let data = self.active_data_mut()?;
        let mut valid = 0usize;
        let mut spent = 0usize;
        for o in data.outputs.iter_mut().filter(|o| !o.spent) {
            if let Some(&is_spent) = results.get(&o.public_hash) {
                if is_spent {
                    o.spent = true;
                    if !data.spent_hashes.contains(&o.public_hash) {
                        data.spent_hashes.push(o.public_hash.clone());
                    }
                    spent += 1;
                } else {
                    valid += 1;
                }
            }
        }
        Ok((valid, spent))
    }

    // ── Merge (consolidate outputs) ─────────────────────────────

    pub fn prepare_merge(&self, max_outputs: usize) -> Result<Option<MergeEffect>> {
        let data = self.active_data()?;
        let unspent: Vec<_> = data.outputs.iter().filter(|o| !o.spent).collect();
        if unspent.len() <= 1 {
            return Ok(None);
        }
        let to_merge: Vec<_> = unspent.into_iter().take(max_outputs).collect();
        if to_merge.len() <= 1 {
            return Ok(None);
        }
        let total_amount: i64 = to_merge.iter().map(|o| o.amount).sum();
        let change_depth = data.depths.get("CHANGE").copied().unwrap_or(0);
        let merged_secret =
            derive_output_secret(&data.master_secret_hex, CHAIN_CHANGE, change_depth)?;

        let webcashes: Vec<String> = to_merge
            .iter()
            .map(|o| format_webcash(&o.secret, o.amount))
            .collect();
        let mark_spent: Vec<String> = to_merge.iter().map(|o| o.secret.clone()).collect();

        Ok(Some(MergeEffect {
            replace_request: ReplaceRequest {
                webcashes,
                new_webcashes: vec![format_webcash(&merged_secret, total_amount)],
                legalese: Legalese { terms: true },
            },
            mark_spent_secrets: mark_spent,
            merged_secret,
            merged_amount: total_amount,
            change_depth: change_depth + 1,
        }))
    }

    pub fn apply_merge(&mut self, effect: &MergeEffect) -> Result<()> {
        let data = self.active_data_mut()?;
        for secret in &effect.mark_spent_secrets {
            if let Some(o) = data.outputs.iter_mut().find(|o| o.secret == *secret) {
                o.spent = true;
            }
            let hash = secret_to_public_hash(secret);
            if !data.spent_hashes.contains(&hash) {
                data.spent_hashes.push(hash);
            }
        }
        data.outputs.push(WebcashOutput {
            secret: effect.merged_secret.clone(),
            public_hash: secret_to_public_hash(&effect.merged_secret),
            amount: effect.merged_amount,
            spent: false,
        });
        data.depths.insert("CHANGE".into(), effect.change_depth);
        Ok(())
    }

    // ── Recovery (scan for unspent outputs) ─────────────────────

    pub fn prepare_recover_batch(
        &self,
        chain_name: &str,
        start_depth: u64,
        batch_size: u64,
    ) -> Result<RecoverBatch> {
        let data = self.active_data()?;
        let chain_code = match chain_name {
            "RECEIVE" => CHAIN_RECEIVE,
            "CHANGE" => CHAIN_CHANGE,
            "MINING" => CHAIN_MINING,
            _ => return Err(Error::InvalidFormat(format!("unknown chain: {chain_name}"))),
        };
        let mut secrets = Vec::new();
        let mut public_webcash_strings = Vec::new();
        for i in 0..batch_size {
            let depth = start_depth + i;
            let secret = derive_output_secret(&data.master_secret_hex, chain_code, depth)?;
            let hash = secret_to_public_hash(&secret);
            public_webcash_strings.push(format_public_webcash(&hash, 1));
            secrets.push(secret);
        }
        Ok(RecoverBatch {
            public_webcash_strings,
            secrets,
            start_depth,
            batch_size,
        })
    }

    /// Apply recovery results. Returns number of outputs found.
    /// `results` maps public hash to RecoverResult.
    pub fn apply_recover_batch(
        &mut self,
        batch: &RecoverBatch,
        results: &HashMap<String, RecoverResult>,
    ) -> Result<usize> {
        let data = self.active_data_mut()?;
        let mut found = 0usize;
        for secret in &batch.secrets {
            let hash = secret_to_public_hash(secret);
            if let Some(result) = results.get(&hash) {
                if !result.spent && result.amount > 0 {
                    let already_exists = data.outputs.iter().any(|o| o.secret == *secret);
                    if !already_exists {
                        data.outputs.push(WebcashOutput {
                            secret: secret.clone(),
                            public_hash: hash,
                            amount: result.amount,
                            spent: false,
                        });
                        found += 1;
                    }
                }
            }
        }
        Ok(found)
    }

    pub fn set_depth(&mut self, chain_name: &str, depth: u64) -> Result<()> {
        let data = self.active_data_mut()?;
        data.depths.insert(chain_name.to_string(), depth);
        Ok(())
    }

    pub fn get_depth(&self, chain_name: &str) -> Result<u64> {
        let data = self.active_data()?;
        Ok(data.depths.get(chain_name).copied().unwrap_or(0))
    }

    // ── Snapshot Export ──────────────────────────────────────────

    pub fn export_webcash_snapshot(&self) -> Result<WebcashSnapshot> {
        let data = self.active_data()?;
        Ok(WebcashSnapshot {
            master_secret: data.master_secret_hex.clone(),
            unspent_outputs: data
                .outputs
                .iter()
                .filter(|o| !o.spent)
                .map(|o| SnapshotOutput {
                    secret: o.secret.clone(),
                    amount: o.amount,
                })
                .collect(),
            spent_hashes: data.spent_hashes.clone(),
            depths: data.depths.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_wallet_and_check_balance() {
        let wallet = BrowserWallet::create(None).unwrap();
        assert_eq!(wallet.balance().unwrap(), 0);
        assert!(!wallet.mnemonic().is_empty());
    }

    #[test]
    fn store_mined_output_and_balance() {
        let mut wallet = BrowserWallet::create(None).unwrap();
        let params = wallet.build_mining_params(20, "200").unwrap();
        wallet.store_mined_output(&params.secret, 200 * UNIT).unwrap();
        assert_eq!(wallet.balance().unwrap(), 200 * UNIT);
        assert_eq!(wallet.stats().unwrap().unspent_webcash, 1);
    }

    #[test]
    fn payment_round_trip() {
        let mut wallet = BrowserWallet::create(None).unwrap();
        // Mine some webcash
        let params = wallet.build_mining_params(20, "500").unwrap();
        wallet.store_mined_output(&params.secret, 500 * UNIT).unwrap();

        // Prepare payment for 200
        let effect = wallet.prepare_payment(200 * UNIT).unwrap();
        assert_eq!(effect.change_amount, 300 * UNIT);
        assert!(effect.change_secret.is_some());

        // Apply payment
        wallet.apply_payment(&effect).unwrap();
        assert_eq!(wallet.balance().unwrap(), 300 * UNIT);
        assert_eq!(wallet.stats().unwrap().unspent_webcash, 1); // change output
    }

    #[test]
    fn insert_round_trip() {
        let mut wallet = BrowserWallet::create(None).unwrap();
        let webcash = "e200:secret:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let effect = wallet.prepare_insert(webcash).unwrap();
        assert_eq!(effect.new_amount, 200 * UNIT);
        wallet.apply_insert(&effect).unwrap();
        assert_eq!(wallet.balance().unwrap(), 200 * UNIT);
    }

    #[test]
    fn merge_round_trip() {
        let mut wallet = BrowserWallet::create(None).unwrap();
        // Add two outputs
        wallet.store_mined_output(&"a".repeat(64), 100 * UNIT).unwrap();
        wallet.store_mined_output(&"b".repeat(64), 200 * UNIT).unwrap();

        let effect = wallet.prepare_merge(10).unwrap().unwrap();
        assert_eq!(effect.merged_amount, 300 * UNIT);
        wallet.apply_merge(&effect).unwrap();
        assert_eq!(wallet.balance().unwrap(), 300 * UNIT);
        assert_eq!(wallet.stats().unwrap().unspent_webcash, 1);
    }

    #[test]
    fn creates_24_word_mnemonic() {
        let wallet = BrowserWallet::create(None).unwrap();
        let word_count = wallet.mnemonic().split_whitespace().count();
        assert_eq!(word_count, 24, "new wallets must use 24-word mnemonic");
    }

    #[test]
    fn recover_from_mnemonic_restores_same_keys() {
        let wallet = BrowserWallet::create(None).unwrap();
        let mnemonic = wallet.mnemonic().to_string();
        let original_secret = wallet.master_secret_hex().unwrap();

        // Recover from the 12-word mnemonic
        let restored = BrowserWallet::create(Some(&mnemonic)).unwrap();
        assert_eq!(restored.mnemonic(), mnemonic);
        assert_eq!(restored.master_secret_hex().unwrap(), original_secret);
        assert_eq!(restored.derive_identity_public_key().unwrap(),
                   wallet.derive_identity_public_key().unwrap());
    }

    #[test]
    fn recover_from_hex_via_mnemonic_from_hex() {
        let wallet = BrowserWallet::create(None).unwrap();
        let hex_entropy = wallet.keychain().unwrap().entropy_hex();

        // Convert hex to mnemonic, then create wallet from it
        let mnemonic = mnemonic_from_hex(&hex_entropy).unwrap();
        let restored = BrowserWallet::create(Some(&mnemonic)).unwrap();
        assert_eq!(restored.master_secret_hex().unwrap(),
                   wallet.master_secret_hex().unwrap());
    }

    #[test]
    fn json_round_trip() {
        let mut wallet = BrowserWallet::create(None).unwrap();
        wallet.store_mined_output(&"c".repeat(64), 50 * UNIT).unwrap();
        let json = wallet.to_json().unwrap();
        let restored = BrowserWallet::from_json(&json).unwrap();
        assert_eq!(restored.balance().unwrap(), 50 * UNIT);
        assert_eq!(restored.mnemonic(), wallet.mnemonic());
    }

    #[test]
    fn amount_formatting() {
        assert_eq!(format_amount(0), "0");
        assert_eq!(format_amount(100_000_000), "1");
        assert_eq!(format_amount(200_000_000), "2");
        assert_eq!(format_amount(50_000_000), "0.5");
        assert_eq!(format_amount(1), "0.00000001");
        assert_eq!(parse_amount("200").unwrap(), 200 * UNIT);
        assert_eq!(parse_amount("0.5").unwrap(), 50_000_000);
    }

    #[test]
    fn webcash_parsing() {
        let parsed = parse_webcash("e200:secret:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        assert_eq!(parsed.amount_wats, 200 * UNIT);
        assert_eq!(parsed.secret.len(), 64);

        let formatted = format_webcash("abc123", 500 * UNIT);
        assert_eq!(formatted, "e500:secret:abc123");
    }

    #[test]
    fn recover_batch_derivation() {
        let wallet = BrowserWallet::create(None).unwrap();
        let batch = wallet.prepare_recover_batch("RECEIVE", 0, 5).unwrap();
        assert_eq!(batch.secrets.len(), 5);
        assert_eq!(batch.public_webcash_strings.len(), 5);
    }

    #[test]
    fn create_initializes_all_families() {
        let wallet = BrowserWallet::create(None).unwrap();
        for family in FAMILIES {
            let wallets = wallet.list_wallets(family);
            assert_eq!(wallets.len(), 1);
            assert_eq!(wallets[0].label, "main");
        }
    }

    #[test]
    fn multi_wallet_add_remove_rename() {
        let mut wallet = BrowserWallet::create(None).unwrap();
        wallet.add_wallet("webcash", "savings").unwrap();
        assert_eq!(wallet.list_wallets("webcash").len(), 2);

        wallet.set_active("webcash", "savings").unwrap();
        assert_eq!(wallet.active_label(), "savings");

        wallet.rename_wallet("webcash", "savings", "donations").unwrap();
        assert_eq!(wallet.active_label(), "donations");
        assert_eq!(wallet.list_wallets("webcash").len(), 2);

        wallet.remove_wallet("webcash", "donations").unwrap();
        assert_eq!(wallet.list_wallets("webcash").len(), 1);
        assert_eq!(wallet.active_label(), "main"); // auto-fallback
    }

    #[test]
    fn cannot_remove_main_wallet() {
        let mut wallet = BrowserWallet::create(None).unwrap();
        assert!(wallet.remove_wallet("webcash", "main").is_err());
    }

    #[test]
    fn wallets_have_distinct_secrets() {
        let mut wallet = BrowserWallet::create(None).unwrap();
        wallet.add_wallet("webcash", "second").unwrap();
        let main_secret = wallet.wallets.get("webcash:main").unwrap().master_secret_hex.clone();
        let second_secret = wallet.wallets.get("webcash:second").unwrap().master_secret_hex.clone();
        assert_ne!(main_secret, second_secret);
    }

    #[test]
    fn active_wallet_isolation() {
        let mut wallet = BrowserWallet::create(None).unwrap();
        wallet.add_wallet("webcash", "savings").unwrap();

        // Mine into main
        wallet.set_active("webcash", "main").unwrap();
        wallet.store_mined_output(&"a".repeat(64), 100 * UNIT).unwrap();

        // Savings has zero balance
        wallet.set_active("webcash", "savings").unwrap();
        assert_eq!(wallet.balance().unwrap(), 0);

        // Main still has balance
        wallet.set_active("webcash", "main").unwrap();
        assert_eq!(wallet.balance().unwrap(), 100 * UNIT);
    }
}
