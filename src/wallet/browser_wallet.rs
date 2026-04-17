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

// ── BrowserWallet Lifecycle ─────────────────────────────────────

impl BrowserWallet {
    /// Create a new wallet from an optional mnemonic (generates one if None).
    pub fn create(mnemonic_words: Option<&str>) -> Result<Self> {
        let keychain = match mnemonic_words {
            Some(words) => HdKeychain::from_mnemonic_words(words)?,
            None => HdKeychain::generate_new()?,
        };
        let mnemonic = keychain.mnemonic_words();
        let webcash_secret = keychain.derive_slot_hex("webcash", 0)?;

        let mut wallets = HashMap::new();
        wallets.insert(
            "webcash:main".to_string(),
            WebcashFamily {
                master_secret_hex: webcash_secret,
                outputs: Vec::new(),
                spent_hashes: Vec::new(),
                depths: [
                    ("RECEIVE".into(), 0),
                    ("PAY".into(), 0),
                    ("CHANGE".into(), 0),
                    ("MINING".into(), 0),
                ]
                .into(),
            },
        );

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
}
