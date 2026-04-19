
use crate::{
    error::{Error, Result},
    identity::Identity,
};
use super::keychain::{
    HdKeychain, KEY_MODEL_VERSION_V3, MAX_VAULT_KEYS, SLOT_FAMILY_HARMONIA_VAULT, SLOT_FAMILY_VAULT,
};
use super::store::{canonical_label, HarmoniiStore, PgpIdentityRow};

#[cfg(feature = "native")]
use std::path::Path;
#[cfg(feature = "native")]
use super::store_sqlite::SqliteHarmoniiStore;

// Re-export submodule types for backward compatibility.
pub use super::store::{
    NewPaymentAttempt, NewPaymentTransaction, NewPaymentTransactionEvent,
    PaymentAttemptRecord, PaymentAttemptUpdate, PaymentBlacklistRecord, PaymentLossRecord,
    PaymentTransactionEventRecord, PaymentTransactionRecord, PaymentTransactionUpdate,
    PgpIdentityRecord, PgpIdentitySnapshot, WalletSlotRecord, WalletSnapshot,
};

pub(crate) const META_NICKNAME: &str = "nickname";
pub(crate) const META_ROOT_PRIVATE_KEY_HEX: &str = "root_private_key_hex";
pub(crate) const META_ROOT_MNEMONIC: &str = "root_mnemonic";
pub(crate) const META_RGB_PRIVATE_KEY_HEX: &str = "rgb_private_key_hex";
pub(crate) const META_KEY_MODEL_VERSION: &str = "key_model_version";
pub(crate) const META_WALLET_LABEL: &str = "wallet_label";

/// Harmoniis wallet engine backed by [`HarmoniiStore`].
pub struct WalletCore {
    store: Box<dyn HarmoniiStore>,
}

/// Backward-compatible type alias.
pub type RgbWallet = WalletCore;

impl WalletCore {
    /// Construct from any `HarmoniiStore` implementation.
    pub fn new(store: Box<dyn HarmoniiStore>) -> Self {
        Self { store }
    }

    /// Access the underlying store (e.g. for downcast).
    pub fn store(&self) -> &dyn HarmoniiStore {
        &*self.store
    }
}

// ── WASM constructors (IndexedDB) ───────────────────────────────

#[cfg(target_arch = "wasm32")]
impl WalletCore {
    /// Load master wallet from IndexedDB. Returns None if not found.
    pub async fn open_from_idb(network: &str, key: &str) -> Result<Option<Self>> {
        match super::idb::load(network, key).await? {
            Some(json) => {
                let store = super::store_mem::MemHarmoniiStore::from_json(&json)?;
                Ok(Some(Self::new(Box::new(store))))
            }
            None => Ok(None),
        }
    }

    /// Save master wallet state to IndexedDB.
    pub async fn save_to_idb(&self, network: &str, key: &str) -> Result<()> {
        let mem = self.store.as_any()
            .downcast_ref::<super::store_mem::MemHarmoniiStore>()
            .ok_or_else(|| Error::Other(anyhow::anyhow!("not a MemHarmoniiStore")))?;
        let json = mem.to_json()?;
        super::idb::save(network, key, &json).await
    }

    /// Delete master wallet from IndexedDB.
    pub async fn delete_from_idb(network: &str, key: &str) -> Result<()> {
        super::idb::delete(network, key).await
    }
}

// ── Native constructors ─────────────────────────────────────────

#[cfg(feature = "native")]
impl WalletCore {
    fn derive_wallet_label(path: &Path) -> String {
        let stem = path
            .file_stem()
            .and_then(|x| x.to_str())
            .unwrap_or("wallet");
        if stem.eq_ignore_ascii_case("master")
            || stem.eq_ignore_ascii_case("rgb")
            || stem.eq_ignore_ascii_case("wallet")
        {
            path.parent()
                .and_then(|p| p.file_name())
                .and_then(|x| x.to_str())
                .map(ToString::to_string)
                .unwrap_or_else(|| "wallet".to_string())
        } else {
            stem.to_string()
        }
    }

    /// Create a new wallet at the given path, generating a fresh root key.
    pub fn create(path: &Path) -> Result<Self> {
        let store = SqliteHarmoniiStore::create(path)?;
        let wallet = Self::new(Box::new(store));
        wallet.refresh_slot_registry()?;
        if wallet.wallet_label()?.as_deref().unwrap_or("default") == "default" {
            let derived = Self::derive_wallet_label(path);
            wallet.set_wallet_label(&derived)?;
            let _ = wallet.rename_pgp_label("default", &derived);
            wallet.refresh_slot_registry()?;
        }
        Ok(wallet)
    }

    /// Open an existing wallet at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        let store = SqliteHarmoniiStore::open(path)?;
        let wallet = Self::new(Box::new(store));
        wallet.refresh_slot_registry()?;
        if wallet.wallet_label()?.as_deref().unwrap_or("default") == "default" {
            let derived = Self::derive_wallet_label(path);
            wallet.set_wallet_label(&derived)?;
            let _ = wallet.rename_pgp_label("default", &derived);
            wallet.refresh_slot_registry()?;
        }
        Ok(wallet)
    }

    /// Open an in-memory wallet (for tests).
    pub fn open_memory() -> Result<Self> {
        let store = SqliteHarmoniiStore::open_memory()?;
        let wallet = Self::new(Box::new(store));
        if wallet.wallet_label()?.as_deref().unwrap_or("default") == "default" {
            wallet.set_wallet_label("memory-wallet")?;
            let _ = wallet.rename_pgp_label("default", "memory-wallet");
        }
        wallet.refresh_slot_registry()?;
        Ok(wallet)
    }
}

// ── Identity material ───────────────────────────────────────────

impl WalletCore {
    pub fn root_private_key_hex(&self) -> Result<String> {
        self.store
            .get_meta(META_ROOT_PRIVATE_KEY_HEX)?
            .ok_or_else(|| Error::Other(anyhow::anyhow!("missing master entropy hex")))
    }

    pub fn keychain(&self) -> Result<HdKeychain> {
        if let Some(words) = self.store.get_meta(META_ROOT_MNEMONIC)? {
            return HdKeychain::from_mnemonic_words(&words);
        }
        let entropy_hex = self.root_private_key_hex()?;
        HdKeychain::from_entropy_hex(&entropy_hex)
    }

    pub fn set_master_keychain_material(&self, keychain: &HdKeychain) -> Result<()> {
        self.store
            .set_meta(META_ROOT_PRIVATE_KEY_HEX, &keychain.entropy_hex())?;
        self.store
            .set_meta(META_ROOT_MNEMONIC, &keychain.mnemonic_words())?;
        self.store.set_meta(
            META_RGB_PRIVATE_KEY_HEX,
            &keychain.derive_slot_hex("rgb", 0)?,
        )?;
        self.store
            .set_meta(META_KEY_MODEL_VERSION, KEY_MODEL_VERSION_V3)?;
        Ok(())
    }

    pub fn identity(&self) -> Result<Identity> {
        self.rgb_identity()
    }

    pub fn rgb_identity(&self) -> Result<Identity> {
        let hex = self.derive_slot_hex("rgb", 0)?;
        Identity::from_hex(&hex)
    }

    pub fn derive_webcash_master_secret_hex(&self) -> Result<String> {
        self.derive_slot_hex("webcash", 0)
    }

    pub fn derive_voucher_master_secret_hex(&self) -> Result<String> {
        self.derive_slot_hex("voucher", 0)
    }

    pub fn derive_bitcoin_master_key_hex(&self) -> Result<String> {
        self.derive_slot_hex("bitcoin", 0)
    }

    pub fn derive_vault_master_key_hex(&self) -> Result<String> {
        self.derive_slot_hex(SLOT_FAMILY_VAULT, 0)
    }

    pub fn derive_harmonia_vault_master_key_hex(&self) -> Result<String> {
        self.derive_slot_hex(SLOT_FAMILY_HARMONIA_VAULT, 0)
    }

    pub fn derive_slot_hex(&self, family: &str, index: u32) -> Result<String> {
        self.keychain()?.derive_slot_hex(family, index)
    }

    pub fn export_master_key_hex(&self) -> Result<String> {
        self.root_private_key_hex()
    }

    pub fn export_master_key_mnemonic(&self) -> Result<String> {
        self.keychain().map(|k| k.mnemonic_words())
    }

    pub fn export_recovery_mnemonic(&self) -> Result<String> {
        if let Some(mnemonic) = self.store.get_meta(META_ROOT_MNEMONIC)? {
            return Ok(mnemonic);
        }
        self.export_master_key_mnemonic()
    }

    pub fn apply_master_key_hex(&self, root_private_key_hex: &str) -> Result<()> {
        let keychain = HdKeychain::from_entropy_hex(root_private_key_hex)?;
        self.set_master_keychain_material(&keychain)?;

        let wallet_label = self
            .wallet_label()?
            .unwrap_or_else(|| "default".to_string());
        let label = canonical_label(&wallet_label)?;
        let pgp0_hex = keychain.derive_slot_hex("pgp", 0)?;
        let pgp0 = Identity::from_hex(&pgp0_hex)?;

        self.store.replace_all_pgp(&[PgpIdentityRow {
            label,
            key_index: 0,
            private_key_hex: pgp0_hex,
            public_key_hex: pgp0.public_key_hex(),
            created_at: chrono::Utc::now().to_rfc3339(),
            is_active: true,
        }])?;
        self.refresh_slot_registry()?;
        Ok(())
    }

    pub fn apply_master_key_mnemonic(&self, mnemonic: &str) -> Result<()> {
        let keychain = HdKeychain::from_mnemonic_words(mnemonic)?;
        self.apply_master_key_hex(&keychain.entropy_hex())
    }

    pub fn has_local_state(&self) -> Result<bool> {
        let contracts = self.store.count_contracts()?;
        let certs = self.store.count_certificates()?;
        Ok(contracts > 0 || certs > 0)
    }
}

// ── Vault identities ────────────────────────────────────────────

impl WalletCore {
    pub fn derive_vault_identity_for_index(&self, key_index: u32) -> Result<Identity> {
        if key_index == 0 {
            return Err(Error::Other(anyhow::anyhow!(
                "vault key index 0 is reserved for the vault root"
            )));
        }
        let private_key_hex = self.derive_slot_hex(SLOT_FAMILY_VAULT, key_index)?;
        Identity::from_hex(&private_key_hex)
    }

    pub fn create_vault_identity(&self, label: Option<&str>) -> Result<WalletSlotRecord> {
        let key_index = self.next_vault_key_index()?;
        self.ensure_vault_identity_index(key_index, label)
    }

    pub fn ensure_vault_identity_index(
        &self,
        key_index: u32,
        preferred_label: Option<&str>,
    ) -> Result<WalletSlotRecord> {
        if key_index == 0 || key_index >= MAX_VAULT_KEYS {
            return Err(Error::Other(anyhow::anyhow!(
                "vault key index out of range (valid: 1..{})",
                MAX_VAULT_KEYS - 1
            )));
        }

        let fallback_label = format!("vault-{key_index}-key-pairs");
        let desired_raw = preferred_label.unwrap_or(fallback_label.as_str());
        let desired = canonical_label(desired_raw)?;
        let label = self.unique_vault_label(&desired, key_index)?;
        let identity = self.derive_vault_identity_for_index(key_index)?;
        let public_key_hex = identity.public_key_hex();

        self.store.replace_slot_at(
            SLOT_FAMILY_VAULT,
            key_index,
            &label,
            &public_key_hex,
            &chrono::Utc::now().to_rfc3339(),
        )?;
        self.refresh_slot_registry()?;
        self.vault_identity_by_index(key_index)
    }

    pub fn list_vault_identities(&self) -> Result<Vec<WalletSlotRecord>> {
        self.list_wallet_slots(Some(SLOT_FAMILY_VAULT))
            .map(|items| {
                items
                    .into_iter()
                    .filter(|item| item.slot_index > 0)
                    .collect()
            })
    }

    pub fn vault_identity_by_label(&self, label: &str) -> Result<WalletSlotRecord> {
        let canonical = canonical_label(label)?;
        self.list_vault_identities()?
            .into_iter()
            .find(|item| item.label.as_deref() == Some(canonical.as_str()))
            .ok_or_else(|| Error::NotFound(format!("vault identity label '{canonical}' not found")))
    }

    pub fn vault_identity_by_index(&self, key_index: u32) -> Result<WalletSlotRecord> {
        self.list_vault_identities()?
            .into_iter()
            .find(|item| item.slot_index == key_index)
            .ok_or_else(|| Error::NotFound(format!("vault identity index '{key_index}' not found")))
    }

    fn next_vault_key_index(&self) -> Result<u32> {
        let max_idx = self.store.max_slot_index(SLOT_FAMILY_VAULT)?;
        let next = max_idx.saturating_add(1);
        let next = u32::try_from(next)
            .map_err(|_| Error::Other(anyhow::anyhow!("too many vault identities in wallet")))?;
        if next >= MAX_VAULT_KEYS {
            return Err(Error::Other(anyhow::anyhow!(
                "vault key index out of range (max {})",
                MAX_VAULT_KEYS - 1
            )));
        }
        Ok(next)
    }

    fn unique_vault_label(&self, desired: &str, key_index: u32) -> Result<String> {
        let mut candidate = desired.to_string();
        let mut suffix = 1u32;
        loop {
            match self
                .store
                .get_slot_index_by_label(SLOT_FAMILY_VAULT, &candidate)?
            {
                None => return Ok(candidate),
                Some(existing) if existing == key_index => return Ok(candidate),
                _ => {
                    candidate = format!("{desired}-{suffix}");
                    suffix = suffix.saturating_add(1);
                }
            }
        }
    }
}

// ── Wallet metadata ─────────────────────────────────────────────

impl WalletCore {
    pub fn fingerprint(&self) -> Result<String> {
        Ok(self.rgb_identity()?.fingerprint())
    }

    pub fn nickname(&self) -> Result<Option<String>> {
        self.store.get_meta(META_NICKNAME)
    }

    pub fn set_nickname(&self, nick: &str) -> Result<()> {
        self.store.set_meta(META_NICKNAME, nick)
    }

    pub fn wallet_label(&self) -> Result<Option<String>> {
        self.store.get_meta(META_WALLET_LABEL)
    }

    pub fn set_wallet_label(&self, label: &str) -> Result<()> {
        let canonical = canonical_label(label)?;
        let out = self.store.set_meta(META_WALLET_LABEL, &canonical);
        if out.is_ok() {
            let _ = self.refresh_slot_registry();
        }
        out
    }

    pub fn list_wallet_slots(&self, family: Option<&str>) -> Result<Vec<WalletSlotRecord>> {
        self.store.list_wallet_slots(family)
    }

    pub fn refresh_slot_registry(&self) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let root_hex = self.derive_slot_hex("root", 0)?;
        let rgb_hex = self.derive_slot_hex("rgb", 0)?;
        let webcash_hex = self.derive_slot_hex("webcash", 0)?;
        let voucher_hex = self.derive_slot_hex("voucher", 0)?;
        let bitcoin_hex = self.derive_slot_hex("bitcoin", 0)?;
        let vault_hex = self.derive_slot_hex(SLOT_FAMILY_VAULT, 0)?;

        // Slot-0 entries for wallet families
        let slot_0_entries: &[(&str, &str, Option<&str>, Option<&str>)] = &[
            ("rgb", &rgb_hex, Some("main_rgb.db"), Some("main")),
            ("webcash", &webcash_hex, Some("main_webcash.db"), Some("main")),
            ("bitcoin", &bitcoin_hex, Some("main_bitcoin.db"), Some("main")),
            ("voucher", &voucher_hex, Some("main_voucher.db"), Some("main")),
            ("root", &root_hex, None, None),
            (SLOT_FAMILY_VAULT, &vault_hex, None, None),
        ];
        for &(family, descriptor, db_rel_path, label) in slot_0_entries {
            self.store.upsert_wallet_slot(&WalletSlotRecord {
                family: family.to_string(),
                slot_index: 0,
                descriptor: descriptor.to_string(),
                db_rel_path: db_rel_path.map(ToString::to_string),
                label: label.map(ToString::to_string),
                created_at: now.clone(),
                updated_at: now.clone(),
            })?;
        }

        // Refresh vault identity slots above 0
        let vault_slots = self.store.list_wallet_slots(Some(SLOT_FAMILY_VAULT))?;
        for slot in vault_slots.iter().filter(|s| s.slot_index > 0) {
            let public_key_hex = self
                .derive_vault_identity_for_index(slot.slot_index)?
                .public_key_hex();
            self.store.upsert_wallet_slot(&WalletSlotRecord {
                family: SLOT_FAMILY_VAULT.to_string(),
                slot_index: slot.slot_index,
                descriptor: public_key_hex,
                db_rel_path: None,
                label: slot.label.clone(),
                created_at: slot.created_at.clone(),
                updated_at: now.clone(),
            })?;
        }

        // Refresh PGP identity slots from pgp_identities table
        let pgp_rows = self.store.list_pgp_raw()?;
        for row in &pgp_rows {
            self.store.upsert_wallet_slot(&WalletSlotRecord {
                family: "pgp".to_string(),
                slot_index: row.key_index,
                descriptor: row.public_key_hex.clone(),
                db_rel_path: None,
                label: Some(row.label.clone()),
                created_at: now.clone(),
                updated_at: now.clone(),
            })?;
        }
        Ok(())
    }
}

// ── Labeled wallet operations ───────────────────────────────────

use super::labeled_wallets::{LabeledWallet, wallet_db_filename};

impl WalletCore {
    pub fn derive_secret_for_label(&self, family: &str, label: &str) -> Result<(String, u32)> {
        let index = self.resolve_or_create_wallet_slot(family, label)?;
        let secret = self.derive_slot_hex(family, index)?;
        Ok((secret, index))
    }

    pub fn derive_webcash_secret_for_label(&self, label: &str) -> Result<(String, u32)> {
        self.derive_secret_for_label("webcash", label)
    }

    pub fn derive_bitcoin_secret_for_label(&self, label: &str) -> Result<(String, u32)> {
        self.derive_secret_for_label("bitcoin", label)
    }

    pub fn derive_voucher_secret_for_label(&self, label: &str) -> Result<(String, u32)> {
        self.derive_secret_for_label("voucher", label)
    }

    pub fn derive_rgb_secret_for_label(&self, label: &str) -> Result<(String, u32)> {
        self.derive_secret_for_label("rgb", label)
    }

    pub fn list_labeled_wallets(&self, family: &str) -> Result<Vec<LabeledWallet>> {
        let slots = self.store.list_wallet_slots(Some(family))?;
        Ok(slots
            .into_iter()
            .map(|s| {
                let label = s.label.unwrap_or_else(|| {
                    if s.slot_index == 0 {
                        "main".to_string()
                    } else {
                        format!("{family}-{}", s.slot_index)
                    }
                });
                let db_filename =
                    s.db_rel_path
                        .unwrap_or_else(|| wallet_db_filename(&s.family, &label));
                LabeledWallet {
                    family: s.family,
                    label,
                    slot_index: s.slot_index,
                    db_filename,
                    descriptor: s.descriptor,
                }
            })
            .collect())
    }

    fn resolve_or_create_wallet_slot(&self, family: &str, label: &str) -> Result<u32> {
        let canonical = canonical_label(label)?;

        if let Some(index) = self.store.get_slot_index_by_label(family, &canonical)? {
            return Ok(index);
        }

        if canonical == "main" {
            self.register_wallet_slot(family, 0, "main")?;
            return Ok(0);
        }

        let max_idx = self.store.max_slot_index(family)?;
        let next = (max_idx + 1).max(1) as u32;
        if next >= super::keychain::MAX_LABELED_WALLETS {
            return Err(Error::Other(anyhow::anyhow!(
                "too many {family} wallets (max {})",
                super::keychain::MAX_LABELED_WALLETS - 1
            )));
        }

        self.register_wallet_slot(family, next, &canonical)?;
        Ok(next)
    }

    pub fn remove_wallet_slot(&self, family: &str, label: &str) -> Result<bool> {
        let canonical = canonical_label(label)?;
        if let Some(index) = self.store.get_slot_index_by_label(family, &canonical)? {
            let now = chrono::Utc::now().to_rfc3339();
            self.store.replace_slot_at(family, index, &canonical, "", &now)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn rename_wallet_slot(&self, family: &str, old_label: &str, new_label: &str) -> Result<()> {
        let old_canonical = canonical_label(old_label)?;
        let new_canonical = canonical_label(new_label)?;
        let slots = self.store.list_wallet_slots(Some(family))?;
        let slot = slots.iter().find(|s| s.label.as_deref() == Some(&old_canonical))
            .ok_or_else(|| Error::Other(anyhow::anyhow!("wallet '{}' not found in family '{}'", old_label, family)))?;
        let now = chrono::Utc::now().to_rfc3339();
        self.store.replace_slot_at(family, slot.slot_index, &new_canonical, &slot.descriptor, &now)
    }

    fn register_wallet_slot(&self, family: &str, index: u32, label: &str) -> Result<()> {
        let descriptor = self.derive_slot_hex(family, index)?;
        let db_filename = wallet_db_filename(family, label);
        let now = chrono::Utc::now().to_rfc3339();

        self.store.upsert_wallet_slot(&WalletSlotRecord {
            family: family.to_string(),
            slot_index: index,
            descriptor,
            db_rel_path: Some(db_filename),
            label: Some(label.to_string()),
            created_at: now.clone(),
            updated_at: now,
        })?;
        Ok(())
    }
}

// ── Webcash slot scanning ─────────────────────────────────────────

/// Result of scanning deterministic webcash slots for active wallets.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SlotScanResult {
    /// Label -> webylib wallet state JSON for each slot with recovered outputs.
    pub wallets: std::collections::HashMap<String, String>,
    /// Total outputs recovered across all slots.
    pub total_recovered: usize,
}

#[cfg(target_arch = "wasm32")]
impl WalletCore {
    /// Scan deterministic webcash slots for active wallets (WASM).
    ///
    /// Tries slot indices 0..max_slots, derives the webcash master secret for
    /// each, creates a webylib Wallet, and runs server recovery. Returns wallet
    /// states for every slot that has recovered outputs or non-zero balance.
    /// Active slots are registered in the master slot registry.
    pub async fn scan_webcash_slots(
        &self,
        network: webylib::server::NetworkMode,
        max_slots: u32,
        gap_limit: usize,
    ) -> Result<SlotScanResult> {
        use super::webcash::WebcashWallet;

        let mut wallets = std::collections::HashMap::new();
        let mut total_recovered = 0usize;

        for index in 0..max_slots {
            let label = if index == 0 { "main".to_string() } else { format!("wallet-{index}") };
            let secret = match self.derive_slot_hex("webcash", index) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let wl = WebcashWallet::new_memory(network.clone()).map_err(|e| Error::Other(e.into()))?;
            wl.store_master_secret(&secret).await.map_err(|e| Error::Other(e.into()))?;
            let result = wl.recover_from_wallet(gap_limit).await.map_err(|e| Error::Other(e.into()))?;
            let balance = wl.balance_amount().await.map_err(|e| Error::Other(e.into()))?;

            if result.recovered_count > 0 || balance.wats > 0 {
                let state_json = wl.to_json().map_err(|e| Error::Other(e.into()))?;
                wallets.insert(label.clone(), state_json);
                total_recovered += result.recovered_count;

                if index > 0 {
                    let _ = self.register_wallet_slot("webcash", index, &label);
                }
            }
        }

        Ok(SlotScanResult { wallets, total_recovered })
    }
}

#[cfg(feature = "native")]
impl WalletCore {
    /// Scan deterministic webcash slots for active wallets (native).
    pub async fn scan_webcash_slots(
        &self,
        network: webylib::server::NetworkMode,
        max_slots: u32,
        gap_limit: usize,
    ) -> Result<SlotScanResult> {
        use super::webcash::WebcashWallet;

        let mut wallets = std::collections::HashMap::new();
        let mut total_recovered = 0usize;

        for index in 0..max_slots {
            let label = if index == 0 { "main".to_string() } else { format!("wallet-{index}") };
            let secret = match self.derive_slot_hex("webcash", index) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let wl = WebcashWallet::open_memory_with_network(network.clone()).map_err(|e| Error::Other(e.into()))?;
            wl.store_master_secret(&secret).await.map_err(|e| Error::Other(e.into()))?;
            let result = wl.recover_from_wallet(gap_limit).await.map_err(|e| Error::Other(e.into()))?;
            let balance = wl.balance_amount().await.map_err(|e| Error::Other(e.into()))?;

            if result.recovered_count > 0 || balance.wats > 0 {
                let state_json = wl.to_json().map_err(|e| Error::Other(e.into()))?;
                wallets.insert(label.clone(), state_json);
                total_recovered += result.recovered_count;

                if index > 0 {
                    let _ = self.register_wallet_slot("webcash", index, &label);
                }
            }
        }

        Ok(SlotScanResult { wallets, total_recovered })
    }
}

#[cfg(test)]
mod tests {
    use super::WalletCore;
    use crate::wallet::store::{
        NewPaymentTransaction, NewPaymentTransactionEvent, PaymentTransactionUpdate,
    };

    #[test]
    fn payment_transactions_round_trip_in_memory_wallet() {
        let wallet = WalletCore::open_memory().expect("memory wallet");
        let txn_id = wallet
            .record_payment_transaction(&NewPaymentTransaction {
                attempt_id: Some("pay_123"),
                occurred_at: Some("2026-03-17T10:00:00Z"),
                direction: "inbound",
                role: "payee",
                source_system: "harmonia",
                service_origin: Some("https://node.example"),
                frontend_kind: Some("http2"),
                transport_kind: Some("http2"),
                endpoint_path: Some("/v1/session"),
                method: Some("POST"),
                session_id: Some("session-1"),
                action_kind: "identity-claim",
                resource_ref: Some("identity:alice"),
                contract_ref: None,
                invoice_ref: None,
                challenge_id: Some("challenge-1"),
                rail: "webcash",
                payment_unit: "wats",
                quoted_amount: Some("42"),
                settled_amount: None,
                fee_amount: None,
                proof_ref: None,
                proof_kind: None,
                payer_ref: Some("payer:alice"),
                payee_ref: Some("payee:harmonia"),
                request_hash: Some("hash-1"),
                response_code: Some("payment_required"),
                status: "challenge_received",
                metadata_json: Some("{\"carrier\":\"http2\"}"),
            })
            .expect("record transaction");
        wallet
            .append_payment_transaction_event(&NewPaymentTransactionEvent {
                txn_id: &txn_id,
                event_type: "challenge_received",
                status: "challenge_received",
                actor: "gateway",
                details_json: Some("{\"price\":\"42\"}"),
            })
            .expect("append event");
        wallet
            .update_payment_transaction(
                &txn_id,
                &PaymentTransactionUpdate {
                    occurred_at: None,
                    service_origin: None,
                    frontend_kind: None,
                    transport_kind: None,
                    endpoint_path: None,
                    method: None,
                    session_id: None,
                    action_kind: None,
                    resource_ref: None,
                    contract_ref: None,
                    invoice_ref: None,
                    challenge_id: Some("challenge-1"),
                    quoted_amount: None,
                    settled_amount: Some("42"),
                    fee_amount: Some("1"),
                    proof_ref: Some("proof-hash-1"),
                    proof_kind: Some("webcash_secret_hash"),
                    payer_ref: None,
                    payee_ref: None,
                    request_hash: None,
                    response_code: Some("accepted"),
                    status: "succeeded",
                    metadata_json: Some("{\"settled\":true}"),
                },
            )
            .expect("update transaction");

        let txns = wallet
            .list_payment_transactions()
            .expect("list transactions");
        assert_eq!(txns.len(), 1);
        let txn = &txns[0];
        assert_eq!(txn.txn_id, txn_id);
        assert_eq!(txn.direction, "inbound");
        assert_eq!(txn.role, "payee");
        assert_eq!(txn.action_kind, "identity-claim");
        assert_eq!(txn.challenge_id.as_deref(), Some("challenge-1"));
        assert_eq!(txn.settled_amount.as_deref(), Some("42"));
        assert_eq!(txn.fee_amount.as_deref(), Some("1"));
        assert_eq!(txn.proof_kind.as_deref(), Some("webcash_secret_hash"));
        assert_eq!(txn.proof_ref.as_deref(), Some("proof-hash-1"));
        assert_eq!(txn.status, "succeeded");

        let events = wallet
            .list_payment_transaction_events(Some(&txn_id))
            .expect("list txn events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "challenge_received");
        assert_eq!(events[0].status, "challenge_received");
        assert_eq!(events[0].actor, "gateway");
    }

    #[test]
    fn payment_transactions_enforce_unique_proof_refs_per_direction_and_rail() {
        let wallet = WalletCore::open_memory().expect("memory wallet");
        wallet
            .record_payment_transaction(&NewPaymentTransaction {
                attempt_id: None,
                occurred_at: None,
                direction: "inbound",
                role: "payee",
                source_system: "harmonia",
                service_origin: Some("https://node.example"),
                frontend_kind: Some("http2"),
                transport_kind: Some("http2"),
                endpoint_path: Some("/v1/session"),
                method: Some("POST"),
                session_id: Some("session-1"),
                action_kind: "post",
                resource_ref: None,
                contract_ref: None,
                invoice_ref: None,
                challenge_id: None,
                rail: "voucher",
                payment_unit: "credits",
                quoted_amount: Some("10"),
                settled_amount: Some("10"),
                fee_amount: None,
                proof_ref: Some("proof-ref-1"),
                proof_kind: Some("voucher_public_hash"),
                payer_ref: None,
                payee_ref: None,
                request_hash: None,
                response_code: None,
                status: "succeeded",
                metadata_json: None,
            })
            .expect("insert first proof ref");

        let duplicate = wallet.record_payment_transaction(&NewPaymentTransaction {
            attempt_id: None,
            occurred_at: None,
            direction: "inbound",
            role: "payee",
            source_system: "harmonia",
            service_origin: Some("https://node.example"),
            frontend_kind: Some("mqtt"),
            transport_kind: Some("mqtt"),
            endpoint_path: Some("/topic/posts"),
            method: Some("PUBLISH"),
            session_id: Some("session-2"),
            action_kind: "comment",
            resource_ref: None,
            contract_ref: None,
            invoice_ref: None,
            challenge_id: None,
            rail: "voucher",
            payment_unit: "credits",
            quoted_amount: Some("5"),
            settled_amount: Some("5"),
            fee_amount: None,
            proof_ref: Some("proof-ref-1"),
            proof_kind: Some("voucher_public_hash"),
            payer_ref: None,
            payee_ref: None,
            request_hash: None,
            response_code: None,
            status: "succeeded",
            metadata_json: None,
        });
        assert!(
            duplicate.is_err(),
            "should reject duplicate proof_ref on same direction+rail"
        );

        wallet
            .record_payment_transaction(&NewPaymentTransaction {
                attempt_id: None,
                occurred_at: None,
                direction: "outbound",
                role: "payer",
                source_system: "harmonia",
                service_origin: Some("https://other.example"),
                frontend_kind: None,
                transport_kind: None,
                endpoint_path: None,
                method: None,
                session_id: None,
                action_kind: "refund",
                resource_ref: None,
                contract_ref: None,
                invoice_ref: None,
                challenge_id: None,
                rail: "voucher",
                payment_unit: "credits",
                quoted_amount: Some("10"),
                settled_amount: Some("10"),
                fee_amount: None,
                proof_ref: Some("proof-ref-1"),
                proof_kind: Some("voucher_public_hash"),
                payer_ref: None,
                payee_ref: None,
                request_hash: None,
                response_code: None,
                status: "succeeded",
                metadata_json: None,
            })
            .expect("same proof_ref on different direction should succeed");
    }
}
