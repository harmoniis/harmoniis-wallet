//! BIP32/BIP39 deterministic key derivation.
//!
//! Pure Rust — compiles to native and WASM without C FFI.
//! Uses the `bip32` crate (k256-backed) for HD key derivation.
//!
//! Derivation path: `m / 83696968' / 0' / family' / index'`
//!
//! | Family   | Code | Purpose                  |
//! |----------|------|--------------------------|
//! | root     | 0    | Master root key          |
//! | rgb      | 1    | RGB contract identity    |
//! | webcash  | 2    | Webcash payment secrets  |
//! | bitcoin  | 3    | Bitcoin addresses         |
//! | pgp      | 4    | Ed25519 signing keys     |
//! | vault    | 5    | AEAD / MQTT / signing    |
//! | voucher  | 6    | Voucher bearer secrets   |

use bip32::{ChildNumber, XPrv};
use bip39::Mnemonic;
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

use crate::error::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

pub const KEY_MODEL_VERSION_V3: &str = "v3-bip32";
pub const MAX_PGP_KEYS: u32 = 1_000;
pub const MAX_VAULT_KEYS: u32 = 1_000;
pub const MAX_LABELED_WALLETS: u32 = 256;

const PURPOSE_HARMONIIS: u32 = 83_696_968;
const APP_MAIN: u32 = 0;

pub const FAMILY_ROOT: u32 = 0;
pub const FAMILY_RGB: u32 = 1;
pub const FAMILY_WEBCASH: u32 = 2;
pub const FAMILY_BITCOIN: u32 = 3;
pub const FAMILY_PGP: u32 = 4;
pub const FAMILY_VAULT: u32 = 5;
pub const FAMILY_VOUCHER: u32 = 6;

pub const SLOT_FAMILY_VAULT: &str = "vault";
pub const SLOT_FAMILY_HARMONIA_VAULT: &str = "vault";

// ── HD Keychain ──────────────────────────────────────────────────

pub struct HdKeychain {
    mnemonic: Mnemonic,
    entropy: Vec<u8>,
    master_xpriv: XPrv,
}

impl Zeroize for HdKeychain {
    fn zeroize(&mut self) {
        self.entropy.zeroize();
        // XPrv handles its own zeroization via k256
    }
}

impl Drop for HdKeychain {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl HdKeychain {
    /// Generate a new keychain with a random 32-byte (256-bit) 24-word mnemonic.
    pub fn generate_new() -> Result<Self> {
        let mut entropy = vec![0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        Self::from_entropy(&entropy)
    }

    /// Reconstruct from BIP39 mnemonic words.
    pub fn from_mnemonic_words(words: &str) -> Result<Self> {
        let mnemonic = Mnemonic::parse_normalized(words)
            .map_err(|e| Error::Other(anyhow::anyhow!("invalid mnemonic: {e}")))?;
        let entropy = mnemonic.to_entropy();
        Self::from_mnemonic(mnemonic, entropy)
    }

    /// Reconstruct from raw entropy hex.
    pub fn from_entropy_hex(hex_value: &str) -> Result<Self> {
        let entropy = hex::decode(hex_value.trim())
            .map_err(|e| Error::Other(anyhow::anyhow!("invalid master entropy hex: {e}")))?;
        Self::from_entropy(&entropy)
    }

    /// Reconstruct from raw entropy bytes.
    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        validate_entropy_len(entropy.len())?;
        let mnemonic = Mnemonic::from_entropy(entropy)
            .map_err(|e| Error::Other(anyhow::anyhow!("invalid BIP39 entropy: {e}")))?;
        Self::from_mnemonic(mnemonic, entropy.to_vec())
    }

    fn from_mnemonic(mnemonic: Mnemonic, entropy: Vec<u8>) -> Result<Self> {
        validate_entropy_len(entropy.len())?;
        let seed = mnemonic.to_seed_normalized("");
        let master_xpriv = XPrv::new(&seed)
            .map_err(|e| Error::Other(anyhow::anyhow!("failed to derive BIP32 master key: {e}")))?;
        Ok(Self { mnemonic, entropy, master_xpriv })
    }

    // ── Accessors ────────────────────────────────────────────────

    pub fn mnemonic_words(&self) -> String {
        self.mnemonic.to_string()
    }

    pub fn entropy_hex(&self) -> String {
        hex::encode(&self.entropy)
    }

    // ── Key derivation ───────────────────────────────────────────

    /// Derive a 32-byte secret for the given family and slot index.
    /// Returns the private key as a 64-character hex string.
    pub fn derive_slot_hex(&self, family: &str, index: u32) -> Result<String> {
        let (family_code, slot_index) = family_slot(family, index)?;
        let derived = self.derive_hardened_path(&[
            PURPOSE_HARMONIIS, APP_MAIN, family_code, slot_index,
        ])?;
        Ok(hex::encode(derived.private_key().to_bytes()))
    }

    /// Derive a child key along a hardened path from master.
    fn derive_hardened_path(&self, indices: &[u32]) -> Result<XPrv> {
        let mut key = self.master_xpriv.clone();
        for &idx in indices {
            let child = ChildNumber::new(idx, true)
                .map_err(|e| Error::Other(anyhow::anyhow!("invalid child index {idx}: {e}")))?;
            key = key.derive_child(child)
                .map_err(|e| Error::Other(anyhow::anyhow!("BIP32 derivation failed at index {idx}: {e}")))?;
        }
        Ok(key)
    }
}

// ── Family validation ────────────────────────────────────────────

fn family_slot(family: &str, index: u32) -> Result<(u32, u32)> {
    match family {
        "root" => {
            if index != 0 {
                return Err(Error::Other(anyhow::anyhow!("root family only supports index 0")));
            }
            Ok((FAMILY_ROOT, 0))
        }
        "rgb" => validate_index(FAMILY_RGB, index, MAX_LABELED_WALLETS, "rgb"),
        "webcash" => validate_index(FAMILY_WEBCASH, index, MAX_LABELED_WALLETS, "webcash"),
        "bitcoin" => validate_index(FAMILY_BITCOIN, index, MAX_LABELED_WALLETS, "bitcoin"),
        "pgp" => validate_index(FAMILY_PGP, index, MAX_PGP_KEYS, "PGP"),
        "vault" | "harmonia-vault" => validate_index(FAMILY_VAULT, index, MAX_VAULT_KEYS, "vault"),
        "voucher" => validate_index(FAMILY_VOUCHER, index, MAX_LABELED_WALLETS, "voucher"),
        _ => Err(Error::Other(anyhow::anyhow!("unknown key family '{family}'"))),
    }
}

fn validate_index(family_code: u32, index: u32, max: u32, name: &str) -> Result<(u32, u32)> {
    if index >= max {
        return Err(Error::Other(anyhow::anyhow!("{name} index out of range (max {})", max - 1)));
    }
    Ok((family_code, index))
}

fn validate_entropy_len(len: usize) -> Result<()> {
    match len {
        16 | 20 | 24 | 28 | 32 => Ok(()),
        n => Err(Error::Other(anyhow::anyhow!(
            "invalid BIP39 entropy length: {n} bytes (expected 16/20/24/28/32)"
        ))),
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::HdKeychain;

    #[test]
    fn deterministic_slots_from_known_mnemonic() {
        let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let keychain = HdKeychain::from_mnemonic_words(mnemonic_str).unwrap();

        let root = keychain.derive_slot_hex("root", 0).unwrap();
        let rgb = keychain.derive_slot_hex("rgb", 0).unwrap();
        let webcash = keychain.derive_slot_hex("webcash", 0).unwrap();
        let bitcoin = keychain.derive_slot_hex("bitcoin", 0).unwrap();
        let pgp0 = keychain.derive_slot_hex("pgp", 0).unwrap();
        let pgp1 = keychain.derive_slot_hex("pgp", 1).unwrap();
        let vault = keychain.derive_slot_hex("vault", 0).unwrap();
        let vault_1 = keychain.derive_slot_hex("vault", 1).unwrap();
        let voucher = keychain.derive_slot_hex("voucher", 0).unwrap();

        // All 64-char hex (32 bytes)
        assert_eq!(root.len(), 64);
        assert_eq!(rgb.len(), 64);
        assert_eq!(webcash.len(), 64);
        assert_eq!(bitcoin.len(), 64);
        assert_eq!(pgp0.len(), 64);
        assert_eq!(pgp1.len(), 64);
        assert_eq!(vault.len(), 64);

        // Known test vectors (from the known mnemonic)
        assert_eq!(root, "21b7a946c56bc75928245d56c1057db4ad115c040748e90a0173ec5015ed7c6d");
        assert_eq!(rgb, "cb263f34c16122d362cd1fd2732b7fa62943439b60dfc63f603d17595fdbc92e");
        assert_eq!(webcash, "5017e94b5b8119330e9c42ace800ad1dfb93630f312c56bd3af91d10d88a8684");
        assert_eq!(bitcoin, "f8bbbf1e2223f17a99da8b823d4cd41b764c69133385ad5b1195885ec34a191b");
        assert_eq!(pgp0, "6d24f7bf44372fb0fe0fbc1c202198a830e26e9dcbfae40a168ea09f7ad823d0");
        assert_eq!(pgp1, "38776f21f6c7d4a3a2c22036ff69ce15c14641950cf8eedd41ad3189e67d9890");
        assert_eq!(vault, "dfbb7b8a4fc6e869a3449a580493d7b8df82926d049e9e9eaff345b274e6b368");

        // Different slots produce different keys
        assert_ne!(vault, vault_1);
        assert_ne!(pgp0, pgp1);
        assert_ne!(voucher, vault);
    }

    #[test]
    fn generate_new_produces_24_word_mnemonic() {
        let keychain = HdKeychain::generate_new().unwrap();
        let mnemonic = keychain.mnemonic_words();
        let word_count = mnemonic.split_whitespace().count();
        assert_eq!(word_count, 24, "must generate 24-word mnemonic (256-bit entropy)");
        assert_eq!(keychain.entropy_hex().len(), 64, "32 bytes = 64 hex chars");
    }

    #[test]
    fn mnemonic_roundtrip_12_words() {
        let keychain = HdKeychain::generate_new().unwrap();
        let mnemonic = keychain.mnemonic_words();
        let restored = HdKeychain::from_mnemonic_words(&mnemonic).unwrap();
        assert_eq!(keychain.entropy_hex(), restored.entropy_hex());
        assert_eq!(keychain.derive_slot_hex("webcash", 0).unwrap(),
                   restored.derive_slot_hex("webcash", 0).unwrap());
    }

    #[test]
    fn accepts_all_bip39_entropy_sizes() {
        for bytes in [16usize, 20, 24, 28, 32] {
            let entropy = vec![0x42u8; bytes];
            let keychain = HdKeychain::from_entropy(&entropy).expect("valid entropy len");
            assert_eq!(keychain.entropy_hex().len(), bytes * 2);
            assert!(!keychain.derive_slot_hex("rgb", 0).unwrap().is_empty());
        }
    }
}
