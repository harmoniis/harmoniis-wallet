use std::str::FromStr;

use bdk_wallet::bitcoin::{
    bip32::{ChildNumber, DerivationPath, Xpriv},
    secp256k1::Secp256k1,
    Network,
};
use bip39::Mnemonic;
use rand::{rngs::OsRng, RngCore};

use crate::error::{Error, Result};

pub const KEY_MODEL_VERSION_V3: &str = "v3-bip32";
pub const MAX_PGP_KEYS: u32 = 1_000;
pub const MAX_VAULT_KEYS: u32 = 1_000;
pub const SLOT_FAMILY_VAULT: &str = "vault";
/// Backward-compatible alias for existing integrations.
pub const SLOT_FAMILY_HARMONIA_VAULT: &str = "harmonia-vault";

// m / purpose' / app' / family' / index'
const PURPOSE_HARMONIIS: u32 = 83_696_968;
const APP_MAIN: u32 = 0;
const FAMILY_ROOT: u32 = 0;
const FAMILY_RGB: u32 = 1;
const FAMILY_WEBCASH: u32 = 2;
const FAMILY_BITCOIN: u32 = 3;
const FAMILY_PGP: u32 = 4;
const FAMILY_HARMONIA_VAULT: u32 = 5;
const FAMILY_VOUCHER: u32 = 6;

#[derive(Debug, Clone)]
pub struct HdKeychain {
    mnemonic: Mnemonic,
    entropy: Vec<u8>,
    master_xpriv: Xpriv,
}

impl HdKeychain {
    pub fn generate_new() -> Result<Self> {
        // 128-bit entropy -> 12 words (BIP39).
        let mut entropy = [0u8; 16];
        OsRng.fill_bytes(&mut entropy);
        Self::from_entropy(&entropy)
    }

    pub fn from_mnemonic_words(words: &str) -> Result<Self> {
        let mnemonic = Mnemonic::from_str(words.trim())
            .map_err(|e| Error::Other(anyhow::anyhow!("invalid BIP39 mnemonic: {e}")))?;
        let entropy = mnemonic.to_entropy();
        Self::from_mnemonic(mnemonic, entropy)
    }

    pub fn from_entropy_hex(hex_value: &str) -> Result<Self> {
        let entropy = hex::decode(hex_value.trim())
            .map_err(|e| Error::Other(anyhow::anyhow!("invalid master entropy hex: {e}")))?;
        Self::from_entropy(&entropy)
    }

    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        validate_entropy_len(entropy.len())?;
        let mnemonic = Mnemonic::from_entropy(entropy)
            .map_err(|e| Error::Other(anyhow::anyhow!("invalid BIP39 entropy: {e}")))?;
        Self::from_mnemonic(mnemonic, entropy.to_vec())
    }

    fn from_mnemonic(mnemonic: Mnemonic, entropy: Vec<u8>) -> Result<Self> {
        validate_entropy_len(entropy.len())?;
        let seed = mnemonic.to_seed_normalized("");
        let master_xpriv = Xpriv::new_master(Network::Bitcoin, &seed)
            .map_err(|e| Error::Other(anyhow::anyhow!("failed to derive BIP32 master key: {e}")))?;
        Ok(Self {
            mnemonic,
            entropy,
            master_xpriv,
        })
    }

    pub fn mnemonic_words(&self) -> String {
        self.mnemonic.to_string()
    }

    pub fn entropy_hex(&self) -> String {
        hex::encode(&self.entropy)
    }

    pub fn derive_slot_hex(&self, family: &str, index: u32) -> Result<String> {
        let (family_code, slot_index) = family_slot(family, index)?;
        let path = derivation_path(family_code, slot_index)?;
        let secp = Secp256k1::new();
        let derived = self.master_xpriv.derive_priv(&secp, &path).map_err(|e| {
            Error::Other(anyhow::anyhow!(
                "BIP32 derive failed for {family}[{index}]: {e}"
            ))
        })?;
        Ok(hex::encode(derived.private_key.secret_bytes()))
    }
}

fn family_slot(family: &str, index: u32) -> Result<(u32, u32)> {
    match family {
        "root" => {
            if index != 0 {
                return Err(Error::Other(anyhow::anyhow!(
                    "root family only supports index 0"
                )));
            }
            Ok((FAMILY_ROOT, 0))
        }
        "rgb" => {
            if index != 0 {
                return Err(Error::Other(anyhow::anyhow!(
                    "rgb family only supports index 0"
                )));
            }
            Ok((FAMILY_RGB, 0))
        }
        "webcash" => {
            if index != 0 {
                return Err(Error::Other(anyhow::anyhow!(
                    "webcash family only supports index 0"
                )));
            }
            Ok((FAMILY_WEBCASH, 0))
        }
        "bitcoin" => {
            if index != 0 {
                return Err(Error::Other(anyhow::anyhow!(
                    "bitcoin family only supports index 0"
                )));
            }
            Ok((FAMILY_BITCOIN, 0))
        }
        "pgp" => {
            if index >= MAX_PGP_KEYS {
                return Err(Error::Other(anyhow::anyhow!(
                    "PGP key index out of range (max {})",
                    MAX_PGP_KEYS - 1
                )));
            }
            Ok((FAMILY_PGP, index))
        }
        SLOT_FAMILY_VAULT | SLOT_FAMILY_HARMONIA_VAULT => {
            if index >= MAX_VAULT_KEYS {
                return Err(Error::Other(anyhow::anyhow!(
                    "vault key index out of range (max {})",
                    MAX_VAULT_KEYS - 1
                )));
            }
            Ok((FAMILY_HARMONIA_VAULT, index))
        }
        "voucher" => {
            if index != 0 {
                return Err(Error::Other(anyhow::anyhow!(
                    "voucher family only supports index 0"
                )));
            }
            Ok((FAMILY_VOUCHER, 0))
        }
        _ => Err(Error::Other(anyhow::anyhow!(
            "unknown key family '{family}'"
        ))),
    }
}

fn derivation_path(family_code: u32, slot_index: u32) -> Result<DerivationPath> {
    Ok(DerivationPath::from(vec![
        hard(PURPOSE_HARMONIIS)?,
        hard(APP_MAIN)?,
        hard(family_code)?,
        hard(slot_index)?,
    ]))
}

fn hard(index: u32) -> Result<ChildNumber> {
    ChildNumber::from_hardened_idx(index)
        .map_err(|e| Error::Other(anyhow::anyhow!("invalid hardened child index {index}: {e}")))
}

fn validate_entropy_len(len: usize) -> Result<()> {
    match len {
        16 | 20 | 24 | 28 | 32 => Ok(()),
        n => Err(Error::Other(anyhow::anyhow!(
            "invalid BIP39 entropy length: {n} bytes (expected 16/20/24/28/32)"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{HdKeychain, SLOT_FAMILY_VAULT};

    #[test]
    fn deterministic_slots_from_known_mnemonic() {
        // BIP39 test phrase with known stable output under our BIP32 path scheme.
        let keychain =
            HdKeychain::from_mnemonic_words("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
                .expect("valid mnemonic");
        let root = keychain.derive_slot_hex("root", 0).unwrap();
        let rgb = keychain.derive_slot_hex("rgb", 0).unwrap();
        let webcash = keychain.derive_slot_hex("webcash", 0).unwrap();
        let bitcoin = keychain.derive_slot_hex("bitcoin", 0).unwrap();
        let pgp_0 = keychain.derive_slot_hex("pgp", 0).unwrap();
        let pgp_1 = keychain.derive_slot_hex("pgp", 1).unwrap();
        let vault = keychain.derive_slot_hex(SLOT_FAMILY_VAULT, 0).unwrap();
        let vault_1 = keychain.derive_slot_hex(SLOT_FAMILY_VAULT, 1).unwrap();
        assert_eq!(keychain.entropy_hex(), "00000000000000000000000000000000");
        assert_eq!(
            root,
            "21b7a946c56bc75928245d56c1057db4ad115c040748e90a0173ec5015ed7c6d"
        );
        assert_eq!(
            rgb,
            "cb263f34c16122d362cd1fd2732b7fa62943439b60dfc63f603d17595fdbc92e"
        );
        assert_eq!(
            webcash,
            "5017e94b5b8119330e9c42ace800ad1dfb93630f312c56bd3af91d10d88a8684"
        );
        assert_eq!(
            bitcoin,
            "f8bbbf1e2223f17a99da8b823d4cd41b764c69133385ad5b1195885ec34a191b"
        );
        assert_eq!(
            pgp_0,
            "6d24f7bf44372fb0fe0fbc1c202198a830e26e9dcbfae40a168ea09f7ad823d0"
        );
        assert_eq!(
            pgp_1,
            "38776f21f6c7d4a3a2c22036ff69ce15c14641950cf8eedd41ad3189e67d9890"
        );
        assert_eq!(
            vault,
            "dfbb7b8a4fc6e869a3449a580493d7b8df82926d049e9e9eaff345b274e6b368"
        );
        assert_eq!(vault_1.len(), 64);
        assert_ne!(vault_1, vault);

        let voucher = keychain.derive_slot_hex("voucher", 0).unwrap();
        assert_eq!(voucher.len(), 64);
        assert_ne!(voucher, vault);
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
