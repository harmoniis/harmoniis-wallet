use anyhow::Context;
use bdk_esplora::{esplora_client, EsploraExt};
use bdk_wallet::{
    bitcoin::{bip32::Xpriv, Network},
    template::{Bip84, Bip86},
    KeychainKind, Wallet,
};

use crate::{
    error::{Error, Result},
    wallet::RgbWallet,
};

#[derive(Debug, Clone)]
pub struct BitcoinSyncSnapshot {
    pub network: Network,
    pub esplora_url: String,
    pub taproot_external_descriptor: String,
    pub taproot_internal_descriptor: String,
    pub taproot_receive_address: String,
    pub taproot_receive_index: u32,
    pub segwit_external_descriptor: String,
    pub segwit_internal_descriptor: String,
    pub segwit_receive_address: String,
    pub segwit_receive_index: u32,
    pub unspent_count: usize,
    pub confirmed_sats: u64,
    pub trusted_pending_sats: u64,
    pub untrusted_pending_sats: u64,
    pub immature_sats: u64,
    pub total_sats: u64,
}

#[derive(Debug, Clone)]
pub struct DeterministicBitcoinWallet {
    network: Network,
    slot_seed: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinAddressKind {
    Taproot,
    Segwit,
}

impl BitcoinAddressKind {
    fn label(self) -> &'static str {
        match self {
            Self::Taproot => "taproot",
            Self::Segwit => "segwit",
        }
    }
}

#[derive(Debug, Clone)]
struct WalletScanSnapshot {
    external_descriptor: String,
    internal_descriptor: String,
    receive_address: String,
    receive_index: u32,
    unspent_count: usize,
    confirmed_sats: u64,
    trusted_pending_sats: u64,
    untrusted_pending_sats: u64,
    immature_sats: u64,
    total_sats: u64,
}

impl DeterministicBitcoinWallet {
    pub fn from_rgb_wallet(wallet: &RgbWallet, network: Network) -> Result<Self> {
        let slot_hex = wallet.derive_bitcoin_master_key_hex()?;
        Self::from_slot_seed_hex(&slot_hex, network)
    }

    pub fn from_slot_seed_hex(slot_seed_hex: &str, network: Network) -> Result<Self> {
        let bytes = hex::decode(slot_seed_hex).map_err(|e| {
            Error::Other(anyhow::anyhow!(
                "invalid deterministic bitcoin slot hex: {e}"
            ))
        })?;
        let len = bytes.len();
        let slot_seed: [u8; 32] = bytes.try_into().map_err(|_| {
            Error::Other(anyhow::anyhow!(
                "invalid deterministic bitcoin slot length: expected 32 bytes, got {len}"
            ))
        })?;
        Ok(Self { network, slot_seed })
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn default_esplora_url(network: Network) -> &'static str {
        match network {
            Network::Bitcoin => "https://blockstream.info/api",
            Network::Testnet | Network::Testnet4 => "https://blockstream.info/testnet/api",
            Network::Signet => "https://blockstream.info/signet/api",
            Network::Regtest => "http://127.0.0.1:3002",
        }
    }

    pub fn descriptor_strings(&self) -> Result<(String, String)> {
        self.descriptor_strings_for(BitcoinAddressKind::Taproot)
    }

    pub fn descriptor_strings_for(&self, kind: BitcoinAddressKind) -> Result<(String, String)> {
        let wallet = self.build_wallet(kind)?;
        let external = wallet.public_descriptor(KeychainKind::External).to_string();
        let internal = wallet.public_descriptor(KeychainKind::Internal).to_string();
        Ok((external, internal))
    }

    pub fn receive_address_at(&self, index: u32) -> Result<String> {
        self.receive_address_at_kind(index, BitcoinAddressKind::Taproot)
    }

    pub fn receive_address_at_kind(&self, index: u32, kind: BitcoinAddressKind) -> Result<String> {
        let wallet = self.build_wallet(kind)?;
        let info = wallet.peek_address(KeychainKind::External, index);
        Ok(info.address.to_string())
    }

    pub fn sync(
        &self,
        esplora_url: &str,
        stop_gap: usize,
        parallel_requests: usize,
    ) -> Result<BitcoinSyncSnapshot> {
        let taproot = self.scan_wallet(
            esplora_url,
            stop_gap,
            parallel_requests,
            BitcoinAddressKind::Taproot,
        )?;
        let segwit = self.scan_wallet(
            esplora_url,
            stop_gap,
            parallel_requests,
            BitcoinAddressKind::Segwit,
        )?;

        Ok(BitcoinSyncSnapshot {
            network: self.network,
            esplora_url: esplora_url.to_string(),
            taproot_external_descriptor: taproot.external_descriptor,
            taproot_internal_descriptor: taproot.internal_descriptor,
            taproot_receive_address: taproot.receive_address,
            taproot_receive_index: taproot.receive_index,
            segwit_external_descriptor: segwit.external_descriptor,
            segwit_internal_descriptor: segwit.internal_descriptor,
            segwit_receive_address: segwit.receive_address,
            segwit_receive_index: segwit.receive_index,
            unspent_count: taproot.unspent_count.saturating_add(segwit.unspent_count),
            confirmed_sats: taproot.confirmed_sats.saturating_add(segwit.confirmed_sats),
            trusted_pending_sats: taproot
                .trusted_pending_sats
                .saturating_add(segwit.trusted_pending_sats),
            untrusted_pending_sats: taproot
                .untrusted_pending_sats
                .saturating_add(segwit.untrusted_pending_sats),
            immature_sats: taproot.immature_sats.saturating_add(segwit.immature_sats),
            total_sats: taproot.total_sats.saturating_add(segwit.total_sats),
        })
    }

    fn scan_wallet(
        &self,
        esplora_url: &str,
        stop_gap: usize,
        parallel_requests: usize,
        kind: BitcoinAddressKind,
    ) -> Result<WalletScanSnapshot> {
        let mut wallet = self.build_wallet(kind)?;
        let client = esplora_client::Builder::new(esplora_url).build_blocking();

        let request = wallet.start_full_scan().build();
        let response = client
            .full_scan(request, stop_gap.max(1), parallel_requests.max(1))
            .map_err(|e| {
                Error::Other(anyhow::anyhow!(
                    "esplora full scan failed for {}: {e}",
                    kind.label()
                ))
            })?;
        wallet.apply_update(response).map_err(|e| {
            Error::Other(anyhow::anyhow!(
                "failed to apply bitcoin sync update for {}: {e}",
                kind.label()
            ))
        })?;

        let balance = wallet.balance();
        let receive = wallet.next_unused_address(KeychainKind::External);
        let (external_descriptor, internal_descriptor) = self.descriptor_strings_for(kind)?;

        Ok(WalletScanSnapshot {
            external_descriptor,
            internal_descriptor,
            receive_address: receive.address.to_string(),
            receive_index: receive.index,
            unspent_count: wallet.list_unspent().count(),
            confirmed_sats: balance.confirmed.to_sat(),
            trusted_pending_sats: balance.trusted_pending.to_sat(),
            untrusted_pending_sats: balance.untrusted_pending.to_sat(),
            immature_sats: balance.immature.to_sat(),
            total_sats: balance.total().to_sat(),
        })
    }

    fn build_wallet(&self, kind: BitcoinAddressKind) -> Result<Wallet> {
        let xprv = Xpriv::new_master(self.network, &self.slot_seed)
            .context("failed to create BIP32 master from deterministic bitcoin slot")
            .map_err(Error::Other)?;
        let builder = match kind {
            BitcoinAddressKind::Taproot => Wallet::create(
                Bip86(xprv, KeychainKind::External),
                Bip86(xprv, KeychainKind::Internal),
            ),
            BitcoinAddressKind::Segwit => Wallet::create(
                Bip84(xprv, KeychainKind::External),
                Bip84(xprv, KeychainKind::Internal),
            ),
        };
        builder
            .network(self.network)
            .create_wallet_no_persist()
            .context("failed to create deterministic bitcoin wallet")
            .map_err(Error::Other)
    }
}

#[cfg(test)]
mod tests {
    use super::{BitcoinAddressKind, DeterministicBitcoinWallet};
    use bdk_wallet::bitcoin::Network;

    fn sample_slot_hex() -> String {
        "11".repeat(32)
    }

    #[test]
    fn descriptor_kind_matches_expected_script_type() {
        let wallet =
            DeterministicBitcoinWallet::from_slot_seed_hex(&sample_slot_hex(), Network::Testnet)
                .expect("wallet");
        let (taproot_external, taproot_internal) = wallet
            .descriptor_strings_for(BitcoinAddressKind::Taproot)
            .expect("taproot descriptors");
        let (segwit_external, segwit_internal) = wallet
            .descriptor_strings_for(BitcoinAddressKind::Segwit)
            .expect("segwit descriptors");

        assert!(taproot_external.starts_with("tr("));
        assert!(taproot_internal.starts_with("tr("));
        assert!(segwit_external.starts_with("wpkh("));
        assert!(segwit_internal.starts_with("wpkh("));
    }

    #[test]
    fn address_kind_outputs_are_deterministic_and_distinct() {
        let wallet =
            DeterministicBitcoinWallet::from_slot_seed_hex(&sample_slot_hex(), Network::Testnet)
                .expect("wallet");

        let taproot_a = wallet
            .receive_address_at_kind(0, BitcoinAddressKind::Taproot)
            .expect("taproot");
        let taproot_b = wallet
            .receive_address_at_kind(0, BitcoinAddressKind::Taproot)
            .expect("taproot again");
        let segwit = wallet
            .receive_address_at_kind(0, BitcoinAddressKind::Segwit)
            .expect("segwit");

        assert_eq!(taproot_a, taproot_b);
        assert_ne!(taproot_a, segwit);
        assert!(taproot_a.starts_with("tb1p"));
        assert!(segwit.starts_with("tb1q"));
    }
}
