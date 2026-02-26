use anyhow::Context;
use bdk_esplora::{esplora_client, EsploraExt};
use bdk_wallet::{
    bitcoin::{bip32::Xpriv, Network},
    template::Bip86,
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
    pub external_descriptor: String,
    pub internal_descriptor: String,
    pub receive_address: String,
    pub receive_index: u32,
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
        let wallet = self.build_wallet()?;
        let external = wallet.public_descriptor(KeychainKind::External).to_string();
        let internal = wallet.public_descriptor(KeychainKind::Internal).to_string();
        Ok((external, internal))
    }

    pub fn receive_address_at(&self, index: u32) -> Result<String> {
        let wallet = self.build_wallet()?;
        let info = wallet.peek_address(KeychainKind::External, index);
        Ok(info.address.to_string())
    }

    pub fn sync(
        &self,
        esplora_url: &str,
        stop_gap: usize,
        parallel_requests: usize,
    ) -> Result<BitcoinSyncSnapshot> {
        let mut wallet = self.build_wallet()?;
        let client = esplora_client::Builder::new(esplora_url).build_blocking();

        let request = wallet.start_full_scan().build();
        let response = client
            .full_scan(request, stop_gap.max(1), parallel_requests.max(1))
            .map_err(|e| Error::Other(anyhow::anyhow!("esplora full scan failed: {e}")))?;
        wallet.apply_update(response).map_err(|e| {
            Error::Other(anyhow::anyhow!("failed to apply bitcoin sync update: {e}"))
        })?;

        let balance = wallet.balance();
        let receive = wallet.next_unused_address(KeychainKind::External);
        let unspent_count = wallet.list_unspent().count();
        let (external_descriptor, internal_descriptor) = self.descriptor_strings()?;

        Ok(BitcoinSyncSnapshot {
            network: self.network,
            esplora_url: esplora_url.to_string(),
            external_descriptor,
            internal_descriptor,
            receive_address: receive.address.to_string(),
            receive_index: receive.index,
            unspent_count,
            confirmed_sats: balance.confirmed.to_sat(),
            trusted_pending_sats: balance.trusted_pending.to_sat(),
            untrusted_pending_sats: balance.untrusted_pending.to_sat(),
            immature_sats: balance.immature.to_sat(),
            total_sats: balance.total().to_sat(),
        })
    }

    fn build_wallet(&self) -> Result<Wallet> {
        let xprv = Xpriv::new_master(self.network, &self.slot_seed)
            .context("failed to create BIP32 master from deterministic bitcoin slot")
            .map_err(Error::Other)?;
        Wallet::create(
            Bip86(xprv, KeychainKind::External),
            Bip86(xprv, KeychainKind::Internal),
        )
        .network(self.network)
        .create_wallet_no_persist()
        .context("failed to create deterministic bitcoin wallet")
        .map_err(Error::Other)
    }
}
