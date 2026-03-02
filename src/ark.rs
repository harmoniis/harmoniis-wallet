//! ARK protocol integration — offchain Bitcoin payments via Arkade ASP.
//!
//! Uses VTXOs (Virtual Transaction Outputs) for instant, low-cost payments
//! that settle in batches on-chain. The `ArkPaymentWallet` wraps the
//! `ark-client` + `ark-bdk-wallet` crates, connecting to an Arkade ASP.

use std::collections::{BTreeSet, HashMap};
use std::io::Write;
use std::str::FromStr;
use std::sync::{Arc, Once, RwLock};
use std::time::Duration;

use anyhow::Context;
use ark_client::wallet::{BoardingWallet, OnchainWallet, Persistence};
use ark_client::{Bip32KeyProvider, Blockchain, Client, InMemorySwapStorage, OfflineClient};
use ark_core::{ExplorerUtxo, SelectedUtxo, UtxoCoinSelection};
use bdk_esplora::esplora_client;
use bdk_esplora::EsploraAsyncExt;
use bdk_wallet::bitcoin::{
    bip32::{DerivationPath, Xpriv},
    key::Keypair,
    secp256k1::{schnorr::Signature, All, Message, Secp256k1, SecretKey, XOnlyPublicKey},
    Address, Amount, FeeRate, Network, OutPoint, Psbt, Transaction, Txid,
};
use bdk_wallet::{KeychainKind, SignOptions, TxOrdering, Wallet as BdkWallet};

use crate::bitcoin::DeterministicBitcoinWallet;
use crate::error::{Error, Result};

/// Default Arkade ASP URL (mainnet).
pub const DEFAULT_ASP_URL: &str = "https://arkade.computer";

/// Default Boltz swap API (unused for basic payments, but required by the client).
const DEFAULT_BOLTZ_URL: &str = "https://api.boltz.exchange/v2";

/// Client connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Payment proof prefix used in `X-Bitcoin-Secret` header.
pub const ARK_PROOF_PREFIX: &str = "ark:";

static RUSTLS_PROVIDER_INIT: Once = Once::new();

fn ensure_rustls_provider() {
    // ark-client (tonic/rustls 0.23) requires an explicit process-level provider.
    RUSTLS_PROVIDER_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

// ── In-memory persistence for boarding outputs ───────────────────────────────

#[derive(Default)]
struct InMemoryDb {
    boarding_outputs: RwLock<HashMap<ark_core::BoardingOutput, SecretKey>>,
}

impl Persistence for InMemoryDb {
    fn save_boarding_output(
        &self,
        sk: SecretKey,
        boarding_output: ark_core::BoardingOutput,
    ) -> std::result::Result<(), ark_client::Error> {
        self.boarding_outputs
            .write()
            .map_err(|e| ark_client::Error::consumer(format!("write lock: {e}")))?
            .insert(boarding_output, sk);
        Ok(())
    }

    fn load_boarding_outputs(
        &self,
    ) -> std::result::Result<Vec<ark_core::BoardingOutput>, ark_client::Error> {
        Ok(self
            .boarding_outputs
            .read()
            .map_err(|e| ark_client::Error::consumer(format!("read lock: {e}")))?
            .keys()
            .cloned()
            .collect())
    }

    fn sk_for_pk(&self, pk: &XOnlyPublicKey) -> std::result::Result<SecretKey, ark_client::Error> {
        self.boarding_outputs
            .read()
            .map_err(|e| ark_client::Error::consumer(format!("read lock: {e}")))?
            .iter()
            .find_map(|(b, sk)| if b.owner_pk() == *pk { Some(*sk) } else { None })
            .ok_or_else(|| ark_client::Error::consumer(format!("no SK for PK {pk}")))
    }
}

// ── Local ARK wallet adapter (no system proxy auto-discovery) ───────────────

struct ArkOnchainWallet<DB>
where
    DB: Persistence,
{
    kp: Keypair,
    secp: Secp256k1<All>,
    inner: Arc<RwLock<BdkWallet>>,
    client: esplora_client::AsyncClient,
    db: DB,
}

impl<DB> ArkOnchainWallet<DB>
where
    DB: Persistence,
{
    fn new_from_xpriv(
        xpriv: Xpriv,
        secp: Secp256k1<All>,
        network: Network,
        esplora_url: &str,
        db: DB,
    ) -> std::result::Result<Self, anyhow::Error> {
        let kp = xpriv.to_keypair(&secp);
        let external = bdk_wallet::template::Bip84(xpriv, KeychainKind::External);
        let change = bdk_wallet::template::Bip84(xpriv, KeychainKind::Internal);
        let wallet = BdkWallet::create(external, change)
            .network(network)
            .create_wallet_no_persist()?;

        // Avoid reqwest macOS system proxy auto-discovery, which can panic in sandboxed runs.
        let reqwest_client = reqwest::Client::builder().no_proxy().build()?;
        let client =
            esplora_client::AsyncClient::from_client(esplora_url.to_string(), reqwest_client);

        Ok(Self {
            kp,
            secp,
            inner: Arc::new(RwLock::new(wallet)),
            client,
            db,
        })
    }
}

impl<DB> OnchainWallet for ArkOnchainWallet<DB>
where
    DB: Persistence + Send + Sync,
{
    fn get_onchain_address(&self) -> std::result::Result<Address, ark_client::Error> {
        let info = self
            .inner
            .write()
            .map_err(|e| ark_client::Error::consumer(format!("wallet write lock: {e}")))?
            .next_unused_address(KeychainKind::External);
        Ok(info.address)
    }

    async fn sync(&self) -> std::result::Result<(), ark_client::Error> {
        let request = self
            .inner
            .read()
            .map_err(|e| ark_client::Error::consumer(format!("wallet read lock: {e}")))?
            .start_full_scan()
            .inspect({
                let mut stdout = std::io::stdout();
                let mut once = BTreeSet::<KeychainKind>::new();
                move |keychain, _spk_i, _| {
                    let _ = once.insert(keychain);
                    stdout.flush().expect("must flush");
                }
            });

        let update = self
            .client
            .full_scan(request, 5, 5)
            .await
            .map_err(ark_client::Error::wallet)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.inner
            .write()
            .map_err(|e| ark_client::Error::consumer(format!("wallet write lock: {e}")))?
            .apply_update_at(update, now)
            .map_err(ark_client::Error::wallet)?;
        Ok(())
    }

    fn balance(&self) -> std::result::Result<ark_client::wallet::Balance, ark_client::Error> {
        let bal = self
            .inner
            .read()
            .map_err(|e| ark_client::Error::consumer(format!("wallet read lock: {e}")))?
            .balance();
        Ok(ark_client::wallet::Balance {
            immature: bal.immature,
            trusted_pending: bal.trusted_pending,
            untrusted_pending: bal.untrusted_pending,
            confirmed: bal.confirmed,
        })
    }

    fn prepare_send_to_address(
        &self,
        address: Address,
        amount: Amount,
        fee_rate: FeeRate,
    ) -> std::result::Result<Psbt, ark_client::Error> {
        let wallet = &mut self
            .inner
            .write()
            .map_err(|e| ark_client::Error::consumer(format!("wallet write lock: {e}")))?;
        let mut tx = wallet.build_tx();
        tx.ordering(TxOrdering::Untouched);
        tx.add_recipient(address.script_pubkey(), amount);
        tx.fee_rate(fee_rate);
        tx.finish().map_err(ark_client::Error::wallet)
    }

    fn sign(&self, psbt: &mut Psbt) -> std::result::Result<bool, ark_client::Error> {
        let opts = SignOptions {
            trust_witness_utxo: true,
            ..SignOptions::default()
        };
        self.inner
            .read()
            .map_err(|e| ark_client::Error::consumer(format!("wallet read lock: {e}")))?
            .sign(psbt, opts)
            .map_err(ark_client::Error::wallet)
    }

    fn select_coins(
        &self,
        target_amount: Amount,
    ) -> std::result::Result<UtxoCoinSelection, ark_client::Error> {
        let wallet = self
            .inner
            .read()
            .map_err(|e| ark_client::Error::consumer(format!("wallet read lock: {e}")))?;
        let utxos = wallet.list_unspent();
        let mut selected_utxos = Vec::new();
        let mut total_selected = Amount::ZERO;

        for utxo in utxos {
            if total_selected >= target_amount {
                break;
            }
            let address = wallet
                .peek_address(utxo.keychain, utxo.derivation_index)
                .address;
            selected_utxos.push(SelectedUtxo {
                outpoint: utxo.outpoint,
                amount: utxo.txout.value,
                address,
            });
            total_selected += utxo.txout.value;
        }

        if total_selected < target_amount {
            return Err(ark_client::Error::wallet(format!(
                "insufficient funds: need {target_amount}, have {total_selected}"
            )));
        }

        Ok(UtxoCoinSelection {
            selected_utxos,
            total_selected,
            change_amount: total_selected - target_amount,
        })
    }
}

impl<DB> BoardingWallet for ArkOnchainWallet<DB>
where
    DB: Persistence,
{
    fn new_boarding_output(
        &self,
        server_pubkey: XOnlyPublicKey,
        exit_delay: bdk_wallet::bitcoin::Sequence,
        network: Network,
    ) -> std::result::Result<ark_core::BoardingOutput, ark_client::Error> {
        let sk = self.kp.secret_key();
        let (owner_pk, _) = sk.public_key(&self.secp).x_only_public_key();
        let boarding_output = ark_core::BoardingOutput::new(
            &self.secp,
            server_pubkey,
            owner_pk,
            exit_delay,
            network,
        )?;
        self.db.save_boarding_output(sk, boarding_output.clone())?;
        Ok(boarding_output)
    }

    fn get_boarding_outputs(
        &self,
    ) -> std::result::Result<Vec<ark_core::BoardingOutput>, ark_client::Error> {
        self.db.load_boarding_outputs()
    }

    fn sign_for_pk(
        &self,
        pk: &XOnlyPublicKey,
        msg: &Message,
    ) -> std::result::Result<Signature, ark_client::Error> {
        let sk = self.db.sk_for_pk(pk)?;
        Ok(self
            .secp
            .sign_schnorr_no_aux_rand(msg, &sk.keypair(&self.secp)))
    }
}

// ── Esplora Blockchain adapter (implements ark_client::Blockchain) ───────────

struct EsploraBlockchain {
    client: esplora_client::AsyncClient,
}

impl EsploraBlockchain {
    fn new(url: &str) -> std::result::Result<Self, anyhow::Error> {
        let reqwest_client = reqwest::Client::builder().no_proxy().build()?;
        let client = esplora_client::AsyncClient::from_client(url.to_string(), reqwest_client);
        Ok(Self { client })
    }
}

impl Blockchain for EsploraBlockchain {
    async fn find_outpoints(
        &self,
        address: &Address,
    ) -> std::result::Result<Vec<ExplorerUtxo>, ark_client::Error> {
        let script_pubkey = address.script_pubkey();
        let txs = self
            .client
            .scripthash_txs(&script_pubkey, None)
            .await
            .map_err(ark_client::Error::consumer)?;

        let outputs: Vec<ExplorerUtxo> = txs
            .into_iter()
            .flat_map(|tx| {
                let txid = tx.txid;
                tx.vout
                    .iter()
                    .enumerate()
                    .filter(|(_, v)| v.scriptpubkey == script_pubkey)
                    .map(move |(i, v)| ExplorerUtxo {
                        outpoint: OutPoint {
                            txid,
                            vout: i as u32,
                        },
                        amount: Amount::from_sat(v.value),
                        confirmation_blocktime: tx.status.block_time,
                        is_spent: false,
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        let mut utxos = Vec::new();
        for output in &outputs {
            let op = output.outpoint;
            let status = self
                .client
                .get_output_status(&op.txid, op.vout as u64)
                .await
                .map_err(ark_client::Error::consumer)?;
            match status {
                Some(esplora_client::OutputStatus { spent: true, .. }) => {
                    utxos.push(ExplorerUtxo {
                        is_spent: true,
                        ..*output
                    });
                }
                _ => utxos.push(*output),
            }
        }
        Ok(utxos)
    }

    async fn find_tx(
        &self,
        txid: &Txid,
    ) -> std::result::Result<Option<Transaction>, ark_client::Error> {
        self.client
            .get_tx(txid)
            .await
            .map_err(ark_client::Error::consumer)
    }

    async fn get_tx_status(
        &self,
        txid: &Txid,
    ) -> std::result::Result<ark_client::TxStatus, ark_client::Error> {
        let info = self
            .client
            .get_tx_info(txid)
            .await
            .map_err(ark_client::Error::consumer)?;
        Ok(ark_client::TxStatus {
            confirmed_at: info.and_then(|s| s.status.block_time.map(|t| t as i64)),
        })
    }

    async fn get_output_status(
        &self,
        txid: &Txid,
        vout: u32,
    ) -> std::result::Result<ark_client::SpendStatus, ark_client::Error> {
        let status = self
            .client
            .get_output_status(txid, vout as u64)
            .await
            .map_err(ark_client::Error::consumer)?;
        Ok(ark_client::SpendStatus {
            spend_txid: status.as_ref().and_then(|s| s.txid),
        })
    }

    async fn broadcast(&self, tx: &Transaction) -> std::result::Result<(), ark_client::Error> {
        self.client
            .broadcast(tx)
            .await
            .map_err(ark_client::Error::consumer)
    }

    async fn get_fee_rate(&self) -> std::result::Result<f64, ark_client::Error> {
        Ok(1.0)
    }

    async fn broadcast_package(
        &self,
        _txs: &[&Transaction],
    ) -> std::result::Result<(), ark_client::Error> {
        Err(ark_client::Error::consumer(
            "broadcast_package not implemented",
        ))
    }
}

// ── Type aliases ─────────────────────────────────────────────────────────────

type ArkWallet = ArkOnchainWallet<InMemoryDb>;
type ArkClient = Client<EsploraBlockchain, ArkWallet, InMemorySwapStorage, Bip32KeyProvider>;

// ── Public API ───────────────────────────────────────────────────────────────

/// ARK payment wallet connected to an Arkade ASP.
pub struct ArkPaymentWallet {
    client: ArkClient,
    network: Network,
}

/// Balance returned by the ASP.
#[derive(Debug, Clone)]
pub struct ArkBalance {
    pub confirmed_sats: u64,
    pub pre_confirmed_sats: u64,
    pub total_sats: u64,
}

/// Result of an ARK payment.
#[derive(Debug, Clone)]
pub struct ArkPaymentResult {
    /// VTXO transaction ID (hex).
    pub vtxo_txid: String,
    /// Amount sent in sats.
    pub amount_sats: u64,
}

impl ArkPaymentResult {
    /// Format as payment proof string for `X-Bitcoin-Secret` header.
    pub fn to_proof_string(&self) -> String {
        format!(
            "{}{}:{}",
            ARK_PROOF_PREFIX, self.vtxo_txid, self.amount_sats
        )
    }
}

/// Parse an ARK payment proof string: `ark:<vtxo_txid>:<amount_sats>`.
pub fn parse_ark_proof(proof: &str) -> Option<(String, u64)> {
    let rest = proof.strip_prefix(ARK_PROOF_PREFIX)?;
    let (txid, amount_str) = rest.rsplit_once(':')?;
    if txid.is_empty() {
        return None;
    }
    let amount = amount_str.parse::<u64>().ok()?;
    Some((txid.to_string(), amount))
}

impl ArkPaymentWallet {
    /// Create and connect an ARK wallet from a deterministic Bitcoin wallet.
    ///
    /// Derives the ARK key from the same slot seed used for on-chain BIP86/84.
    pub async fn connect(btc_wallet: &DeterministicBitcoinWallet, asp_url: &str) -> Result<Self> {
        ensure_rustls_provider();

        let network = btc_wallet.network();
        let slot_seed = btc_wallet.slot_seed();
        let xpriv = Xpriv::new_master(network, slot_seed)
            .context("failed to create master xpriv for ARK")
            .map_err(Error::Other)?;

        let esplora_url = DeterministicBitcoinWallet::default_esplora_url(network);
        let blockchain = Arc::new(EsploraBlockchain::new(esplora_url).map_err(Error::Other)?);

        let secp = Secp256k1::new();
        let db = InMemoryDb::default();
        let wallet = Arc::new(
            ArkOnchainWallet::new_from_xpriv(xpriv, secp, network, esplora_url, db)
                .map_err(|e| Error::Other(anyhow::anyhow!("ARK BDK wallet: {e}")))?,
        );

        let storage = Arc::new(InMemorySwapStorage::new());

        let offline = OfflineClient::<_, _, _, Bip32KeyProvider>::new_with_bip32(
            "harmoniis-wallet".to_string(),
            xpriv,
            None::<DerivationPath>,
            blockchain,
            wallet,
            asp_url.to_string(),
            storage,
            DEFAULT_BOLTZ_URL.to_string(),
            CONNECT_TIMEOUT,
        );

        let client = offline
            .connect()
            .await
            .map_err(|e| Error::Other(anyhow::anyhow!("ARK ASP connect: {e}")))?;

        Ok(Self { client, network })
    }

    /// Get the on-chain boarding address (deposit BTC into ARK).
    pub fn get_boarding_address(&self) -> Result<String> {
        let addr = self
            .client
            .get_boarding_address()
            .map_err(|e| Error::Other(anyhow::anyhow!("boarding address: {e}")))?;
        Ok(addr.to_string())
    }

    /// Get a fresh on-chain receive address controlled by this ARK wallet.
    pub fn get_onchain_address(&self) -> Result<String> {
        let addr = self
            .client
            .get_onchain_address()
            .map_err(|e| Error::Other(anyhow::anyhow!("onchain address: {e}")))?;
        Ok(addr.to_string())
    }

    /// Get the offchain ARK address for receiving VTXOs.
    pub fn get_offchain_address(&self) -> Result<String> {
        let (addr, _vtxo) = self
            .client
            .get_offchain_address()
            .map_err(|e| Error::Other(anyhow::anyhow!("offchain address: {e}")))?;
        Ok(addr.encode())
    }

    /// Query offchain balance from the ASP.
    pub async fn offchain_balance(&self) -> Result<ArkBalance> {
        let bal = self
            .client
            .offchain_balance()
            .await
            .map_err(|e| Error::Other(anyhow::anyhow!("balance: {e}")))?;
        let confirmed = bal.confirmed().to_sat();
        let pre_confirmed = bal.pre_confirmed().to_sat();
        Ok(ArkBalance {
            confirmed_sats: confirmed,
            pre_confirmed_sats: pre_confirmed,
            total_sats: confirmed.saturating_add(pre_confirmed),
        })
    }

    /// Send a VTXO payment to another ARK address.
    pub async fn send_payment(
        &self,
        recipient_ark_address: &str,
        amount_sats: u64,
    ) -> Result<ArkPaymentResult> {
        let addr = ark_core::ArkAddress::decode(recipient_ark_address)
            .map_err(|e| Error::Other(anyhow::anyhow!("invalid ARK address: {e}")))?;
        let amount = Amount::from_sat(amount_sats);

        let txid = self
            .client
            .send_vtxo(addr, amount)
            .await
            .map_err(|e| Error::Other(anyhow::anyhow!("send_vtxo: {e}")))?;

        Ok(ArkPaymentResult {
            vtxo_txid: txid.to_string(),
            amount_sats,
        })
    }

    /// Move ARK-controlled funds to an on-chain Bitcoin address.
    pub async fn send_onchain(&self, address: &str, amount_sats: u64) -> Result<String> {
        let to_address = Address::from_str(address)
            .map_err(|e| Error::Other(anyhow::anyhow!("invalid bitcoin address: {e}")))?
            .require_network(self.network)
            .map_err(|e| {
                Error::Other(anyhow::anyhow!(
                    "bitcoin address network mismatch (expected {}): {e}",
                    self.network
                ))
            })?;
        let to_amount = Amount::from_sat(amount_sats);
        let txid = self
            .client
            .send_on_chain(to_address, to_amount)
            .await
            .map_err(|e| Error::Other(anyhow::anyhow!("send_on_chain: {e}")))?;
        Ok(txid.to_string())
    }

    /// Settle pending VTXOs (confirm boarding deposits on-chain).
    pub async fn settle(&self) -> Result<Option<String>> {
        let mut rng = rand::thread_rng();
        let maybe_tx = self
            .client
            .settle(&mut rng)
            .await
            .map_err(|e| Error::Other(anyhow::anyhow!("settle: {e}")))?;
        Ok(maybe_tx.map(|tx| tx.to_string()))
    }

    /// Pay Harmoniis fees via ARK: send to the given ARK address, return proof string.
    pub async fn pay_harmoniis(
        &self,
        harmoniis_ark_address: &str,
        amount_sats: u64,
    ) -> Result<String> {
        let result = self
            .send_payment(harmoniis_ark_address, amount_sats)
            .await?;
        Ok(result.to_proof_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ark_proof_roundtrip() {
        let result = ArkPaymentResult {
            vtxo_txid: "abc123def456".to_string(),
            amount_sats: 42000,
        };
        let proof = result.to_proof_string();
        assert_eq!(proof, "ark:abc123def456:42000");

        let (txid, amount) = parse_ark_proof(&proof).expect("valid proof");
        assert_eq!(txid, "abc123def456");
        assert_eq!(amount, 42000);
    }

    #[test]
    fn parse_ark_proof_invalid() {
        assert!(parse_ark_proof("").is_none());
        assert!(parse_ark_proof("ark:").is_none());
        assert!(parse_ark_proof("ark::123").is_none());
        assert!(parse_ark_proof("bitcoin:abc:123").is_none());
        assert!(parse_ark_proof("ark:txid:notanumber").is_none());
    }
}
