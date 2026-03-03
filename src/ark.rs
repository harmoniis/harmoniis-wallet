//! ARK protocol integration — offchain Bitcoin payments via Arkade ASP.
//!
//! Uses VTXOs (Virtual Transaction Outputs) for instant, low-cost payments
//! that settle in batches on-chain. The `ArkPaymentWallet` wraps the
//! `ark-client` + `ark-bdk-wallet` crates, connecting to an Arkade ASP.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
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
use rand::SeedableRng;
use rusqlite::params;

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

// ── SQLite persistence for boarding outputs (bitcoin.db) ─────────────────────

/// SQLite-backed persistence for ARK boarding outputs.
///
/// Stores boarding output metadata and secret keys in `bitcoin.db`,
/// surviving across CLI invocations. Use `open_memory()` for stateless
/// contexts (e.g. Lambda backend).
pub struct SqliteArkDb {
    conn: std::sync::Mutex<rusqlite::Connection>,
}

impl SqliteArkDb {
    /// Open (or create) a persistent database at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Other(anyhow::anyhow!("cannot create bitcoin.db dir: {e}")))?;
        }
        let conn = rusqlite::Connection::open(path)
            .map_err(|e| Error::Other(anyhow::anyhow!("open bitcoin.db: {e}")))?;
        Self::init(conn)
    }

    /// Open an in-memory database (no persistence). Suitable for Lambda/backend.
    pub fn open_memory() -> Result<Self> {
        let conn = rusqlite::Connection::open_in_memory()
            .map_err(|e| Error::Other(anyhow::anyhow!("open in-memory bitcoin db: {e}")))?;
        Self::init(conn)
    }

    fn init(conn: rusqlite::Connection) -> Result<Self> {
        conn.execute_batch(
            "
            PRAGMA journal_mode=WAL;

            CREATE TABLE IF NOT EXISTS ark_boarding_outputs (
                boarding_address TEXT PRIMARY KEY,
                owner_pk_hex     TEXT NOT NULL,
                server_pk_hex    TEXT NOT NULL,
                exit_delay_u32   INTEGER NOT NULL,
                secret_key_hex   TEXT NOT NULL,
                network          TEXT NOT NULL,
                created_at       TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS bitcoin_metadata (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            ",
        )
        .map_err(|e| Error::Other(anyhow::anyhow!("init bitcoin.db schema: {e}")))?;
        Ok(Self {
            conn: std::sync::Mutex::new(conn),
        })
    }
}

impl Persistence for SqliteArkDb {
    fn save_boarding_output(
        &self,
        sk: SecretKey,
        boarding_output: ark_core::BoardingOutput,
    ) -> std::result::Result<(), ark_client::Error> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ark_client::Error::consumer(format!("db lock: {e}")))?;
        let secp = Secp256k1::new();
        let (owner_pk, _) = sk.public_key(&secp).x_only_public_key();
        let address = boarding_output.address().to_string();
        let owner_pk_hex = owner_pk.to_string();
        let exit_delay = boarding_output.exit_delay().to_consensus_u32();
        let secret_key_hex = hex::encode(sk.secret_bytes());
        let now = chrono::Utc::now().to_rfc3339();
        // server_pk and network are filled by new_boarding_output (UPDATE after INSERT).
        // On first save they're empty; the BoardingWallet impl fills them immediately after.
        conn.execute(
            "INSERT OR REPLACE INTO ark_boarding_outputs
             (boarding_address, owner_pk_hex, server_pk_hex, exit_delay_u32, secret_key_hex, network, created_at)
             VALUES (?1, ?2, COALESCE((SELECT server_pk_hex FROM ark_boarding_outputs WHERE boarding_address = ?1), ''), ?3, ?4, COALESCE((SELECT network FROM ark_boarding_outputs WHERE boarding_address = ?1), ''), ?5)",
            params![address, owner_pk_hex, exit_delay, secret_key_hex, now],
        )
        .map_err(|e| ark_client::Error::consumer(format!("save boarding output: {e}")))?;
        Ok(())
    }

    fn load_boarding_outputs(
        &self,
    ) -> std::result::Result<Vec<ark_core::BoardingOutput>, ark_client::Error> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ark_client::Error::consumer(format!("db lock: {e}")))?;
        let mut stmt = conn
            .prepare("SELECT owner_pk_hex, server_pk_hex, exit_delay_u32, network FROM ark_boarding_outputs")
            .map_err(|e| ark_client::Error::consumer(format!("prepare: {e}")))?;
        let secp = Secp256k1::new();
        let rows = stmt
            .query_map([], |row| {
                let owner_pk_hex: String = row.get(0)?;
                let server_pk_hex: String = row.get(1)?;
                let exit_delay: u32 = row.get(2)?;
                let network_str: String = row.get(3)?;
                Ok((owner_pk_hex, server_pk_hex, exit_delay, network_str))
            })
            .map_err(|e| ark_client::Error::consumer(format!("query: {e}")))?;

        let mut outputs = Vec::new();
        for row in rows {
            let (owner_pk_hex, server_pk_hex, exit_delay, network_str) =
                row.map_err(|e| ark_client::Error::consumer(format!("row: {e}")))?;
            let owner_pk = XOnlyPublicKey::from_str(&owner_pk_hex)
                .map_err(|e| ark_client::Error::consumer(format!("owner pk: {e}")))?;
            let server_pk = XOnlyPublicKey::from_str(&server_pk_hex)
                .map_err(|e| ark_client::Error::consumer(format!("server pk: {e}")))?;
            let network = Network::from_str(&network_str).unwrap_or(Network::Bitcoin);
            let exit_delay_seq = bdk_wallet::bitcoin::Sequence::from_consensus(exit_delay);
            let bo =
                ark_core::BoardingOutput::new(&secp, server_pk, owner_pk, exit_delay_seq, network)
                    .map_err(|e| {
                        ark_client::Error::consumer(format!("reconstruct boarding output: {e}"))
                    })?;
            outputs.push(bo);
        }
        Ok(outputs)
    }

    fn sk_for_pk(&self, pk: &XOnlyPublicKey) -> std::result::Result<SecretKey, ark_client::Error> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ark_client::Error::consumer(format!("db lock: {e}")))?;
        let pk_hex = pk.to_string();
        let secret_hex: String = conn
            .query_row(
                "SELECT secret_key_hex FROM ark_boarding_outputs WHERE owner_pk_hex = ?1 LIMIT 1",
                params![pk_hex],
                |row| row.get(0),
            )
            .map_err(|e| ark_client::Error::consumer(format!("no SK for PK {pk}: {e}")))?;
        let bytes = hex::decode(&secret_hex)
            .map_err(|e| ark_client::Error::consumer(format!("decode SK hex: {e}")))?;
        SecretKey::from_slice(&bytes)
            .map_err(|e| ark_client::Error::consumer(format!("parse SK: {e}")))
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

impl BoardingWallet for ArkOnchainWallet<SqliteArkDb> {
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
        // Save the boarding output (sk + address + owner_pk + exit_delay).
        self.db.save_boarding_output(sk, boarding_output.clone())?;
        // Also store server_pk and network so load_boarding_outputs can reconstruct.
        // The Persistence trait doesn't carry this context, so we write it directly.
        {
            let conn = self
                .db
                .conn
                .lock()
                .map_err(|e| ark_client::Error::consumer(format!("db lock: {e}")))?;
            let addr = boarding_output.address().to_string();
            conn.execute(
                "UPDATE ark_boarding_outputs SET server_pk_hex = ?1, network = ?2 WHERE boarding_address = ?3",
                params![server_pubkey.to_string(), network.to_string(), addr],
            ).map_err(|e| ark_client::Error::consumer(format!("update boarding context: {e}")))?;
        }
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

type ArkWallet = ArkOnchainWallet<SqliteArkDb>;
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

/// Verified incoming VTXO metadata.
#[derive(Debug, Clone)]
pub struct VerifiedVtxo {
    pub txid: String,
    pub amount_sats: u64,
    pub expires_at: i64,
    pub is_preconfirmed: bool,
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
    /// Pass `SqliteArkDb::open(path)` for persistent boarding outputs (CLI) or
    /// `SqliteArkDb::open_memory()` for stateless contexts (Lambda).
    pub async fn connect(
        btc_wallet: &DeterministicBitcoinWallet,
        asp_url: &str,
        db: SqliteArkDb,
    ) -> Result<Self> {
        ensure_rustls_provider();

        let network = btc_wallet.network();
        let slot_seed = btc_wallet.slot_seed();
        let xpriv = Xpriv::new_master(network, slot_seed)
            .context("failed to create master xpriv for ARK")
            .map_err(Error::Other)?;

        let esplora_url = DeterministicBitcoinWallet::default_esplora_url(network);
        let blockchain = Arc::new(EsploraBlockchain::new(esplora_url).map_err(Error::Other)?);

        let secp = Secp256k1::new();
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
        // Source of truth is the wallet VTXO set visible via ASP.
        // Some deployments can report stale aggregate balances while list_vtxos
        // is fresh; use list_vtxos first and only fall back to aggregate API.
        match self.vtxo_balance_from_list().await {
            Ok(bal) => Ok(bal),
            Err(_list_err) => {
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
        }
    }

    async fn vtxo_balance_from_list(&self) -> Result<ArkBalance> {
        let (vtxo_list, _) = self
            .client
            .list_vtxos()
            .await
            .map_err(|e| Error::Other(anyhow::anyhow!("list_vtxos: {e}")))?;

        let mut confirmed_sats = 0u64;
        let mut pre_confirmed_sats = 0u64;
        for vtxo in vtxo_list.all_unspent() {
            let sats = vtxo.amount.to_sat();
            if vtxo.is_preconfirmed {
                pre_confirmed_sats = pre_confirmed_sats.saturating_add(sats);
            } else {
                confirmed_sats = confirmed_sats.saturating_add(sats);
            }
        }

        Ok(ArkBalance {
            confirmed_sats,
            pre_confirmed_sats,
            total_sats: confirmed_sats.saturating_add(pre_confirmed_sats),
        })
    }

    /// Verify that a VTXO with the given txid was received by this wallet,
    /// is unspent, and carries at least `min_amount_sats`.
    pub async fn verify_incoming_vtxo(
        &self,
        vtxo_txid: &str,
        min_amount_sats: u64,
    ) -> Result<VerifiedVtxo> {
        let target_txid = Txid::from_str(vtxo_txid)
            .map_err(|e| Error::InvalidFormat(format!("invalid VTXO txid: {e}")))?;

        let (vtxo_list, _) = self
            .client
            .list_vtxos()
            .await
            .map_err(|e| Error::Other(anyhow::anyhow!("list_vtxos: {e}")))?;

        if let Some(vtxo) = vtxo_list
            .all_unspent()
            .find(|v| v.outpoint.txid == target_txid)
        {
            if vtxo.is_spent {
                return Err(Error::Other(anyhow::anyhow!("VTXO already spent")));
            }

            let amount_sats = vtxo.amount.to_sat();
            if amount_sats < min_amount_sats {
                return Err(Error::Other(anyhow::anyhow!(
                    "VTXO amount insufficient: have {amount_sats}, need at least {min_amount_sats}"
                )));
            }

            return Ok(VerifiedVtxo {
                txid: vtxo.outpoint.txid.to_string(),
                amount_sats,
                expires_at: vtxo.expires_at,
                is_preconfirmed: vtxo.is_preconfirmed,
            });
        }

        if vtxo_list.spent().any(|v| v.outpoint.txid == target_txid) {
            return Err(Error::Other(anyhow::anyhow!("VTXO already spent")));
        }

        Err(Error::NotFound("VTXO not found in wallet".to_string()))
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
        let mut rng = rand::rngs::StdRng::from_entropy();
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
