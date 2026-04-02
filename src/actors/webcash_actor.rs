//! Actor wrapping a live [`WebcashWallet`] for thread-safe webcash operations.
//!
//! The webcash wallet (from webylib) uses async methods for insert/pay/balance.
//! This actor owns the wallet instance and a tokio runtime handle, using
//! `SyncContext` so handlers can call `rt.block_on(...)` for async operations.

use actix::prelude::*;

use crate::error::{Error, Result};
use crate::wallet::webcash::{Amount, SecretWebcash, WebcashWallet, WebcashWalletSnapshot};

/// Actor that owns a live [`WebcashWallet`] and a tokio runtime handle.
///
/// Uses `SyncContext` so handlers can block on async wallet operations.
pub struct WebcashActor {
    wallet: Option<WebcashWallet>,
    rt: tokio::runtime::Handle,
    dirty: bool,
}

impl WebcashActor {
    pub fn new(rt: tokio::runtime::Handle) -> Self {
        Self {
            wallet: None,
            rt,
            dirty: false,
        }
    }
}

impl Actor for WebcashActor {
    type Context = SyncContext<Self>;
}

// ── Messages ────────────────────────────────────────────────────────────────

/// Load (or reload) the wallet from a snapshot or create a fresh memory wallet.
#[derive(Message)]
#[rtype(result = "Result<()>")]
pub struct LoadWallet {
    pub snapshot: Option<WebcashWalletSnapshot>,
    pub master_secret: Option<String>,
}

#[derive(Message)]
#[rtype(result = "Result<()>")]
pub struct InsertWebcash(pub SecretWebcash);

/// Pay the given amount. Returns the payment proof string.
#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct Pay {
    pub amount_wats: i64,
    pub memo: String,
}

#[derive(Message)]
#[rtype(result = "Result<Amount>")]
pub struct GetBalance;

#[derive(Message)]
#[rtype(result = "Result<Vec<SecretWebcash>>")]
pub struct ListUnspent;

#[derive(Message)]
#[rtype(result = "Result<WebcashWalletSnapshot>")]
pub struct ExportSnapshot;

/// Returns the snapshot if the wallet is dirty, `None` otherwise.
#[derive(Message)]
#[rtype(result = "Option<WebcashWalletSnapshot>")]
pub struct FlushIfDirty;

#[derive(Message)]
#[rtype(result = "()")]
pub struct MarkClean;

/// Drop the wallet instance and reset dirty flag.
#[derive(Message)]
#[rtype(result = "()")]
pub struct Invalidate;

// ── Handlers ────────────────────────────────────────────────────────────────

impl Handler<LoadWallet> for WebcashActor {
    type Result = Result<()>;
    fn handle(&mut self, msg: LoadWallet, _ctx: &mut SyncContext<Self>) -> Self::Result {
        let wallet = WebcashWallet::open_memory()
            .map_err(|e| Error::Other(anyhow::anyhow!("webcash open_memory: {e}")))?;
        if let Some(snap) = msg.snapshot {
            wallet
                .import_snapshot(&snap)
                .map_err(|e| Error::Other(anyhow::anyhow!("webcash import_snapshot: {e}")))?;
        }
        if let Some(ref secret) = msg.master_secret {
            self.rt
                .block_on(wallet.store_master_secret(secret))
                .map_err(|e| Error::Other(anyhow::anyhow!("webcash store_master_secret: {e}")))?;
        }
        self.wallet = Some(wallet);
        self.dirty = false;
        Ok(())
    }
}

impl Handler<InsertWebcash> for WebcashActor {
    type Result = Result<()>;
    fn handle(&mut self, msg: InsertWebcash, _ctx: &mut SyncContext<Self>) -> Self::Result {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or_else(|| Error::Other(anyhow::anyhow!("webcash wallet not loaded")))?;
        self.rt
            .block_on(wallet.insert(msg.0))
            .map_err(|e| Error::Other(anyhow::anyhow!("webcash insert: {e}")))?;
        self.dirty = true;
        Ok(())
    }
}

impl Handler<Pay> for WebcashActor {
    type Result = Result<String>;
    fn handle(&mut self, msg: Pay, _ctx: &mut SyncContext<Self>) -> Self::Result {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or_else(|| Error::Other(anyhow::anyhow!("webcash wallet not loaded")))?;
        let amount = Amount::from_wats(msg.amount_wats);
        let proof = self
            .rt
            .block_on(wallet.pay(amount, &msg.memo))
            .map_err(|e| Error::Other(anyhow::anyhow!("webcash pay: {e}")))?;
        self.dirty = true;
        Ok(proof)
    }
}

impl Handler<GetBalance> for WebcashActor {
    type Result = Result<Amount>;
    fn handle(&mut self, _: GetBalance, _ctx: &mut SyncContext<Self>) -> Self::Result {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or_else(|| Error::Other(anyhow::anyhow!("webcash wallet not loaded")))?;
        let balance = self
            .rt
            .block_on(wallet.balance_amount())
            .map_err(|e| Error::Other(anyhow::anyhow!("webcash balance: {e}")))?;
        Ok(balance)
    }
}

impl Handler<ListUnspent> for WebcashActor {
    type Result = Result<Vec<SecretWebcash>>;
    fn handle(&mut self, _: ListUnspent, _ctx: &mut SyncContext<Self>) -> Self::Result {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or_else(|| Error::Other(anyhow::anyhow!("webcash wallet not loaded")))?;
        let list = self
            .rt
            .block_on(wallet.list_webcash())
            .map_err(|e| Error::Other(anyhow::anyhow!("webcash list: {e}")))?;
        Ok(list)
    }
}

impl Handler<ExportSnapshot> for WebcashActor {
    type Result = Result<WebcashWalletSnapshot>;
    fn handle(&mut self, _: ExportSnapshot, _ctx: &mut SyncContext<Self>) -> Self::Result {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or_else(|| Error::Other(anyhow::anyhow!("webcash wallet not loaded")))?;
        wallet
            .export_snapshot()
            .map_err(|e| Error::Other(anyhow::anyhow!("webcash export_snapshot: {e}")))
    }
}

impl Handler<FlushIfDirty> for WebcashActor {
    type Result = Option<WebcashWalletSnapshot>;
    fn handle(&mut self, _: FlushIfDirty, _ctx: &mut SyncContext<Self>) -> Self::Result {
        if !self.dirty {
            return None;
        }
        self.wallet.as_ref().and_then(|w| w.export_snapshot().ok())
    }
}

impl Handler<MarkClean> for WebcashActor {
    type Result = ();
    fn handle(&mut self, _: MarkClean, _ctx: &mut SyncContext<Self>) -> Self::Result {
        self.dirty = false;
    }
}

impl Handler<Invalidate> for WebcashActor {
    type Result = ();
    fn handle(&mut self, _: Invalidate, _ctx: &mut SyncContext<Self>) -> Self::Result {
        self.wallet = None;
        self.dirty = false;
    }
}
