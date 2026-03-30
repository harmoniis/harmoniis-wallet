//! Actor wrapping [`VoucherWallet`] for thread-safe voucher operations.
//!
//! The voucher wallet uses SQLite internally (via `Mutex<Connection>`). Most
//! operations are synchronous. This actor owns the wallet and uses
//! `Context<Self>` for sync-only operations.

use actix::prelude::*;

use crate::error::Result;
use crate::types::VoucherSecret;
use crate::wallet::voucher::{VoucherStats, VoucherWallet};

/// Actor that owns a [`VoucherWallet`].
///
/// All SQLite operations run on the actor's thread, avoiding contention on
/// the wallet's internal mutex.
pub struct VoucherActor {
    wallet: VoucherWallet,
}

impl VoucherActor {
    pub fn new(wallet: VoucherWallet) -> Self {
        Self { wallet }
    }
}

impl Actor for VoucherActor {
    type Context = Context<Self>;
}

// ── Messages ────────────────────────────────────────────────────────────────

#[derive(Message)]
#[rtype(result = "Result<()>")]
pub struct Insert(pub VoucherSecret);

#[derive(Message)]
#[rtype(result = "Result<u64>")]
pub struct Balance;

#[derive(Message)]
#[rtype(result = "Result<VoucherStats>")]
pub struct Stats;

#[derive(Message)]
#[rtype(result = "Result<Vec<VoucherSecret>>")]
pub struct ListLiveOutputs;

#[derive(Message)]
#[rtype(result = "Result<()>")]
pub struct StoreMasterSecret(pub String);

// ── Handlers ────────────────────────────────────────────────────────────────

impl Handler<Insert> for VoucherActor {
    type Result = Result<()>;
    fn handle(&mut self, msg: Insert, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.insert(msg.0)
    }
}

impl Handler<Balance> for VoucherActor {
    type Result = Result<u64>;
    fn handle(&mut self, _: Balance, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.balance()
    }
}

impl Handler<Stats> for VoucherActor {
    type Result = Result<VoucherStats>;
    fn handle(&mut self, _: Stats, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.stats()
    }
}

impl Handler<ListLiveOutputs> for VoucherActor {
    type Result = Result<Vec<VoucherSecret>>;
    fn handle(&mut self, _: ListLiveOutputs, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.list_live_outputs()
    }
}

impl Handler<StoreMasterSecret> for VoucherActor {
    type Result = Result<()>;
    fn handle(&mut self, msg: StoreMasterSecret, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.store_master_secret(&msg.0)
    }
}
