//! Actor wrapping [`ArkPaymentWallet`] for thread-safe ARK offchain payments.
//!
//! The ARK wallet uses async methods for connect, balance, send, and settle.
//! This actor owns the wallet and a tokio runtime handle, using `SyncContext`
//! so handlers can call `rt.block_on(...)` for async operations.

use actix::prelude::*;

use crate::error::{Error, Result};
use crate::wallet::ark::{ArkBalance, ArkPaymentResult, ArkPaymentWallet, SqliteArkDb};
use crate::wallet::bitcoin::DeterministicBitcoinWallet;

/// Actor that owns an [`ArkPaymentWallet`].
///
/// Uses `SyncContext` so handlers can block on async ARK client operations.
pub struct ArkActor {
    wallet: Option<ArkPaymentWallet>,
    rt: tokio::runtime::Handle,
}

impl ArkActor {
    pub fn new(rt: tokio::runtime::Handle) -> Self {
        Self { wallet: None, rt }
    }
}

impl Actor for ArkActor {
    type Context = SyncContext<Self>;
}

// ── Messages ────────────────────────────────────────────────────────────────

#[derive(Message)]
#[rtype(result = "Result<()>")]
pub struct Connect {
    pub btc_wallet: DeterministicBitcoinWallet,
    pub asp_url: String,
    pub db: SqliteArkDb,
}

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct GetOffchainAddress;

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct GetBoardingAddress;

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct GetOnchainAddress;

#[derive(Message)]
#[rtype(result = "Result<ArkPaymentResult>")]
pub struct SendPayment {
    pub address: String,
    pub amount_sats: u64,
}

#[derive(Message)]
#[rtype(result = "Result<ArkBalance>")]
pub struct GetBalance;

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct SendOnchain {
    pub address: String,
    pub amount_sats: u64,
}

#[derive(Message)]
#[rtype(result = "Result<Option<String>>")]
pub struct Settle;

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct PayHarmoniis {
    pub ark_address: String,
    pub amount_sats: u64,
}

// ── Handlers ────────────────────────────────────────────────────────────────

impl Handler<Connect> for ArkActor {
    type Result = Result<()>;
    fn handle(&mut self, msg: Connect, _ctx: &mut SyncContext<Self>) -> Self::Result {
        let wallet = self
            .rt
            .block_on(ArkPaymentWallet::connect(&msg.btc_wallet, &msg.asp_url, msg.db))?;
        self.wallet = Some(wallet);
        Ok(())
    }
}

impl Handler<GetOffchainAddress> for ArkActor {
    type Result = Result<String>;
    fn handle(&mut self, _: GetOffchainAddress, _ctx: &mut SyncContext<Self>) -> Self::Result {
        self.wallet
            .as_ref()
            .ok_or_else(|| Error::Other(anyhow::anyhow!("ARK wallet not connected")))?
            .get_offchain_address()
    }
}

impl Handler<GetBoardingAddress> for ArkActor {
    type Result = Result<String>;
    fn handle(&mut self, _: GetBoardingAddress, _ctx: &mut SyncContext<Self>) -> Self::Result {
        self.wallet
            .as_ref()
            .ok_or_else(|| Error::Other(anyhow::anyhow!("ARK wallet not connected")))?
            .get_boarding_address()
    }
}

impl Handler<GetOnchainAddress> for ArkActor {
    type Result = Result<String>;
    fn handle(&mut self, _: GetOnchainAddress, _ctx: &mut SyncContext<Self>) -> Self::Result {
        self.wallet
            .as_ref()
            .ok_or_else(|| Error::Other(anyhow::anyhow!("ARK wallet not connected")))?
            .get_onchain_address()
    }
}

impl Handler<SendPayment> for ArkActor {
    type Result = Result<ArkPaymentResult>;
    fn handle(&mut self, msg: SendPayment, _ctx: &mut SyncContext<Self>) -> Self::Result {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or_else(|| Error::Other(anyhow::anyhow!("ARK wallet not connected")))?;
        self.rt
            .block_on(wallet.send_payment(&msg.address, msg.amount_sats))
    }
}

impl Handler<GetBalance> for ArkActor {
    type Result = Result<ArkBalance>;
    fn handle(&mut self, _: GetBalance, _ctx: &mut SyncContext<Self>) -> Self::Result {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or_else(|| Error::Other(anyhow::anyhow!("ARK wallet not connected")))?;
        self.rt.block_on(wallet.offchain_balance())
    }
}

impl Handler<SendOnchain> for ArkActor {
    type Result = Result<String>;
    fn handle(&mut self, msg: SendOnchain, _ctx: &mut SyncContext<Self>) -> Self::Result {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or_else(|| Error::Other(anyhow::anyhow!("ARK wallet not connected")))?;
        self.rt
            .block_on(wallet.send_onchain(&msg.address, msg.amount_sats))
    }
}

impl Handler<Settle> for ArkActor {
    type Result = Result<Option<String>>;
    fn handle(&mut self, _: Settle, _ctx: &mut SyncContext<Self>) -> Self::Result {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or_else(|| Error::Other(anyhow::anyhow!("ARK wallet not connected")))?;
        self.rt.block_on(wallet.settle())
    }
}

impl Handler<PayHarmoniis> for ArkActor {
    type Result = Result<String>;
    fn handle(&mut self, msg: PayHarmoniis, _ctx: &mut SyncContext<Self>) -> Self::Result {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or_else(|| Error::Other(anyhow::anyhow!("ARK wallet not connected")))?;
        self.rt
            .block_on(wallet.pay_harmoniis(&msg.ark_address, msg.amount_sats))
    }
}
