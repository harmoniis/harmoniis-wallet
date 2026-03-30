//! Actor wrapping [`DeterministicBitcoinWallet`] for thread-safe Bitcoin operations.
//!
//! The Bitcoin wallet uses blocking BDK operations (sync, send). This actor
//! owns the wallet and uses `SyncContext` for blocking I/O.

use actix::prelude::*;
use bdk_wallet::bitcoin::Txid;

use crate::error::Result;
use crate::wallet::bitcoin::{BitcoinAddressKind, BitcoinSyncSnapshot, DeterministicBitcoinWallet};

/// Actor that owns a [`DeterministicBitcoinWallet`].
///
/// All BDK operations (Esplora sync, signing, broadcast) run on the actor's
/// dedicated thread via `SyncContext`.
pub struct BitcoinActor {
    wallet: DeterministicBitcoinWallet,
}

impl BitcoinActor {
    pub fn new(wallet: DeterministicBitcoinWallet) -> Self {
        Self { wallet }
    }
}

impl Actor for BitcoinActor {
    type Context = SyncContext<Self>;
}

// ── Messages ────────────────────────────────────────────────────────────────

#[derive(Message)]
#[rtype(result = "Result<BitcoinSyncSnapshot>")]
pub struct SyncWallet {
    pub esplora_url: String,
    pub stop_gap: usize,
    pub parallel: usize,
}

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct ReceiveAddress {
    pub index: u32,
    pub kind: BitcoinAddressKind,
}

#[derive(Message)]
#[rtype(result = "Result<(String, String)>")]
pub struct DescriptorStrings {
    pub kind: BitcoinAddressKind,
}

#[derive(Message)]
#[rtype(result = "Result<Txid>")]
pub struct CreateSpend {
    pub dest: String,
    pub amount_sats: u64,
    pub fee_rate: u64,
    pub esplora_url: String,
    pub stop_gap: usize,
    pub parallel: usize,
}

// ── Handlers ────────────────────────────────────────────────────────────────

impl Handler<SyncWallet> for BitcoinActor {
    type Result = Result<BitcoinSyncSnapshot>;
    fn handle(&mut self, msg: SyncWallet, _ctx: &mut SyncContext<Self>) -> Self::Result {
        self.wallet.sync(&msg.esplora_url, msg.stop_gap, msg.parallel)
    }
}

impl Handler<ReceiveAddress> for BitcoinActor {
    type Result = Result<String>;
    fn handle(&mut self, msg: ReceiveAddress, _ctx: &mut SyncContext<Self>) -> Self::Result {
        self.wallet.receive_address_at_kind(msg.index, msg.kind)
    }
}

impl Handler<DescriptorStrings> for BitcoinActor {
    type Result = Result<(String, String)>;
    fn handle(&mut self, msg: DescriptorStrings, _ctx: &mut SyncContext<Self>) -> Self::Result {
        self.wallet.descriptor_strings_for(msg.kind)
    }
}

impl Handler<CreateSpend> for BitcoinActor {
    type Result = Result<Txid>;
    fn handle(&mut self, msg: CreateSpend, _ctx: &mut SyncContext<Self>) -> Self::Result {
        self.wallet.send_taproot_onchain(
            &msg.esplora_url,
            &msg.dest,
            msg.amount_sats,
            msg.fee_rate,
            msg.stop_gap,
            msg.parallel,
        )
    }
}
