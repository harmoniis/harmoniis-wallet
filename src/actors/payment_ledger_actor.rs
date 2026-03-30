//! Actor wrapping the payment audit ledger.

use actix::prelude::*;

use crate::error::Result;
use crate::wallet::payments::{
    NewPaymentAttempt, NewPaymentTransaction, NewPaymentTransactionEvent, PaymentAttemptUpdate,
    PaymentTransactionRecord, PaymentTransactionUpdate,
};
use crate::wallet::WalletCore;

/// Actor for recording payment transactions and audit events.
///
/// Wraps the payment ledger methods on [`WalletCore`], providing
/// thread-safe access via message passing.
pub struct PaymentLedgerActor {
    wallet: WalletCore,
}

impl PaymentLedgerActor {
    pub fn new(wallet: WalletCore) -> Self {
        Self { wallet }
    }
}

impl Actor for PaymentLedgerActor {
    type Context = Context<Self>;
}

// ── Messages ──────────────��─────────────────────────────────────────────────

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct RecordAttempt(pub NewPaymentAttempt<'static>);

#[derive(Message)]
#[rtype(result = "Result<()>")]
pub struct UpdateAttempt {
    pub attempt_id: String,
    pub update: PaymentAttemptUpdate<'static>,
}

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct RecordTransaction(pub NewPaymentTransaction<'static>);

#[derive(Message)]
#[rtype(result = "Result<()>")]
pub struct UpdateTransaction {
    pub txn_id: String,
    pub update: PaymentTransactionUpdate<'static>,
}

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct AppendEvent(pub NewPaymentTransactionEvent<'static>);

#[derive(Message)]
#[rtype(result = "Result<Vec<PaymentTransactionRecord>>")]
pub struct ListTransactions;

// ── Handlers ───────���────────────────────────────────────────────────────────

impl Handler<RecordAttempt> for PaymentLedgerActor {
    type Result = Result<String>;
    fn handle(&mut self, msg: RecordAttempt, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.record_payment_attempt_start(&msg.0)
    }
}

impl Handler<UpdateAttempt> for PaymentLedgerActor {
    type Result = Result<()>;
    fn handle(&mut self, msg: UpdateAttempt, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet
            .update_payment_attempt(&msg.attempt_id, &msg.update)
    }
}

impl Handler<RecordTransaction> for PaymentLedgerActor {
    type Result = Result<String>;
    fn handle(&mut self, msg: RecordTransaction, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.record_payment_transaction(&msg.0)
    }
}

impl Handler<UpdateTransaction> for PaymentLedgerActor {
    type Result = Result<()>;
    fn handle(&mut self, msg: UpdateTransaction, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet
            .update_payment_transaction(&msg.txn_id, &msg.update)
    }
}

impl Handler<AppendEvent> for PaymentLedgerActor {
    type Result = Result<String>;
    fn handle(&mut self, msg: AppendEvent, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.append_payment_transaction_event(&msg.0)
    }
}

impl Handler<ListTransactions> for PaymentLedgerActor {
    type Result = Result<Vec<PaymentTransactionRecord>>;
    fn handle(&mut self, _: ListTransactions, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.list_payment_transactions()
    }
}
