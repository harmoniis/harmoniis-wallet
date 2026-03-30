//! Actor wrapping the webcash wallet snapshot management.
//!
//! The webcash wallet (from webylib) uses async methods for most operations.
//! This actor manages wallet snapshot state for the backend's persistence layer.
//! Insert/pay operations go through the snapshot import/export cycle since
//! the actual wallet lives in the consumer's async runtime.

use actix::prelude::*;

use crate::wallet::webcash::WebcashWalletSnapshot;

/// Actor managing webcash wallet snapshot state.
///
/// The consumer (backend) loads/saves snapshots to S3. This actor tracks
/// the current snapshot and dirty state for debounced persistence.
pub struct WebcashActor {
    snapshot: Option<WebcashWalletSnapshot>,
    dirty: bool,
}

impl WebcashActor {
    pub fn new(snapshot: Option<WebcashWalletSnapshot>) -> Self {
        Self {
            snapshot,
            dirty: false,
        }
    }
}

impl Actor for WebcashActor {
    type Context = Context<Self>;
}

// ── Messages ────────────────────────────────────────────────────────────────

#[derive(Message)]
#[rtype(result = "bool")]
pub struct HasSnapshot;

#[derive(Message)]
#[rtype(result = "()")]
pub struct SetSnapshot(pub WebcashWalletSnapshot);

#[derive(Message)]
#[rtype(result = "bool")]
pub struct IsDirty;

#[derive(Message)]
#[rtype(result = "()")]
pub struct MarkClean;

// ── Handlers ────────────────────────────────────────────────────────────────

impl Handler<HasSnapshot> for WebcashActor {
    type Result = bool;
    fn handle(&mut self, _: HasSnapshot, _ctx: &mut Context<Self>) -> Self::Result {
        self.snapshot.is_some()
    }
}

impl Handler<SetSnapshot> for WebcashActor {
    type Result = ();
    fn handle(&mut self, msg: SetSnapshot, _ctx: &mut Context<Self>) -> Self::Result {
        self.snapshot = Some(msg.0);
        self.dirty = true;
    }
}

impl Handler<IsDirty> for WebcashActor {
    type Result = bool;
    fn handle(&mut self, _: IsDirty, _ctx: &mut Context<Self>) -> Self::Result {
        self.dirty
    }
}

impl Handler<MarkClean> for WebcashActor {
    type Result = ();
    fn handle(&mut self, _: MarkClean, _ctx: &mut Context<Self>) -> Self::Result {
        self.dirty = false;
    }
}
