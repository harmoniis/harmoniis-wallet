//! Actor wrapping [`WalletCore`] for thread-safe access to the master wallet.

use actix::prelude::*;

use crate::error::Result;
use crate::identity::Identity;
use crate::wallet::identities::PgpIdentityRecord;
use crate::wallet::snapshots::WalletSnapshot;
use crate::wallet::{WalletCore, WalletSlotRecord};

/// Actor that owns a [`WalletCore`] instance.
///
/// All SQLite operations run on the actor's thread, avoiding `!Send` issues.
pub struct WalletActor {
    wallet: WalletCore,
}

impl WalletActor {
    pub fn new(wallet: WalletCore) -> Self {
        Self { wallet }
    }
}

impl Actor for WalletActor {
    type Context = Context<Self>;
}

// ── Messages ────────────────────────────────────────────────────────────────

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct GetFingerprint;

#[derive(Message)]
#[rtype(result = "Result<Identity>")]
pub struct GetIdentity;

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct DeriveSlotHex {
    pub family: String,
    pub index: u32,
}

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct ExportRecoveryMnemonic;

#[derive(Message)]
#[rtype(result = "Result<WalletSnapshot>")]
pub struct ExportSnapshot;

#[derive(Message)]
#[rtype(result = "Result<()>")]
pub struct ImportSnapshot(pub WalletSnapshot);

#[derive(Message)]
#[rtype(result = "Result<(PgpIdentityRecord, Identity)>")]
pub struct GetActivePgpIdentity;

#[derive(Message)]
#[rtype(result = "Result<Vec<WalletSlotRecord>>")]
pub struct ListVaultIdentities;

#[derive(Message)]
#[rtype(result = "Result<WalletSlotRecord>")]
pub struct CreateVaultIdentity {
    pub label: Option<String>,
}

#[derive(Message)]
#[rtype(result = "Result<Option<String>>")]
pub struct GetNickname;

#[derive(Message)]
#[rtype(result = "Result<()>")]
pub struct SetNickname(pub String);

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct DeriveWebcashMasterSecret;

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct DeriveBitcoinMasterKey;

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct DeriveVoucherMasterSecret;

// ── Handlers ────────────────────────────────────────────────────────────────

impl Handler<GetFingerprint> for WalletActor {
    type Result = Result<String>;
    fn handle(&mut self, _: GetFingerprint, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.fingerprint()
    }
}

impl Handler<GetIdentity> for WalletActor {
    type Result = Result<Identity>;
    fn handle(&mut self, _: GetIdentity, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.identity()
    }
}

impl Handler<DeriveSlotHex> for WalletActor {
    type Result = Result<String>;
    fn handle(&mut self, msg: DeriveSlotHex, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.derive_slot_hex(&msg.family, msg.index)
    }
}

impl Handler<ExportRecoveryMnemonic> for WalletActor {
    type Result = Result<String>;
    fn handle(&mut self, _: ExportRecoveryMnemonic, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.export_recovery_mnemonic()
    }
}

impl Handler<ExportSnapshot> for WalletActor {
    type Result = Result<WalletSnapshot>;
    fn handle(&mut self, _: ExportSnapshot, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.export_snapshot()
    }
}

impl Handler<ImportSnapshot> for WalletActor {
    type Result = Result<()>;
    fn handle(&mut self, msg: ImportSnapshot, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.import_snapshot(&msg.0)
    }
}

impl Handler<GetActivePgpIdentity> for WalletActor {
    type Result = Result<(PgpIdentityRecord, Identity)>;
    fn handle(&mut self, _: GetActivePgpIdentity, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.active_pgp_identity()
    }
}

impl Handler<ListVaultIdentities> for WalletActor {
    type Result = Result<Vec<WalletSlotRecord>>;
    fn handle(&mut self, _: ListVaultIdentities, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.list_vault_identities()
    }
}

impl Handler<CreateVaultIdentity> for WalletActor {
    type Result = Result<WalletSlotRecord>;
    fn handle(&mut self, msg: CreateVaultIdentity, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.create_vault_identity(msg.label.as_deref())
    }
}

impl Handler<GetNickname> for WalletActor {
    type Result = Result<Option<String>>;
    fn handle(&mut self, _: GetNickname, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.nickname()
    }
}

impl Handler<SetNickname> for WalletActor {
    type Result = Result<()>;
    fn handle(&mut self, msg: SetNickname, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.set_nickname(&msg.0)
    }
}

impl Handler<DeriveWebcashMasterSecret> for WalletActor {
    type Result = Result<String>;
    fn handle(&mut self, _: DeriveWebcashMasterSecret, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.derive_webcash_master_secret_hex()
    }
}

impl Handler<DeriveBitcoinMasterKey> for WalletActor {
    type Result = Result<String>;
    fn handle(&mut self, _: DeriveBitcoinMasterKey, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.derive_bitcoin_master_key_hex()
    }
}

impl Handler<DeriveVoucherMasterSecret> for WalletActor {
    type Result = Result<String>;
    fn handle(&mut self, _: DeriveVoucherMasterSecret, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.derive_voucher_master_secret_hex()
    }
}
