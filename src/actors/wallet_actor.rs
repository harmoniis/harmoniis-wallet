//! Actor wrapping [`WalletCore`] for thread-safe access to the master wallet.

use actix::prelude::*;

use crate::error::Result;
use crate::identity::Identity;
use crate::types::{Certificate, Contract};
use crate::wallet::identities::PgpIdentityRecord;
use crate::wallet::labeled_wallets::LabeledWallet;
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

// -- Identity material --

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct GetFingerprint;

#[derive(Message)]
#[rtype(result = "Result<Identity>")]
pub struct GetIdentity;

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct RootPrivateKeyHex;

#[derive(Message)]
#[rtype(result = "Result<Identity>")]
pub struct RgbIdentity;

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct DeriveSlotHex {
    pub family: String,
    pub index: u32,
}

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct DeriveVaultMasterKeyHex;

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct DeriveHarmoniaVaultMasterKeyHex;

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct ExportMasterKeyHex;

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct ExportMasterKeyMnemonic;

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct ExportRecoveryMnemonic;

#[derive(Message)]
#[rtype(result = "Result<()>")]
pub struct ApplyMasterKeyHex(pub String);

#[derive(Message)]
#[rtype(result = "Result<()>")]
pub struct ApplyMasterKeyMnemonic(pub String);

#[derive(Message)]
#[rtype(result = "Result<bool>")]
pub struct HasLocalState;

// -- Vault identities --

#[derive(Message)]
#[rtype(result = "Result<Identity>")]
pub struct DeriveVaultIdentityForIndex {
    pub key_index: u32,
}

#[derive(Message)]
#[rtype(result = "Result<WalletSlotRecord>")]
pub struct EnsureVaultIdentityIndex {
    pub key_index: u32,
    pub label: Option<String>,
}

#[derive(Message)]
#[rtype(result = "Result<Vec<WalletSlotRecord>>")]
pub struct ListVaultIdentities;

#[derive(Message)]
#[rtype(result = "Result<WalletSlotRecord>")]
pub struct CreateVaultIdentity {
    pub label: Option<String>,
}

#[derive(Message)]
#[rtype(result = "Result<WalletSlotRecord>")]
pub struct VaultIdentityByLabel(pub String);

#[derive(Message)]
#[rtype(result = "Result<WalletSlotRecord>")]
pub struct VaultIdentityByIndex(pub u32);

// -- Wallet metadata --

#[derive(Message)]
#[rtype(result = "Result<Option<String>>")]
pub struct GetNickname;

#[derive(Message)]
#[rtype(result = "Result<()>")]
pub struct SetNickname(pub String);

#[derive(Message)]
#[rtype(result = "Result<Option<String>>")]
pub struct GetWalletLabel;

#[derive(Message)]
#[rtype(result = "Result<()>")]
pub struct SetWalletLabel(pub String);

#[derive(Message)]
#[rtype(result = "Result<Vec<WalletSlotRecord>>")]
pub struct ListWalletSlots {
    pub family: Option<String>,
}

// -- PGP identities --

#[derive(Message)]
#[rtype(result = "Result<(PgpIdentityRecord, Identity)>")]
pub struct GetActivePgpIdentity;

#[derive(Message)]
#[rtype(result = "Result<(PgpIdentityRecord, Identity)>")]
pub struct PgpIdentityByLabel(pub String);

#[derive(Message)]
#[rtype(result = "Result<Vec<PgpIdentityRecord>>")]
pub struct ListPgpIdentities;

#[derive(Message)]
#[rtype(result = "Result<PgpIdentityRecord>")]
pub struct CreatePgpIdentity(pub String);

#[derive(Message)]
#[rtype(result = "Result<PgpIdentityRecord>")]
pub struct EnsurePgpIdentityIndex {
    pub key_index: u32,
    pub label: Option<String>,
    pub set_active: bool,
}

#[derive(Message)]
#[rtype(result = "Result<()>")]
pub struct SetActivePgpIdentity(pub String);

#[derive(Message)]
#[rtype(result = "Result<()>")]
pub struct RenamePgpLabel {
    pub from: String,
    pub to: String,
}

// -- Contracts & certificates --

#[derive(Message)]
#[rtype(result = "Result<()>")]
pub struct StoreContract(pub Contract);

#[derive(Message)]
#[rtype(result = "Result<()>")]
pub struct UpdateContract(pub Contract);

#[derive(Message)]
#[rtype(result = "Result<Option<Contract>>")]
pub struct GetContract(pub String);

#[derive(Message)]
#[rtype(result = "Result<Vec<Contract>>")]
pub struct ListContracts;

#[derive(Message)]
#[rtype(result = "Result<()>")]
pub struct StoreCertificate(pub Certificate);

#[derive(Message)]
#[rtype(result = "Result<Vec<Certificate>>")]
pub struct ListCertificates;

// -- Snapshot --

#[derive(Message)]
#[rtype(result = "Result<WalletSnapshot>")]
pub struct ExportSnapshot;

#[derive(Message)]
#[rtype(result = "Result<()>")]
pub struct ImportSnapshot(pub WalletSnapshot);

// -- Derivation secrets --

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct DeriveWebcashMasterSecret;

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct DeriveBitcoinMasterKey;

#[derive(Message)]
#[rtype(result = "Result<String>")]
pub struct DeriveVoucherMasterSecret;

// -- Labeled wallets --

#[derive(Message)]
#[rtype(result = "Result<(String, u32)>")]
pub struct DeriveWebcashSecretForLabel(pub String);

#[derive(Message)]
#[rtype(result = "Result<(String, u32)>")]
pub struct DeriveBitcoinSecretForLabel(pub String);

#[derive(Message)]
#[rtype(result = "Result<(String, u32)>")]
pub struct DeriveVoucherSecretForLabel(pub String);

#[derive(Message)]
#[rtype(result = "Result<Vec<LabeledWallet>>")]
pub struct ListLabeledWallets(pub String);

// ── Handlers ────────────────────────────────────────────────────────────────

// -- Identity material --

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

impl Handler<RootPrivateKeyHex> for WalletActor {
    type Result = Result<String>;
    fn handle(&mut self, _: RootPrivateKeyHex, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.root_private_key_hex()
    }
}

impl Handler<RgbIdentity> for WalletActor {
    type Result = Result<Identity>;
    fn handle(&mut self, _: RgbIdentity, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.rgb_identity()
    }
}

impl Handler<DeriveSlotHex> for WalletActor {
    type Result = Result<String>;
    fn handle(&mut self, msg: DeriveSlotHex, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.derive_slot_hex(&msg.family, msg.index)
    }
}

impl Handler<DeriveVaultMasterKeyHex> for WalletActor {
    type Result = Result<String>;
    fn handle(&mut self, _: DeriveVaultMasterKeyHex, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.derive_vault_master_key_hex()
    }
}

impl Handler<DeriveHarmoniaVaultMasterKeyHex> for WalletActor {
    type Result = Result<String>;
    fn handle(
        &mut self,
        _: DeriveHarmoniaVaultMasterKeyHex,
        _ctx: &mut Context<Self>,
    ) -> Self::Result {
        self.wallet.derive_harmonia_vault_master_key_hex()
    }
}

impl Handler<ExportMasterKeyHex> for WalletActor {
    type Result = Result<String>;
    fn handle(&mut self, _: ExportMasterKeyHex, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.export_master_key_hex()
    }
}

impl Handler<ExportMasterKeyMnemonic> for WalletActor {
    type Result = Result<String>;
    fn handle(&mut self, _: ExportMasterKeyMnemonic, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.export_master_key_mnemonic()
    }
}

impl Handler<ExportRecoveryMnemonic> for WalletActor {
    type Result = Result<String>;
    fn handle(&mut self, _: ExportRecoveryMnemonic, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.export_recovery_mnemonic()
    }
}

impl Handler<ApplyMasterKeyHex> for WalletActor {
    type Result = Result<()>;
    fn handle(&mut self, msg: ApplyMasterKeyHex, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.apply_master_key_hex(&msg.0)
    }
}

impl Handler<ApplyMasterKeyMnemonic> for WalletActor {
    type Result = Result<()>;
    fn handle(&mut self, msg: ApplyMasterKeyMnemonic, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.apply_master_key_mnemonic(&msg.0)
    }
}

impl Handler<HasLocalState> for WalletActor {
    type Result = Result<bool>;
    fn handle(&mut self, _: HasLocalState, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.has_local_state()
    }
}

// -- Vault identities --

impl Handler<DeriveVaultIdentityForIndex> for WalletActor {
    type Result = Result<Identity>;
    fn handle(
        &mut self,
        msg: DeriveVaultIdentityForIndex,
        _ctx: &mut Context<Self>,
    ) -> Self::Result {
        self.wallet.derive_vault_identity_for_index(msg.key_index)
    }
}

impl Handler<EnsureVaultIdentityIndex> for WalletActor {
    type Result = Result<WalletSlotRecord>;
    fn handle(&mut self, msg: EnsureVaultIdentityIndex, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet
            .ensure_vault_identity_index(msg.key_index, msg.label.as_deref())
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

impl Handler<VaultIdentityByLabel> for WalletActor {
    type Result = Result<WalletSlotRecord>;
    fn handle(&mut self, msg: VaultIdentityByLabel, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.vault_identity_by_label(&msg.0)
    }
}

impl Handler<VaultIdentityByIndex> for WalletActor {
    type Result = Result<WalletSlotRecord>;
    fn handle(&mut self, msg: VaultIdentityByIndex, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.vault_identity_by_index(msg.0)
    }
}

// -- Wallet metadata --

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

impl Handler<GetWalletLabel> for WalletActor {
    type Result = Result<Option<String>>;
    fn handle(&mut self, _: GetWalletLabel, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.wallet_label()
    }
}

impl Handler<SetWalletLabel> for WalletActor {
    type Result = Result<()>;
    fn handle(&mut self, msg: SetWalletLabel, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.set_wallet_label(&msg.0)
    }
}

impl Handler<ListWalletSlots> for WalletActor {
    type Result = Result<Vec<WalletSlotRecord>>;
    fn handle(&mut self, msg: ListWalletSlots, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.list_wallet_slots(msg.family.as_deref())
    }
}

// -- PGP identities --

impl Handler<GetActivePgpIdentity> for WalletActor {
    type Result = Result<(PgpIdentityRecord, Identity)>;
    fn handle(&mut self, _: GetActivePgpIdentity, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.active_pgp_identity()
    }
}

impl Handler<PgpIdentityByLabel> for WalletActor {
    type Result = Result<(PgpIdentityRecord, Identity)>;
    fn handle(&mut self, msg: PgpIdentityByLabel, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.pgp_identity_by_label(&msg.0)
    }
}

impl Handler<ListPgpIdentities> for WalletActor {
    type Result = Result<Vec<PgpIdentityRecord>>;
    fn handle(&mut self, _: ListPgpIdentities, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.list_pgp_identities()
    }
}

impl Handler<CreatePgpIdentity> for WalletActor {
    type Result = Result<PgpIdentityRecord>;
    fn handle(&mut self, msg: CreatePgpIdentity, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.create_pgp_identity(&msg.0)
    }
}

impl Handler<EnsurePgpIdentityIndex> for WalletActor {
    type Result = Result<PgpIdentityRecord>;
    fn handle(&mut self, msg: EnsurePgpIdentityIndex, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet
            .ensure_pgp_identity_index(msg.key_index, msg.label.as_deref(), msg.set_active)
    }
}

impl Handler<SetActivePgpIdentity> for WalletActor {
    type Result = Result<()>;
    fn handle(&mut self, msg: SetActivePgpIdentity, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.set_active_pgp_identity(&msg.0)
    }
}

impl Handler<RenamePgpLabel> for WalletActor {
    type Result = Result<()>;
    fn handle(&mut self, msg: RenamePgpLabel, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.rename_pgp_label(&msg.from, &msg.to)
    }
}

// -- Contracts & certificates --

impl Handler<StoreContract> for WalletActor {
    type Result = Result<()>;
    fn handle(&mut self, msg: StoreContract, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.store_contract(&msg.0)
    }
}

impl Handler<UpdateContract> for WalletActor {
    type Result = Result<()>;
    fn handle(&mut self, msg: UpdateContract, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.update_contract(&msg.0)
    }
}

impl Handler<GetContract> for WalletActor {
    type Result = Result<Option<Contract>>;
    fn handle(&mut self, msg: GetContract, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.get_contract(&msg.0)
    }
}

impl Handler<ListContracts> for WalletActor {
    type Result = Result<Vec<Contract>>;
    fn handle(&mut self, _: ListContracts, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.list_contracts()
    }
}

impl Handler<StoreCertificate> for WalletActor {
    type Result = Result<()>;
    fn handle(&mut self, msg: StoreCertificate, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.store_certificate(&msg.0)
    }
}

impl Handler<ListCertificates> for WalletActor {
    type Result = Result<Vec<Certificate>>;
    fn handle(&mut self, _: ListCertificates, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.list_certificates()
    }
}

// -- Snapshot --

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

// -- Derivation secrets --

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

// -- Labeled wallets --

impl Handler<DeriveWebcashSecretForLabel> for WalletActor {
    type Result = Result<(String, u32)>;
    fn handle(
        &mut self,
        msg: DeriveWebcashSecretForLabel,
        _ctx: &mut Context<Self>,
    ) -> Self::Result {
        self.wallet.derive_webcash_secret_for_label(&msg.0)
    }
}

impl Handler<DeriveBitcoinSecretForLabel> for WalletActor {
    type Result = Result<(String, u32)>;
    fn handle(
        &mut self,
        msg: DeriveBitcoinSecretForLabel,
        _ctx: &mut Context<Self>,
    ) -> Self::Result {
        self.wallet.derive_bitcoin_secret_for_label(&msg.0)
    }
}

impl Handler<DeriveVoucherSecretForLabel> for WalletActor {
    type Result = Result<(String, u32)>;
    fn handle(
        &mut self,
        msg: DeriveVoucherSecretForLabel,
        _ctx: &mut Context<Self>,
    ) -> Self::Result {
        self.wallet.derive_voucher_secret_for_label(&msg.0)
    }
}

impl Handler<ListLabeledWallets> for WalletActor {
    type Result = Result<Vec<LabeledWallet>>;
    fn handle(&mut self, msg: ListLabeledWallets, _ctx: &mut Context<Self>) -> Self::Result {
        self.wallet.list_labeled_wallets(&msg.0)
    }
}
