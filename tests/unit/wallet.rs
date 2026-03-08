use harmoniis_wallet::{
    types::{Contract, ContractStatus, ContractType, Role},
    wallet::RgbWallet,
    Identity,
};

fn make_contract(id: &str) -> Contract {
    let now = chrono::Utc::now().to_rfc3339();
    Contract {
        contract_id: id.to_string(),
        contract_type: ContractType::Service,
        status: ContractStatus::Issued,
        witness_secret: Some(format!("n:{id}:secret:{}", "ab".repeat(32))),
        witness_proof: Some(format!("n:{id}:public:{}", "cd".repeat(32))),
        amount_units: 100_000_000,
        work_spec: "Write unit tests".to_string(),
        buyer_fingerprint: "aa".repeat(32),
        seller_fingerprint: Some("bb".repeat(32)),
        reference_post: Some("POST_xyz".to_string()),
        delivery_deadline: Some("2026-12-31T00:00:00Z".to_string()),
        role: Role::Buyer,
        delivered_text: None,
        certificate_id: None,
        created_at: now.clone(),
        updated_at: now,
    }
}

#[test]
fn open_memory_wallet_ok() {
    let wallet = RgbWallet::open_memory().expect("in-memory wallet should open");
    let fp = wallet.fingerprint().expect("fingerprint");
    assert_eq!(fp.len(), 64, "fingerprint must be 64-char hex");
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn identity_roundtrip() {
    let wallet = RgbWallet::open_memory().unwrap();
    let id1 = wallet.identity().unwrap();
    let priv_hex = id1.private_key_hex();

    // Restore from hex
    let id2 = Identity::from_hex(&priv_hex).unwrap();
    assert_eq!(id1.fingerprint(), id2.fingerprint());
    assert_eq!(id1.public_key_hex(), id2.public_key_hex());
}

#[test]
fn root_derives_distinct_rgb_and_webcash_material() {
    let wallet = RgbWallet::open_memory().unwrap();
    let root = wallet.root_private_key_hex().unwrap();
    let rgb = wallet.rgb_identity().unwrap().private_key_hex();
    let webcash = wallet.derive_webcash_master_secret_hex().unwrap();
    assert_ne!(root, rgb, "RGB key must be derived and distinct from root");
    assert_ne!(root, webcash, "Webcash master must be distinct from root");
    assert_ne!(rgb, webcash, "Webcash master must be distinct from RGB key");
}

#[test]
fn pgp_identities_are_labeled_and_switchable() {
    let wallet = RgbWallet::open_memory().unwrap();
    let initial = wallet.list_pgp_identities().unwrap();
    assert_eq!(
        initial.len(),
        1,
        "wallet should create one default PGP identity"
    );
    assert!(initial[0].is_active);

    let created = wallet.create_pgp_identity("alice-signing").unwrap();
    assert_eq!(created.label, "alice-signing");
    wallet.set_active_pgp_identity("alice-signing").unwrap();

    let (active_meta, active_id) = wallet.active_pgp_identity().unwrap();
    assert_eq!(active_meta.label, "alice-signing");
    assert_eq!(active_meta.public_key_hex, active_id.public_key_hex());
    assert_ne!(
        active_id.public_key_hex(),
        wallet.rgb_identity().unwrap().public_key_hex(),
        "PGP key should be separate from RGB identity key"
    );
}

#[test]
fn master_key_export_import_roundtrip_hex_and_mnemonic() {
    let wallet = RgbWallet::open_memory().unwrap();
    let root_hex = wallet.export_master_key_hex().unwrap();
    let mnemonic = wallet.export_master_key_mnemonic().unwrap();
    assert!(!mnemonic.trim().is_empty());

    let in_memory_wallet_hex_restored = RgbWallet::open_memory().unwrap();
    in_memory_wallet_hex_restored
        .apply_master_key_hex(&root_hex)
        .unwrap();
    assert_eq!(
        in_memory_wallet_hex_restored
            .export_master_key_hex()
            .unwrap(),
        root_hex
    );

    let in_memory_wallet_mnemonic_restored = RgbWallet::open_memory().unwrap();
    in_memory_wallet_mnemonic_restored
        .apply_master_key_mnemonic(&mnemonic)
        .unwrap();
    assert_eq!(
        in_memory_wallet_mnemonic_restored
            .export_master_key_hex()
            .unwrap(),
        root_hex,
        "24-word mnemonic export/import must be lossless"
    );
}

#[test]
fn deterministic_slot_derivation_is_stable() {
    let wallet = RgbWallet::open_memory().unwrap();
    let root = wallet.derive_slot_hex("root", 0).unwrap();
    let rgb = wallet.derive_slot_hex("rgb", 0).unwrap();
    let webcash = wallet.derive_slot_hex("webcash", 0).unwrap();
    let bitcoin = wallet.derive_slot_hex("bitcoin", 0).unwrap();
    let pgp_0 = wallet.derive_slot_hex("pgp", 0).unwrap();
    let pgp_1 = wallet.derive_slot_hex("pgp", 1).unwrap();

    assert_eq!(root.len(), 64);
    assert_eq!(rgb.len(), 64);
    assert_eq!(webcash.len(), 64);
    assert_eq!(bitcoin.len(), 64);
    assert_eq!(pgp_0.len(), 64);
    assert_eq!(pgp_1.len(), 64);
    assert_ne!(pgp_0, pgp_1);
}

#[test]
fn mnemonic_roundtrip_preserves_all_slot_derivations() {
    let wallet = RgbWallet::open_memory().unwrap();
    let mnemonic = wallet.export_recovery_mnemonic().unwrap();
    let root_0 = wallet.derive_slot_hex("root", 0).unwrap();
    let rgb_0 = wallet.derive_slot_hex("rgb", 0).unwrap();
    let webcash_0 = wallet.derive_slot_hex("webcash", 0).unwrap();
    let bitcoin_0 = wallet.derive_slot_hex("bitcoin", 0).unwrap();
    let pgp_7 = wallet.derive_slot_hex("pgp", 7).unwrap();

    let in_memory_wallet_restored = RgbWallet::open_memory().unwrap();
    in_memory_wallet_restored
        .apply_master_key_mnemonic(&mnemonic)
        .unwrap();

    assert_eq!(
        in_memory_wallet_restored
            .derive_slot_hex("root", 0)
            .unwrap(),
        root_0
    );
    assert_eq!(
        in_memory_wallet_restored.derive_slot_hex("rgb", 0).unwrap(),
        rgb_0
    );
    assert_eq!(
        in_memory_wallet_restored
            .derive_slot_hex("webcash", 0)
            .unwrap(),
        webcash_0
    );
    assert_eq!(
        in_memory_wallet_restored
            .derive_slot_hex("bitcoin", 0)
            .unwrap(),
        bitcoin_0
    );
    assert_eq!(
        in_memory_wallet_restored.derive_slot_hex("pgp", 7).unwrap(),
        pgp_7
    );
}

#[test]
fn known_bip39_mnemonic_derives_expected_wallet_slots() {
    let wallet = RgbWallet::open_memory().unwrap();
    wallet
        .apply_master_key_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
    // 12-word BIP39 entropy for the well-known test phrase.
    assert_eq!(
        wallet.export_master_key_hex().unwrap(),
        "00000000000000000000000000000000"
    );
    assert_eq!(
        wallet.derive_slot_hex("rgb", 0).unwrap(),
        "cb263f34c16122d362cd1fd2732b7fa62943439b60dfc63f603d17595fdbc92e"
    );
    assert_eq!(
        wallet.derive_slot_hex("bitcoin", 0).unwrap(),
        "f8bbbf1e2223f17a99da8b823d4cd41b764c69133385ad5b1195885ec34a191b"
    );
}

#[test]
fn store_and_load_contract() {
    let wallet = RgbWallet::open_memory().unwrap();
    let c = make_contract("CTR_test001");
    wallet.store_contract(&c).unwrap();

    let loaded = wallet.get_contract("CTR_test001").unwrap().unwrap();
    assert_eq!(loaded.contract_id, "CTR_test001");
    assert_eq!(loaded.amount_units, 100_000_000);
    assert!(matches!(loaded.status, ContractStatus::Issued));
    assert!(matches!(loaded.role, Role::Buyer));
    assert_eq!(loaded.witness_secret, c.witness_secret);
    assert_eq!(loaded.witness_proof, c.witness_proof);
}

#[test]
fn update_contract_status() {
    let wallet = RgbWallet::open_memory().unwrap();
    let c = make_contract("CTR_upd001");
    wallet.store_contract(&c).unwrap();

    let mut updated = wallet.get_contract("CTR_upd001").unwrap().unwrap();
    updated.status = ContractStatus::Active;
    wallet.update_contract(&updated).unwrap();

    let reloaded = wallet.get_contract("CTR_upd001").unwrap().unwrap();
    assert!(matches!(reloaded.status, ContractStatus::Active));
}

#[test]
fn list_contracts_returns_all() {
    let wallet = RgbWallet::open_memory().unwrap();
    wallet.store_contract(&make_contract("CTR_a")).unwrap();
    wallet.store_contract(&make_contract("CTR_b")).unwrap();
    wallet.store_contract(&make_contract("CTR_c")).unwrap();

    let list = wallet.list_contracts().unwrap();
    assert_eq!(list.len(), 3);
}

#[test]
fn rgb_state_is_not_partitioned_by_active_pgp_identity() {
    let wallet = RgbWallet::open_memory().unwrap();
    wallet
        .store_contract(&make_contract("CTR_shared_1"))
        .unwrap();

    wallet.create_pgp_identity("ops-signing").unwrap();
    wallet.set_active_pgp_identity("ops-signing").unwrap();
    assert!(
        wallet.get_contract("CTR_shared_1").unwrap().is_some(),
        "contract state must remain visible after switching active PGP key"
    );

    wallet
        .store_contract(&make_contract("CTR_shared_2"))
        .unwrap();
    wallet.set_active_pgp_identity("memory-wallet").unwrap();
    let contracts = wallet.list_contracts().unwrap();
    assert_eq!(contracts.len(), 2);
    assert!(contracts.iter().any(|c| c.contract_id == "CTR_shared_1"));
    assert!(contracts.iter().any(|c| c.contract_id == "CTR_shared_2"));
}

#[test]
fn get_nonexistent_contract_returns_none() {
    let wallet = RgbWallet::open_memory().unwrap();
    let result = wallet.get_contract("CTR_does_not_exist").unwrap();
    assert!(result.is_none());
}

#[test]
fn nickname_store_and_retrieve() {
    let wallet = RgbWallet::open_memory().unwrap();
    assert!(wallet.nickname().unwrap().is_none());

    wallet.set_nickname("alice").unwrap();
    assert_eq!(wallet.nickname().unwrap().as_deref(), Some("alice"));

    // Overwrite
    wallet.set_nickname("bob").unwrap();
    assert_eq!(wallet.nickname().unwrap().as_deref(), Some("bob"));
}

#[test]
fn snapshot_export_and_import() {
    let wallet = RgbWallet::open_memory().unwrap();
    wallet.set_nickname("snaptest").unwrap();
    wallet.store_contract(&make_contract("CTR_snap1")).unwrap();

    let snap = wallet.export_snapshot().unwrap();
    assert_eq!(snap.nickname.as_deref(), Some("snaptest"));
    assert_eq!(snap.contracts.len(), 1);

    // Import into a new in-memory wallet
    let in_memory_wallet_restored = RgbWallet::open_memory().unwrap();
    in_memory_wallet_restored.import_snapshot(&snap).unwrap();
    assert_eq!(
        in_memory_wallet_restored.nickname().unwrap().as_deref(),
        Some("snaptest")
    );
    assert_eq!(
        in_memory_wallet_restored.fingerprint().unwrap(),
        wallet.fingerprint().unwrap()
    );
    assert!(in_memory_wallet_restored
        .get_contract("CTR_snap1")
        .unwrap()
        .is_some());
}

#[test]
fn snapshot_import_rejects_non_derived_rgb_key() {
    let wallet = RgbWallet::open_memory().unwrap();
    let mut snap = wallet.export_snapshot().unwrap();
    snap.private_key_hex = "11".repeat(32);
    if snap.private_key_hex.eq_ignore_ascii_case(
        &wallet
            .derive_slot_hex("rgb", 0)
            .expect("must derive RGB slot deterministically"),
    ) {
        snap.private_key_hex = "22".repeat(32);
    }

    let in_memory_wallet_restored = RgbWallet::open_memory().unwrap();
    let err = in_memory_wallet_restored
        .import_snapshot(&snap)
        .expect_err("snapshot with mismatched RGB key must be rejected");
    assert!(
        err.to_string().contains("does not match"),
        "unexpected error: {err}"
    );
}

#[test]
fn snapshot_import_accepts_root_mnemonic_without_root_entropy_hex() {
    let wallet = RgbWallet::open_memory().unwrap();
    wallet.set_nickname("mnemonic-only").unwrap();
    let mut snap = wallet.export_snapshot().unwrap();
    snap.root_private_key_hex = None;
    assert!(snap.root_mnemonic.is_some());

    let in_memory_wallet_restored = RgbWallet::open_memory().unwrap();
    in_memory_wallet_restored.import_snapshot(&snap).unwrap();
    assert_eq!(
        in_memory_wallet_restored.fingerprint().unwrap(),
        wallet.fingerprint().unwrap()
    );
    assert_eq!(
        in_memory_wallet_restored
            .export_recovery_mnemonic()
            .unwrap(),
        wallet.export_recovery_mnemonic().unwrap()
    );
}

#[test]
fn identity_sign_and_verify() {
    let wallet = RgbWallet::open_memory().unwrap();
    let id = wallet.identity().unwrap();
    let msg = "deliver:CTR_test:hello world";
    let sig = id.sign(msg);
    assert_eq!(sig.len(), 128, "ed25519 sig = 64 bytes = 128 hex chars");

    let ok = Identity::verify(&id.public_key_hex(), msg, &sig).unwrap();
    assert!(ok, "signature should verify");

    let bad = Identity::verify(&id.public_key_hex(), "different message", &sig).unwrap();
    assert!(!bad, "wrong message should not verify");
}
