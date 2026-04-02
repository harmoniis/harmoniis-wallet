use harmoniis_wallet::{
    error::Error,
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
        arbitration_profit_wats: None,
        seller_value_wats: None,
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
fn vault_identities_are_labeled_and_wallet_derived() {
    let wallet = RgbWallet::open_memory().unwrap();

    let alice = wallet
        .create_vault_identity(Some("harmonia-agent-bob"))
        .unwrap();
    let bob = wallet
        .create_vault_identity(Some("mqtt-client-alice"))
        .unwrap();

    assert_eq!(alice.label.as_deref(), Some("harmonia-agent-bob"));
    assert_eq!(alice.slot_index, 1);
    assert_eq!(bob.label.as_deref(), Some("mqtt-client-alice"));
    assert_eq!(bob.slot_index, 2);
    assert_ne!(alice.descriptor, bob.descriptor);

    let listed = wallet.list_vault_identities().unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].label.as_deref(), Some("harmonia-agent-bob"));
    assert_eq!(listed[1].label.as_deref(), Some("mqtt-client-alice"));

    let alice_identity = wallet
        .derive_vault_identity_for_index(alice.slot_index)
        .unwrap();
    assert_eq!(alice_identity.public_key_hex(), alice.descriptor);
    assert_ne!(
        wallet.derive_vault_master_key_hex().unwrap(),
        alice_identity.private_key_hex()
    );
}

#[test]
fn vault_identity_private_key_exports_as_pkcs8_pem() {
    let wallet = RgbWallet::open_memory().unwrap();
    let slot = wallet
        .create_vault_identity(Some("mqtt-client-alice"))
        .unwrap();
    let identity = wallet
        .derive_vault_identity_for_index(slot.slot_index)
        .unwrap();
    let pem = identity.private_key_pkcs8_pem().unwrap();
    assert!(pem.contains("BEGIN PRIVATE KEY"));
    assert!(pem.contains("END PRIVATE KEY"));
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

// ---------------------------------------------------------------------------
// Wallet key-material protection tests (Bug 1: prevent silent key regeneration)
// ---------------------------------------------------------------------------

#[test]
fn create_then_open_preserves_fingerprint() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db_path = tmp.path().join("master.db");

    let fingerprint_a = {
        let w = RgbWallet::create(&db_path).unwrap();
        w.fingerprint().unwrap()
    };

    let fingerprint_b = {
        let w = RgbWallet::open(&db_path).unwrap();
        w.fingerprint().unwrap()
    };

    assert_eq!(
        fingerprint_a, fingerprint_b,
        "opening an existing wallet must preserve identity — not regenerate keys"
    );
}

#[test]
fn open_nonexistent_wallet_returns_not_found() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db_path = tmp.path().join("does-not-exist").join("master.db");
    match RgbWallet::open(&db_path) {
        Err(Error::NotFound(_)) => {} // expected
        Err(e) => panic!("expected NotFound, got: {e}"),
        Ok(_) => panic!("expected error for nonexistent wallet"),
    }
}

#[test]
fn open_wallet_with_missing_keys_returns_error_not_regeneration() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db_path = tmp.path().join("master.db");

    // Create a wallet and record its fingerprint.
    let original_fingerprint = {
        let w = RgbWallet::create(&db_path).unwrap();
        w.fingerprint().unwrap()
    };

    // Corrupt the wallet by deleting the root key material.
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "DELETE FROM wallet_metadata WHERE key IN ('root_mnemonic', 'root_private_key_hex')",
            [],
        )
        .unwrap();
    }

    // Opening should now fail instead of silently generating new keys.
    match RgbWallet::open(&db_path) {
        Err(Error::KeyMaterialMissing(_)) => {} // expected
        Err(e) => panic!("expected KeyMaterialMissing, got: {e}"),
        Ok(_) => panic!("expected error when key material is missing, but wallet opened — keys were silently regenerated!"),
    }

    // Verify the database was NOT overwritten with new keys.
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let mnemonic: Option<String> = conn
            .query_row(
                "SELECT value FROM wallet_metadata WHERE key = 'root_mnemonic'",
                [],
                |row| row.get(0),
            )
            .ok();
        assert!(
            mnemonic.is_none(),
            "key material must NOT be regenerated on failed open — wallet data would be lost. \
             Original fingerprint was: {original_fingerprint}"
        );
    }
}
#[test]
fn labeled_webcash_wallets_derive_distinct_secrets() {
    let wallet = RgbWallet::open_memory().expect("memory wallet");

    // Main (slot 0) and donation (slot 1) should produce different secrets
    let (main_secret, main_idx) = wallet
        .derive_webcash_secret_for_label("main")
        .expect("main webcash");
    let (donation_secret, donation_idx) = wallet
        .derive_webcash_secret_for_label("donation")
        .expect("donation webcash");

    assert_eq!(main_idx, 0, "main should be slot 0");
    assert_eq!(donation_idx, 1, "donation should be slot 1");
    assert_ne!(
        main_secret, donation_secret,
        "different slots = different secrets"
    );

    // Same label returns same slot
    let (main_again, idx_again) = wallet
        .derive_webcash_secret_for_label("main")
        .expect("main again");
    assert_eq!(main_again, main_secret);
    assert_eq!(idx_again, 0);

    // List should show both
    let wallets = wallet.list_labeled_wallets("webcash").expect("list");
    assert!(wallets.len() >= 2);
    assert!(wallets.iter().any(|w| w.label == "main"));
    assert!(wallets.iter().any(|w| w.label == "donation"));
}

#[test]
fn labeled_bitcoin_and_voucher_wallets_work() {
    let wallet = RgbWallet::open_memory().expect("memory wallet");

    let (btc_main, _) = wallet
        .derive_bitcoin_secret_for_label("main")
        .expect("btc main");
    let (btc_hot, _) = wallet
        .derive_bitcoin_secret_for_label("hot")
        .expect("btc hot");
    assert_ne!(btc_main, btc_hot);

    let (v_main, _) = wallet
        .derive_voucher_secret_for_label("main")
        .expect("voucher main");
    let (v_shop, _) = wallet
        .derive_voucher_secret_for_label("shop")
        .expect("voucher shop");
    assert_ne!(v_main, v_shop);

    // DB filenames follow convention
    assert_eq!(
        harmoniis_wallet::wallet::WalletCore::wallet_db_filename("webcash", "donation"),
        "donation_webcash.db"
    );
    assert_eq!(
        harmoniis_wallet::wallet::WalletCore::wallet_db_filename("bitcoin", "main"),
        "main_bitcoin.db"
    );
}
