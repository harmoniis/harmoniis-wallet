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

    // DB filenames follow convention: {label}_{family}.db
    assert_eq!(
        harmoniis_wallet::wallet::WalletCore::wallet_db_filename("webcash", "donation"),
        "donation_webcash.db"
    );
    assert_eq!(
        harmoniis_wallet::wallet::WalletCore::wallet_db_filename("bitcoin", "main"),
        "main_bitcoin.db"
    );
    assert_eq!(
        harmoniis_wallet::wallet::WalletCore::wallet_db_filename("voucher", "cloudminer"),
        "cloudminer_voucher.db"
    );
    assert_eq!(
        harmoniis_wallet::wallet::WalletCore::wallet_db_filename("rgb", "secondary"),
        "secondary_rgb.db"
    );
}

#[test]
fn slot_0_is_always_main_for_all_wallet_families() {
    let wallet = RgbWallet::open_memory().expect("memory wallet");

    // First access with "main" should always get slot 0
    for family in &["webcash", "bitcoin", "voucher", "rgb"] {
        let method = match *family {
            "webcash" => wallet.derive_webcash_secret_for_label("main"),
            "bitcoin" => wallet.derive_bitcoin_secret_for_label("main"),
            "voucher" => wallet.derive_voucher_secret_for_label("main"),
            "rgb" => wallet.derive_rgb_secret_for_label("main"),
            _ => unreachable!(),
        };
        let (_secret, index) = method.unwrap_or_else(|e| panic!("{family} main failed: {e}"));
        assert_eq!(index, 0, "{family}: 'main' label must always map to slot 0");
    }
}

#[test]
fn labeled_wallet_slot_reuse_is_stable() {
    let wallet = RgbWallet::open_memory().expect("memory wallet");

    // Create a labeled wallet, then access it again — same slot, same secret.
    let (secret_a, idx_a) = wallet
        .derive_webcash_secret_for_label("savings")
        .expect("first access");
    let (secret_b, idx_b) = wallet
        .derive_webcash_secret_for_label("savings")
        .expect("second access");
    assert_eq!(idx_a, idx_b, "same label must reuse the same slot");
    assert_eq!(secret_a, secret_b, "same slot must produce the same secret");

    // Different label gets a different slot
    let (_secret_c, idx_c) = wallet
        .derive_webcash_secret_for_label("donations")
        .expect("different label");
    assert_ne!(idx_a, idx_c, "different labels must get different slots");
}

#[test]
fn wallet_slots_registry_is_consistent_after_refresh() {
    let wallet = RgbWallet::open_memory().expect("memory wallet");

    // After open_memory, refresh_slot_registry has already been called.
    // Verify that slot 0 entries have label="main" for wallet families.
    let slots = wallet.list_wallet_slots(None).expect("list all slots");
    for family in &["webcash", "bitcoin", "voucher", "rgb"] {
        let slot = slots
            .iter()
            .find(|s| s.family == *family && s.slot_index == 0);
        assert!(slot.is_some(), "{family} slot 0 must exist in wallet_slots");
        let slot = slot.unwrap();
        assert_eq!(
            slot.label.as_deref(),
            Some("main"),
            "{family} slot 0 label must be 'main'"
        );
        assert!(
            !slot.descriptor.is_empty(),
            "{family} slot 0 must have a descriptor"
        );
    }

    // ALL wallet families follow {label}_{family}.db for db_rel_path
    for family in &["webcash", "bitcoin", "voucher", "rgb"] {
        let slot = slots
            .iter()
            .find(|s| s.family == *family && s.slot_index == 0)
            .unwrap();
        let expected_db = format!("main_{family}.db");
        assert_eq!(
            slot.db_rel_path.as_deref(),
            Some(expected_db.as_str()),
            "{family} slot 0 db_rel_path must be '{expected_db}'"
        );
    }
}

#[test]
fn multiple_families_labeled_wallets_dont_collide() {
    let wallet = RgbWallet::open_memory().expect("memory wallet");

    // Create "hot" label in webcash and bitcoin — they should get independent slots
    let (wc_secret, wc_idx) = wallet
        .derive_webcash_secret_for_label("hot")
        .expect("webcash hot");
    let (btc_secret, btc_idx) = wallet
        .derive_bitcoin_secret_for_label("hot")
        .expect("bitcoin hot");

    // Both get slot 1 (first non-main slot) in their respective families
    assert_eq!(wc_idx, 1, "webcash hot should be slot 1");
    assert_eq!(btc_idx, 1, "bitcoin hot should be slot 1");

    // But the secrets are different because the family derivation paths differ
    assert_ne!(
        wc_secret, btc_secret,
        "webcash and bitcoin must derive different secrets even at same slot index"
    );

    // The two should be listed independently
    let wc_wallets = wallet
        .list_labeled_wallets("webcash")
        .expect("list webcash");
    let btc_wallets = wallet
        .list_labeled_wallets("bitcoin")
        .expect("list bitcoin");
    assert!(wc_wallets.iter().any(|w| w.label == "hot"));
    assert!(btc_wallets.iter().any(|w| w.label == "hot"));
}

#[test]
fn list_labeled_wallets_shows_all_created_labels() {
    let wallet = RgbWallet::open_memory().expect("memory wallet");

    // Create several labeled webcash wallets
    wallet
        .derive_webcash_secret_for_label("main")
        .expect("main");
    wallet
        .derive_webcash_secret_for_label("savings")
        .expect("savings");
    wallet
        .derive_webcash_secret_for_label("cloudminer")
        .expect("cloudminer");

    let wallets = wallet.list_labeled_wallets("webcash").expect("list");
    // Should have at least main (slot 0), savings, cloudminer
    assert!(
        wallets.len() >= 3,
        "expected at least 3 wallets, got {}",
        wallets.len()
    );
    assert!(wallets
        .iter()
        .any(|w| w.label == "main" && w.slot_index == 0));
    assert!(wallets.iter().any(|w| w.label == "savings"));
    assert!(wallets.iter().any(|w| w.label == "cloudminer"));

    // DB filenames follow convention
    let savings = wallets.iter().find(|w| w.label == "savings").unwrap();
    assert_eq!(savings.db_filename, "savings_webcash.db");
    let cloudminer = wallets.iter().find(|w| w.label == "cloudminer").unwrap();
    assert_eq!(cloudminer.db_filename, "cloudminer_webcash.db");
}

#[test]
fn vault_slot_0_is_reserved_and_cannot_be_derived() {
    let wallet = RgbWallet::open_memory().expect("memory wallet");
    let err = wallet.derive_vault_identity_for_index(0);
    assert!(
        err.is_err(),
        "vault index 0 must be rejected (reserved root)"
    );
    let msg = err.unwrap_err().to_string();
    assert!(
        msg.contains("reserved"),
        "error should mention 'reserved', got: {msg}"
    );
}

#[test]
fn pgp_slots_have_no_db_rel_path() {
    let wallet = RgbWallet::open_memory().expect("memory wallet");
    let slots = wallet.list_wallet_slots(Some("pgp")).expect("pgp slots");
    assert!(
        !slots.is_empty(),
        "should have at least default PGP identity"
    );
    for slot in &slots {
        assert!(
            slot.db_rel_path.is_none(),
            "PGP slot {} should have no db_rel_path (keys stored in master.db)",
            slot.slot_index
        );
    }
}
