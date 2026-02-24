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
    let wallet2 = RgbWallet::open_memory().unwrap();
    wallet2.import_snapshot(&snap).unwrap();
    assert_eq!(wallet2.nickname().unwrap().as_deref(), Some("snaptest"));
    assert_eq!(
        wallet2.fingerprint().unwrap(),
        wallet.fingerprint().unwrap()
    );
    assert!(wallet2.get_contract("CTR_snap1").unwrap().is_some());
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
