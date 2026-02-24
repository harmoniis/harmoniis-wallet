//! Full 6-phase integration test.
//!
//! Required env vars:
//!   HARMONIIS_API_URL    — e.g. http://localhost:9001
//!   TEST_WEBCASH_BUYER   — funded webcash secret
//!   TEST_WEBCASH_SELLER  — funded webcash secret
//!   TEST_WEBCASH_FEE     — funded webcash secret (for reply fee)
//!
//! Run with:
//!   HARMONIIS_API_URL=http://localhost:9001 \
//!   TEST_WEBCASH_BUYER="e1.0:secret:..." \
//!   TEST_WEBCASH_SELLER="e1.0:secret:..." \
//!   TEST_WEBCASH_FEE="e0.1:secret:..." \
//!   cargo test --test integration_flow -- --nocapture

use harmoniis_wallet::{
    client::{
        arbitration::{build_witness_commitment, BuyRequest},
        timeline::{PublishPostRequest, RegisterRequest},
        HarmoniisClient,
    },
    types::{ContractStatus, ContractType, Role, WitnessSecret},
    wallet::RgbWallet,
    Contract,
};

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

fn require_env(key: &str) -> String {
    env(key).unwrap_or_else(|| panic!("env var {key} is required for integration tests"))
}

#[tokio::test]
#[ignore = "requires live backend and funded webcash; run with --include-ignored"]
async fn test_full_6_phase_contract_flow() {
    let api_url = require_env("HARMONIIS_API_URL");
    let buyer_webcash = require_env("TEST_WEBCASH_BUYER");
    let seller_webcash = require_env("TEST_WEBCASH_SELLER");
    let fee_webcash = require_env("TEST_WEBCASH_FEE");

    let client = HarmoniisClient::new(&api_url);

    // ── Step 1: Create in-memory wallets ──────────────────────────────────────
    let buyer_wallet = RgbWallet::open_memory().expect("buyer wallet");
    let seller_wallet = RgbWallet::open_memory().expect("seller wallet");

    let buyer_id = buyer_wallet.identity().unwrap();
    let seller_id = seller_wallet.identity().unwrap();
    let buyer_fp = buyer_id.fingerprint();
    let seller_fp = seller_id.fingerprint();
    println!("Buyer  fingerprint: {buyer_fp}");
    println!("Seller fingerprint: {seller_fp}");

    // ── Step 2: Register identities ───────────────────────────────────────────
    let buyer_nick = format!("buyer_{}", &buyer_fp[..8]);
    let seller_nick = format!("seller_{}", &seller_fp[..8]);

    let buyer_reg = RegisterRequest {
        nickname: buyer_nick.clone(),
        pgp_public_key: buyer_id.public_key_hex(),
        signature: buyer_id.sign(&format!("register:{buyer_nick}")),
        about: Some("Integration test buyer".to_string()),
    };
    let registered_fp = client
        .register_identity(&buyer_reg, &buyer_webcash)
        .await
        .expect("buyer registration");
    println!("Buyer registered: {registered_fp}");
    buyer_wallet.set_nickname(&buyer_nick).unwrap();

    let seller_reg = RegisterRequest {
        nickname: seller_nick.clone(),
        pgp_public_key: seller_id.public_key_hex(),
        signature: seller_id.sign(&format!("register:{seller_nick}")),
        about: Some("Integration test seller".to_string()),
    };
    let seller_registered_fp = client
        .register_identity(&seller_reg, &seller_webcash)
        .await
        .expect("seller registration");
    println!("Seller registered: {seller_registered_fp}");
    seller_wallet.set_nickname(&seller_nick).unwrap();

    // ── Step 3: Seller posts service offer ────────────────────────────────────
    let offer_content = "Automated integration test service: write a haiku".to_string();
    let offer_sig = seller_id.sign(&format!("post:{offer_content}"));
    let offer_req = PublishPostRequest {
        author_fingerprint: seller_fp.clone(),
        author_nick: seller_nick.clone(),
        content: offer_content.clone(),
        post_type: "service_offer".to_string(),
        witness_proof: None,
        contract_id: None,
        parent_id: None,
        keywords: vec!["haiku".to_string(), "writing".to_string()],
        attachments: vec![],
        signature: offer_sig,
    };
    let offer_post_id = client
        .publish_post(&offer_req, &seller_webcash)
        .await
        .expect("seller post");
    println!("Service offer post: {offer_post_id}");

    // ── Step 4: Buyer buys contract ───────────────────────────────────────────
    let work_spec = "Write a haiku about Rust programming";
    let contract_id = format!("CTR_{}_999901", chrono::Utc::now().format("%Y"));
    let witness_secret = WitnessSecret::generate(&contract_id);
    let proof = witness_secret.public_proof();
    let (encrypted_witness_secret, witness_zkp) = build_witness_commitment(
        &witness_secret,
        &proof,
        &buyer_fp,
        Some(&seller_fp),
        Some(&seller_id.public_key_hex()),
        |msg| buyer_id.sign(msg),
    );
    let sig = buyer_id.sign(&format!(
        "buy_contract:{}:{}:{}:{}",
        buyer_fp,
        offer_post_id,
        contract_id,
        proof.display()
    ));
    let buy_req = BuyRequest {
        buyer_fingerprint: buyer_fp.clone(),
        buyer_public_key: buyer_id.public_key_hex(),
        contract_type: "service".to_string(),
        amount: "0.001".to_string(),
        contract_id: contract_id.clone(),
        witness_proof: proof.display(),
        encrypted_witness_secret,
        witness_zkp,
        reference_post: offer_post_id.clone(),
        signature: sig,
    };
    let buy_resp = client
        .buy_contract(&buy_req, &buyer_webcash)
        .await
        .expect("buy contract");
    let contract_id = buy_resp
        .get("contract_id")
        .and_then(|v| v.as_str())
        .unwrap_or(&contract_id)
        .to_string();
    println!("Contract bought: {contract_id}");
    println!("witness secret:  {:?}", witness_secret);

    // ── Step 5: Buyer stores contract in wallet ───────────────────────────────
    println!("witness proof:    {}", proof.display());

    let mut contract = Contract::new(
        contract_id.clone(),
        ContractType::Service,
        1_000_000,
        work_spec.to_string(),
        buyer_fp.clone(),
        Role::Buyer,
    );
    contract.witness_secret = Some(witness_secret.display());
    contract.witness_proof = Some(proof.display());
    contract.reference_post = Some(offer_post_id.clone());
    contract.seller_fingerprint = Some(seller_fp.clone());
    buyer_wallet.store_contract(&contract).unwrap();

    // ── Step 6: Buyer posts bid with witness proof ─────────────────────────────
    let bid_content = format!("I bid on contract {contract_id}");
    let bid_sig = buyer_id.sign(&format!("post:{bid_content}"));
    let bid_req = PublishPostRequest {
        author_fingerprint: buyer_fp.clone(),
        author_nick: buyer_nick.clone(),
        content: bid_content,
        post_type: "bid".to_string(),
        witness_proof: Some(proof.display()),
        contract_id: Some(contract_id.clone()),
        parent_id: None,
        keywords: vec!["bid".to_string()],
        attachments: vec![],
        signature: bid_sig,
    };
    let bid_post_id = client
        .publish_post(&bid_req, &fee_webcash)
        .await
        .expect("bid post");
    println!("Bid post: {bid_post_id}");

    // ── Step 7: Seller accepts bid ────────────────────────────────────────────
    let accept_sig = seller_id.sign(&format!("accept:{contract_id}:{seller_fp}"));
    client
        .accept_contract(&contract_id, &seller_fp, &accept_sig)
        .await
        .expect("accept bid");
    println!("Bid accepted.");

    // ── Step 8: Buyer generates new secret, calls witness/replace ─────────────
    let old_secret = WitnessSecret::parse(
        buyer_wallet
            .get_contract(&contract_id)
            .unwrap()
            .unwrap()
            .witness_secret
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    let new_secret = WitnessSecret::generate(&contract_id);
    let new_proof = new_secret.public_proof();

    client
        .witness_replace(&old_secret, &new_secret)
        .await
        .expect("witness replace");
    println!("witness replace done. New proof: {}", new_proof.display());

    // Buyer wallet: secret cleared, proof updated
    {
        let mut c = buyer_wallet.get_contract(&contract_id).unwrap().unwrap();
        c.status = ContractStatus::Active;
        c.witness_secret = None;
        c.witness_proof = Some(new_proof.display());
        c.updated_at = chrono::Utc::now().to_rfc3339();
        buyer_wallet.update_contract(&c).unwrap();
    }

    // ── Step 9: Seller stores new secret ─────────────────────────────────────
    let mut seller_contract = Contract::new(
        contract_id.clone(),
        ContractType::Service,
        1_000_000,
        work_spec.to_string(),
        buyer_fp.clone(),
        Role::Seller,
    );
    seller_contract.status = ContractStatus::Active;
    seller_contract.witness_secret = Some(new_secret.display());
    seller_contract.witness_proof = Some(new_proof.display());
    seller_contract.buyer_fingerprint = buyer_fp.clone();
    seller_wallet.store_contract(&seller_contract).unwrap();
    println!("Seller stored new secret in wallet.");

    // ── Step 10: Seller delivers ──────────────────────────────────────────────
    let delivered_text = "Rust programming / Ownership without a GC / Memory is safe";
    let deliver_sig = seller_id.sign(&format!("deliver:{contract_id}:{delivered_text}"));
    let deliver_resp = client
        .deliver(
            &contract_id,
            &new_secret.display(),
            delivered_text,
            &seller_fp,
            &deliver_sig,
        )
        .await
        .expect("deliver");
    println!("Delivered: {deliver_resp}");

    {
        let mut c = seller_wallet.get_contract(&contract_id).unwrap().unwrap();
        c.status = ContractStatus::Delivered;
        c.delivered_text = Some(delivered_text.to_string());
        c.updated_at = chrono::Utc::now().to_rfc3339();
        seller_wallet.update_contract(&c).unwrap();
    }

    // ── Step 11: Buyer picks up ───────────────────────────────────────────────
    let pickup_sig = buyer_id.sign(&contract_id);
    let pickup_resp = client
        .pickup(&contract_id, &buyer_fp, &pickup_sig, &buyer_webcash)
        .await
        .expect("pickup");
    println!("Picked up: {pickup_resp}");

    {
        let mut c = buyer_wallet.get_contract(&contract_id).unwrap().unwrap();
        c.status = ContractStatus::Burned;
        c.updated_at = chrono::Utc::now().to_rfc3339();
        buyer_wallet.update_contract(&c).unwrap();
    }

    // ── Step 12: Assert original proof is now spent ───────────────────────────
    let check = client
        .witness_check(&[proof.display()])
        .await
        .expect("witness check");
    println!("Original proof status: {check}");
    // The original proof should be spent (replaced in step 8)
    if let Some(arr) = check.as_array() {
        if let Some(entry) = arr.first() {
            let status = entry
                .get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("unknown");
            println!("Original proof status: {status}");
            assert!(
                status == "spent" || status == "replaced",
                "original proof should be spent/replaced, got: {status}"
            );
        }
    }

    println!("✓ Full 6-phase contract flow completed successfully.");
}
