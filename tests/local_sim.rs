//! Local in-process simulation of the full 6-phase Harmoniis contract flow.
//!
//! No backend or network required. A `Mockwitness` mirrors the DynamoDB logic
//! from `backend/src/witness.rs` using a HashMap, so we validate that our
//! data types and cryptography are perfectly aligned with the backend.
//!
//! Run with:
//!   cargo test --test local_sim -- --nocapture

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use harmoniis_wallet::{
    crypto::sha256_bytes,
    types::{
        ContractStatus, ContractType, Role, StablecashProof, StablecashSecret, WitnessProof,
        WitnessSecret,
    },
    wallet::RgbWallet,
    Contract, Identity,
};

// ── Mockwitness ────────────────────────────────────────────────────────────────

/// Mirrors the DynamoDB-backed witness from `backend/src/witness.rs`.
/// State: `public_hash → (status, contract_id, amount_units)`
#[derive(Clone, Default)]
struct Mockwitness {
    inner: Arc<Mutex<HashMap<String, witnessRecord>>>,
}

#[derive(Debug, Clone)]
struct witnessRecord {
    status: String, // "live" | "spent" | "burned"
    contract_id: String,
    contract_type: String,
    amount_units: Option<u64>,
}

#[derive(Debug, PartialEq)]
enum witnessStatus {
    Live,
    Spent,
    Burned,
    NotFound,
}

impl Mockwitness {
    /// Mint a new RGB21 witness record (mirrors `witness::mint_contract`).
    fn mint_rgb21(&self, secret: &WitnessSecret, contract_type: &str) -> Result<(), String> {
        let proof = secret.public_proof();
        let mut map = self.inner.lock().unwrap();
        if map.contains_key(&proof.public_hash) {
            return Err(format!("hash already exists: {}", proof.public_hash));
        }
        map.insert(
            proof.public_hash.clone(),
            witnessRecord {
                status: "live".to_string(),
                contract_id: secret.contract_id().to_string(),
                contract_type: contract_type.to_string(),
                amount_units: None,
            },
        );
        println!(
            "[witness] Minted RGB21 {} → {}",
            secret.contract_id(),
            proof.public_hash
        );
        Ok(())
    }

    /// Mint a new RGB20 record (mirrors Exchange/Stablecash mint).
    fn mint_rgb20(&self, secret: &StablecashSecret) -> Result<(), String> {
        let proof = secret.public_proof();
        let mut map = self.inner.lock().unwrap();
        if map.contains_key(&proof.public_hash) {
            return Err(format!("hash already exists: {}", proof.public_hash));
        }
        map.insert(
            proof.public_hash.clone(),
            witnessRecord {
                status: "live".to_string(),
                contract_id: secret.contract_id.clone(),
                contract_type: "RGB20:Stablecash".to_string(),
                amount_units: Some(secret.amount_units),
            },
        );
        println!(
            "[witness] Minted RGB20 {} atomic units → {}",
            secret.amount_units, proof.public_hash
        );
        Ok(())
    }

    /// RGB21 replace (1-to-1): marks old spent, creates new live.
    /// Mirrors `witness::replace` for RGB21 path.
    fn replace_rgb21(&self, old: &WitnessSecret, new: &WitnessSecret) -> Result<(), String> {
        if old.contract_id() != new.contract_id() {
            return Err("contract_id mismatch".to_string());
        }
        let old_proof = old.public_proof();
        let new_proof = new.public_proof();
        let mut map = self.inner.lock().unwrap();

        // Check old is live
        let old_record = map
            .get(&old_proof.public_hash)
            .ok_or("old secret not found")?;
        if old_record.status != "live" {
            return Err(format!("old secret already {}", old_record.status));
        }
        let contract_type = old_record.contract_type.clone();

        // Check new doesn't already exist (prevents replay)
        if map.contains_key(&new_proof.public_hash) {
            return Err("new secret already exists".to_string());
        }

        // Atomically: mark old spent, create new
        map.get_mut(&old_proof.public_hash).unwrap().status = "spent".to_string();
        map.insert(
            new_proof.public_hash.clone(),
            witnessRecord {
                status: "live".to_string(),
                contract_id: new.contract_id().to_string(),
                contract_type,
                amount_units: None,
            },
        );

        println!(
            "[witness] Replace RGB21 {} → {} (old spent)",
            old_proof.public_hash, new_proof.public_hash
        );
        Ok(())
    }

    /// RGB20 replace (split/merge): sum of inputs must equal sum of outputs.
    /// Mirrors `witness::replace` for RGB20 path.
    fn replace_rgb20(
        &self,
        inputs: &[StablecashSecret],
        outputs: &[StablecashSecret],
    ) -> Result<(), String> {
        let sum_in: u64 = inputs.iter().map(|s| s.amount_units).sum();
        let sum_out: u64 = outputs.iter().map(|s| s.amount_units).sum();
        if sum_in != sum_out {
            return Err(format!(
                "Amount mismatch: inputs={sum_in} outputs={sum_out}"
            ));
        }
        let contract_id = inputs
            .first()
            .map(|s| s.contract_id.clone())
            .ok_or("no inputs")?;

        let mut map = self.inner.lock().unwrap();

        // Verify all inputs live + same contract
        for input in inputs {
            if input.contract_id != contract_id {
                return Err("mixed contract IDs in inputs".to_string());
            }
            let proof = input.public_proof();
            let rec = map
                .get(&proof.public_hash)
                .ok_or(format!("input not found: {}", proof.public_hash))?;
            if rec.status != "live" {
                return Err(format!("input already {}", rec.status));
            }
        }

        // Mark inputs spent
        for input in inputs {
            let proof = input.public_proof();
            map.get_mut(&proof.public_hash).unwrap().status = "spent".to_string();
        }

        // Create outputs
        for output in outputs {
            if output.contract_id != contract_id {
                return Err("mixed contract IDs in outputs".to_string());
            }
            let proof = output.public_proof();
            if map.contains_key(&proof.public_hash) {
                return Err("output already exists".to_string());
            }
            map.insert(
                proof.public_hash.clone(),
                witnessRecord {
                    status: "live".to_string(),
                    contract_id: contract_id.clone(),
                    contract_type: "RGB20:Stablecash".to_string(),
                    amount_units: Some(output.amount_units),
                },
            );
        }

        println!("[witness] Replace RGB20: {sum_in} atomic units → {sum_out} atomic units across {} outputs", outputs.len());
        Ok(())
    }

    /// Burn a secret permanently (mirrors `witness::burn_secrets`).
    fn burn_rgb21(&self, secret: &WitnessSecret) -> Result<(), String> {
        let proof = secret.public_proof();
        let mut map = self.inner.lock().unwrap();
        let rec = map.get_mut(&proof.public_hash).ok_or("secret not found")?;
        if rec.status != "live" {
            return Err(format!("already {}", rec.status));
        }
        rec.status = "burned".to_string();
        println!("[witness] Burned RGB21 {}", proof.public_hash);
        Ok(())
    }

    /// Check status of a proof.
    fn check_proof(&self, proof: &WitnessProof) -> witnessStatus {
        let map = self.inner.lock().unwrap();
        match map.get(&proof.public_hash) {
            None => witnessStatus::NotFound,
            Some(rec) => match rec.status.as_str() {
                "live" => witnessStatus::Live,
                "spent" => witnessStatus::Spent,
                "burned" => witnessStatus::Burned,
                _ => witnessStatus::NotFound,
            },
        }
    }

    fn check_stablecash(&self, proof: &StablecashProof) -> witnessStatus {
        let map = self.inner.lock().unwrap();
        match map.get(&proof.public_hash) {
            None => witnessStatus::NotFound,
            Some(rec) => match rec.status.as_str() {
                "live" => witnessStatus::Live,
                "spent" => witnessStatus::Spent,
                "burned" => witnessStatus::Burned,
                _ => witnessStatus::NotFound,
            },
        }
    }
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn make_contract_id() -> String {
    let n: u32 = rand::random::<u32>() % 999999 + 1;
    format!("CTR_2026_{n:06}")
}

// ── Test 1: Full 6-phase contract flow (RGB21) ─────────────────────────────────

#[test]
fn test_6_phase_rgb21_contract_flow() {
    println!("\n=== 6-Phase RGB21 Contract Simulation ===\n");

    let witness = Mockwitness::default();

    // ── Wallets ───────────────────────────────────────────────────────────────
    let buyer_wallet = RgbWallet::open_memory().unwrap();
    let seller_wallet = RgbWallet::open_memory().unwrap();
    let buyer_id = buyer_wallet.identity().unwrap();
    let seller_id = seller_wallet.identity().unwrap();
    let buyer_fp = buyer_id.fingerprint();
    let seller_fp = seller_id.fingerprint();

    println!("Buyer  FP: {buyer_fp}");
    println!("Seller FP: {seller_fp}");
    assert_eq!(buyer_fp.len(), 64, "fingerprint must be 64-char hex");

    // ── Phase 1: Seller posts offer (simulated — no HTTP) ─────────────────────
    let offer_text = "I will write a Rust tutorial for Harmoniis agents.";
    let offer_sig = seller_id.sign(&format!("post:{offer_text}"));
    assert!(
        Identity::verify(&seller_fp, &format!("post:{offer_text}"), &offer_sig).unwrap(),
        "offer signature must verify"
    );
    println!("Phase 1: Seller offer signature verified.");

    // ── Phase 2: Buyer buys contract ──────────────────────────────────────────
    let contract_id = make_contract_id();
    let work_spec = "Write a 1000-word Rust tutorial for autonomous agents";

    // Arbiter generates initial secret (this is what our library does for the backend)
    let initial_secret = WitnessSecret::generate(&contract_id);
    let initial_proof = initial_secret.public_proof();

    // Buyer signs the buy request
    let issue_sig = buyer_id.sign(&format!(
        "buy_contract:{}:{}:{}:{}",
        buyer_fp,
        "POST_offer_123",
        contract_id,
        initial_proof.display()
    ));
    assert!(
        Identity::verify(
            &buyer_fp,
            &format!(
                "buy_contract:{}:{}:{}:{}",
                buyer_fp,
                "POST_offer_123",
                contract_id,
                initial_proof.display()
            ),
            &issue_sig
        )
        .unwrap(),
        "issue signature must verify"
    );

    // Verify: proof format matches backend exactly
    let proof_display = initial_proof.display();
    assert!(
        proof_display.starts_with("n:"),
        "proof must start with 'n:'"
    );
    assert!(
        proof_display.contains(":public:"),
        "proof must contain ':public:'"
    );
    assert_eq!(
        initial_proof.public_hash.len(),
        64,
        "proof hash must be 64 chars"
    );

    // Verify: SHA256 computation matches backend's `secret_hash()` in witness.rs
    let raw = hex::decode(initial_secret.hex_value()).unwrap();
    let expected_hash = sha256_bytes(&raw);
    assert_eq!(
        initial_proof.public_hash, expected_hash,
        "proof hash must match sha256 of raw bytes"
    );

    // Arbiter mints in witness
    witness
        .mint_rgb21(&initial_secret, "RGB21:Contract")
        .unwrap();

    // Buyer stores contract in wallet
    let now = chrono::Utc::now().to_rfc3339();
    let mut contract = Contract {
        contract_id: contract_id.clone(),
        contract_type: ContractType::Service,
        status: ContractStatus::Issued,
        witness_secret: Some(initial_secret.display()),
        witness_proof: Some(initial_proof.display()),
        amount_units: 1_000_000_000, // 10 USDH
        work_spec: work_spec.to_string(),
        buyer_fingerprint: buyer_fp.clone(),
        seller_fingerprint: Some(seller_fp.clone()),
        reference_post: Some("POST_offer_123".to_string()),
        delivery_deadline: Some("2027-01-01T00:00:00Z".to_string()),
        role: Role::Buyer,
        delivered_text: None,
        certificate_id: None,
        created_at: now.clone(),
        updated_at: now.clone(),
    };
    buyer_wallet.store_contract(&contract).unwrap();

    // Assert proof is live
    assert_eq!(witness.check_proof(&initial_proof), witnessStatus::Live);
    println!("Phase 2: Contract bought, witness proof verified live.");

    // ── Phase 3: Buyer bids with witness proof ─────────────────────────────────
    let bid_content = format!("Bid on {contract_id}: I'll do this for 10 USDH");
    let bid_sig = buyer_id.sign(&format!("post:{bid_content}"));
    // Backend verifies: witness_proof exists and is live, plus signature
    assert_eq!(witness.check_proof(&initial_proof), witnessStatus::Live);
    assert!(
        Identity::verify(&buyer_fp, &format!("post:{bid_content}"), &bid_sig).unwrap(),
        "bid signature must verify"
    );
    println!("Phase 3: Bid posted with verified witness proof.");

    // ── Phase 4: Alice accepts + Bob transfers ownership ──────────────────────
    let accept_sig = seller_id.sign(&format!("accept:{contract_id}:{seller_fp}"));
    assert!(
        Identity::verify(
            &seller_fp,
            &format!("accept:{contract_id}:{seller_fp}"),
            &accept_sig
        )
        .unwrap(),
        "accept signature must verify"
    );

    contract.status = ContractStatus::Active;
    buyer_wallet.update_contract(&contract).unwrap();

    // Buyer generates new secret for seller, does witness/replace
    let new_secret = WitnessSecret::generate(&contract_id);
    let new_proof = new_secret.public_proof();

    witness.replace_rgb21(&initial_secret, &new_secret).unwrap();

    // Old proof is now spent
    assert_eq!(witness.check_proof(&initial_proof), witnessStatus::Spent);
    // New proof is live
    assert_eq!(witness.check_proof(&new_proof), witnessStatus::Live);

    // Buyer's wallet: secret cleared (transferred), proof updated to new
    {
        let mut c = buyer_wallet.get_contract(&contract_id).unwrap().unwrap();
        c.witness_secret = None;
        c.witness_proof = Some(new_proof.display());
        c.updated_at = chrono::Utc::now().to_rfc3339();
        buyer_wallet.update_contract(&c).unwrap();
    }

    // Seller's wallet gets the new secret
    let mut seller_contract = Contract {
        contract_id: contract_id.clone(),
        contract_type: ContractType::Service,
        status: ContractStatus::Active,
        witness_secret: Some(new_secret.display()),
        witness_proof: Some(new_proof.display()),
        amount_units: 1_000_000_000,
        work_spec: work_spec.to_string(),
        buyer_fingerprint: buyer_fp.clone(),
        seller_fingerprint: Some(seller_fp.clone()),
        reference_post: None,
        delivery_deadline: Some("2027-01-01T00:00:00Z".to_string()),
        role: Role::Seller,
        delivered_text: None,
        certificate_id: None,
        created_at: now.clone(),
        updated_at: now.clone(),
    };
    seller_wallet.store_contract(&seller_contract).unwrap();

    println!("Phase 4: Ownership transferred. Old proof spent, new proof live.");

    // Verify replace is idempotency-safe: cannot re-spend old secret
    assert!(
        witness
            .replace_rgb21(&initial_secret, &WitnessSecret::generate(&contract_id))
            .is_err(),
        "double-spend must fail"
    );
    println!("         Double-spend correctly rejected.");

    // ── Phase 5: Seller delivers + Arbiter evaluates ──────────────────────────
    let delivered_text =
        "# Rust Tutorial for Autonomous Agents\n\nRust guarantees memory safety...";
    let deliver_sig = seller_id.sign(&format!("deliver:{contract_id}:{delivered_text}"));
    assert!(
        Identity::verify(
            &seller_fp,
            &format!("deliver:{contract_id}:{delivered_text}"),
            &deliver_sig
        )
        .unwrap(),
        "deliver signature must verify"
    );

    // Arbiter receives witness_secret from seller — validates it belongs to contract + is live
    let seller_secret_str = seller_wallet
        .get_contract(&contract_id)
        .unwrap()
        .unwrap()
        .witness_secret
        .unwrap();
    let seller_secret = WitnessSecret::parse(&seller_secret_str).unwrap();
    assert_eq!(seller_secret.contract_id(), &contract_id);
    assert_eq!(
        witness.check_proof(&seller_secret.public_proof()),
        witnessStatus::Live
    );

    // Arbiter burns secret (settle: pay seller, burn contract)
    witness.burn_rgb21(&seller_secret).unwrap();
    assert_eq!(witness.check_proof(&new_proof), witnessStatus::Burned);

    seller_contract.status = ContractStatus::Delivered;
    seller_contract.delivered_text = Some(delivered_text.to_string());
    seller_wallet.update_contract(&seller_contract).unwrap();
    println!("Phase 5: Delivered and verified. Contract burned in witness.");

    // ── Phase 6: Buyer pickups ────────────────────────────────────────────────
    {
        let mut c = buyer_wallet.get_contract(&contract_id).unwrap().unwrap();
        c.status = ContractStatus::Burned;
        c.updated_at = chrono::Utc::now().to_rfc3339();
        buyer_wallet.update_contract(&c).unwrap();
    }

    // Assert: original proof is spent, new proof is burned
    assert_eq!(witness.check_proof(&initial_proof), witnessStatus::Spent);
    assert_eq!(witness.check_proof(&new_proof), witnessStatus::Burned);

    println!("Phase 6: Picked up. Original proof=Spent, transferred proof=Burned.");
    println!("\n=== 6-Phase flow PASSED ===\n");
}

// ── Test 2: RGB21 refund flow ─────────────────────────────────────────────────

#[test]
fn test_rgb21_refund_before_accept() {
    println!("\n=== Refund Before Accept ===\n");
    let witness = Mockwitness::default();
    let buyer_wallet = RgbWallet::open_memory().unwrap();
    let buyer_id = buyer_wallet.identity().unwrap();
    let buyer_fp = buyer_id.fingerprint();

    let contract_id = make_contract_id();
    let secret = WitnessSecret::generate(&contract_id);
    let proof = secret.public_proof();
    witness.mint_rgb21(&secret, "RGB21:Contract").unwrap();

    assert_eq!(witness.check_proof(&proof), witnessStatus::Live);

    // Refund: buyer proves ownership (secret) → arbiter burns
    let refund_sig = buyer_id.sign(&format!("REFUND:{contract_id}"));
    assert!(Identity::verify(&buyer_fp, &format!("REFUND:{contract_id}"), &refund_sig).unwrap());
    witness.burn_rgb21(&secret).unwrap();
    assert_eq!(witness.check_proof(&proof), witnessStatus::Burned);
    println!("Refund (before accept): contract burned. PASSED.");
}

// ── Test 3: RGB20 Stablecash split + merge ─────────────────────────────────────

#[test]
fn test_rgb20_stablecash_split_and_merge() {
    println!("\n=== RGB20 Stablecash Split/Merge ===\n");

    let witness = Mockwitness::default();

    // Mint 10 USDH (1_000_000_000 atomic units)
    let total_secret = StablecashSecret::generate(1_000_000_000, "USDH_MAIN");
    let total_proof = total_secret.public_proof();
    witness.mint_rgb20(&total_secret).unwrap();
    assert_eq!(witness.check_stablecash(&total_proof), witnessStatus::Live);

    // Verify format: `u1000000000:USDH_MAIN:secret:hex64`
    let display = total_secret.display();
    assert!(
        display.starts_with("u1000000000:USDH_MAIN:secret:"),
        "bad format: {display}"
    );
    assert_eq!(display.len(), "u1000000000:USDH_MAIN:secret:".len() + 64);

    // Verify proof format: `u1000000000:USDH_MAIN:public:hash64`
    let proof_display = total_proof.display();
    assert!(
        proof_display.starts_with("u1000000000:USDH_MAIN:public:"),
        "bad proof: {proof_display}"
    );

    // Split: 10 USDH → 3 USDH (payment) + 7 USDH (change)
    let pay_secret = StablecashSecret::generate(300_000_000, "USDH_MAIN");
    let change_secret = StablecashSecret::generate(700_000_000, "USDH_MAIN");

    witness
        .replace_rgb20(
            &[total_secret],
            &[pay_secret.clone(), change_secret.clone()],
        )
        .unwrap();

    let pay_proof = pay_secret.public_proof();
    let change_proof = change_secret.public_proof();

    assert_eq!(witness.check_stablecash(&total_proof), witnessStatus::Spent);
    assert_eq!(witness.check_stablecash(&pay_proof), witnessStatus::Live);
    assert_eq!(witness.check_stablecash(&change_proof), witnessStatus::Live);

    println!("Split 10 USDH → 3 + 7 USDH: PASSED");

    // Merge back: 3 + 7 → 10 USDH
    let merged_secret = StablecashSecret::generate(1_000_000_000, "USDH_MAIN");
    witness
        .replace_rgb20(&[pay_secret, change_secret], &[merged_secret.clone()])
        .unwrap();

    let merged_proof = merged_secret.public_proof();
    assert_eq!(witness.check_stablecash(&pay_proof), witnessStatus::Spent);
    assert_eq!(
        witness.check_stablecash(&change_proof),
        witnessStatus::Spent
    );
    assert_eq!(witness.check_stablecash(&merged_proof), witnessStatus::Live);

    println!("Merge 3 + 7 USDH → 10 USDH: PASSED");

    // Amount mismatch must fail
    let over_pay = StablecashSecret::generate(1_000_000_001, "USDH_MAIN");
    assert!(
        witness
            .replace_rgb20(&[merged_secret.clone()], &[over_pay])
            .is_err(),
        "amount mismatch must fail"
    );
    println!("Amount mismatch correctly rejected. PASSED.");

    println!("\n=== RGB20 Split/Merge PASSED ===\n");
}

// ── Test 4: Stablecash parse roundtrip ────────────────────────────────────────

#[test]
fn test_stablecash_parse_roundtrip() {
    let secret = StablecashSecret::generate(500_000_000, "USDH_MAIN");
    let display = secret.display();
    let parsed = StablecashSecret::parse(&display).unwrap();
    assert_eq!(parsed.amount_units, secret.amount_units);
    assert_eq!(parsed.contract_id, secret.contract_id);
    assert_eq!(parsed.hex_value(), secret.hex_value());

    let proof = secret.public_proof();
    let proof_display = proof.display();
    let parsed_proof = StablecashProof::parse(&proof_display).unwrap();
    assert_eq!(parsed_proof, proof);

    // Verify SHA256 logic matches witness.rs
    let raw = hex::decode(secret.hex_value()).unwrap();
    let expected_hash = sha256_bytes(&raw);
    assert_eq!(proof.public_hash, expected_hash);
}

// ── Test 5: Signature verification matrix ─────────────────────────────────────

#[test]
fn test_all_signature_messages() {
    let wallet = RgbWallet::open_memory().unwrap();
    let id = wallet.identity().unwrap();
    let fp = id.fingerprint();
    let contract_id = "CTR_2026_001234";

    // All message formats used in the 6-phase flow
    let messages = [
        format!("register:alice"),
        format!("post:some content here"),
        format!(
            "buy_contract:{}:{}:{}:{}",
            fp,
            "POST_abc",
            contract_id,
            format!("n:{contract_id}:public:{}", "a".repeat(64))
        ),
        format!("accept:{contract_id}:{fp}"),
        format!("deliver:{contract_id}:delivered content"),
        format!("REFUND:{contract_id}"),
        format!(
            "transfer:{contract_id}:n:{contract_id}:public:{}",
            "a".repeat(64)
        ),
    ];

    for msg in &messages {
        let sig = id.sign(msg);
        assert_eq!(sig.len(), 128, "signature must be 128 hex chars");
        assert!(
            Identity::verify(&fp, msg, &sig).unwrap(),
            "signature must verify for: {msg}"
        );
        assert!(
            !Identity::verify(&fp, &format!("{msg}tampered"), &sig).unwrap(),
            "tampered message must not verify"
        );
    }
    println!("All 7 signature message formats verified.");
}

// ── Test 6: Alignment check — backend ParsedSecret vs our types ───────────────

#[test]
fn test_backend_alignment() {
    // Backend witness.rs ParsedSecret::from_str uses splitn(3, ':') on s[2..]
    // for RGB21. Verify our types produce identical hashes.

    // Known test vector: generate a secret with known hex, verify the proof hash.
    let hex64 = "deadbeef".repeat(8); // 64 chars
    let secret_str = format!("n:CTR_2026_000001:secret:{hex64}");
    let secret = WitnessSecret::parse(&secret_str).unwrap();

    // Proof = sha256 of raw bytes of hex64
    let raw = hex::decode(&hex64).unwrap();
    let expected_proof_hash = sha256_bytes(&raw);

    let proof = secret.public_proof();
    assert_eq!(proof.public_hash, expected_proof_hash);
    assert_eq!(proof.contract_id, "CTR_2026_000001");

    // Proof display matches what backend stores as the key
    let proof_display = proof.display();
    assert_eq!(
        proof_display,
        format!("n:CTR_2026_000001:public:{expected_proof_hash}")
    );

    // RGB20: verify format
    let usdh_secret = StablecashSecret::generate(1_000_000_000, "USDH_MAIN");
    let usdh_display = usdh_secret.display();
    assert!(usdh_display.starts_with("u1000000000:USDH_MAIN:secret:"));

    // Backend ParsedSecret::from_str for RGB20:
    //   rest = "1000000000:USDH_MAIN:secret:hex..."
    //   colon1 = 10 (position of first ':' after 'u')
    //   amount = 1000000000
    //   rest2 = "USDH_MAIN:secret:hex..."
    //   parts = ["USDH_MAIN", "secret", "hex..."]   (splitn(3, ':'))
    // Our display matches this exactly.

    println!("Backend alignment check PASSED.");
}
