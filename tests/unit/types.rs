use harmoniis_wallet::types::{WitnessProof, WitnessSecret};

// ── WitnessSecret ──────────────────────────────────────────────────────────────

#[test]
fn witness_secret_generate_and_parse_roundtrip() {
    let secret = WitnessSecret::generate("CTR_abc123");
    let display = secret.display();
    let parsed = WitnessSecret::parse(&display).expect("parse should succeed");
    assert_eq!(parsed.contract_id(), secret.contract_id());
    assert_eq!(parsed.hex_value(), secret.hex_value());
    assert_eq!(parsed.display(), display);
}

#[test]
fn witness_secret_format_correct() {
    let secret = WitnessSecret::generate("CTR_abc123");
    let display = secret.display();
    assert!(display.starts_with("n:CTR_abc123:secret:"));
    assert_eq!(display.len(), "n:CTR_abc123:secret:".len() + 64);
}

#[test]
fn witness_secret_parse_rejects_wrong_prefix() {
    let err = WitnessSecret::parse("x:CTR_abc:secret:aa".repeat(1).as_str());
    assert!(err.is_err());
}

#[test]
fn witness_secret_parse_rejects_short_hex() {
    let err = WitnessSecret::parse("n:CTR_abc:secret:deadbeef");
    assert!(err.is_err(), "should reject hex shorter than 64 chars");
}

#[test]
fn witness_secret_parse_rejects_missing_secret_segment() {
    let err = WitnessSecret::parse("n:CTR_abc:public:aabbcc");
    assert!(err.is_err());
}

#[test]
fn witness_secret_public_proof_is_sha256_of_raw_bytes() {
    use harmoniis_wallet::crypto::sha256_bytes;

    let hex_value = "00".repeat(32);
    let secret_str = format!("n:CTR_test:secret:{hex_value}");
    let secret = WitnessSecret::parse(&secret_str).unwrap();
    let proof = secret.public_proof();

    let raw = hex::decode(&hex_value).unwrap();
    let expected_hash = sha256_bytes(&raw);

    assert_eq!(proof.public_hash, expected_hash);
    assert_eq!(proof.contract_id, "CTR_test");
}

// ── WitnessProof ───────────────────────────────────────────────────────────────

#[test]
fn witness_proof_parse_and_display_roundtrip() {
    let hash = "a".repeat(64);
    let s = format!("n:CTR_xyz:public:{hash}");
    let proof = WitnessProof::parse(&s).expect("parse should succeed");
    assert_eq!(proof.contract_id, "CTR_xyz");
    assert_eq!(proof.public_hash, hash);
    assert_eq!(proof.display(), s);
}

#[test]
fn witness_proof_from_secret_display_roundtrip() {
    let secret = WitnessSecret::generate("CTR_roundtrip");
    let proof = secret.public_proof();
    let display = proof.display();
    let parsed = WitnessProof::parse(&display).expect("proof display should be parseable");
    assert_eq!(parsed, proof);
}

#[test]
fn witness_proof_parse_rejects_bad_format() {
    assert!(WitnessProof::parse("n:CTR_x:secret:aa").is_err());
    assert!(WitnessProof::parse("bad").is_err());
    assert!(WitnessProof::parse("n:CTR_x:public:short").is_err());
}

// ── Contract IDs with colons ───────────────────────────────────────────────────

#[test]
fn witness_secret_contract_id_with_colon() {
    // Some contract IDs might contain colons; rfind ensures we split at the last :secret:
    let secret = WitnessSecret::generate("CTR_abc:def");
    let display = secret.display();
    let parsed = WitnessSecret::parse(&display).unwrap();
    assert_eq!(parsed.contract_id(), "CTR_abc:def");
}
