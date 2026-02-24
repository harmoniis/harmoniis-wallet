use harmoniis_wallet::crypto::{generate_secret_hex, sha256_bytes};

#[test]
fn secret_hex_is_64_chars_lowercase_hex() {
    let hex = generate_secret_hex();
    assert_eq!(hex.len(), 64, "secret hex must be 64 chars");
    assert!(
        hex.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
        "secret hex must be lowercase hex"
    );
}

#[test]
fn two_secrets_are_different() {
    let a = generate_secret_hex();
    let b = generate_secret_hex();
    assert_ne!(a, b);
}

#[test]
fn sha256_known_vector() {
    // SHA256 of empty bytes
    let result = sha256_bytes(&[]);
    assert_eq!(
        result,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn sha256_of_raw_bytes_not_hex_string() {
    // Secret hex "abcd" = 2 raw bytes [0xab, 0xcd]
    let raw = hex::decode("abcd").unwrap();
    let hash = sha256_bytes(&raw);
    // SHA256([0xab, 0xcd]) — python3: hashlib.sha256(bytes.fromhex('abcd')).hexdigest()
    assert_eq!(
        hash,
        "123d4c7ef2d1600a1b3a0f6addc60a10f05a3495c9409f2ecbf4cc095d000a6b"
    );
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn witness_proof_matches_backend_logic() {
    // Simulate what the backend does in witness.rs `secret_hash()`:
    //   sha256 of the raw 32 bytes decoded from the hex secret
    let secret_hex = "00".repeat(32); // 32 zero bytes → 64 zero chars
    let raw = hex::decode(&secret_hex).unwrap();
    let hash = sha256_bytes(&raw);

    // SHA256 of 32 zero bytes (known vector)
    assert_eq!(
        hash,
        "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
    );
}
