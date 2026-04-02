//! SSH operations using vault-derived Ed25519 keys.
//!
//! The SSH key pair is derived from the wallet vault with namespace "vast-ssh".
//! This means the key is deterministic — same master wallet always produces
//! the same SSH key. No separate key files needed.

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;

use crate::wallet::vault::VaultRootMaterial;
use crate::wallet::WalletCore;

/// Derive the SSH Ed25519 key pair from the wallet vault.
pub fn derive_ssh_keypair(wallet: &WalletCore) -> Result<SigningKey> {
    let vault = VaultRootMaterial::from_wallet(wallet)
        .context("failed to access vault for SSH key derivation")?;
    vault
        .derive_signing_key("vast-ssh")
        .context("failed to derive SSH key from vault")
}

/// Format an Ed25519 public key as an SSH authorized_keys line.
pub fn ssh_public_key_string(signing_key: &SigningKey) -> String {
    let verifying = signing_key.verifying_key();
    let pub_bytes = verifying.to_bytes();

    // SSH wire format for Ed25519:
    //   4 bytes: length of key type string (11)
    //   11 bytes: "ssh-ed25519"
    //   4 bytes: length of public key (32)
    //   32 bytes: public key
    let key_type = b"ssh-ed25519";
    let mut wire = Vec::with_capacity(4 + key_type.len() + 4 + pub_bytes.len());
    wire.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
    wire.extend_from_slice(key_type);
    wire.extend_from_slice(&(pub_bytes.len() as u32).to_be_bytes());
    wire.extend_from_slice(&pub_bytes);

    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&wire);
    format!("ssh-ed25519 {b64} hrmw-cloud-mining")
}

/// Execute a command on a remote host via SSH.
///
/// Uses the system `ssh` binary with the vault-derived key written to a
/// temporary file.  This avoids pulling in a full SSH library while still
/// using deterministic vault keys.
pub fn exec(signing_key: &SigningKey, host: &str, port: u16, command: &str) -> Result<String> {
    let key_file = write_temp_key_file(signing_key)?;
    let output = std::process::Command::new("ssh")
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-i",
            &key_file.to_string_lossy(),
            "-p",
            &port.to_string(),
            &format!("root@{host}"),
            command,
        ])
        .output()
        .context("ssh exec failed")?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() && !stderr.is_empty() {
        anyhow::bail!("SSH command failed: {stderr}");
    }
    Ok(format!("{stdout}{stderr}"))
}

/// Execute a command in the background on the remote host.
pub fn exec_background(
    signing_key: &SigningKey,
    host: &str,
    port: u16,
    command: &str,
) -> Result<()> {
    let key_file = write_temp_key_file(signing_key)?;
    let bg_cmd = format!("nohup {command} > /root/miner.log 2>&1 &");
    let status = std::process::Command::new("ssh")
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-i",
            &key_file.to_string_lossy(),
            "-p",
            &port.to_string(),
            &format!("root@{host}"),
            &bg_cmd,
        ])
        .status()
        .context("ssh background exec failed")?;

    if !status.success() {
        anyhow::bail!("SSH background command failed");
    }
    Ok(())
}

/// Write the Ed25519 private key to a temporary file in PEM format.
///
/// SSH requires the key as a file. We write it with restrictive permissions
/// and return the path. The temp file is cleaned up by the OS.
/// Write the key to a temp file — needed for ssh/scp system commands.
pub fn write_temp_key_file(signing_key: &SigningKey) -> Result<std::path::PathBuf> {
    let dir = std::env::temp_dir().join("hrmw-ssh");
    std::fs::create_dir_all(&dir)?;
    let key_path = dir.join("vast_ed25519");

    // OpenSSH PEM format for Ed25519
    let secret_bytes = signing_key.to_bytes();
    let public_bytes = signing_key.verifying_key().to_bytes();

    // Build OpenSSH private key format
    let pem = encode_openssh_ed25519_private_key(&secret_bytes, &public_bytes);
    std::fs::write(&key_path, &pem)?;

    // Set permissions to 600 (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(key_path)
}

/// Encode an Ed25519 key pair in OpenSSH private key PEM format.
fn encode_openssh_ed25519_private_key(secret: &[u8; 32], public: &[u8; 32]) -> String {
    // OpenSSH private key format (simplified, no passphrase):
    // AUTH_MAGIC: "openssh-key-v1\0"
    // ciphername: "none"
    // kdfname: "none"
    // kdfoptions: "" (empty)
    // number of keys: 1
    // public key blob
    // private key blob (with checkint)

    let mut buf = Vec::new();

    // AUTH_MAGIC
    buf.extend_from_slice(b"openssh-key-v1\0");

    // ciphername
    push_string(&mut buf, b"none");
    // kdfname
    push_string(&mut buf, b"none");
    // kdfoptions (empty string)
    push_string(&mut buf, b"");

    // number of keys
    buf.extend_from_slice(&1u32.to_be_bytes());

    // public key blob
    let mut pub_blob = Vec::new();
    push_string(&mut pub_blob, b"ssh-ed25519");
    push_bytes(&mut pub_blob, public);
    push_bytes(&mut buf, &pub_blob);

    // private key section
    let mut priv_section = Vec::new();
    // checkint (random, but we use 0 for determinism)
    let check: u32 = 0x12345678;
    priv_section.extend_from_slice(&check.to_be_bytes());
    priv_section.extend_from_slice(&check.to_be_bytes());

    // key type
    push_string(&mut priv_section, b"ssh-ed25519");
    // public key
    push_bytes(&mut priv_section, public);
    // private key (OpenSSH stores 64 bytes: secret || public)
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(secret);
    combined[32..].copy_from_slice(public);
    push_bytes(&mut priv_section, &combined);
    // comment
    push_string(&mut priv_section, b"hrmw-cloud-mining");

    // padding to block size (8)
    let pad_len = (8 - (priv_section.len() % 8)) % 8;
    for i in 0..pad_len {
        priv_section.push((i + 1) as u8);
    }

    push_bytes(&mut buf, &priv_section);

    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&buf);

    // Wrap at 70 chars
    let mut pem = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    pem
}

fn push_string(buf: &mut Vec<u8>, s: &[u8]) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s);
}

fn push_bytes(buf: &mut Vec<u8>, s: &[u8]) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s);
}
