//! SSH key generation and remote command execution.
//!
//! Uses the system `ssh` and `scp` binaries for remote operations.
//! Keys are generated with `ssh-keygen` and stored in `~/.harmoniis/cloud/`.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

use super::config;

/// Ensure an SSH key pair exists for cloud mining.
/// Returns the public key content.
pub fn ensure_ssh_key() -> Result<String> {
    let priv_path = config::ssh_key_path();
    let pub_path = config::ssh_pubkey_path();

    if !priv_path.exists() {
        let dir = priv_path.parent().unwrap();
        std::fs::create_dir_all(dir)?;

        let status = Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-f",
                &priv_path.to_string_lossy(),
                "-N",
                "",
                "-C",
                "hrmw-cloud-mining",
            ])
            .status()
            .context("failed to run ssh-keygen")?;

        if !status.success() {
            anyhow::bail!("ssh-keygen failed");
        }
    }

    let pubkey = std::fs::read_to_string(&pub_path).context("failed to read SSH public key")?;
    Ok(pubkey.trim().to_string())
}

/// Upload a file to a remote host via SCP.
pub fn scp_upload(local_path: &Path, host: &str, port: u16, remote_path: &str) -> Result<()> {
    let key_path = config::ssh_key_path();
    let status = Command::new("scp")
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-i",
            &key_path.to_string_lossy(),
            "-P",
            &port.to_string(),
            &local_path.to_string_lossy(),
            &format!("root@{host}:{remote_path}"),
        ])
        .status()
        .context("scp failed")?;

    if !status.success() {
        anyhow::bail!("SCP upload failed (exit {})", status.code().unwrap_or(-1));
    }
    Ok(())
}

/// Download a file from a remote host via SCP.
pub fn scp_download(host: &str, port: u16, remote_path: &str, local_path: &Path) -> Result<()> {
    let key_path = config::ssh_key_path();
    let status = Command::new("scp")
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-i",
            &key_path.to_string_lossy(),
            "-P",
            &port.to_string(),
            &format!("root@{host}:{remote_path}"),
            &local_path.to_string_lossy(),
        ])
        .status()
        .context("scp failed")?;

    if !status.success() {
        anyhow::bail!("SCP download failed (exit {})", status.code().unwrap_or(-1));
    }
    Ok(())
}

/// Execute a command on the remote host via SSH and return stdout.
pub fn ssh_exec(host: &str, port: u16, command: &str) -> Result<String> {
    let key_path = config::ssh_key_path();
    let output = Command::new("ssh")
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-i",
            &key_path.to_string_lossy(),
            "-p",
            &port.to_string(),
            &format!("root@{host}"),
            command,
        ])
        .output()
        .context("ssh exec failed")?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        if !stderr.is_empty() {
            anyhow::bail!("SSH command failed: {stderr}");
        }
        anyhow::bail!(
            "SSH command failed (exit {})",
            output.status.code().unwrap_or(-1)
        );
    }
    Ok(format!("{stdout}{stderr}"))
}

/// Execute a command in the background on the remote host (nohup + disown).
pub fn ssh_exec_background(host: &str, port: u16, command: &str) -> Result<()> {
    let key_path = config::ssh_key_path();
    let bg_cmd = format!("nohup {command} > /root/miner.log 2>&1 &");
    let status = Command::new("ssh")
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-i",
            &key_path.to_string_lossy(),
            "-p",
            &port.to_string(),
            &format!("root@{host}"),
            &bg_cmd,
        ])
        .status()
        .context("ssh background exec failed")?;

    if !status.success() {
        anyhow::bail!(
            "SSH background command failed (exit {})",
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}
