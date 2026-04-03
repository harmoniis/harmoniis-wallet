//! Cloud mining orchestration — start, stop, destroy, status, info.
//!
//! Security model:
//! - SSH key derived from wallet vault (namespace "vast-ssh") — deterministic, no files
//! - Only a derived labeled webcash wallet goes to the cloud
//! - Recovery uses the local deterministic secret — no SCP download needed

use anyhow::{Context, Result};
use std::path::Path;

use super::config::{self, InstanceState};
use super::ssh;
use super::vast::VastClient;

const REMOTE_HRMW: &str = "/root/.local/bin/hrmw";
const REMOTE_WALLET: &str = "/root/cloudminer_webcash.db";

/// Print the top offers table and let the user select.
pub fn print_offers_table(offers: &[super::vast::Offer]) {
    println!();
    println!(
        "{:<3} {:<5} {:<16} {:>10} {:>8} {:>10}  {:>10}",
        "#", "GPUs", "GPU", "TFLOPS", "$/hr", "FLOPS/$", "Offer ID"
    );
    println!("{}", "-".repeat(75));
    for (i, o) in offers.iter().enumerate() {
        println!(
            "{:<3} {:<5} {:<16} {:>10.1} {:>8.2} {:>10.1}  {:>10}",
            i + 1,
            format!("{}x", o.num_gpus),
            o.gpu_name,
            o.tflops(),
            o.dph_total,
            o.flops_per_dollar(),
            o.id,
        );
    }
    println!();
}

/// Prompt user to select an offer.
pub fn prompt_offer_selection(offers: &[super::vast::Offer]) -> Result<&super::vast::Offer> {
    if offers.is_empty() {
        anyhow::bail!("No GPU offers found matching criteria");
    }
    if offers.len() == 1 {
        println!("Only one offer available — selecting it.");
        return Ok(&offers[0]);
    }

    print!("Select offer [1-{}] (default 1): ", offers.len());
    use std::io::Write;
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let input = input.trim();

    let idx = if input.is_empty() {
        0
    } else {
        input
            .parse::<usize>()
            .context("invalid selection")?
            .checked_sub(1)
            .context("selection must be >= 1")?
    };

    offers
        .get(idx)
        .ok_or_else(|| anyhow::anyhow!("selection out of range"))
}

/// Full cloud mining start: search → select → provision → install → mine.
///
/// Called by `hrmw webminer cloud start`. Does everything in one flow.
pub async fn start(
    label: &str,
    machine_id: Option<u64>,
    wallet_db_path: &Path,
    ssh_key: &ed25519_dalek::SigningKey,
) -> Result<InstanceState> {
    let cfg = config::load_config()?;
    let api_key = config::resolve_api_key(&cfg)?;
    let client = VastClient::new(&api_key);

    // 1. Upload SSH key to Vast.ai account
    println!("[1/6] Uploading SSH key to Vast.ai...");
    let pubkey = ssh::ssh_public_key_string(ssh_key);
    client.upload_ssh_key(&pubkey).await?;

    // 2. Select offer
    let offer_id = if let Some(id) = machine_id {
        println!("[2/6] Using specified machine: {id}");
        id
    } else {
        println!("[2/6] Searching for best GPU offers...");
        let offers = client.find_best_offers().await?;
        if offers.is_empty() {
            anyhow::bail!("No GPU offers found. Check Vast.ai availability.");
        }
        print_offers_table(&offers);
        let selected = prompt_offer_selection(&offers)?;
        println!(
            "  Selected: {}x {} (${:.2}/hr, {:.1} TFLOPS)",
            selected.num_gpus,
            selected.gpu_name,
            selected.dph_total,
            selected.tflops()
        );
        selected.id
    };

    // 3. Create instance (no onstart — we install everything via SSH after boot)
    println!("[3/6] Creating instance...");
    let instance_id = client.create_instance(offer_id, "").await?;
    println!("  Instance: {instance_id}");

    // 4. Wait for running (5 min max, auto-destroy if stuck)
    println!("[4/6] Waiting for instance to start...");
    let instance = wait_for_running(&client, instance_id).await?;
    let (ssh_host, ssh_port) = instance
        .ssh_connection()
        .ok_or_else(|| anyhow::anyhow!("No SSH connection info"))?;
    println!("  SSH: root@{ssh_host}:{ssh_port}");

    // Wait for SSH to accept connections
    wait_for_ssh(ssh_key, &ssh_host, ssh_port).await?;

    // 5. Install GLIBC + hrmw via SSH
    println!("[5/6] Installing hrmw...");
    install_hrmw_remote(ssh_key, &ssh_host, ssh_port).await?;

    // Verify GPUs
    match ssh::exec(
        ssh_key,
        &ssh_host,
        ssh_port,
        &format!("{REMOTE_HRMW} webminer list-devices"),
    ) {
        Ok(output) => {
            for line in output.trim().lines() {
                println!("  {line}");
            }
        }
        Err(_) => println!("  GPU detection unavailable"),
    }

    // Upload the labeled webcash wallet
    println!("  Uploading mining wallet...");
    upload_file(ssh_key, &ssh_host, ssh_port, wallet_db_path, REMOTE_WALLET)?;

    // 6. Start mining
    println!("[6/6] Starting miner...");
    let _ = ssh::exec(
        ssh_key,
        &ssh_host,
        ssh_port,
        "mkdir -p /root/.harmoniis/wallet",
    );
    let cmd = format!("{REMOTE_HRMW} webminer run --accept-terms --webcash-wallet {REMOTE_WALLET}");
    ssh::exec_background(ssh_key, &ssh_host, ssh_port, &cmd)?;

    // Verify miner started
    tokio::time::sleep(std::time::Duration::from_secs(8)).await;
    let check = ssh::exec(ssh_key, &ssh_host, ssh_port, "pgrep -a hrmw")?;
    if check.trim().is_empty() {
        let log =
            ssh::exec(ssh_key, &ssh_host, ssh_port, "cat /root/miner.log").unwrap_or_default();
        // Auto-destroy on failure
        let _ = client.destroy_instance(instance_id).await;
        config::clear_state()?;
        anyhow::bail!("Miner failed to start. Instance destroyed.\n{log}");
    }

    // Show initial miner output
    if let Ok(log) = ssh::exec(ssh_key, &ssh_host, ssh_port, "head -25 /root/miner.log") {
        println!();
        for line in log.trim().lines() {
            println!("  {line}");
        }
    }

    // Save state
    let state = InstanceState {
        instance_id,
        offer_id,
        label: label.to_string(),
        ssh_host: ssh_host.clone(),
        ssh_port,
        gpu_name: instance.gpu_name.unwrap_or_else(|| "Unknown".to_string()),
        num_gpus: instance.num_gpus.unwrap_or(0),
        cost_per_hour: instance.dph_total.unwrap_or(0.0),
        started_at: chrono::Utc::now().to_rfc3339(),
    };
    config::save_state(&state)?;

    println!();
    println!("Mining started.");
    println!("  GPU: {}x {}", state.num_gpus, state.gpu_name);
    println!("  Cost: ${:.2}/hr", state.cost_per_hour);
    println!("  Status: hrmw webminer cloud status");
    println!("  Stop:   hrmw webminer cloud stop");

    Ok(state)
}

/// Stop mining and recover locally. Instance keeps running (charges continue).
pub async fn stop(state: &InstanceState, ssh_key: &ed25519_dalek::SigningKey) -> Result<()> {
    println!("Stopping miner on instance {}...", state.instance_id);
    let _ = ssh::exec(
        ssh_key,
        &state.ssh_host,
        state.ssh_port,
        "kill $(pgrep hrmw) 2>/dev/null || true",
    );
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    println!("Miner stopped.");
    println!();
    println!("Recovering mined webcash locally...");
    // Recovery happens in the CLI handler (needs wallet objects).
    // This function just stops the remote process.
    println!();
    println!("WARNING: Instance is still running. Vast.ai is still charging.");
    println!("  Use `hrmw webminer cloud destroy` to stop charges.");

    Ok(())
}

/// Destroy the instance. Stops charges.
pub async fn destroy(state: &InstanceState) -> Result<()> {
    let cfg = config::load_config()?;
    let api_key = config::resolve_api_key(&cfg)?;
    let client = VastClient::new(&api_key);

    println!("Destroying instance {}...", state.instance_id);
    client.destroy_instance(state.instance_id).await?;
    config::clear_state()?;
    println!("Instance destroyed. Charges stopped.");

    Ok(())
}

/// Show remote miner status.
pub async fn status(state: &InstanceState, ssh_key: &ed25519_dalek::SigningKey) -> Result<()> {
    let cfg = config::load_config()?;
    let api_key = config::resolve_api_key(&cfg)?;
    let client = VastClient::new(&api_key);

    let instance = client.get_instance(state.instance_id).await?;

    println!("Cloud Mining Status");
    println!("  Instance: {}", state.instance_id);
    println!(
        "  Status:   {}",
        instance.actual_status.as_deref().unwrap_or("unknown")
    );
    println!("  GPU:      {}x {}", state.num_gpus, state.gpu_name);
    println!("  Cost:     ${:.2}/hr", state.cost_per_hour);
    println!("  Started:  {}", state.started_at);
    println!();

    // Check miner process
    match ssh::exec(
        ssh_key,
        &state.ssh_host,
        state.ssh_port,
        "pgrep -a hrmw || echo 'NOT_RUNNING'",
    ) {
        Ok(output) if output.contains("NOT_RUNNING") => println!("Miner: NOT RUNNING"),
        Ok(_) => println!("Miner: RUNNING"),
        Err(e) => println!("Miner check: {e}"),
    }

    // Show miner log tail
    if let Ok(log) = ssh::exec(
        ssh_key,
        &state.ssh_host,
        state.ssh_port,
        "tail -10 /root/miner.log 2>/dev/null",
    ) {
        println!();
        println!("Last 10 lines:");
        for line in log.trim().lines() {
            println!("  {line}");
        }
    }

    Ok(())
}

/// Show local mining wallet info.
pub fn info(label: &str) {
    println!("Mining label: {label}");
    println!("Wallet: {label}_webcash.db");
    println!("Check balance: hrmw webcash info --label {label}");
    println!("Recover mined: hrmw webcash recover --label {label}");
    if let Ok(Some(state)) = config::load_state() {
        println!();
        println!("Active instance: {}", state.instance_id);
        println!("  GPU: {}x {}", state.num_gpus, state.gpu_name);
        println!("  Cost: ${:.2}/hr", state.cost_per_hour);
    } else {
        println!("No active cloud mining instance.");
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────

/// Upload a file to remote via SCP.
fn upload_file(
    ssh_key: &ed25519_dalek::SigningKey,
    host: &str,
    port: u16,
    local_path: &Path,
    remote_path: &str,
) -> Result<()> {
    let key_file = ssh::write_temp_key_file(ssh_key)?;
    let status = std::process::Command::new("scp")
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-i",
            &key_file.to_string_lossy(),
            "-P",
            &port.to_string(),
            &local_path.to_string_lossy(),
            &format!("root@{host}:{remote_path}"),
        ])
        .status()
        .context("scp failed")?;
    if !status.success() {
        anyhow::bail!("SCP upload failed");
    }
    Ok(())
}

async fn wait_for_running(client: &VastClient, instance_id: u64) -> Result<super::vast::Instance> {
    for i in 0..30 {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        match client.get_instance(instance_id).await {
            Ok(inst) if inst.is_running() => return Ok(inst),
            Ok(inst) => {
                let s = inst.actual_status.as_deref().unwrap_or("unknown");
                if i % 3 == 0 {
                    println!("  Status: {s}...");
                }
            }
            Err(e) if i > 5 => {
                let _ = client.destroy_instance(instance_id).await;
                return Err(e);
            }
            Err(_) => {}
        }
    }
    println!("  Instance did not start in 5 minutes — destroying...");
    let _ = client.destroy_instance(instance_id).await;
    config::clear_state()?;
    anyhow::bail!("Instance did not start. Destroyed to stop charges. Try a different offer.")
}

async fn wait_for_ssh(ssh_key: &ed25519_dalek::SigningKey, host: &str, port: u16) -> Result<()> {
    for _ in 0..30 {
        if let Ok(out) = ssh::exec(ssh_key, host, port, "echo ok") {
            if out.contains("ok") {
                return Ok(());
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
    anyhow::bail!("SSH not ready after 2.5 minutes")
}

async fn install_hrmw_remote(
    ssh_key: &ed25519_dalek::SigningKey,
    host: &str,
    port: u16,
) -> Result<()> {
    // Install hrmw (binary built for GLIBC 2.31 — no upgrade needed)
    println!("  Installing hrmw...");
    ssh::exec(
        ssh_key,
        host,
        port,
        "mkdir -p /root/.harmoniis/wallet /root/.local/bin && curl --proto '=https' --tlsv1.2 -sSf https://harmoniis.com/wallet/install | sh",
    )
    .context("hrmw install failed")?;

    // Verify
    let version = ssh::exec(ssh_key, host, port, &format!("{REMOTE_HRMW} --version"))
        .context("hrmw verification failed")?;
    println!("  {}", version.trim());

    Ok(())
}
