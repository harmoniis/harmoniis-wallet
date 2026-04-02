//! Cloud mining orchestration — deploy, start, stop, destroy, status, info.

use anyhow::{Context, Result};
use std::path::Path;

use super::config::{self, InstanceState};
use super::ssh;
use super::vast::VastClient;

const REMOTE_WALLET_PATH: &str = "/root/mining_webcash.db";
const REMOTE_HRMW: &str = "/root/.local/bin/hrmw";

/// The onstart script that runs when the Vast.ai instance boots.
/// Installs hrmw from the install script.
fn onstart_script() -> String {
    r#"#!/bin/bash
set -e
mkdir -p /root/.harmoniis/wallet /root/.local/bin
# Try install script first, fallback to direct download
curl --proto '=https' --tlsv1.2 -sSf https://harmoniis.com/wallet/install | sh || {
  apt-get update -qq && apt-get install -yqq wget
  wget -q -O /tmp/hrmw.tar.gz "https://github.com/harmoniis/harmoniis-wallet/releases/latest/download/harmoniis-wallet-linux-x86_64.tar.gz" || \
  wget -q -O /tmp/hrmw.tar.gz "https://github.com/harmoniis/harmoniis-wallet/releases/download/v0.1.44/harmoniis-wallet-0.1.44-linux-x86_64.tar.gz"
  tar xzf /tmp/hrmw.tar.gz -C /tmp/
  cp /tmp/harmoniis-wallet-*/bin/hrmw /root/.local/bin/hrmw
  chmod +x /root/.local/bin/hrmw
}
"#
    .to_string()
}

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

/// Prompt user to select an offer (1-indexed). Returns the selected offer.
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
        .ok_or_else(|| anyhow::anyhow!("selection {idx} out of range"))
}

/// Deploy: search for offers, let user pick, create instance.
pub async fn deploy(
    label: &str,
    machine_id: Option<u64>,
    wallet_db_path: &Path,
) -> Result<InstanceState> {
    let cfg = config::load_config()?;
    let api_key = config::resolve_api_key(&cfg)?;
    let client = VastClient::new(&api_key);

    // Ensure SSH key exists and is uploaded
    println!("Ensuring SSH key...");
    let pubkey = ssh::ensure_ssh_key()?;
    client.upload_ssh_key(&pubkey).await?;

    // Select offer
    let offer_id = if let Some(id) = machine_id {
        println!("Using specified machine: {id}");
        id
    } else {
        println!("Searching for best GPU offers...");
        let offers = client.find_best_offers().await?;
        if offers.is_empty() {
            anyhow::bail!("No GPU offers found. Check Vast.ai availability and your filters.");
        }
        print_offers_table(&offers);
        let selected = prompt_offer_selection(&offers)?;
        println!(
            "Selected: {}x {} (${:.2}/hr, {:.1} TFLOPS, {:.1} FLOPS/$)",
            selected.num_gpus,
            selected.gpu_name,
            selected.dph_total,
            selected.tflops(),
            selected.flops_per_dollar()
        );
        selected.id
    };

    // Create instance
    println!("Creating instance...");
    let instance_id = client.create_instance(offer_id, &onstart_script()).await?;
    println!("Instance created: {instance_id}");

    // Wait for running
    println!("Waiting for instance to start (this may take a few minutes)...");
    let instance = wait_for_running(&client, instance_id).await?;
    let (ssh_host, ssh_port) = instance
        .ssh_connection()
        .ok_or_else(|| anyhow::anyhow!("Instance has no SSH connection info"))?;
    println!("Instance running: ssh root@{ssh_host} -p {ssh_port}");

    // Wait for SSH to be ready
    println!("Waiting for SSH...");
    wait_for_ssh(&ssh_host, ssh_port).await?;

    // Upload the isolated webcash wallet
    println!("Uploading mining wallet...");
    ssh::scp_upload(wallet_db_path, &ssh_host, ssh_port, REMOTE_WALLET_PATH)?;
    println!("Wallet uploaded to {REMOTE_WALLET_PATH}");

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
    println!("Cloud mining instance deployed.");
    println!("  Instance: {instance_id}");
    println!("  GPU: {}x {}", state.num_gpus, state.gpu_name);
    println!("  Cost: ${:.2}/hr", state.cost_per_hour);
    println!();
    println!("Next: hrmw webminer cloud start");

    Ok(state)
}

/// Start mining on a deployed instance.
pub async fn start(state: &InstanceState) -> Result<()> {
    println!(
        "Starting miner on instance {} ({})...",
        state.instance_id, state.ssh_host
    );

    // Wait a bit for hrmw install from onstart to complete
    let hrmw_check = ssh::ssh_exec(
        &state.ssh_host,
        state.ssh_port,
        &format!("test -x {REMOTE_HRMW} && echo 'FOUND' || echo 'NOT_FOUND'"),
    )?;
    if hrmw_check.contains("NOT_FOUND") {
        println!("hrmw not yet installed, waiting for onstart script...");
        for _ in 0..30 {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            let check = ssh::ssh_exec(
                &state.ssh_host,
                state.ssh_port,
                &format!("test -x {REMOTE_HRMW} && echo 'FOUND' || echo 'NOT_FOUND'"),
            )?;
            if !check.contains("NOT_FOUND") {
                break;
            }
            print!(".");
            use std::io::Write;
            std::io::stdout().flush()?;
        }
        println!();
    }

    // Ensure the miner's data directory exists on the remote
    let _ = ssh::ssh_exec(
        &state.ssh_host,
        state.ssh_port,
        "mkdir -p /root/.harmoniis/wallet",
    );

    // Verify CUDA / GPU availability
    println!("Checking GPU availability...");
    match ssh::ssh_exec(
        &state.ssh_host,
        state.ssh_port,
        "nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader 2>&1",
    ) {
        Ok(output) => {
            println!("GPUs detected:");
            for line in output.trim().lines() {
                println!("  {line}");
            }
        }
        Err(_) => {
            println!("WARNING: nvidia-smi not available — GPUs may not be accessible.");
            println!("  The miner may fall back to CPU. Check instance GPU setup.");
        }
    }

    // Also check what hrmw sees
    match ssh::ssh_exec(
        &state.ssh_host,
        state.ssh_port,
        &format!("{REMOTE_HRMW} webminer list-devices 2>&1"),
    ) {
        Ok(output) => {
            println!("hrmw GPU detection:");
            for line in output.trim().lines() {
                println!("  {line}");
            }
        }
        Err(e) => println!("hrmw device detection failed: {e}"),
    }

    // Start the miner
    let cmd =
        format!("{REMOTE_HRMW} webminer run --accept-terms --webcash-wallet {REMOTE_WALLET_PATH}");
    ssh::ssh_exec_background(&state.ssh_host, state.ssh_port, &cmd)?;

    // Verify the miner actually started
    println!("Verifying miner process...");
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let check = ssh::ssh_exec(
        &state.ssh_host,
        state.ssh_port,
        "pgrep -a hrmw || echo 'NOT_RUNNING'",
    )?;
    if check.contains("NOT_RUNNING") {
        let log = ssh::ssh_exec(
            &state.ssh_host,
            state.ssh_port,
            "cat /root/miner.log 2>/dev/null || echo 'No log'",
        )
        .unwrap_or_default();
        anyhow::bail!("Miner failed to start. Remote log:\n{log}");
    }

    // Show first few lines of miner output
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    if let Ok(log) = ssh::ssh_exec(
        &state.ssh_host,
        state.ssh_port,
        "head -20 /root/miner.log 2>/dev/null",
    ) {
        println!();
        println!("Miner output:");
        for line in log.lines() {
            println!("  {line}");
        }
    }

    println!();
    println!("Miner started and verified.");
    println!("  Check status: hrmw webminer cloud status");
    println!("  Stop mining:  hrmw webminer cloud stop");

    Ok(())
}

/// Stop mining on the remote instance and download the wallet.
pub async fn stop_and_download(state: &InstanceState, local_wallet_path: &Path) -> Result<()> {
    println!("Stopping miner on instance {}...", state.instance_id);
    let _ = ssh::ssh_exec(
        &state.ssh_host,
        state.ssh_port,
        "pkill -f 'hrmw webminer' || pkill -f '.local/bin/hrmw' || true",
    );
    // Wait for process to exit and wallet to flush
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    println!("Miner stopped.");
    println!();
    println!("⚠  Instance is still running and Vast.ai is still charging.");
    println!("   Use `hrmw webminer cloud destroy` to stop charges.");
    println!();

    // Download the wallet with mined webcash
    println!("Downloading mining wallet...");
    ssh::scp_download(
        &state.ssh_host,
        state.ssh_port,
        REMOTE_WALLET_PATH,
        local_wallet_path,
    )
    .context("Failed to download mining wallet from remote")?;
    println!("Wallet downloaded to {}", local_wallet_path.display());

    Ok(())
}

/// Stop miner, download wallet, destroy instance.
pub async fn destroy(state: &InstanceState, local_wallet_path: &Path) -> Result<()> {
    let cfg = config::load_config()?;
    let api_key = config::resolve_api_key(&cfg)?;
    let client = VastClient::new(&api_key);

    // Stop and download wallet
    stop_and_download(state, local_wallet_path).await?;

    // Destroy the instance
    println!("Destroying instance {}...", state.instance_id);
    client.destroy_instance(state.instance_id).await?;

    // Clear state
    config::clear_state()?;
    println!("Instance destroyed.");

    Ok(())
}

/// Get remote miner status and wallet info.
pub async fn status(state: &InstanceState) -> Result<()> {
    let cfg = config::load_config()?;
    let api_key = config::resolve_api_key(&cfg)?;
    let client = VastClient::new(&api_key);

    // Instance info from Vast.ai
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

    // Check if miner process is running
    match ssh::ssh_exec(
        &state.ssh_host,
        state.ssh_port,
        "pgrep -a hrmw || echo 'NOT_RUNNING'",
    ) {
        Ok(output) => {
            if output.contains("NOT_RUNNING") {
                println!("Remote miner: NOT RUNNING");
            } else {
                println!("Remote miner: RUNNING");
                for line in output.lines() {
                    println!("  PID: {line}");
                }
            }
        }
        Err(e) => println!("Process check unavailable: {e}"),
    }

    println!();

    // Show miner log tail (contains live hashrate, solutions, difficulty)
    match ssh::ssh_exec(
        &state.ssh_host,
        state.ssh_port,
        "tail -15 /root/miner.log 2>/dev/null || echo 'No miner log'",
    ) {
        Ok(output) => {
            println!("Miner log (last 15 lines):");
            for line in output.lines() {
                println!("  {line}");
            }
        }
        Err(e) => println!("Miner log unavailable: {e}"),
    }

    println!();

    // Remote wallet balance via sqlite3 (works without our custom --label flag)
    let balance_cmd = format!(
        "sqlite3 {REMOTE_WALLET_PATH} \"SELECT COALESCE(SUM(amount), 0) FROM webcash WHERE spent = 0;\" 2>/dev/null || echo '0'"
    );
    match ssh::ssh_exec(&state.ssh_host, state.ssh_port, &balance_cmd) {
        Ok(output) => {
            let raw = output.trim();
            println!("Remote mining wallet balance: {raw} wats");
        }
        Err(e) => println!("Remote wallet balance unavailable: {e}"),
    }

    Ok(())
}

/// Show local mining wallet info.
pub fn info(label: &str) {
    println!("Mining label: {label}");
    println!("Use `hrmw webcash info --label {label}` to see local balance.");
    if let Ok(Some(state)) = config::load_state() {
        println!();
        println!("Active instance: {}", state.instance_id);
        println!("  GPU: {}x {}", state.num_gpus, state.gpu_name);
        println!("  Cost: ${:.2}/hr", state.cost_per_hour);
        println!("  Started: {}", state.started_at);
    } else {
        println!("No active cloud mining instance.");
    }
}

async fn wait_for_running(client: &VastClient, instance_id: u64) -> Result<super::vast::Instance> {
    // 5 minutes max — if the instance doesn't start, destroy it to stop charges.
    for i in 0..30 {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        match client.get_instance(instance_id).await {
            Ok(instance) if instance.is_running() => return Ok(instance),
            Ok(instance) => {
                let status = instance.actual_status.as_deref().unwrap_or("unknown");
                if i % 3 == 0 {
                    println!("  Status: {status}...");
                }
            }
            Err(e) => {
                if i > 5 {
                    // Destroy to stop charges before bailing.
                    let _ = client.destroy_instance(instance_id).await;
                    return Err(e);
                }
            }
        }
    }
    // Auto-destroy to stop charges.
    println!("Instance did not start in 5 minutes — destroying to stop charges...");
    let _ = client.destroy_instance(instance_id).await;
    config::clear_state()?;
    anyhow::bail!("Instance did not start. Destroyed to stop charges. Try a different offer.")
}

async fn wait_for_ssh(host: &str, port: u16) -> Result<()> {
    for _ in 0..30 {
        match ssh::ssh_exec(host, port, "echo ok") {
            Ok(out) if out.contains("ok") => return Ok(()),
            _ => tokio::time::sleep(std::time::Duration::from_secs(5)).await,
        }
    }
    anyhow::bail!("SSH not ready after 2.5 minutes")
}
