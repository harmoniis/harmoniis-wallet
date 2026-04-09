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
        "{:<3} {:<5} {:<16} {:>10} {:>8} {:>10} {:>8}",
        "#", "GPUs", "GPU", "TFLOPS", "$/hr", "TF/$/hr", "Score"
    );
    println!("{}", "-".repeat(75));
    for (i, o) in offers.iter().enumerate() {
        println!(
            "{:<3} {:<5} {:<16} {:>10.1} {:>8.2} {:>10.1} {:>8.0}",
            i + 1,
            format!("{}x", o.num_gpus),
            o.gpu_name,
            o.tflops(),
            o.dph_total,
            o.flops_per_dollar(),
            o.composite_score(),
        );
    }
    println!();
}

/// Print a summary of active cloud mining instances.
pub fn print_active_summary(instances: &[config::InstanceState]) {
    if instances.is_empty() {
        return;
    }
    println!("Active cloud mining instances:");
    println!(
        "{:<3} {:<20} {:<6} {:<16} {:>8}",
        "#", "Label", "GPUs", "GPU", "$/hr"
    );
    println!("{}", "-".repeat(60));
    for (i, s) in instances.iter().enumerate() {
        println!(
            "{:<3} {:<20} {:<6} {:<16} {:>8.2}",
            i + 1,
            s.label,
            format!("{}x", s.num_gpus),
            s.gpu_name,
            s.cost_per_hour,
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
        println!("[2/6] Using offer: {id}");
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

    // Wait for SSH to accept connections.
    // If SSH fails, destroy instance to stop charges.
    if let Err(e) = wait_for_ssh(ssh_key, &ssh_host, ssh_port).await {
        eprintln!("  SSH failed — destroying instance to stop charges...");
        let _ = client.destroy_instance(instance_id).await;
        config::remove_instance(instance_id).ok();
        return Err(e);
    }

    // 5. Install GLIBC + hrmw via SSH.
    // If install fails, destroy instance to stop charges.
    println!("[5/6] Installing hrmw...");
    if let Err(e) = install_hrmw_remote(ssh_key, &ssh_host, ssh_port).await {
        eprintln!("  Install failed — destroying instance to stop charges...");
        let _ = client.destroy_instance(instance_id).await;
        config::remove_instance(instance_id).ok();
        return Err(e);
    }

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
    let cmd =
        format!("{REMOTE_HRMW} webminer start -f --accept-terms --webcash-wallet {REMOTE_WALLET}");
    ssh::exec_background(ssh_key, &ssh_host, ssh_port, &cmd)?;

    // Verify miner started
    tokio::time::sleep(std::time::Duration::from_secs(8)).await;
    let check = ssh::exec(ssh_key, &ssh_host, ssh_port, "pgrep -a hrmw")?;
    if check.trim().is_empty() {
        let log =
            ssh::exec(ssh_key, &ssh_host, ssh_port, "cat /root/miner.log").unwrap_or_default();
        // Auto-destroy on failure
        let _ = client.destroy_instance(instance_id).await;
        config::remove_instance(instance_id)?;
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
    config::add_instance(&state)?;

    println!();
    println!("Mining started.");
    println!("  GPU: {}x {}", state.num_gpus, state.gpu_name);
    println!("  Cost: ${:.2}/hr", state.cost_per_hour);
    println!("  Status: hrmw webminer cloud status");
    println!("  Stop:   hrmw webminer cloud stop");

    Ok(state)
}

/// Stop a cloud mining instance and collect its solution files.
///
/// 1. Download solution files while miner is still running (safety snapshot)
/// 2. SIGINT — miner drains submitter queue, writes final solutions to disk
/// 3. Wait up to 15s for graceful exit, then force kill
/// 4. Download again — catches solutions written between step 1 and shutdown
///
/// No retry here — `hrmw webminer collect` handles server submission.
/// No recovery here — caller handles `recover + transfer`.
pub async fn stop(state: &InstanceState, ssh_key: &ed25519_dalek::SigningKey) -> Result<()> {
    println!(
        "Stopping instance {} ({}x {})...",
        state.instance_id, state.num_gpus, state.gpu_name
    );

    // Step 1: Snapshot solution files while miner is still running.
    println!("  Downloading solution files...");
    append_remote_logs(ssh_key, &state.ssh_host, state.ssh_port);

    // Step 2: SIGINT — miner enters graceful shutdown, drains submitter queue.
    let _ = ssh::exec(
        ssh_key,
        &state.ssh_host,
        state.ssh_port,
        "kill -INT $(pgrep -f 'webminer start') 2>/dev/null || true",
    );

    // Step 3: Wait for miner to exit (up to 15s, then force kill).
    for i in 0..8 {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        if ssh::exec(
            ssh_key,
            &state.ssh_host,
            state.ssh_port,
            "pgrep -f 'webminer start' > /dev/null 2>&1 && echo R || echo S",
        )
        .unwrap_or_default()
        .contains('S')
        {
            break;
        }
        if i == 7 {
            let _ = ssh::exec(
                ssh_key,
                &state.ssh_host,
                state.ssh_port,
                "kill -9 $(pgrep -f 'webminer start') 2>/dev/null || true",
            );
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }

    // Step 4: Download again — miner may have written more solutions during drain.
    append_remote_logs(ssh_key, &state.ssh_host, state.ssh_port);

    println!("  Instance {} stopped.", state.instance_id);
    Ok(())
}

// ── Shared: append remote log files to local with deduplication ────────────

const REMOTE_LOG_FILES: [&str; 3] = [
    "/root/.harmoniis/wallet/miner_pending_solutions.log",
    "/root/.harmoniis/wallet/miner_pending_keeps.log",
    "/root/.harmoniis/wallet/miner_overflow_solutions.log",
];

/// Append remote solution/keep files to local copies.
/// Deduplicates by line — safe to call repeatedly from any number of instances.
/// Returns the number of new solution lines synced.
pub fn append_remote_logs(ssh_key: &ed25519_dalek::SigningKey, host: &str, port: u16) -> usize {
    let local_dir = dirs_next::home_dir()
        .unwrap_or_default()
        .join(".harmoniis")
        .join("wallet");
    let _ = std::fs::create_dir_all(&local_dir);
    let mut total_new = 0usize;

    for remote_file in REMOTE_LOG_FILES {
        let filename = std::path::Path::new(remote_file)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();

        let content = match ssh::exec(
            ssh_key,
            host,
            port,
            &format!("cat {remote_file} 2>/dev/null"),
        ) {
            Ok(c) if !c.trim().is_empty() => c,
            _ => continue,
        };

        let local_path = local_dir.join(&*filename);
        use std::collections::HashSet;
        let existing: HashSet<String> = std::fs::read_to_string(&local_path)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.to_string())
            .collect();

        let mut new_count = 0usize;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&local_path)
        {
            use std::io::Write;
            for line in content.lines() {
                if !line.trim().is_empty() && !existing.contains(line) {
                    let _ = writeln!(f, "{}", line);
                    new_count += 1;
                }
            }
        }
        if new_count > 0 {
            total_new += new_count;
        }
    }
    total_new
}

/// Backup pending files from a running instance (called by `cloud status`).
pub fn backup_pending_files(state: &InstanceState, ssh_key: &ed25519_dalek::SigningKey) {
    append_remote_logs(ssh_key, &state.ssh_host, state.ssh_port);
}

/// Destroy a single instance. Stops charges.
pub async fn destroy(state: &InstanceState) -> Result<()> {
    let cfg = config::load_config()?;
    let api_key = config::resolve_api_key(&cfg)?;
    let client = VastClient::new(&api_key);

    println!("Destroying instance {}...", state.instance_id);
    client.destroy_instance(state.instance_id).await?;
    config::remove_instance(state.instance_id)?;
    println!("Instance destroyed. Charges stopped.");

    Ok(())
}

/// Destroy all instances.
pub async fn destroy_all() -> Result<()> {
    let instances = config::load_instances()?;
    if instances.is_empty() {
        println!("No active instances.");
        return Ok(());
    }
    let cfg = config::load_config()?;
    let api_key = config::resolve_api_key(&cfg)?;
    let client = VastClient::new(&api_key);

    for state in &instances {
        println!("Destroying instance {}...", state.instance_id);
        let _ = client.destroy_instance(state.instance_id).await;
    }
    config::clear_state()?;
    println!(
        "All {} instances destroyed. Charges stopped.",
        instances.len()
    );

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
    let running = match ssh::exec(
        ssh_key,
        &state.ssh_host,
        state.ssh_port,
        "pgrep -a hrmw || echo 'NOT_RUNNING'",
    ) {
        Ok(output) if output.contains("NOT_RUNNING") => {
            println!("  Miner:    NOT RUNNING");
            false
        }
        Ok(_) => {
            println!("  Miner:    RUNNING");
            true
        }
        Err(e) => {
            println!("  Miner:    unknown ({e})");
            false
        }
    };

    // Extract mining stats from the latest log line
    if running {
        if let Ok(log) = ssh::exec(
            ssh_key,
            &state.ssh_host,
            state.ssh_port,
            "grep 'speed=' /root/miner.log | tail -1",
        ) {
            let line = log.trim();
            if !line.is_empty() {
                // Parse speed= and solutions= from the line
                let speed = line
                    .split("speed=")
                    .nth(1)
                    .map(|s| {
                        let mut parts = s.split_whitespace();
                        let num = parts.next().unwrap_or("?");
                        let unit = parts.next().unwrap_or("");
                        format!("{num} {unit}")
                    })
                    .unwrap_or_else(|| "?".to_string());
                let solutions = line
                    .split("solutions=")
                    .nth(1)
                    .and_then(|s| s.split_whitespace().next())
                    .unwrap_or("?");
                println!("  Speed:      {speed}");
                println!("  Solutions:  {solutions} (collected/found)");
            }
        }
        // Count total mined
        if let Ok(count) = ssh::exec(
            ssh_key,
            &state.ssh_host,
            state.ssh_port,
            "grep -c 'SOLUTION FOUND' /root/miner.log 2>/dev/null || echo 0",
        ) {
            let n = count.trim();
            if n != "0" {
                let amount = n.parse::<u64>().unwrap_or(0) as f64 * 185.546875;
                println!("  Mined:    {n} solutions ({amount} webcash)");
            }
        }
    }

    // Show last few log lines
    if let Ok(log) = ssh::exec(
        ssh_key,
        &state.ssh_host,
        state.ssh_port,
        "tail -5 /root/miner.log 2>/dev/null",
    ) {
        let trimmed = log.trim();
        if !trimmed.is_empty() {
            println!();
            for line in trimmed.lines() {
                println!("  {line}");
            }
        }
    }

    // Silently backup pending files on every status check.
    backup_pending_files(state, ssh_key);

    Ok(())
}

/// Show mining wallet info — remote balance if instance is active, otherwise local.
pub fn info(label: &str, ssh_key: &ed25519_dalek::SigningKey, instance: Option<&InstanceState>) {
    println!("Mining label: {label}");
    println!("Wallet: {label}_webcash.db");
    let state = instance
        .cloned()
        .or_else(|| config::load_state().ok().flatten());
    if let Some(state) = state {
        println!();
        println!("Active instance: {}", state.instance_id);
        println!("  GPU: {}x {}", state.num_gpus, state.gpu_name);
        println!("  Cost: ${:.2}/hr", state.cost_per_hour);
        println!("  Started: {}", state.started_at);

        // Show remote mining stats from log
        if let Ok(output) = ssh::exec(
            ssh_key,
            &state.ssh_host,
            state.ssh_port,
            "echo \"solutions=$(grep -c 'SOLUTION FOUND' /root/miner.log 2>/dev/null || echo 0)\"; echo \"inserted=$(grep -c 'Inserted amount' /root/miner.log 2>/dev/null || echo 0)\"; grep 'speed=' /root/miner.log 2>/dev/null | tail -1",
        ) {
            println!();
            println!("Remote mining:");
            for line in output.trim().lines() {
                if line.starts_with("solutions=") {
                    let n: u64 = line.trim_start_matches("solutions=").parse().unwrap_or(0);
                    let amount = n as f64 * 185.546875;
                    println!("  Solutions found: {n} ({amount} webcash)");
                } else if line.starts_with("inserted=") {
                    let n: u64 = line.trim_start_matches("inserted=").parse().unwrap_or(0);
                    let amount = n as f64 * 185.546875;
                    println!("  Inserted to wallet: {n} ({amount} webcash)");
                } else if line.contains("speed=") {
                    let speed = line.split("speed=").nth(1).and_then(|s| s.split_whitespace().next()).unwrap_or("?");
                    println!("  Current speed: {speed}");
                }
            }
        }
    } else {
        println!("No active cloud mining instance.");
        println!();
        println!("Recover mined webcash: hrmw webcash recover --label {label}");
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
    // 36 × 5s = 3 minutes max. If not running in 3 min, bad machine — move on.
    for i in 0..36 {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
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
    println!("  Instance did not start in 3 minutes — destroying...");
    let _ = client.destroy_instance(instance_id).await;
    config::remove_instance(instance_id).ok();
    anyhow::bail!("Instance did not start. Destroyed to stop charges. Try a different offer.")
}

async fn wait_for_ssh(ssh_key: &ed25519_dalek::SigningKey, host: &str, port: u16) -> Result<()> {
    // 24 × 5s = 2 minutes max. Instance is running — SSH should be fast.
    for _ in 0..24 {
        if let Ok(out) = ssh::exec(ssh_key, host, port, "echo ok") {
            if out.contains("ok") {
                return Ok(());
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
    anyhow::bail!("SSH not ready after 2 minutes")
}

async fn install_hrmw_remote(
    ssh_key: &ed25519_dalek::SigningKey,
    host: &str,
    port: u16,
) -> Result<()> {
    // Step 1: Ensure system deps are available.
    // - UBUNTU24: has GLIBC 2.39 + libssl3, but may lack NVRTC
    // - Ubuntu 20.04: needs GLIBC + libssl upgrade from noble repo
    println!("  Checking system dependencies...");
    let glibc_check =
        ssh::exec(ssh_key, host, port, "ldd --version 2>&1 | head -1").unwrap_or_default();
    if glibc_check.contains("2.31") || glibc_check.contains("2.35") {
        println!("  Upgrading GLIBC + libssl...");
        ssh::exec(
            ssh_key,
            host,
            port,
            "echo 'deb http://archive.ubuntu.com/ubuntu noble main' >> /etc/apt/sources.list && apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -yqq libc6 libssl3t64",
        )
        .context("GLIBC/libssl upgrade failed")?;
    }

    // Ensure NVRTC is available (needed for CUDA kernel compilation at runtime).
    // UBUNTU24 template has libcuda but not libnvrtc.
    // Try multiple package names to cover CUDA 12.x and 13.x.
    let nvrtc_check =
        ssh::exec(ssh_key, host, port, "ldconfig -p | grep libnvrtc").unwrap_or_default();
    if nvrtc_check.is_empty() {
        println!("  Installing CUDA NVRTC...");
        ssh::exec(
            ssh_key,
            host,
            port,
            concat!(
                "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -yqq ",
                "cuda-nvrtc-13-0 2>/dev/null || ",
                "DEBIAN_FRONTEND=noninteractive apt-get install -yqq cuda-nvrtc-12-6 2>/dev/null || ",
                "DEBIAN_FRONTEND=noninteractive apt-get install -yqq cuda-nvrtc-12-4 2>/dev/null || ",
                "DEBIAN_FRONTEND=noninteractive apt-get install -yqq cuda-nvrtc-12-0 2>/dev/null || ",
                "DEBIAN_FRONTEND=noninteractive apt-get install -yqq libnvrtc12 2>/dev/null || true",
            ),
        )
        .ok();
    }

    // Step 2: Install hrmw
    println!("  Installing hrmw...");
    ssh::exec(
        ssh_key,
        host,
        port,
        "mkdir -p /root/.harmoniis/wallet /root/.local/bin && curl --proto '=https' --tlsv1.2 -sSf https://harmoniis.com/wallet/install | sh",
    )
    .context("hrmw install failed")?;

    // Step 3: Verify — if it fails, show the actual error for debugging.
    match ssh::exec(
        ssh_key,
        host,
        port,
        &format!("{REMOTE_HRMW} --version 2>&1"),
    ) {
        Ok(version) if version.contains("hrmw") => {
            println!("  {}", version.trim());
        }
        Ok(output) => {
            // Binary exists but can't run — likely missing shared library.
            let ldd = ssh::exec(
                ssh_key,
                host,
                port,
                &format!("ldd {REMOTE_HRMW} 2>&1 | grep 'not found'"),
            )
            .unwrap_or_default();
            let glibc =
                ssh::exec(ssh_key, host, port, "ldd --version 2>&1 | head -1").unwrap_or_default();
            anyhow::bail!(
                "hrmw binary cannot run.\n  Output: {}\n  Missing libs: {}\n  GLIBC: {}",
                output.trim(),
                if ldd.trim().is_empty() {
                    "none"
                } else {
                    ldd.trim()
                },
                glibc.trim()
            );
        }
        Err(e) => {
            anyhow::bail!("hrmw verification failed: {e}");
        }
    }

    Ok(())
}
