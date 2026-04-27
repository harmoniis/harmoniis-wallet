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
/// If `difficulty` is Some, shows estimated hash rate and capacity warnings.
pub fn print_offers_table(offers: &[super::vast::Offer]) {
    print_offers_table_with_difficulty(offers, None);
}

pub fn print_offers_table_with_difficulty(offers: &[super::vast::Offer], difficulty: Option<u32>) {
    use super::vast::Offer;
    println!();
    if let Some(d) = difficulty {
        let max_bw = Offer::max_useful_mem_bw(d);
        let max_ghs = Offer::max_useful_hashrate_ghs(d);
        println!(
            "  Difficulty={d} → max useful: {:.0} GB/s mem_bw ({:.1} GH/s, {:.2} sol/s, w/ 115-min forward-date buffer over 10-min burst)",
            max_bw,
            max_ghs,
            Offer::max_solutions_per_sec()
        );
        println!(
            "{:<3} {:<5} {:<16} {:>7} {:>7} {:>7} {:>6} {:>7}",
            "#", "GPUs", "GPU", "BW", "~GH/s", "$/hr", "sol/s", "Score"
        );
        println!("{}", "-".repeat(68));
        for (i, o) in offers.iter().enumerate() {
            let est_ghs = o.estimated_hashrate_ghs();
            let sol_s = o.estimated_solutions_per_sec(d);
            let score = o.capacity_score(d);
            let bw_total = o.gpu_mem_bw * o.num_gpus as f64;
            let flag = if bw_total > max_bw * 0.8 { " ⚠" } else { "" };
            println!(
                "{:<3} {:<5} {:<16} {:>7.0} {:>7.1} {:>7.2} {:>6.2} {:>7.0}{}",
                i + 1,
                format!("{}x", o.num_gpus),
                o.gpu_name,
                bw_total,
                est_ghs,
                o.dph_total,
                sol_s,
                score,
                flag,
            );
        }
        if offers.is_empty() {
            println!();
            println!("  ⚠ All offers exceed server capacity at difficulty {d}.");
            println!("  Wait for higher difficulty or use a smaller GPU.");
        }
    } else {
        println!(
            "{:<3} {:<5} {:<16} {:>7} {:>7} {:>7}",
            "#", "GPUs", "GPU", "BW", "~GH/s", "$/hr"
        );
        println!("{}", "-".repeat(55));
        for (i, o) in offers.iter().enumerate() {
            println!(
                "{:<3} {:<5} {:<16} {:>7.0} {:>7.1} {:>7.2}",
                i + 1,
                format!("{}x", o.num_gpus),
                o.gpu_name,
                o.gpu_mem_bw * o.num_gpus as f64,
                o.estimated_hashrate_ghs(),
                o.dph_total,
            );
        }
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

/// Dev mode cloud start: provision → install build tools → clone → build.
///
/// Does NOT start mining. The developer SSHs in and runs manually.
/// Called by `hrmw webminer cloud start --env dev`.
pub async fn start_dev(
    label: &str,
    machine_id: Option<u64>,
    wallet_db_path: &Path,
    ssh_key: &ed25519_dalek::SigningKey,
) -> Result<InstanceState> {
    let cfg = config::load_config()?;
    let api_key = config::resolve_api_key(&cfg)?;
    let client = VastClient::new(&api_key);

    // 1. Upload SSH key
    println!("[1/5] Uploading SSH key to Vast.ai...");
    let pubkey = ssh::ssh_public_key_string(ssh_key);
    client.upload_ssh_key(&pubkey).await?;

    // Fetch current difficulty for capacity-aware offer scoring.
    let difficulty = {
        use crate::miner::protocol::MiningProtocol;
        match MiningProtocol::new(webylib::NetworkMode::Production.base_url()) {
            Ok(p) => match p.get_target().await {
                Ok(t) => {
                    println!("  Current mining difficulty: {}", t.difficulty);
                    Some(t.difficulty)
                }
                Err(_) => None,
            },
            Err(_) => None,
        }
    };

    // 2. Select offer
    let offer_id = if let Some(id) = machine_id {
        println!("[2/5] Using offer: {id}");
        id
    } else {
        println!("[2/5] Searching for best GPU offers...");
        let mut offers = client.find_best_offers().await?;
        if offers.is_empty() {
            anyhow::bail!("No GPU offers found.");
        }
        // When difficulty is known: filter out overcapacity, sort by capacity_score.
        if let Some(d) = difficulty {
            offers.retain(|o| !o.exceeds_capacity(d));
            offers.sort_by(|a, b| {
                b.capacity_score(d)
                    .partial_cmp(&a.capacity_score(d))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            if offers.is_empty() {
                anyhow::bail!(
                    "No offers within reporting capacity at difficulty {d} (max {:.0} GB/s mem_bw). Wait for higher difficulty.",
                    super::vast::Offer::max_useful_mem_bw(d)
                );
            }
        }
        print_offers_table_with_difficulty(&offers, difficulty);
        let selected = prompt_offer_selection(&offers)?;
        println!(
            "  Selected: {}x {} (${:.2}/hr, ~{:.1} GH/s, ~{:.2} sol/s)",
            selected.num_gpus,
            selected.gpu_name,
            selected.dph_total,
            selected.estimated_hashrate_ghs(),
            difficulty
                .map(|d| selected.estimated_solutions_per_sec(d))
                .unwrap_or(0.0)
        );
        selected.id
    };

    // 3. Create instance
    println!("[3/5] Creating instance...");
    let instance_id = client.create_instance(offer_id, "").await?;
    println!("  Instance: {instance_id}");

    // 4. Wait for running + SSH
    println!("[4/5] Waiting for instance to start...");
    let instance = wait_for_running(&client, instance_id).await?;
    let (ssh_host, ssh_port) = instance
        .ssh_connection()
        .ok_or_else(|| anyhow::anyhow!("No SSH connection info"))?;
    println!("  SSH: root@{ssh_host}:{ssh_port}");

    if let Err(e) = wait_for_ssh(ssh_key, &ssh_host, ssh_port).await {
        eprintln!("  SSH failed — destroying instance...");
        let _ = client.destroy_instance(instance_id).await;
        config::remove_instance(instance_id).ok();
        return Err(e);
    }

    // 5. Install dev environment: build tools, Rust, clone repo, build
    println!("[5/5] Setting up dev environment (clone + build from source)...");
    if let Err(e) = install_dev_remote(ssh_key, &ssh_host, ssh_port).await {
        eprintln!("  Dev setup failed — destroying instance...");
        let _ = client.destroy_instance(instance_id).await;
        config::remove_instance(instance_id).ok();
        return Err(e);
    }

    // Upload the labeled webcash wallet
    println!("  Uploading mining wallet...");
    upload_file(ssh_key, &ssh_host, ssh_port, wallet_db_path, REMOTE_WALLET)?;
    let _ = ssh::exec(
        ssh_key,
        &ssh_host,
        ssh_port,
        "mkdir -p /root/.harmoniis/wallet",
    );

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

    // Save state (same as production — allows cloud stop/destroy later)
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
    println!("Dev instance ready (mining NOT started).");
    println!("  GPU: {}x {}", state.num_gpus, state.gpu_name);
    println!("  Cost: ${:.2}/hr", state.cost_per_hour);

    Ok(state)
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

    // 2. Select offer (with difficulty-aware capacity scoring)
    let offer_id = if let Some(id) = machine_id {
        println!("[2/6] Using offer: {id}");
        id
    } else {
        println!("[2/6] Searching for best GPU offers...");
        let mut offers = client.find_best_offers().await?;
        if offers.is_empty() {
            anyhow::bail!("No GPU offers found. Check Vast.ai availability.");
        }
        // Use difficulty from the already-fetched target if available.
        let difficulty = {
            use crate::miner::protocol::MiningProtocol;
            match MiningProtocol::new(webylib::NetworkMode::Production.base_url()) {
                Ok(p) => p.get_target().await.ok().map(|t| t.difficulty),
                Err(_) => None,
            }
        };
        // Filter out overcapacity, sort by capacity_score.
        if let Some(d) = difficulty {
            offers.retain(|o| !o.exceeds_capacity(d));
            offers.sort_by(|a, b| {
                b.capacity_score(d)
                    .partial_cmp(&a.capacity_score(d))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            if offers.is_empty() {
                anyhow::bail!("No offers within reporting capacity at difficulty {d}.");
            }
        }
        print_offers_table_with_difficulty(&offers, difficulty);
        let selected = prompt_offer_selection(&offers)?;
        println!(
            "  Selected: {}x {} (${:.2}/hr, ~{:.1} GH/s)",
            selected.num_gpus,
            selected.gpu_name,
            selected.dph_total,
            selected.estimated_hashrate_ghs()
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

    // Verify miner started (wallet insertion is built-in, no separate process)
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
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

/// Restart an exited/stopped instance — re-provision from the Vast.ai side,
/// wait for SSH, re-install hrmw, re-upload wallet, start miner.
pub async fn restart(
    state: &InstanceState,
    wallet_db_path: &Path,
    ssh_key: &ed25519_dalek::SigningKey,
) -> Result<()> {
    let cfg = config::load_config()?;
    let api_key = config::resolve_api_key(&cfg)?;
    let client = VastClient::new(&api_key);

    // 1. Restart via API
    println!("[1/4] Restarting instance {}...", state.instance_id);
    client.restart_instance(state.instance_id).await?;

    // 2. Wait for running + SSH
    println!("[2/4] Waiting for instance to come back...");
    let instance = wait_for_running(&client, state.instance_id).await?;
    let (ssh_host, ssh_port) = instance
        .ssh_connection()
        .ok_or_else(|| anyhow::anyhow!("No SSH connection info after restart"))?;
    println!("  SSH: root@{ssh_host}:{ssh_port}");
    wait_for_ssh(ssh_key, &ssh_host, ssh_port).await?;

    // 3. Re-install hrmw (fresh boot = clean filesystem)
    println!("[3/4] Installing hrmw...");
    install_hrmw_remote(ssh_key, &ssh_host, ssh_port).await?;

    // Re-upload wallet
    println!("  Uploading mining wallet...");
    upload_file(ssh_key, &ssh_host, ssh_port, wallet_db_path, REMOTE_WALLET)?;

    // 4. Start miner
    println!("[4/4] Starting miner...");
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
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let check = ssh::exec(ssh_key, &ssh_host, ssh_port, "pgrep -a hrmw")?;
    if check.trim().is_empty() {
        let log =
            ssh::exec(ssh_key, &ssh_host, ssh_port, "cat /root/miner.log").unwrap_or_default();
        anyhow::bail!("Miner failed to start after restart.\n{log}");
    }

    // Update state with new SSH info (IP/port may change after restart)
    config::remove_instance(state.instance_id)?;
    let new_state = InstanceState {
        instance_id: state.instance_id,
        offer_id: state.offer_id,
        label: state.label.clone(),
        ssh_host,
        ssh_port,
        gpu_name: instance.gpu_name.unwrap_or_else(|| state.gpu_name.clone()),
        num_gpus: instance.num_gpus.unwrap_or(state.num_gpus),
        cost_per_hour: instance.dph_total.unwrap_or(state.cost_per_hour),
        started_at: chrono::Utc::now().to_rfc3339(),
    };
    config::add_instance(&new_state)?;

    println!("  Instance {} restarted and mining.", state.instance_id);
    Ok(())
}

/// Check live status of instances against Vast.ai API.
/// Returns (running, exited/stopped) split.
pub async fn check_live_status(
    instances: &[InstanceState],
) -> Result<(Vec<InstanceState>, Vec<InstanceState>)> {
    let cfg = config::load_config()?;
    let api_key = config::resolve_api_key(&cfg)?;
    let client = VastClient::new(&api_key);

    let mut running = Vec::new();
    let mut dead = Vec::new();

    for inst in instances {
        match client.get_instance(inst.instance_id).await {
            Ok(live) => {
                if live.is_running() {
                    running.push(inst.clone());
                } else {
                    let status = live.status().unwrap_or_else(|| "unknown".to_string());
                    eprintln!(
                        "  Instance {} ({}) — status: {}",
                        inst.instance_id, inst.label, status
                    );
                    dead.push(inst.clone());
                }
            }
            Err(_) => {
                // API error (destroyed, expired, etc.) — treat as dead.
                eprintln!(
                    "  Instance {} ({}) — not found on Vast.ai",
                    inst.instance_id, inst.label
                );
                dead.push(inst.clone());
            }
        }
    }

    Ok((running, dead))
}

/// Stop a cloud mining instance and collect its solution files.
///
/// 1. Download solution files while miner is still running (safety snapshot)
/// 2. SIGINT — miner drains submitter queue, writes final solutions to disk
/// 3. Wait up to 15s for graceful exit, then force kill
/// 4. Download again — catches solutions written between step 1 and shutdown
///
/// No retry here — `hrmw webminer collect` handles server submission.
/// No recovery here — caller handles `recover + transfer` and (optionally) a
/// local collect daemon to drain `miner_pending_solutions.log` at the user's
/// home rate, free of cloud cost.
///
/// Design: download files → SIGINT briefly → SIGKILL → final snapshot. We
/// **deliberately do not wait for cloud-side drain**. With forward-dated
/// timestamps (v0.1.125+), every queued solution stays valid in the server's
/// ±2h window for up to 230 minutes from mining time, so local replay can
/// drain hundreds of solutions over hours at no cloud cost. The previous
/// 600-second drain-on-cloud loop wasted ~$0.18 per stop on cheap instances
/// and 2+ hours of cloud cost on saturated 4× 4090 sessions.
pub async fn stop(state: &InstanceState, ssh_key: &ed25519_dalek::SigningKey) -> Result<()> {
    println!(
        "Stopping instance {} ({}x {})...",
        state.instance_id, state.num_gpus, state.gpu_name
    );

    // Step 1: Snapshot solution files while miner is still running. This
    // captures the in-flight queue — every line here will be replayed locally.
    println!("  Downloading solution files...");
    let n0 = append_remote_logs(ssh_key, &state.ssh_host, state.ssh_port);
    if n0 > 0 {
        println!("  ({n0} new lines synced)");
    }

    // Step 2: SIGINT — give the miner a brief moment to flush in-memory state
    // to disk. We then SIGKILL unconditionally; we do not block waiting for a
    // cloud-side drain (that work happens locally now).
    //
    // pkill matches against the binary's absolute path so the kill command's
    // own bash wrapper (which would otherwise contain "webminer start" in
    // argv) does NOT match itself — this was a long-standing bug that made
    // the polling loop never see the miner exit.
    let _ = ssh::exec(
        ssh_key,
        &state.ssh_host,
        state.ssh_port,
        "pkill -INT -f /root/.local/bin/hrmw 2>/dev/null || true",
    );
    println!("  Waiting 5s for clean shutdown signal...");
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // Step 3: SIGKILL anything still alive. Idempotent — succeeds even if the
    // SIGINT already terminated the process.
    let _ = ssh::exec(
        ssh_key,
        &state.ssh_host,
        state.ssh_port,
        "pkill -KILL -f /root/.local/bin/hrmw 2>/dev/null || true",
    );
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // Step 4: Re-snapshot to capture anything written between SIGINT and
    // SIGKILL (e.g. accepts that landed during the 5s grace window).
    println!("  Downloading solution files (post-shutdown)...");
    let n1 = append_remote_logs(ssh_key, &state.ssh_host, state.ssh_port);
    if n1 > 0 {
        println!("  ({n1} new lines synced)");
    }

    println!("  Miner exited on instance {}.", state.instance_id);
    Ok(())
}

// ── Shared: append remote log files to local with deduplication ────────────

const REMOTE_LOG_FILES: [&str; 4] = [
    "/root/.harmoniis/wallet/miner_pending_solutions.log",
    "/root/.harmoniis/wallet/miner_pending_keeps.log",
    "/root/.harmoniis/wallet/miner_overflow_solutions.log",
    // Orphans (server-rejected or stale-skipped) preserve the audit trail
    // for diagnostics. Without this, cloud-destroy throws away the record
    // of every solution that hit a 504/5xx or was past-target — and the
    // operator can't tell whether a session was healthy or degraded.
    "/root/.harmoniis/wallet/miner_orphans.log",
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

/// PID file recording the currently-running local collect daemon, if any.
/// Used to prevent multiple daemons racing on the same `pending_solutions.log`
/// when an operator runs several `cloud stop` / `cloud destroy` calls in a
/// short window.
pub fn collect_pid_file() -> std::path::PathBuf {
    dirs_next::home_dir()
        .unwrap_or_default()
        .join(".harmoniis")
        .join("wallet")
        .join("collect.pid")
}

/// Returns `Some(pid)` if a collect daemon is currently alive (PID file
/// present AND the recorded PID is a running `hrmw` process). Otherwise
/// returns `None` and sweeps the stale PID file.
pub fn live_collect_daemon_pid() -> Option<u32> {
    let pf = collect_pid_file();
    let pid: u32 = std::fs::read_to_string(&pf)
        .ok()?
        .trim()
        .parse()
        .ok()?;
    // `kill -0 <pid>` returns 0 if the process exists and we own it.
    // `pgrep -af` confirms the PID matches an `hrmw` process (not some
    // unrelated PID that recycled after our daemon exited).
    let alive = std::process::Command::new("pgrep")
        .args(["-af", "hrmw webminer collect"])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .any(|l| l.split_whitespace().next() == Some(&pid.to_string()))
        })
        .unwrap_or(false);
    if alive {
        Some(pid)
    } else {
        let _ = std::fs::remove_file(&pf);
        None
    }
}

/// Spawn the local collect daemon **only if one isn't already running**.
/// Caller passes how many entries were just queued so we can decide whether
/// the start is necessary at all (no point spawning if the queue is empty).
///
/// Single source of truth for the daemon-spawn logic — replaces the
/// duplicated inline spawn blocks in `CloudCmd::Stop` and `CloudCmd::Destroy`
/// that previously created a new process every time, leading to N-way races
/// between siblings on the same `pending_solutions.log`.
pub fn ensure_collect_daemon(pending: usize) -> anyhow::Result<()> {
    if pending == 0 {
        return Ok(());
    }
    if let Some(pid) = live_collect_daemon_pid() {
        println!(
            "{pending} uncollected solutions found — collect daemon already running (PID {pid}), not spawning a duplicate."
        );
        return Ok(());
    }
    println!("{pending} uncollected solutions found — starting collect daemon...");
    let exe = std::env::current_exe()?;
    let child = std::process::Command::new(exe)
        .args(["webminer", "collect"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let pid = child.id();
    let _ = std::fs::write(collect_pid_file(), pid.to_string());
    println!("Collect daemon started (PID {pid}).");
    Ok(())
}

/// Print local collect-daemon status: PID, total queued solutions, count
/// already accepted (or duplicates skipped), remaining to drain, and the
/// approximate ETA at the documented healthy server pace (~30 s / accept).
///
/// Called at the end of `cloud status` so the operator sees the local replay
/// progress alongside any active cloud instances.
pub fn print_local_collect_status() {
    let local_dir = dirs_next::home_dir()
        .unwrap_or_default()
        .join(".harmoniis")
        .join("wallet");

    let pending_path = local_dir.join("miner_pending_solutions.log");
    let keeps_path = local_dir.join("miner_pending_keeps.log");
    let orphans_path = local_dir.join("miner_orphans.log");

    let count_lines = |p: &std::path::Path| -> usize {
        std::fs::read_to_string(p)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count()
    };

    let pending_total = count_lines(&pending_path);
    let keeps_total = count_lines(&keeps_path);
    let orphans_total = count_lines(&orphans_path);

    let daemon_pid = live_collect_daemon_pid().map(|p| p.to_string());

    if pending_total == 0 && daemon_pid.is_none() {
        return;
    }

    println!();
    println!("Local replay (drain-from-disk):");
    if let Some(pid) = &daemon_pid {
        println!("  Daemon:     RUNNING (PID {pid})");
    } else if pending_total > 0 {
        println!(
            "  Daemon:     not running — `hrmw webminer collect` to drain {pending_total} queued"
        );
    } else {
        println!("  Daemon:     not running (queue drained)");
    }
    println!("  Queue:      {pending_total} solutions in pending_solutions.log");
    println!(
        "  Lifetime:   {keeps_total} keeps accepted, {orphans_total} orphans (across all sessions)"
    );
    // ETA assumes worst case: every queued line is fresh and gets submitted.
    // Stale-skip and keeps-dedupe will both shorten the actual drain — this
    // is an upper bound at the documented healthy server pace (~30 s/accept).
    if pending_total > 0 {
        let eta_secs = pending_total as u64 * 30;
        let h = eta_secs / 3600;
        let m = (eta_secs % 3600) / 60;
        if h > 0 {
            println!("  ETA:        ≤{h}h {m}m at 30 s/accept (less if many already in keeps log)");
        } else {
            println!("  ETA:        ≤{m}m at 30 s/accept (less if many already in keeps log)");
        }
    }
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
        instance.status().unwrap_or_else(|| "unknown".to_string())
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
    // No hard timeout — only fail on error/exited status.
    // Docker image pulls on uncached machines can take 10+ minutes.
    let mut api_errors = 0u32;
    let mut prev_msg = String::new();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        match client.get_instance(instance_id).await {
            Ok(inst) if inst.is_running() => return Ok(inst),
            Ok(inst) => {
                api_errors = 0;
                let status_str = inst.status().unwrap_or_else(|| "unknown".to_string());
                let s = status_str.as_str();
                let msg = inst.status_msg.as_deref().unwrap_or("");

                // Fail on terminal states or error messages.
                let is_error_state = s == "exited" || s == "error" || s == "offline";
                let has_error_msg = msg.contains("Error response")
                    || msg.contains("OCI runtime")
                    || msg.contains("failed to create");
                if is_error_state || has_error_msg {
                    let _ = client.destroy_instance(instance_id).await;
                    config::remove_instance(instance_id).ok();
                    anyhow::bail!("Instance failed (status: {s}). Destroyed.\n  {msg}");
                }

                // Print status when it changes (avoid flooding identical lines).
                let current = format!("{s} — {msg}");
                if current != prev_msg {
                    if msg.is_empty() {
                        println!("  Status: {s}...");
                    } else {
                        println!("  Status: {s} — {msg}");
                    }
                    prev_msg = current;
                }
            }
            Err(_) => {
                api_errors += 1;
                // 10 consecutive API failures (50s) = give up.
                if api_errors >= 10 {
                    let _ = client.destroy_instance(instance_id).await;
                    config::remove_instance(instance_id).ok();
                    anyhow::bail!("Lost contact with Vast.ai API. Instance destroyed.");
                }
            }
        }
    }
}

async fn wait_for_ssh(ssh_key: &ed25519_dalek::SigningKey, host: &str, port: u16) -> Result<()> {
    // Poll every 3s for up to 5 minutes. CUDA Docker images take longer to boot.
    for i in 0..100 {
        if let Ok(out) = ssh::exec(ssh_key, host, port, "echo ok") {
            if out.contains("ok") {
                return Ok(());
            }
        }
        if i % 10 == 9 {
            eprintln!(
                "  SSH not ready yet, waiting... ({:.0}s)",
                (i + 1) as f64 * 3.0
            );
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
    anyhow::bail!("SSH not ready after 5 minutes")
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
        match ssh::exec(
            ssh_key,
            host,
            port,
            "echo 'deb http://archive.ubuntu.com/ubuntu noble main' >> /etc/apt/sources.list && apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -yqq libc6 libssl3t64 2>&1",
        ) {
            Ok(_out) => {
                let glibc_after = ssh::exec(ssh_key, host, port, "ldd --version 2>&1 | head -1")
                    .unwrap_or_default();
                println!("  GLIBC after upgrade: {}", glibc_after.trim());
            }
            Err(e) => {
                eprintln!("  GLIBC upgrade failed: {e}");
                anyhow::bail!("GLIBC/libssl upgrade failed: {e}");
            }
        }
    }

    // Ensure NVRTC is available (needed for CUDA kernel compilation at runtime).
    // UBUNTU24 template has libcuda but not libnvrtc, AND no NVIDIA apt repo.
    // The remote script bootstraps the apt repo first, then installs nvrtc.
    let nvrtc_check =
        ssh::exec(ssh_key, host, port, "ldconfig -p | grep libnvrtc").unwrap_or_default();
    if nvrtc_check.is_empty() {
        println!("  Installing CUDA NVRTC...");
        let cmd = crate::miner::cuda_install::nvrtc_remote_install_script(13);
        ssh::exec(ssh_key, host, port, &cmd).ok();
    }

    // Step 2: Install hrmw
    println!("  Installing hrmw...");
    match ssh::exec(
        ssh_key,
        host,
        port,
        "mkdir -p /root/.harmoniis/wallet /root/.local/bin && curl --proto '=https' --tlsv1.2 -sSf https://harmoniis.com/wallet/install 2>&1 | sh 2>&1",
    ) {
        Ok(out) => {
            for line in out.trim().lines().rev().take(5).collect::<Vec<_>>().into_iter().rev() {
                println!("  {line}");
            }
        }
        Err(e) => {
            eprintln!("  Install script output: {e}");
            anyhow::bail!("hrmw install failed: {e}");
        }
    }

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

/// Install dev environment: build tools, Rust, gcc-10, clone repo, build.
///
/// Unlike `install_hrmw_remote` which downloads a pre-built binary,
/// this installs a full build toolchain so the developer can edit code
/// on the remote machine, rebuild in ~1.5 minutes, and test interactively.
async fn install_dev_remote(
    ssh_key: &ed25519_dalek::SigningKey,
    host: &str,
    port: u16,
) -> Result<()> {
    // Step 1: Install build tools + gcc-10/g++-10.
    // gcc-10 is required because aws-lc-sys (dep of rustls) has a bug
    // detection check that rejects gcc-9. Ubuntu 20.04 ships gcc-9.
    println!("  Installing build tools...");
    ssh::exec(
        ssh_key,
        host,
        port,
        "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -yqq \
         build-essential pkg-config libssl-dev git gcc-10 g++-10 2>&1 | tail -3",
    )
    .map_err(|e| anyhow::anyhow!("Build tools install failed: {e}"))?;

    // Ensure NVRTC is available (needed for CUDA kernel compilation).
    // The remote script bootstraps NVIDIA's apt repo if missing — fresh
    // cloud images ship with the driver but no apt source for cuda-nvrtc-*.
    let nvrtc_check =
        ssh::exec(ssh_key, host, port, "ldconfig -p | grep libnvrtc").unwrap_or_default();
    if nvrtc_check.is_empty() {
        println!("  Installing CUDA NVRTC...");
        let cmd = crate::miner::cuda_install::nvrtc_remote_install_script(13);
        ssh::exec(ssh_key, host, port, &cmd).ok();
    }

    // Step 2: Install Rust toolchain.
    println!("  Installing Rust toolchain...");
    ssh::exec(
        ssh_key,
        host,
        port,
        "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y 2>&1 | tail -3",
    )
    .map_err(|e| anyhow::anyhow!("Rust install failed: {e}"))?;

    // Step 3: Clone the repo.
    println!("  Cloning harmoniis-wallet...");
    ssh::exec(
        ssh_key,
        host,
        port,
        "source ~/.cargo/env && \
         git clone https://github.com/harmoniis/harmoniis-wallet.git /root/hw 2>&1 | tail -3",
    )
    .map_err(|e| anyhow::anyhow!("Git clone failed: {e}"))?;

    // Step 4: Build release.
    println!("  Building release (this takes ~2 minutes)...");
    ssh::exec(
        ssh_key,
        host,
        port,
        // Build with the cuda feature on top of default `native` so the dev
        // binary matches release CI's `native,cuda` matrix and can drive the
        // NVIDIA backend on the cloud GPU. Without `--features cuda`, the
        // `cuda` feature gates in `enumerate_all_devices()` compile out and
        // hrmw silently reports "No mining devices found" even though the
        // driver and libnvrtc are present.
        "source ~/.cargo/env && cd /root/hw && \
         CC=gcc-10 CXX=g++-10 cargo build --release --features cuda 2>&1 | tail -5",
    )
    .map_err(|e| anyhow::anyhow!("Cargo build failed: {e}"))?;

    // Step 5: Install the binary.
    println!("  Installing hrmw...");
    ssh::exec(
        ssh_key,
        host,
        port,
        "mkdir -p /root/.local/bin && cp /root/hw/target/release/hrmw /root/.local/bin/hrmw",
    )
    .map_err(|e| anyhow::anyhow!("Binary install failed: {e}"))?;

    // Verify.
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
            anyhow::bail!("hrmw binary cannot run: {}", output.trim());
        }
        Err(e) => {
            anyhow::bail!("hrmw verification failed: {e}");
        }
    }

    Ok(())
}
