//! Daemon process management: start, stop, status, and the main mining loop.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::protocol::MiningProtocol;
use super::sha256::Sha256Midstate;
use super::stats::{self, StatsTracker};
use super::work_unit::{NonceTable, WorkUnit};

use super::{select_backend, select_backend_for_devices, BackendChoice, MinerConfig};

fn default_wallet_root() -> PathBuf {
    if let Ok(path) = std::env::var("HARMONIIS_WALLET_ROOT") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".harmoniis").join("wallet")
}

/// PID file path: wallet-root/miner.pid
pub fn pid_file_path() -> PathBuf {
    default_wallet_root().join("miner.pid")
}

/// Log file path: wallet-root/miner.log
pub fn log_file_path() -> PathBuf {
    default_wallet_root().join("miner.log")
}

/// Orphan log (solutions that were rejected): wallet-root/miner_orphans.log
pub fn orphan_log_path() -> PathBuf {
    default_wallet_root().join("miner_orphans.log")
}

/// Pending keep log (accepted on server but not persisted locally yet): wallet-root/miner_pending_keeps.log
pub fn pending_keep_log_path() -> PathBuf {
    default_wallet_root().join("miner_pending_keeps.log")
}

/// Pending solutions file — solutions persisted to disk BEFORE async submission.
/// If the miner crashes, these can be retried on next startup.
pub fn pending_solutions_path() -> PathBuf {
    default_wallet_root().join("miner_pending_solutions.log")
}

/// Overflow solutions — solutions that could not be submitted during burst
/// drain on shutdown. Can be retried with `hrmw webminer collect`.
pub fn overflow_solutions_path() -> PathBuf {
    default_wallet_root().join("miner_overflow_solutions.log")
}

/// Retry unsubmitted solutions from miner_pending_solutions.log.
///
/// Reads the file, checks each against miner_pending_keeps.log (already accepted),
/// submits unsubmitted ones to the server, and inserts accepted keeps into the wallet.
/// Returns (submitted, already_accepted, failed).
/// Retry unsubmitted solutions from miner_pending_solutions.log.
/// Uses 4 parallel threads for faster submission (~28 solutions/min vs 7/min).
/// Returns (submitted, already_accepted, failed).
pub fn retry_pending_solutions(server_url: &str) -> anyhow::Result<(usize, usize, usize)> {
    retry_pending_solutions_inner(server_url, false)
}

/// Like `retry_pending_solutions` but prints per-solution feedback to stdout.
pub fn retry_pending_solutions_verbose(server_url: &str) -> anyhow::Result<(usize, usize, usize)> {
    retry_pending_solutions_inner(server_url, true)
}

fn retry_pending_solutions_inner(server_url: &str, verbose: bool) -> anyhow::Result<(usize, usize, usize)> {
    use super::protocol::MiningProtocol;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let solutions_path = pending_solutions_path();
    if !solutions_path.exists() {
        return Ok((0, 0, 0));
    }

    let solutions_text = std::fs::read_to_string(&solutions_path)?;
    if solutions_text.trim().is_empty() {
        return Ok((0, 0, 0));
    }

    // Load already-accepted keep secrets to skip them.
    let keeps_path = pending_keep_log_path();
    let accepted_keeps: HashSet<String> = if keeps_path.exists() {
        std::fs::read_to_string(&keeps_path)
            .unwrap_or_default()
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    } else {
        HashSet::new()
    };

    // Parse all entries, filter already-accepted.
    struct PendingEntry {
        preimage: String,
        hash: [u8; 32],
        keep_secret: String,
    }

    let mut pre_already = 0usize;
    let mut entries = Vec::new();
    for line in solutions_text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 3 {
            continue;
        }
        let keep_secret = parts[2].to_string();
        if accepted_keeps.contains(&keep_secret) {
            pre_already += 1;
            continue;
        }
        let hash_hex = parts[1].trim_start_matches("0x");
        if let Ok(b) = hex::decode(hash_hex) {
            if b.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                entries.push(PendingEntry {
                    preimage: parts[0].to_string(),
                    hash: arr,
                    keep_secret,
                });
            }
        }
    }

    if entries.is_empty() {
        if pre_already > 0 {
            let _ = std::fs::write(&solutions_path, "");
        }
        return Ok((0, pre_already, 0));
    }

    let total = entries.len();

    // Both modes use 4 parallel threads.
    // Verbose mode additionally prints per-solution progress.
    const RETRY_THREADS: usize = 4;
    let submitted = Arc::new(AtomicUsize::new(0));
    let already = Arc::new(AtomicUsize::new(pre_already));
    let failed = Arc::new(AtomicUsize::new(0));
    let progress = Arc::new(AtomicUsize::new(0));
    let entries = Arc::new(entries);
    let keeps_path = Arc::new(keeps_path);
    let server_url = server_url.to_string();

    let mut handles = Vec::new();
    let chunk_size = (total + RETRY_THREADS - 1) / RETRY_THREADS;

    for t in 0..RETRY_THREADS {
        let start = t * chunk_size;
        let end = (start + chunk_size).min(total);
        if start >= total {
            break;
        }
        let entries = entries.clone();
        let submitted = submitted.clone();
        let already = already.clone();
        let failed = failed.clone();
        let progress = progress.clone();
        let keeps_path = keeps_path.clone();
        let server_url = server_url.clone();

        handles.push(std::thread::spawn(move || {
            let proto = match MiningProtocol::new(&server_url) {
                Ok(p) => p,
                Err(_) => return,
            };
            for i in start..end {
                let entry = &entries[i];
                let n = progress.fetch_add(1, Ordering::Relaxed) + 1;
                match proto.submit_report_blocking(&entry.preimage, &entry.hash) {
                    Ok(_) => {
                        submitted.fetch_add(1, Ordering::Relaxed);
                        let _ = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(&*keeps_path)
                            .and_then(|mut f| {
                                use std::io::Write;
                                writeln!(f, "{}", entry.keep_secret)
                            });
                        if verbose {
                            let preview = &entry.keep_secret[..entry.keep_secret.len().min(24)];
                            println!("  [{n}/{total}] Submitted  {preview}...");
                        }
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        if msg.contains("Didn't use a new secret") {
                            already.fetch_add(1, Ordering::Relaxed);
                            if verbose {
                                println!("  [{n}/{total}] Already accepted");
                            }
                        } else {
                            failed.fetch_add(1, Ordering::Relaxed);
                            if verbose {
                                println!("  [{n}/{total}] Failed: {msg}");
                            }
                        }
                    }
                }
            }
        }));
    }

    for h in handles {
        let _ = h.join();
    }

    let s = submitted.load(Ordering::Relaxed);
    let a = already.load(Ordering::Relaxed);
    let f = failed.load(Ordering::Relaxed);

    if s > 0 || a > 0 {
        let _ = std::fs::write(&solutions_path, "");
    }

    Ok((s, a, f))
}

/// Check if a miner process is already running.
pub fn is_running() -> Option<u32> {
    let pid_path = pid_file_path();
    if !pid_path.exists() {
        return None;
    }
    let pid_str = std::fs::read_to_string(&pid_path).ok()?;
    let pid: u32 = pid_str.trim().parse().ok()?;

    // Check if process is alive
    #[cfg(unix)]
    {
        // kill -0 checks if process exists without sending a signal
        let result = unsafe { libc::kill(pid as i32, 0) };
        if result == 0 {
            Some(pid)
        } else {
            // Stale PID file — clean up
            let _ = std::fs::remove_file(&pid_path);
            None
        }
    }
    #[cfg(not(unix))]
    {
        // Verify the process is actually alive via `tasklist`.
        let alive = std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
            .unwrap_or(false);
        if alive {
            Some(pid)
        } else {
            let _ = std::fs::remove_file(&pid_path);
            None
        }
    }
}

/// Start the miner as a detached background process.
pub fn start(config: &MinerConfig) -> anyhow::Result<()> {
    if let Some(pid) = is_running() {
        anyhow::bail!("miner already running (PID {})", pid);
    }

    // Ensure ~/.harmoniis/ exists
    let dir = pid_file_path().parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&dir)?;

    let log_file = std::fs::File::create(log_file_path())?;
    let log_err = log_file.try_clone()?;

    let exe = std::env::current_exe()?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("webminer")
        .arg("run")
        .arg("--server")
        .arg(&config.server_url)
        .arg("--backend")
        .arg(config.backend.as_cli_str())
        .arg("--max-difficulty")
        .arg(config.max_difficulty.to_string());

    if let Some(cpu_threads) = config.cpu_threads {
        cmd.arg("--cpu-threads").arg(cpu_threads.to_string());
    }

    if config.backend == BackendChoice::Cpu {
        cmd.arg("--cpu-only");
    }
    if config.accept_terms {
        cmd.arg("--accept-terms");
    }
    if let Some(ref devices) = config.devices {
        let s: Vec<String> = devices.iter().map(|d| d.to_string()).collect();
        cmd.arg("--device").arg(s.join(","));
    }

    // Pass wallet paths
    cmd.arg("--wallet")
        .arg(&config.wallet_path)
        .arg("--webcash-wallet")
        .arg(&config.webcash_wallet_path);

    cmd.stdout(log_file)
        .stderr(log_err)
        .stdin(std::process::Stdio::null());

    // Detach child process from parent's console/session.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        cmd.creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS);
    }

    let child = cmd.spawn()?;
    let pid = child.id();

    std::fs::write(pid_file_path(), pid.to_string())?;
    println!("Miner started (PID: {})", pid);
    println!("Log: {}", log_file_path().display());

    Ok(())
}

/// Stop the running miner.
pub fn stop() -> anyhow::Result<()> {
    let pid = match is_running() {
        Some(pid) => pid,
        None => {
            println!("No miner running.");
            return Ok(());
        }
    };

    #[cfg(unix)]
    {
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    // Wait for process to exit (up to 5 seconds)
    for _ in 0..50 {
        if is_running().is_none() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Clean up PID file
    let _ = std::fs::remove_file(pid_file_path());

    if is_running().is_some() {
        println!(
            "Miner (PID {}) did not stop gracefully, may need manual kill.",
            pid
        );
    } else {
        println!("Miner stopped (PID {}).", pid);
    }

    Ok(())
}

/// Show miner status.
pub fn status() -> anyhow::Result<()> {
    match is_running() {
        Some(pid) => {
            println!("Miner running (PID: {})", pid);

            let status_path = stats::status_file_path();
            if status_path.exists() {
                let json = std::fs::read_to_string(&status_path)?;
                let s: stats::MinerStats = serde_json::from_str(&json)?;
                println!("  Backend:    {}", s.backend);
                println!(
                    "  Hash rate:  {}",
                    stats::format_hash_rate(s.hash_rate_mhs * 1_000_000.0)
                );
                println!("  Attempts:   {}", s.total_attempts);
                println!(
                    "  Solutions:  {} found, {} accepted",
                    s.solutions_found, s.solutions_accepted
                );
                println!("  Difficulty: {}", s.difficulty);
                println!("  Uptime:     {}s", s.uptime_secs);
                let hps = s.hash_rate_mhs * 1_000_000.0;
                println!("  ETA:        {}", stats::estimate_time(hps, s.difficulty));
            } else {
                println!("  (no stats available yet)");
            }
        }
        None => {
            println!("No miner running.");
        }
    }
    Ok(())
}

/// The actual mining loop (called by `hrmw webminer run`).
pub async fn run_mining_loop(config: MinerConfig) -> anyhow::Result<()> {
    println!("Webcash miner starting...");
    println!("Server: {}", config.server_url);

    // Set up SIGTERM handler
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let shutdown = shutdown.clone();
        signal_hook::flag::register(signal_hook::consts::SIGTERM, shutdown.clone())?;
        signal_hook::flag::register(signal_hook::consts::SIGINT, shutdown)?;
    }

    // Write PID file (for the `run` process itself)
    let pid = std::process::id();
    std::fs::write(pid_file_path(), pid.to_string())?;

    // Select backend
    let backend = if let Some(ref devices) = config.devices {
        select_backend_for_devices(devices).await?
    } else {
        select_backend(config.backend, config.cpu_threads).await?
    };
    let chunk_size = backend.max_batch_hint();
    let pipeline_depth = backend.recommended_pipeline_depth().clamp(1, 1024);
    println!("Mining setup:");
    println!("  backend_mode={}", config.backend.as_cli_str());
    println!("  backend_name={}", backend.name());
    println!("  nonce_chunk_size={}", chunk_size);
    println!("  workunit_pipeline_depth={}", pipeline_depth);
    println!(
        "  cpu_system_threads={}",
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    );
    for line in backend.startup_summary() {
        println!("  {}", line);
    }

    // Initialize protocol client (Arc-shared with background submitter)
    let protocol = Arc::new(MiningProtocol::new(&config.server_url)?);

    // Initialize stats
    let tracker = Arc::new(StatsTracker::new(backend.name()));
    let status_path = stats::status_file_path();

    let pending_keep_path = pending_keep_log_path();
    println!("Webcash wallet: {}", config.webcash_wallet_path.display());
    println!("Pending keep log: {}", pending_keep_path.display());

    // Initialize nonce table (shared across all work units)
    let nonce_table = NonceTable::new();

    // Fetch initial target
    println!("Fetching mining target...");
    let mut target = protocol.get_target().await?;
    tracker.set_difficulty(target.difficulty);
    println!(
        "  difficulty={} mining_amount={} subsidy={} epoch={}",
        target.difficulty, target.mining_amount, target.subsidy_amount, target.epoch
    );

    let mut last_stats_print = std::time::Instant::now();
    let target_refresh_interval = std::time::Duration::from_secs(15);
    let stats_print_interval = std::time::Duration::from_secs(5);
    let mut work_unit_timer;
    let mut pending_work_units: Option<Vec<WorkUnit>> = None;
    let shared_target = Arc::new(std::sync::RwLock::new(target.clone()));

    // ── Subprocess reporter (N independent clients, separate address space) ──
    //
    // Spawns `hrmw webminer report-worker` as a child process. Solutions are
    // piped to its stdin (sub-microsecond write, zero allocation). The child
    // runs N independent HTTP clients, each with its own TCP connection —
    // simulating N separate miners. Server processes them in parallel.
    //
    // Why subprocess: ANY in-process threads (even idle reqwest::blocking)
    // cause TLB shootdowns from malloc/free that stall CUDA dispatch.
    // 3 threads = -3 GH/s, 64 threads = -78 GH/s. Subprocess = ZERO impact.
    //
    // Why N clients: At 100 GH/s, 1.46 solutions/sec × 7s/report = 10.2
    // concurrent connections minimum. 12 clients = 1.71 reports/sec headroom.
    // Each client has its own TCP connection — server sees 12 independent miners.
    // Auto-scale reporter clients based on GPU count.
    // Constraint: webcash.org nginx has 60s gateway timeout. Server processes
    // ~1 report/7s. Max concurrent before 504: 60/7 ≈ 8.
    // With N GPUs: need ~N concurrent connections (each GPU ≈ 1 solution/10s).
    // Add small buffer for bursts. Clamped to 3..20 range.
    // Override with HRMW_REPORTER_CLIENTS env var.
    let gpu_count = backend.recommended_pipeline_depth() / 32;
    let gpu_count = gpu_count.max(1);
    let auto_clients = (gpu_count + 2).clamp(3, 20);
    let reporter_clients: usize = std::env::var("HRMW_REPORTER_CLIENTS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(auto_clients);

    // Pre-resolve server hostname (parent process where DNS works reliably).
    let server_host = config
        .server_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("webcash.org");
    let resolved_addr = tokio::net::lookup_host(format!("{server_host}:443"))
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve {server_host}"))?;
    println!("  reporter_clients={reporter_clients} resolved={resolved_addr}");

    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("hrmw"));
    let mut reporter_process = match std::process::Command::new(&exe)
        .args([
            "webminer",
            "report-worker",
            "--server",
            &config.server_url,
            "--resolved-addr",
            &resolved_addr.to_string(),
            "--clients",
            &reporter_clients.to_string(),
            "--webcash-wallet",
            &config.webcash_wallet_path.to_string_lossy(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
    {
        Ok(child) => {
            println!("Reporter subprocess started (PID {})", child.id());
            Some(child)
        }
        Err(e) => {
            eprintln!("Warning: failed to spawn report-worker: {e}");
            eprintln!("Solutions will only be written to file (use `hrmw webminer collect`).");
            None
        }
    };
    let mut reporter_pipe = reporter_process
        .as_mut()
        .and_then(|c| c.stdin.take());
    // Background target refresher — polls server every 15s without ever
    // blocking the mining loop. Updates are picked up atomically next cycle.
    {
        let refresh_target = shared_target.clone();
        let refresh_protocol = protocol.clone();
        let refresh_tracker = tracker.clone();
        let refresh_status = status_path.clone();
        let refresh_shutdown = shutdown.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(target_refresh_interval);
            interval.tick().await; // skip first immediate tick
            loop {
                interval.tick().await;
                if refresh_shutdown.load(Ordering::Relaxed) {
                    break;
                }
                match refresh_protocol.get_target().await {
                    Ok(new_target) => {
                        let mut t = refresh_target.write().unwrap();
                        if new_target.difficulty != t.difficulty {
                            println!(
                                "Difficulty changed: {} -> {}",
                                t.difficulty, new_target.difficulty
                            );
                        }
                        *t = new_target;
                        refresh_tracker.set_difficulty(t.difficulty);
                    }
                    Err(e) => eprintln!("Warning: failed to fetch target: {e}"),
                }
                let _ = refresh_tracker.write_to_file(&refresh_status);
            }
        });
    }

    // Main mining loop — ZERO network I/O, never blocks.
    while !shutdown.load(Ordering::Relaxed) {
        // Read latest target atomically (non-blocking RwLock read).
        target = shared_target.read().unwrap().clone();

        // Skip if difficulty exceeds our max
        if target.difficulty > config.max_difficulty {
            println!(
                "Difficulty {} exceeds max {}, waiting...",
                target.difficulty, config.max_difficulty
            );
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            continue;
        }

        let t_cycle = std::time::Instant::now();

        // Use pre-built batch from previous cycle if available and difficulty
        // hasn't changed, otherwise create fresh with rayon parallelism.
        let work_units = match pending_work_units.take() {
            Some(pending) if !pending.is_empty() && pending[0].difficulty == target.difficulty => {
                pending
            }
            _ => {
                let d = target.difficulty;
                let a = target.mining_amount;
                let s = target.subsidy_amount;
                let n = pipeline_depth;
                tokio::task::spawn_blocking(move || {
                    use rayon::prelude::*;
                    (0..n)
                        .into_par_iter()
                        .map(|_| WorkUnit::new(d, a, s))
                        .collect()
                })
                .await?
            }
        };

        // Build midstate refs — Arc avoids cloning 32 Sha256Midstates per cycle.
        let midstates: Arc<Vec<Sha256Midstate>> =
            Arc::new(work_units.iter().map(|wu| wu.midstate.clone()).collect());

        // Start creating NEXT batch in background with rayon (overlapped with
        // GPU mining). On a 122-thread machine, 32 WUs finish in ~30μs.
        let next_d = target.difficulty;
        let next_a = target.mining_amount;
        let next_s = target.subsidy_amount;
        let next_n = pipeline_depth;
        let next_batch_handle = tokio::task::spawn_blocking(move || {
            use rayon::prelude::*;
            (0..next_n)
                .into_par_iter()
                .map(|_| WorkUnit::new(next_d, next_a, next_s))
                .collect::<Vec<_>>()
        });

        // Mine current batch on GPUs (overlapped with next batch creation).
        work_unit_timer = std::time::Instant::now();
        let chunks = backend
            .mine_work_units(&midstates, &nonce_table, target.difficulty, None)
            .await?;
        let mine_us = work_unit_timer.elapsed().as_micros();

        // Collect pre-built next batch (should be ready by now).
        pending_work_units = next_batch_handle.await.ok();

        let cycle_us = t_cycle.elapsed().as_micros();
        let mut attempts_this_work_unit = 0u64;
        for chunk in &chunks {
            attempts_this_work_unit = attempts_this_work_unit.saturating_add(chunk.attempted);
        }

        tracker.add_attempts(attempts_this_work_unit);

        // Print stats periodically using rolling average (not per-cycle).
        if last_stats_print.elapsed() >= stats_print_interval {
            let snapshot = tracker.snapshot();
            let hps = snapshot.hash_rate_mhs * 1_000_000.0;
            let expected_solutions = if target.difficulty > 0 {
                let denom = 2.0_f64.powi(target.difficulty as i32);
                snapshot.total_attempts as f64 / denom
            } else {
                0.0
            };
            let p_zero_pct = (-expected_solutions).exp() * 100.0;
            println!(
                "speed={} difficulty={} solutions={}/{} eta={} expected={:.2} p0={:.2}% (mine={}μs cycle={}μs)",
                stats::format_hash_rate(hps),
                target.difficulty,
                snapshot.solutions_accepted,
                snapshot.solutions_found,
                stats::estimate_time(hps, target.difficulty),
                expected_solutions,
                p_zero_pct,
                mine_us,
                cycle_us,
            );
            last_stats_print = std::time::Instant::now();
        }

        for (wu, chunk) in work_units.into_iter().zip(chunks.into_iter()) {
            if let Some(solution) = chunk.result {
                tracker.record_solution();
                let preimage =
                    wu.preimage_string(&nonce_table, solution.nonce1_idx, solution.nonce2_idx);

                println!(
                    "SOLUTION FOUND! difficulty={} hash=0x{}",
                    solution.difficulty_achieved,
                    hex::encode(&solution.hash)
                );

                // Persist to disk FIRST (crash safety), then queue for
                // background submission on the dedicated OS thread.
                let pending_line = format!(
                    "{}\t0x{}\t{}\tdifficulty={}\n",
                    preimage,
                    hex::encode(&solution.hash),
                    wu.keep_secret,
                    solution.difficulty_achieved,
                );
                let _ = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(pending_solutions_path())
                    .and_then(|mut f| {
                        use std::io::Write;
                        f.write_all(pending_line.as_bytes())
                    });

                // Pipe to subprocess reporter (instant write, zero allocation).
                if let Some(ref mut pipe) = reporter_pipe {
                    use std::io::Write;
                    let _ = pipe.write_all(pending_line.as_bytes());
                    let _ = pipe.flush();
                }
            }
        }
    }

    // Graceful shutdown: close pipe → subprocess drains remaining solutions.
    println!("Miner shutting down...");
    let drain_start = std::time::Instant::now();

    // Close pipe → subprocess sees EOF → drains its queues → exits.
    drop(reporter_pipe);
    if let Some(ref mut child) = reporter_process {
        println!("  Waiting for reporter subprocess to drain...");
        match child.wait() {
            Ok(status) => {
                let drain_secs = drain_start.elapsed().as_secs();
                println!("  Reporter exited ({status}) in {drain_secs}s");
            }
            Err(e) => eprintln!("  Reporter wait failed: {e}"),
        }
    }

    let _ = std::fs::remove_file(pid_file_path());
    let _ = tracker.write_to_file(&status_path);
    println!("Miner stopped.");

    Ok(())
}
