//! Daemon process management: start, stop, status, and the main mining loop.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use webylib::SecretWebcash;

use super::protocol::MiningProtocol;
use super::stats::{self, StatsTracker};
use super::work_unit::{NonceTable, WorkUnit};
use super::{select_backend, BackendChoice, MinerConfig};

/// PID file path: ~/.harmoniis/miner.pid
pub fn pid_file_path() -> PathBuf {
    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".harmoniis").join("miner.pid")
}

/// Log file path: ~/.harmoniis/miner.log
pub fn log_file_path() -> PathBuf {
    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".harmoniis").join("miner.log")
}

/// Orphan log (solutions that were rejected): ~/.harmoniis/miner_orphans.log
pub fn orphan_log_path() -> PathBuf {
    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".harmoniis").join("miner_orphans.log")
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
        // On non-unix, just trust the PID file
        Some(pid)
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
        .arg("--max-difficulty")
        .arg(config.max_difficulty.to_string());

    if config.backend == BackendChoice::Cpu {
        cmd.arg("--cpu-only");
    }
    if config.accept_terms {
        cmd.arg("--accept-terms");
    }

    // Pass wallet paths
    cmd.arg("--wallet")
        .arg(&config.wallet_path)
        .arg("--webcash-wallet")
        .arg(&config.webcash_wallet_path);

    cmd.stdout(log_file)
        .stderr(log_err)
        .stdin(std::process::Stdio::null());

    // Detach on unix
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
        anyhow::bail!("stop not implemented on this platform");
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
        println!("Miner (PID {}) did not stop gracefully, may need manual kill.", pid);
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
                println!("  Hash rate:  {}", stats::format_hash_rate(s.hash_rate_mhs * 1_000_000.0));
                println!("  Attempts:   {}", s.total_attempts);
                println!("  Solutions:  {} found, {} accepted", s.solutions_found, s.solutions_accepted);
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
    let backend = select_backend(config.backend).await?;

    // Initialize protocol client
    let protocol = MiningProtocol::new(&config.server_url)?;

    // Initialize stats
    let tracker = Arc::new(StatsTracker::new(backend.name()));
    let status_path = stats::status_file_path();

    // Open the webcash wallet for inserting mined coins
    let webcash_wallet = webylib::Wallet::open(&config.webcash_wallet_path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to open webcash wallet: {}", e))?;
    println!("Webcash wallet: {}", config.webcash_wallet_path.display());

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

    let mut last_target_fetch = std::time::Instant::now();
    let target_refresh_interval = std::time::Duration::from_secs(15);

    // Main mining loop
    while !shutdown.load(Ordering::Relaxed) {
        // Refresh target periodically
        if last_target_fetch.elapsed() >= target_refresh_interval {
            match protocol.get_target().await {
                Ok(new_target) => {
                    if new_target.difficulty != target.difficulty {
                        println!("Difficulty changed: {} → {}", target.difficulty, new_target.difficulty);
                    }
                    target = new_target;
                    tracker.set_difficulty(target.difficulty);
                }
                Err(e) => {
                    eprintln!("Warning: failed to fetch target: {}", e);
                }
            }
            last_target_fetch = std::time::Instant::now();

            // Write stats
            let _ = tracker.write_to_file(&status_path);

            // Print stats
            let s = tracker.snapshot();
            println!(
                "speed={} difficulty={} solutions={}/{} eta={}",
                stats::format_hash_rate(s.hash_rate_mhs * 1_000_000.0),
                s.difficulty,
                s.solutions_accepted,
                s.solutions_found,
                stats::estimate_time(s.hash_rate_mhs * 1_000_000.0, s.difficulty),
            );
        }

        // Skip if difficulty exceeds our max
        if target.difficulty > config.max_difficulty {
            println!(
                "Difficulty {} exceeds max {}, waiting...",
                target.difficulty, config.max_difficulty
            );
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            continue;
        }

        // Build work unit
        let wu = WorkUnit::new(target.difficulty, target.mining_amount, target.subsidy_amount);

        // Mine
        let result = backend
            .mine_work_unit(&wu.midstate, &nonce_table, target.difficulty)
            .await?;

        tracker.add_attempts(1_000_000);

        if let Some(solution) = result {
            tracker.record_solution();
            let preimage = wu.preimage_string(&nonce_table, solution.nonce1_idx, solution.nonce2_idx);

            println!(
                "SOLUTION FOUND! difficulty={} hash=0x{}",
                solution.difficulty_achieved,
                hex::encode(&solution.hash)
            );

            // Submit to server
            match protocol.submit_report(&preimage, &solution.hash).await {
                Ok(resp) => {
                    tracker.record_accepted();
                    println!(
                        "Mining report accepted! keep={}",
                        wu.keep_secret
                    );

                    // Update difficulty if server says so
                    if let Some(new_diff) = resp.difficulty_target {
                        if new_diff != target.difficulty {
                            println!("Difficulty adjustment: {} → {}", target.difficulty, new_diff);
                            target.difficulty = new_diff;
                            tracker.set_difficulty(new_diff);
                        }
                    }

                    // Insert mined webcash into the wallet
                    let keep_str = wu.keep_secret.to_string();
                    match SecretWebcash::parse(&keep_str) {
                        Ok(parsed) => {
                            match webcash_wallet.insert(parsed).await {
                                Ok(()) => println!("Inserted into wallet: {}", config.webcash_wallet_path.display()),
                                Err(e) => eprintln!("Warning: failed to insert into wallet: {}", e),
                            }
                        }
                        Err(e) => eprintln!("Warning: failed to parse mined secret: {}", e),
                    }
                }
                Err(e) => {
                    eprintln!("Mining report rejected: {}", e);

                    // Save orphaned solution
                    let orphan_line = format!(
                        "{} 0x{} {} difficulty={}\n",
                        preimage,
                        hex::encode(&solution.hash),
                        wu.keep_secret,
                        solution.difficulty_achieved
                    );
                    let _ = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(orphan_log_path())
                        .and_then(|mut f| {
                            use std::io::Write;
                            f.write_all(orphan_line.as_bytes())
                        });
                }
            }
        }
    }

    // Clean up
    println!("Miner shutting down...");
    let _ = std::fs::remove_file(pid_file_path());
    let _ = tracker.write_to_file(&status_path);

    Ok(())
}
