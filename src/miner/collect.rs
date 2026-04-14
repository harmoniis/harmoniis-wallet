//! Collect unclaimed mining solutions and subprocess reporter.
//!
//! - `run()`: offline retry from `miner_pending_solutions.log`
//! - `report_worker()`: pipe-fed subprocess with N independent HTTP clients,
//!   each simulating a separate miner with its own TCP connection.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use super::daemon;
use super::protocol::MiningProtocol;

/// Result of a collect operation.
pub struct CollectResult {
    pub pending: usize,
    pub already_accepted: usize,
    pub submitted: usize,
    pub failed: usize,
}

/// Collect and submit pending mining solutions to the server.
///
/// When `verbose` is true, prints per-solution feedback to stdout.
/// Merges overflow solutions (from burst drain timeout) into pending first.
pub fn run(server_url: &str, verbose: bool) -> anyhow::Result<CollectResult> {
    let solutions_path = daemon::pending_solutions_path();
    let overflow_path = daemon::overflow_solutions_path();
    let keeps_path = daemon::pending_keep_log_path();

    // Merge overflow solutions into pending (same format, dedup not needed —
    // overflow contains solutions that were never submitted).
    if overflow_path.exists() {
        let overflow = std::fs::read_to_string(&overflow_path).unwrap_or_default();
        if !overflow.trim().is_empty() {
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&solutions_path)
                .and_then(|mut f| {
                    use std::io::Write;
                    f.write_all(overflow.as_bytes())
                });
            // Clear overflow after merging.
            let _ = std::fs::write(&overflow_path, "");
        }
    }

    let pending = if solutions_path.exists() {
        std::fs::read_to_string(&solutions_path)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count()
    } else {
        0
    };

    let already_known = if keeps_path.exists() {
        std::fs::read_to_string(&keeps_path)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count()
    } else {
        0
    };

    if pending == 0 {
        return Ok(CollectResult {
            pending: 0,
            already_accepted: already_known,
            submitted: 0,
            failed: 0,
        });
    }

    let (submitted, already, failed) = if verbose {
        daemon::retry_pending_solutions_verbose(server_url)?
    } else {
        daemon::retry_pending_solutions(server_url)?
    };

    Ok(CollectResult {
        pending,
        already_accepted: already,
        submitted,
        failed,
    })
}

/// Pipe-fed subprocess reporter with N independent HTTP clients.
///
/// Each client is a separate thread with its own `reqwest::blocking::Client`
/// (= own TCP connection). The server sees N independent miners, processes
/// them in parallel. Solutions arrive via stdin pipe from the parent mining
/// process and are distributed round-robin to clients.
///
/// This runs in a SEPARATE PROCESS — zero TLB shootdown impact on GPU mining.
pub fn report_worker(
    server_url: &str,
    resolved_addr: SocketAddr,
    num_clients: usize,
    webcash_wallet_path: &std::path::Path,
) -> anyhow::Result<()> {
    use std::io::BufRead;

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, stop.clone());
    let _ = signal_hook::flag::register(signal_hook::consts::SIGTERM, stop.clone());

    let keeps_path = daemon::pending_keep_log_path();
    let orphan_path = daemon::orphan_log_path();
    let submitted = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicUsize::new(0));

    // Extract hostname for the .resolve() call.
    let host = server_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("webcash.org")
        .to_string();

    // Per-client channels — round-robin dispatch, zero contention between clients.
    let mut client_txs = Vec::with_capacity(num_clients);
    let mut handles = Vec::with_capacity(num_clients);

    for c in 0..num_clients {
        let (tx, rx) = std::sync::mpsc::channel::<(String, [u8; 32], String)>();
        client_txs.push(tx);

        let server = server_url.to_string();
        let host = host.clone();
        let addr = resolved_addr;
        let kp = keeps_path.clone();
        let op = orphan_path.clone();
        let sub = submitted.clone();
        let fail = failed.clone();
        let wallet_path = webcash_wallet_path.to_path_buf();

        let handle = std::thread::Builder::new()
            .name(format!("client-{c}"))
            .spawn(move || {
                // Each client creates its OWN reqwest::blocking::Client with
                // pre-resolved DNS → own TCP connection to server. Server sees
                // this as an independent miner.
                let client = match reqwest::blocking::Client::builder()
                    .resolve(&host, addr)
                    .http1_only()
                    .timeout(std::time::Duration::from_secs(120))
                    .build()
                {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("[client-{c}] failed to build HTTP client: {e}");
                        return;
                    }
                };

                eprintln!("[client-{c}] ready (TCP → {addr})");

                while let Ok((preimage, hash, keep)) = rx.recv() {
                    let t0 = std::time::Instant::now();

                    match MiningProtocol::submit_report_with_client(
                        &client, &server, &preimage, &hash,
                    ) {
                        Ok(resp) => {
                            let ms = t0.elapsed().as_millis();
                            sub.fetch_add(1, Ordering::Relaxed);
                            eprintln!(
                                "[client-{c}] accepted in {ms}ms: {}...",
                                &keep[..keep.len().min(24)]
                            );

                            // Log difficulty changes from server response.
                            if let Some(new_diff) = resp.difficulty_target {
                                eprintln!("[client-{c}] server difficulty={new_diff}");
                            }

                            // Write keep to pending log (crash safety).
                            let _ = std::fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open(&kp)
                                .and_then(|mut f| {
                                    use std::io::Write;
                                    writeln!(f, "{}", keep)
                                });

                            // Insert into webcash wallet.
                            if let Ok(rt) = tokio::runtime::Runtime::new() {
                                if let Ok(secret) = webylib::SecretWebcash::parse(&keep) {
                                    let _ = rt.block_on(async {
                                        let wallet = webylib::Wallet::open(&wallet_path).await?;
                                        wallet.insert(secret).await
                                    });
                                }
                            }
                        }
                        Err(e) => {
                            let ms = t0.elapsed().as_millis();
                            let msg = e.to_string();
                            if msg.contains("Didn't use a new secret") {
                                // Already accepted — record keep.
                                sub.fetch_add(1, Ordering::Relaxed);
                                let _ = std::fs::OpenOptions::new()
                                    .create(true)
                                    .append(true)
                                    .open(&kp)
                                    .and_then(|mut f| {
                                        use std::io::Write;
                                        writeln!(f, "{}", keep)
                                    });
                            } else {
                                fail.fetch_add(1, Ordering::Relaxed);
                                eprintln!("[client-{c}] FAILED in {ms}ms: {msg}");
                                // Write to orphan log for later retry.
                                let _ = std::fs::OpenOptions::new()
                                    .create(true)
                                    .append(true)
                                    .open(&op)
                                    .and_then(|mut f| {
                                        use std::io::Write;
                                        writeln!(f, "{preimage}\t0x{}\t{keep}", hex::encode(hash))
                                    });
                            }
                        }
                    }
                }
                eprintln!("[client-{c}] exiting (channel closed)");
            })
            .expect("failed to spawn client thread");
        handles.push(handle);
    }

    eprintln!(
        "report-worker: {num_clients} clients, resolved={resolved_addr}, server={server_url}"
    );

    // Main thread: read solution lines from stdin pipe, dispatch round-robin.
    let stdin = std::io::stdin().lock();
    let mut rr = 0usize;
    for line in stdin.lines() {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let line = match line {
            Ok(l) => l,
            Err(_) => break, // parent closed pipe
        };
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        // Format: preimage\t0xhash\tkeep_secret\tdifficulty=N
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 3 {
            continue;
        }
        let preimage = parts[0].to_string();
        let keep = parts[2].to_string();
        let hash_hex = parts[1].trim_start_matches("0x");
        if let Ok(b) = hex::decode(hash_hex) {
            if b.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                let _ = client_txs[rr % num_clients].send((preimage, arr, keep));
                rr = rr.wrapping_add(1);
            }
        }
    }

    // stdin EOF = mining stopped. Drop senders → threads drain remaining → exit.
    eprintln!("report-worker: pipe closed, draining {num_clients} clients...");
    drop(client_txs);

    for handle in handles {
        let _ = handle.join();
    }

    let s = submitted.load(Ordering::Relaxed);
    let f = failed.load(Ordering::Relaxed);
    eprintln!("report-worker: done. submitted={s} failed={f}");
    Ok(())
}
