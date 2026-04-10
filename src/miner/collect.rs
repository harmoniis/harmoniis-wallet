//! Collect unclaimed mining solutions.
//!
//! Reads `miner_pending_solutions.log`, submits unsubmitted solutions
//! to the webcash server in parallel, and reports results.

use std::collections::HashSet;

use super::daemon;

/// Result of a collect operation.
pub struct CollectResult {
    pub pending: usize,
    pub already_accepted: usize,
    pub submitted: usize,
    pub failed: usize,
}

/// Collect and submit pending mining solutions to the server.
///
/// Merges both `miner_pending_solutions.log` and `miner_overflow_solutions.log`
/// before submitting.  When `verbose` is true, prints per-solution feedback.
pub fn run(server_url: &str, verbose: bool) -> anyhow::Result<CollectResult> {
    // Merge overflow into pending (dedup by line).
    merge_overflow_into_pending();

    let solutions_path = daemon::pending_solutions_path();
    let keeps_path = daemon::pending_keep_log_path();

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

/// Watch mode — continuously tail the solutions file and report immediately.
/// Runs as a separate OS process alongside the miner. 32 parallel threads.
/// Polls every 200ms for near-instant submission.
pub fn watch(server_url: &str) -> anyhow::Result<()> {
    use std::io::Read;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, stop2);
    let _ = signal_hook::flag::register(signal_hook::consts::SIGTERM, stop.clone());

    let solutions_path = daemon::pending_solutions_path();
    let keeps_path = daemon::pending_keep_log_path();

    // Pre-create blocking protocol clients for submitter threads.
    let mut protocol = super::protocol::MiningProtocol::new(server_url)?;
    protocol.ensure_blocking_client();
    let protocol = Arc::new(protocol);

    // Track file position to only process new lines.
    let mut file_pos: u64 = if solutions_path.exists() {
        std::fs::metadata(&solutions_path)
            .map(|m| m.len())
            .unwrap_or(0)
    } else {
        0
    };

    // Load existing keeps to skip already-submitted.
    let mut known_keeps: HashSet<String> = if keeps_path.exists() {
        std::fs::read_to_string(&keeps_path)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.to_string())
            .collect()
    } else {
        HashSet::new()
    };

    println!("Solution reporter started (watching for new solutions)");
    println!("  File: {}", solutions_path.display());
    println!("  Server: {server_url}");
    let mut total_submitted = 0usize;
    let mut total_failed = 0usize;

    while !stop.load(Ordering::Relaxed) {
        // Check for new data in the solutions file.
        let current_len = std::fs::metadata(&solutions_path)
            .map(|m| m.len())
            .unwrap_or(0);

        if current_len > file_pos {
            // Read only the new bytes.
            let mut file = match std::fs::File::open(&solutions_path) {
                Ok(f) => f,
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    continue;
                }
            };
            use std::io::Seek;
            let _ = file.seek(std::io::SeekFrom::Start(file_pos));
            let mut new_data = String::new();
            let _ = file.read_to_string(&mut new_data);
            file_pos = current_len;

            // Parse new entries and filter already-submitted.
            let mut entries = Vec::new();
            for line in new_data.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() < 3 {
                    continue;
                }
                let keep_secret = parts[2].to_string();
                if known_keeps.contains(&keep_secret) {
                    continue;
                }
                let hash_hex = parts[1].trim_start_matches("0x");
                if let Ok(b) = hex::decode(hash_hex) {
                    if b.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&b);
                        entries.push((parts[0].to_string(), arr, keep_secret));
                    }
                }
            }

            if !entries.is_empty() {
                let count = entries.len();
                // Submit all in parallel (up to 32 threads).
                let threads = count.min(32);
                let entries = Arc::new(entries);
                let keeps_path = keeps_path.clone();
                let mut handles = Vec::new();
                let chunk = (count + threads - 1) / threads;

                for t in 0..threads {
                    let start = t * chunk;
                    let end = (start + chunk).min(count);
                    if start >= count {
                        break;
                    }
                    let entries = entries.clone();
                    let proto = protocol.clone();
                    let kp = keeps_path.clone();

                    handles.push(std::thread::spawn(move || {
                        let mut sub = 0usize;
                        let mut fail = 0usize;
                        for i in start..end {
                            let (ref preimage, ref hash, ref keep) = entries[i];
                            match proto.submit_report_blocking(preimage, hash) {
                                Ok(_) => {
                                    sub += 1;
                                    let _ = std::fs::OpenOptions::new()
                                        .create(true)
                                        .append(true)
                                        .open(&kp)
                                        .and_then(|mut f| {
                                            use std::io::Write;
                                            writeln!(f, "{}", keep)
                                        });
                                    println!("  Reported: {}", &keep[..keep.len().min(30)]);
                                }
                                Err(e) => {
                                    let msg = e.to_string();
                                    if msg.contains("Didn't use a new secret") {
                                        // Already accepted — write keep to avoid retry.
                                        let _ = std::fs::OpenOptions::new()
                                            .create(true)
                                            .append(true)
                                            .open(&kp)
                                            .and_then(|mut f| {
                                                use std::io::Write;
                                                writeln!(f, "{}", keep)
                                            });
                                    } else {
                                        fail += 1;
                                        eprintln!("  Failed: {msg}");
                                    }
                                }
                            }
                        }
                        (sub, fail)
                    }));
                }

                for h in handles {
                    if let Ok((s, f)) = h.join() {
                        total_submitted += s;
                        total_failed += f;
                    }
                }

                // Update known keeps.
                if let Ok(text) = std::fs::read_to_string(&keeps_path) {
                    known_keeps = text
                        .lines()
                        .filter(|l| !l.trim().is_empty())
                        .map(|l| l.to_string())
                        .collect();
                }

                println!(
                    "[reporter] batch={count} submitted={total_submitted} failed={total_failed}"
                );
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    println!("Reporter stopped. Total: submitted={total_submitted} failed={total_failed}");
    Ok(())
}

/// Pipe-fed reporter worker — runs as a SEPARATE PROCESS spawned by the miner.
///
/// Reads solution lines from stdin (pipe from parent miner process), distributes
/// to `threads` worker threads for parallel HTTP submission. Each thread has its
/// own `reqwest::blocking::Client` — safe because this runs in a separate address
/// space with zero GPU/TLB interference.
///
/// Line format: `preimage\t0xhash\tkeep_secret\tdifficulty=N`
pub fn report_worker(server_url: &str, threads: usize) -> anyhow::Result<()> {
    use std::io::BufRead;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    let stop = Arc::new(AtomicBool::new(false));
    let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, stop.clone());
    let _ = signal_hook::flag::register(signal_hook::consts::SIGTERM, stop.clone());

    let keeps_path = daemon::pending_keep_log_path();
    let submitted = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicUsize::new(0));

    // Per-worker mpsc channels — round-robin dispatch, zero contention.
    let mut txs = Vec::with_capacity(threads);
    for t in 0..threads {
        let (tx, rx) = std::sync::mpsc::channel::<(String, [u8; 32], String)>();
        txs.push(tx);
        let server = server_url.to_string();
        let kp = keeps_path.clone();
        let sub = submitted.clone();
        let fail = failed.clone();
        std::thread::Builder::new()
            .name(format!("rw-{t}"))
            .spawn(move || {
                let mut proto = match super::protocol::MiningProtocol::new(&server) {
                    Ok(p) => p,
                    Err(_) => return,
                };
                proto.ensure_blocking_client();
                while let Ok((preimage, hash, keep)) = rx.recv() {
                    match proto.submit_report_blocking(&preimage, &hash) {
                        Ok(_) => {
                            sub.fetch_add(1, Ordering::Relaxed);
                            let _ = std::fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open(&kp)
                                .and_then(|mut f| {
                                    use std::io::Write;
                                    writeln!(f, "{}", keep)
                                });
                            eprintln!("  Reported: {}...", &keep[..keep.len().min(24)]);
                        }
                        Err(e) => {
                            let msg = e.to_string();
                            if msg.contains("Didn't use a new secret") {
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
                                eprintln!("  Submit failed: {msg}");
                            }
                        }
                    }
                }
            })
            .ok();
    }

    eprintln!("report-worker: {threads} threads, reading stdin, server={server_url}");

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
                let _ = txs[rr % threads].send((preimage, arr, keep));
                rr = rr.wrapping_add(1);
            }
        }
    }

    // Drop senders to signal workers to exit.
    drop(txs);
    // Brief wait for in-flight submissions.
    std::thread::sleep(std::time::Duration::from_secs(2));

    let s = submitted.load(Ordering::Relaxed);
    let f = failed.load(Ordering::Relaxed);
    eprintln!("report-worker exiting: submitted={s} failed={f}");
    Ok(())
}

/// Merge overflow solutions into the main pending file (dedup by line).
fn merge_overflow_into_pending() {
    let overflow = daemon::overflow_solutions_path();
    if !overflow.exists() {
        return;
    }
    let overflow_text = match std::fs::read_to_string(&overflow) {
        Ok(t) if !t.trim().is_empty() => t,
        _ => return,
    };

    let pending = daemon::pending_solutions_path();
    let existing: HashSet<String> = std::fs::read_to_string(&pending)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.to_string())
        .collect();

    let mut new_count = 0usize;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&pending)
    {
        use std::io::Write;
        for line in overflow_text.lines() {
            if !line.trim().is_empty() && !existing.contains(line) {
                let _ = writeln!(f, "{}", line);
                new_count += 1;
            }
        }
    }

    // Clear overflow file after successful merge.
    if new_count > 0 {
        let _ = std::fs::write(&overflow, "");
    }
}
