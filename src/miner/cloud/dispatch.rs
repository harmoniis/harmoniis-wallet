//! Solution dispatch daemon — continuously syncs solutions from remote
//! cloud mining instances and submits them locally in parallel.
//!
//! Coordination protocol:
//!   - Remote: 3 submitter threads write to remote `miner_pending_keeps.log`
//!   - Local:  4 submitter threads write to local  `miner_pending_keeps.log`
//!   - Sync:   both solutions AND keeps are downloaded — keeps merge prevents
//!             re-submitting what the remote already reported
//!   - Safety: double-submission to webcash server is idempotent ("already accepted")
//!
//! The dispatch daemon runs until all instances stop or SIGINT is received.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;

use super::config::{self, InstanceState};
use super::provision;
use crate::miner::collect;

/// Summary returned when the dispatch loop exits.
pub struct DispatchSummary {
    pub cycles: u64,
    pub total_synced: usize,
    pub total_submitted: usize,
    pub total_already: usize,
    pub total_failed: usize,
}

/// Run the dispatch loop — syncs and submits continuously until instances
/// are gone or `stop` is signalled.
///
/// `poll_secs`: seconds between sync cycles (default 30).
/// `verbose`: print per-solution feedback.
pub fn run(
    ssh_key: &SigningKey,
    server_url: &str,
    poll_secs: u64,
    verbose: bool,
) -> anyhow::Result<DispatchSummary> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, stop2);

    let interval = Duration::from_secs(poll_secs);
    let mut summary = DispatchSummary {
        cycles: 0,
        total_synced: 0,
        total_submitted: 0,
        total_already: 0,
        total_failed: 0,
    };

    println!("Solution dispatcher started (poll every {poll_secs}s, 4 submission threads)");
    println!("Press Ctrl+C to stop.\n");

    loop {
        if stop.load(Ordering::Relaxed) {
            println!("\nDispatcher interrupted.");
            break;
        }

        let instances = config::load_instances().unwrap_or_default();
        if instances.is_empty() {
            println!("No active instances — dispatcher exiting.");
            break;
        }

        summary.cycles += 1;
        let cycle_start = Instant::now();

        // Phase 1: Sync solutions + keeps from all instances.
        let mut cycle_synced = 0usize;
        for inst in &instances {
            let synced = sync_instance(ssh_key, inst);
            cycle_synced += synced;
        }
        summary.total_synced += cycle_synced;

        // Phase 2: Merge overflow + submit locally (4 threads × dedup).
        let cr = collect::run(server_url, verbose)?;
        let s = cr.submitted;
        let a = cr.already_accepted;
        let f = cr.failed;
        summary.total_submitted += s;
        summary.total_already += a;
        summary.total_failed += f;

        // Status line.
        let elapsed = cycle_start.elapsed();
        let inst_count = instances.len();
        if cycle_synced > 0 || s > 0 || f > 0 {
            println!(
                "[cycle {}] {} instance(s) | synced: {} | submitted: {} | already: {} | failed: {} | {:.1}s",
                summary.cycles, inst_count, cycle_synced, s, a, f, elapsed.as_secs_f64()
            );
        } else {
            print!(
                "\r[cycle {}] {} instance(s) | no new solutions | {:.1}s   ",
                summary.cycles, inst_count, elapsed.as_secs_f64()
            );
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }

        // Wait for next cycle (interruptible).
        let deadline = Instant::now() + interval;
        while Instant::now() < deadline {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    println!();
    println!("Dispatch summary:");
    println!("  Cycles:    {}", summary.cycles);
    println!("  Synced:    {}", summary.total_synced);
    println!("  Submitted: {}", summary.total_submitted);
    println!("  Already:   {}", summary.total_already);
    println!("  Failed:    {}", summary.total_failed);

    Ok(summary)
}

/// Sync solutions + keeps from a single remote instance.
/// Returns count of new solution lines synced.
fn sync_instance(ssh_key: &SigningKey, inst: &InstanceState) -> usize {
    provision::append_remote_logs(ssh_key, &inst.ssh_host, inst.ssh_port)
}
