//! Collect unclaimed mining solutions.
//!
//! Reads `miner_pending_solutions.log`, submits unsubmitted solutions
//! to the webcash server in parallel, and reports results.

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
