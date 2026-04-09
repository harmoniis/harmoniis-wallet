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
