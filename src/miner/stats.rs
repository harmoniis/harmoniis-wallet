//! Mining statistics tracking and serialization.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

/// Miner statistics, written to JSON periodically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerStats {
    pub backend: String,
    pub hash_rate_mhs: f64,
    pub total_attempts: u64,
    pub solutions_found: u32,
    pub solutions_accepted: u32,
    pub difficulty: u32,
    pub uptime_secs: u64,
}

/// Thread-safe statistics tracker.
pub struct StatsTracker {
    backend_name: String,
    start_time: Instant,
    attempts: AtomicU64,
    solutions_found: AtomicU32,
    solutions_accepted: AtomicU32,
    difficulty: AtomicU32,
    last_snapshot_attempts: AtomicU64,
    last_snapshot_time: std::sync::Mutex<Instant>,
}

impl StatsTracker {
    pub fn new(backend_name: &str) -> Self {
        let now = Instant::now();
        StatsTracker {
            backend_name: backend_name.to_string(),
            start_time: now,
            attempts: AtomicU64::new(0),
            solutions_found: AtomicU32::new(0),
            solutions_accepted: AtomicU32::new(0),
            difficulty: AtomicU32::new(0),
            last_snapshot_attempts: AtomicU64::new(0),
            last_snapshot_time: std::sync::Mutex::new(now),
        }
    }

    pub fn add_attempts(&self, count: u64) {
        self.attempts.fetch_add(count, Ordering::Relaxed);
    }

    pub fn record_solution(&self) {
        self.solutions_found.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_accepted(&self) {
        self.solutions_accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_difficulty(&self, d: u32) {
        self.difficulty.store(d, Ordering::Relaxed);
    }

    /// Compute current hash rate based on attempts since last snapshot.
    pub fn snapshot(&self) -> MinerStats {
        let now = Instant::now();
        let total = self.attempts.load(Ordering::Relaxed);
        let prev_total = self.last_snapshot_attempts.swap(total, Ordering::Relaxed);

        let mut last_time = self.last_snapshot_time.lock().unwrap();
        let elapsed = now.duration_since(*last_time).as_secs_f64();
        *last_time = now;

        let delta = total.saturating_sub(prev_total);
        let hash_rate = if elapsed > 0.0 {
            delta as f64 / elapsed
        } else {
            0.0
        };

        MinerStats {
            backend: self.backend_name.clone(),
            hash_rate_mhs: hash_rate / 1_000_000.0,
            total_attempts: total,
            solutions_found: self.solutions_found.load(Ordering::Relaxed),
            solutions_accepted: self.solutions_accepted.load(Ordering::Relaxed),
            difficulty: self.difficulty.load(Ordering::Relaxed),
            uptime_secs: self.start_time.elapsed().as_secs(),
        }
    }

    /// Write stats to the JSON status file.
    pub fn write_to_file(&self, path: &PathBuf) -> anyhow::Result<()> {
        let stats = self.snapshot();
        let json = serde_json::to_string_pretty(&stats)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

/// Default status file path: ~/.harmoniis/miner_status.json
pub fn status_file_path() -> PathBuf {
    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".harmoniis").join("miner_status.json")
}

/// Format a hash rate for display.
pub fn format_hash_rate(hps: f64) -> String {
    if hps >= 1_000_000_000.0 {
        format!("{:.2} Gh/s", hps / 1_000_000_000.0)
    } else if hps >= 1_000_000.0 {
        format!("{:.2} Mh/s", hps / 1_000_000.0)
    } else if hps >= 1_000.0 {
        format!("{:.2} Kh/s", hps / 1_000.0)
    } else {
        format!("{:.0} h/s", hps)
    }
}

/// Estimate time to find a solution at the given hash rate and difficulty.
pub fn estimate_time(hash_rate: f64, difficulty: u32) -> String {
    if hash_rate <= 0.0 || difficulty == 0 {
        return "unknown".to_string();
    }
    // Expected hashes to find solution: 2^difficulty
    let expected_hashes = 2.0_f64.powi(difficulty as i32);
    let seconds = expected_hashes / hash_rate;

    if seconds < 60.0 {
        format!("{:.0}s", seconds)
    } else if seconds < 3600.0 {
        format!("{:.1}m", seconds / 60.0)
    } else if seconds < 86400.0 {
        format!("{:.1}h", seconds / 3600.0)
    } else {
        format!("{:.1}d", seconds / 86400.0)
    }
}
