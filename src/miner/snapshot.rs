//! Serialisable mining-session state for background survival.
//!
//! The PWA saves this to localStorage before the page goes to background.
//! On return (or next mount) it restores accumulated stats and resumes.

use serde::{Deserialize, Serialize};

/// Snapshot of a running mining session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningSessionSnapshot {
    pub active: bool,
    /// `Date.now()` when the session started.
    pub started_at_ms: f64,
    /// Cumulative nonces tried.
    pub total_attempted: u64,
    pub solutions_found: u32,
    pub solutions_submitted: u32,
    pub difficulty: u32,
    pub mining_amount: String,
    /// Last computed hash-rate (H/s).
    pub hash_rate: f64,
    pub history: Vec<MinedSolutionEntry>,
}

/// One accepted proof-of-work, kept for the session history list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinedSolutionEntry {
    pub time: String,
    pub hash_hex: String,
    pub difficulty_achieved: u32,
    pub amount: String,
    pub submitted: bool,
}

impl MiningSessionSnapshot {
    pub fn new() -> Self {
        Self {
            active: true,
            started_at_ms: 0.0,
            total_attempted: 0,
            solutions_found: 0,
            solutions_submitted: 0,
            difficulty: 0,
            mining_amount: String::new(),
            hash_rate: 0.0,
            history: Vec::new(),
        }
    }

    /// Update after one `gpu_mine` batch completes.
    pub fn record_batch(
        &mut self,
        attempted: u64,
        found: bool,
        hash_hex: &str,
        difficulty_achieved: u32,
        amount: &str,
    ) {
        self.total_attempted += attempted;
        if found {
            self.solutions_found += 1;
            self.solutions_submitted += 1;
            self.history.push(MinedSolutionEntry {
                time: String::new(), // filled by caller
                hash_hex: hash_hex.to_owned(),
                difficulty_achieved,
                amount: amount.to_owned(),
                submitted: true,
            });
        }
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}
