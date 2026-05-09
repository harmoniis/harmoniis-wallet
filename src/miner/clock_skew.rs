//! Server-anchored clock skew for the preimage timestamp.
//!
//! The webcash server (maaku reference, `server.cc:1314-1319`) accepts
//! mining solutions whose embedded preimage timestamp is within ±2 h of
//! the server's own clock. The preimage is locked into the SHA256 input
//! at WorkUnit creation, so once a solution is mined the timestamp can
//! no longer be adjusted.
//!
//! Sourcing that timestamp from a bare `SystemTime::now()` makes the
//! miner depend on the local system clock being correct. On a machine
//! whose RTC has drifted by more than 2 h (dead CMOS battery, missing
//! NTP, wrong timezone-handled-as-UTC), every fresh solution gets
//! rejected with HTTP 400 `{"error":"Bad timestamp"}` — and the user
//! has no clue why.
//!
//! This module owns one process-global atomic `i64` measuring
//! `server_unix_secs - local_unix_secs`. The reporter and target poller
//! observe the server clock via the HTTP `Date:` header and feed it
//! through `observe()`; everything that builds a preimage uses
//! `server_now_secs_f64()` instead of `SystemTime::now()` so the
//! embedded timestamp lands in the server's window regardless of how
//! wrong the local clock is.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

/// Process-global skew, in whole seconds. `server - local`.
/// Positive => the server clock is ahead of ours.
static SKEW_SECS: AtomicI64 = AtomicI64::new(0);
/// Whether `observe()` has been called at least once. Until then the
/// preimage timestamp falls back to the bare local clock.
static OBSERVED: AtomicBool = AtomicBool::new(false);

/// Threshold above which a single observation jump is loud-warned.
const JUMP_WARN_SECS: i64 = 60;

fn local_now_secs_f64() -> f64 {
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0)
    }
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now() / 1000.0
    }
}

/// Current skew in whole seconds (`server - local`). Zero before the
/// first `observe()` call.
pub fn current_skew_secs() -> i64 {
    SKEW_SECS.load(Ordering::Relaxed)
}

/// Whether the skew has been seeded from a real server observation.
pub fn has_observed() -> bool {
    OBSERVED.load(Ordering::Relaxed)
}

/// `server now` in fractional unix seconds, ready to feed into the
/// preimage. Falls back to the local clock if no observation has
/// landed yet (first cycle).
pub fn server_now_secs_f64() -> f64 {
    local_now_secs_f64() + (current_skew_secs() as f64)
}

/// Feed a server-time observation. The first call is taken as truth;
/// subsequent calls EWMA-smooth (75% old, 25% new) to absorb the
/// 1-second granularity of the HTTP `Date:` header.
///
/// Returns the (previous, new) skew so callers can decide whether to
/// log a jump. Use `observe_and_warn` for the standard path.
pub fn observe(server_unix_secs: f64) -> (i64, i64) {
    let raw_skew = (server_unix_secs - local_now_secs_f64()).round() as i64;
    let prev = SKEW_SECS.load(Ordering::Relaxed);
    let new = if !OBSERVED.swap(true, Ordering::Relaxed) {
        raw_skew
    } else {
        // EWMA: 75% old + 25% new. Keep the math in i64 to avoid
        // floating-point drift across many cycles.
        ((prev * 3 + raw_skew) as f64 / 4.0).round() as i64
    };
    SKEW_SECS.store(new, Ordering::Relaxed);
    (prev, new)
}

/// Like `observe`, but also prints a single-line warning when the
/// skew jumps by more than `JUMP_WARN_SECS` (60 s) — caught for
/// DST corrections and big NTP step-changes.
pub fn observe_and_warn(server_unix_secs: f64) -> i64 {
    let (prev, new) = observe(server_unix_secs);
    let jumped = (new - prev).abs() >= JUMP_WARN_SECS && OBSERVED.load(Ordering::Relaxed);
    // First observation almost always shows a delta vs the all-zeros
    // baseline; suppress that one explicitly.
    let first_observation = prev == 0 && new.abs() >= JUMP_WARN_SECS;
    if jumped && !first_observation {
        eprintln!(
            "[clock] system clock jumped ({} -> {}) — skew is now {}s vs server",
            format_skew(prev),
            format_skew(new),
            new
        );
    }
    new
}

/// Human-readable skew, e.g. `+3h12m`, `-45s`, `+0s`.
pub fn format_skew(skew_secs: i64) -> String {
    let sign = if skew_secs < 0 { '-' } else { '+' };
    let abs = skew_secs.unsigned_abs();
    let h = abs / 3600;
    let m = (abs % 3600) / 60;
    let s = abs % 60;
    if h > 0 {
        format!("{sign}{h}h{m:02}m")
    } else if m > 0 {
        format!("{sign}{m}m{s:02}s")
    } else {
        format!("{sign}{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Tests share the global state; serialize them so they don't
    // step on each other.
    static LOCK: Mutex<()> = Mutex::new(());

    fn reset() {
        SKEW_SECS.store(0, Ordering::Relaxed);
        OBSERVED.store(false, Ordering::Relaxed);
    }

    #[test]
    fn first_observe_is_taken_as_truth() {
        let _g = LOCK.lock().unwrap();
        reset();
        let local = local_now_secs_f64();
        let (_prev, new) = observe(local + 7200.0); // server 2h ahead
        assert!((new - 7200).abs() <= 1, "expected ~7200, got {new}");
        assert!(has_observed());
    }

    #[test]
    fn ewma_smooths_subsequent_samples() {
        let _g = LOCK.lock().unwrap();
        reset();
        let local = local_now_secs_f64();
        observe(local + 100.0);
        let new = observe(local + 200.0).1;
        // EWMA(100, 200) at 25% weight → 125
        assert!((new - 125).abs() <= 1, "expected ~125, got {new}");
    }

    #[test]
    fn server_now_lifts_local_into_window() {
        let _g = LOCK.lock().unwrap();
        reset();
        let local = local_now_secs_f64();
        observe(local + 10_000.0);
        let server_now = server_now_secs_f64();
        assert!(
            (server_now - (local + 10_000.0)).abs() <= 2.0,
            "expected anchored time within 2s of observed"
        );
    }

    #[test]
    fn format_skew_renders() {
        assert_eq!(format_skew(0), "+0s");
        assert_eq!(format_skew(45), "+45s");
        assert_eq!(format_skew(-45), "-45s");
        assert_eq!(format_skew(125), "+2m05s");
        assert_eq!(format_skew(7200), "+2h00m");
        assert_eq!(format_skew(-(3 * 3600 + 12 * 60)), "-3h12m");
    }
}
