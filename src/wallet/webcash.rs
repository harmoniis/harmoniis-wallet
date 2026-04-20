//! Webcash types re-exported from [`webylib`].
//!
//! Available on all targets (native + WASM). webylib v0.3.2+ supports WASM
//! with MemStore + reqwest browser fetch.

pub use webylib::amount::Amount;
pub use webylib::error::Error as WebcashError;
pub use webylib::hd::HDWallet as WebcashHDWallet;
pub use webylib::hd::ChainCode as WebcashChainCode;
pub use webylib::webcash::{PublicWebcash, SecretWebcash};

// Server + Wallet available when HTTP client is compiled (native or wasm)
#[cfg(any(feature = "native", feature = "wasm"))]
pub use webylib::server::ServerClient as WebcashServerClient;
#[cfg(any(feature = "native", feature = "wasm"))]
pub use webylib::wallet::{Wallet as WebcashWallet, WalletSnapshot as WebcashWalletSnapshot};

// ── Mining claim: submit report + insert with HD secret ─────────

/// Submit a mining report and insert the mined webcash into the wallet.
///
/// Reproduces the native daemon flow (daemon.rs:557-689):
/// 1. Submit mining report to server → server creates webcash for the random secret
/// 2. Call `wallet.insert(keep_secret)` → server `/replace` swaps random → HD RECEIVE secret
/// 3. The HD RECEIVE secret is now stored in the wallet and is deterministically recoverable
#[cfg(any(feature = "native", feature = "wasm"))]
pub async fn submit_and_claim_mining_solution(
    wallet: &WebcashWallet,
    network: &webylib::server::NetworkMode,
    preimage: &str,
    hash: &[u8; 32],
    keep_webcash_str: &str,
) -> Result<(), webylib::error::Error> {
    use crate::miner::protocol::MiningProtocol;

    // 1. Submit the mining report
    let protocol = MiningProtocol::from_network(network)
        .map_err(|e| webylib::error::Error::Server { message: e.to_string() })?;
    let report = protocol.submit_report(preimage, hash).await
        .map_err(|e| webylib::error::Error::Server { message: e.to_string() })?;
    if let Some(ref err) = report.error {
        if !err.contains("Didn't use a new secret") {
            return Err(webylib::error::Error::Server { message: err.clone() });
        }
    }

    // 2. Insert: server /replace swaps random secret → HD RECEIVE secret
    let keep = SecretWebcash::parse(keep_webcash_str)?;
    wallet.insert(keep).await?;

    Ok(())
}

/// Extract the bearer **secret** webcash string (`e…:secret:…`) from `pay` / CLI output.
pub fn extract_webcash_secret(payment_output: &str) -> anyhow::Result<String> {
    let trimmed = payment_output.trim();
    if trimmed.starts_with('e') && trimmed.contains(":secret:") {
        return Ok(trimmed.to_string());
    }
    if let Some((_, right)) = trimmed.rsplit_once("recipient:") {
        let secret = right.trim();
        if secret.starts_with('e') && secret.contains(":secret:") {
            return Ok(secret.to_string());
        }
    }
    for line in trimmed.lines().rev() {
        let line = line.trim();
        if line.starts_with('e') && line.contains(":secret:") {
            return Ok(line.to_string());
        }
    }
    anyhow::bail!("failed to extract webcash secret from payment output: {trimmed}")
}
