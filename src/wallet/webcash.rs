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

/// Submit a mining report and insert the mined webcash into the wallet with
/// an HD-derived RECEIVE secret, making it recoverable from the master key.
///
/// Flow: submit_report(preimage, hash) → insert(keep_webcash) → updated wallet state
#[cfg(any(feature = "native", feature = "wasm"))]
pub async fn submit_and_claim_mining_solution(
    wallet: &WebcashWallet,
    network: &webylib::server::NetworkMode,
    preimage: &str,
    hash: &[u8; 32],
    keep_webcash_str: &str,
) -> anyhow::Result<()> {
    use super::super::miner::protocol::MiningProtocol;

    // 1. Submit the mining report to the server
    let protocol = MiningProtocol::from_network(network)?;
    let report = protocol.submit_report(preimage, hash).await?;
    if let Some(ref err) = report.error {
        anyhow::bail!("Mining report rejected: {err}");
    }

    // 2. Insert the mined webcash — replaces random secret with HD RECEIVE secret
    let keep = SecretWebcash::parse(keep_webcash_str)
        .map_err(|e| anyhow::anyhow!("invalid keep webcash: {e}"))?;
    wallet.insert(keep).await
        .map_err(|e| anyhow::anyhow!("insert after mining failed: {e}"))?;

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
