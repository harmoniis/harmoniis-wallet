//! Webcash types re-exported from [`webylib`].
//!
//! Pure crypto types are always available (WASM-compatible).
//! Network/storage types require the `native` feature.

// Always available — pure data types
pub use webylib::amount::Amount;
pub use webylib::error::Error as WebcashError;
pub use webylib::hd::HDWallet as WebcashHDWallet;
pub use webylib::webcash::{PublicWebcash, SecretWebcash};
pub use webylib::hd::ChainCode as WebcashChainCode;

// Native only — require networking/storage
#[cfg(feature = "native")]
pub use webylib::server::ServerClient as WebcashServerClient;
#[cfg(feature = "native")]
pub use webylib::wallet::{Wallet as WebcashWallet, WalletSnapshot as WebcashWalletSnapshot};

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
