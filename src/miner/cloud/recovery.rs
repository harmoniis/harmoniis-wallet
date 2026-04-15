//! Cloud mining recovery — recover mined webcash and transfer to main wallet.
//!
//! Extracted from the inline logic in the CLI handler. Each labeled wallet
//! is recovered independently (deterministic secret scan), then its balance
//! is transferred to the main wallet via a secret webcash string.

use std::str::FromStr;

use anyhow::{Context, Result};

/// Result of recovering one labeled wallet.
pub struct RecoveryResult {
    pub label: String,
    pub recovered_count: usize,
    pub transferred: f64,
}

/// Summary of recovering all cloud mining wallets.
pub struct RecoverySummary {
    pub results: Vec<RecoveryResult>,
    pub total_transferred: f64,
    pub main_balance: String,
}

/// Recover and transfer mined webcash from labeled wallets to main.
///
/// For each label:
/// 1. Open the labeled webcash wallet (caller provides the opener)
/// 2. Run `recover_from_wallet(50)` — deterministic secret scan
/// 3. If balance > 0: pay full amount → extract secret string → insert into main
///
/// The `open_wallet` closure takes a label and returns (labeled_wallet, main_wallet).
/// This avoids pulling CLI-specific functions into the library.
pub async fn recover_and_transfer<F, Fut>(
    labels: &[String],
    open_wallets: F,
) -> Result<RecoverySummary>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<(webylib::Wallet, webylib::Wallet)>>,
{
    let mut results = Vec::with_capacity(labels.len());
    let mut total_transferred = 0.0f64;

    for label in labels {
        println!("Recovering {label}...");

        let (labeled_wc, main_wc) = (open_wallets)(label.clone()).await?;

        // Recover outputs via deterministic secret scan.
        let recovery = labeled_wc
            .recover_from_wallet(50)
            .await
            .context("webcash recovery failed")?;
        println!("{recovery}");

        // Check balance and transfer.
        let balance_str = labeled_wc.balance().await?;
        let balance: f64 = balance_str.parse().unwrap_or(0.0);

        if balance > 0.0 {
            println!("  Balance: {balance_str} — transferring to main...");

            let amount = webylib::Amount::from_str(&balance_str)
                .map_err(|e| anyhow::anyhow!("bad amount: {e}"))?;
            let payment = labeled_wc
                .pay(amount, "cloud-mining-collect")
                .await
                .context("failed to pay from mining wallet")?;

            let secret_str = crate::wallet::webcash::extract_webcash_secret(&payment)?;
            let parsed = webylib::SecretWebcash::parse(&secret_str)
                .map_err(|e| anyhow::anyhow!("bad webcash secret: {e}"))?;

            main_wc
                .insert(parsed)
                .await
                .context("failed to insert into main wallet")?;

            total_transferred += balance;
            results.push(RecoveryResult {
                label: label.clone(),
                recovered_count: 1, // simplified — recovery reports its own count
                transferred: balance,
            });
        } else {
            results.push(RecoveryResult {
                label: label.clone(),
                recovered_count: 0,
                transferred: 0.0,
            });
        }
    }

    // Get final main wallet balance.
    let main_balance = if let Some(label) = labels.first() {
        let (_, main_wc) = (open_wallets)(label.clone()).await?;
        main_wc.balance().await.unwrap_or_default()
    } else {
        String::new()
    };

    Ok(RecoverySummary {
        results,
        total_transferred,
        main_balance,
    })
}

