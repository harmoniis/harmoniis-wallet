use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;

use anyhow::Context;
use harmoniis_wallet::{
    client::{
        timeline::{PostActivityMetadata, PostAttachment},
        HarmoniisClient,
    },
    voucher_wallet::VoucherWallet,
    wallet::RgbWallet,
    VoucherSecret,
};
use rand::Rng;
use webylib::{Amount as WebcashAmount, Wallet as WebcashWallet};

pub fn default_wallet_root() -> PathBuf {
    let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".harmoniis").join("wallet")
}

pub fn resolve_wallet_path(cli_wallet: Option<PathBuf>) -> PathBuf {
    if let Some(path) = cli_wallet {
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.eq_ignore_ascii_case("webcash.db"))
            .unwrap_or(false)
        {
            let master_path = path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."))
                .join("master.db");
            eprintln!(
                "Note: --wallet points to webcash.db; using master wallet {}",
                master_path.display()
            );
            return master_path;
        }
        return path;
    }
    default_wallet_root().join("master.db")
}

pub fn open_or_create_wallet(path: &Path) -> anyhow::Result<RgbWallet> {
    let wallet = if path.exists() {
        RgbWallet::open(path).context("failed to open wallet")?
    } else {
        RgbWallet::create(path).context("failed to create wallet")?
    };
    write_recovery_sidecar(path, &wallet, false)?;
    Ok(wallet)
}

fn recovery_sidecar_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("master.db");
    path.with_file_name(format!("{file_name}.recovery.txt"))
}

pub fn write_recovery_sidecar(
    path: &Path,
    wallet: &RgbWallet,
    overwrite: bool,
) -> anyhow::Result<()> {
    let sidecar = recovery_sidecar_path(path);
    if sidecar.exists() && !overwrite {
        return Ok(());
    }

    let root_hex = wallet
        .export_master_key_hex()
        .context("failed to export root private key for recovery sidecar")?;
    let mnemonic = wallet
        .export_recovery_mnemonic()
        .context("failed to export mnemonic for recovery sidecar")?;
    let fingerprint = wallet
        .fingerprint()
        .context("failed to derive wallet fingerprint for recovery sidecar")?;

    let mut file = fs::File::create(&sidecar)
        .with_context(|| format!("failed to create recovery sidecar {}", sidecar.display()))?;
    writeln!(
        file,
        "Harmoniis Wallet Recovery (KEEP OFFLINE)\nwallet_path={}\nfingerprint={}\nroot_private_key_hex={}\nmnemonic_words={}\n",
        path.display(),
        fingerprint,
        root_hex,
        mnemonic
    )?;
    file.flush()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        fs::set_permissions(&sidecar, perms).with_context(|| {
            format!(
                "failed to set permissions on recovery sidecar {}",
                sidecar.display()
            )
        })?;
    }

    eprintln!(
        "Recovery sidecar created at {} (permissions 600). Move it to offline storage.",
        sidecar.display()
    );
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub enum PasswordManagerBackend {
    #[cfg(target_os = "macos")]
    MacOsKeychain,
    #[cfg(target_os = "linux")]
    LinuxSecretService,
    #[cfg(target_os = "windows")]
    WindowsCredentialManager,
}

impl PasswordManagerBackend {
    pub fn label(self) -> &'static str {
        match self {
            #[cfg(target_os = "macos")]
            Self::MacOsKeychain => "macOS Keychain",
            #[cfg(target_os = "linux")]
            Self::LinuxSecretService => "Linux Secret Service",
            #[cfg(target_os = "windows")]
            Self::WindowsCredentialManager => "Windows Credential Manager",
        }
    }
}

pub fn store_master_in_password_manager(
    path: &Path,
    wallet: &RgbWallet,
) -> anyhow::Result<PasswordManagerBackend> {
    #[cfg(target_os = "macos")]
    {
        if command_exists("security") {
            store_master_macos_keychain(path, wallet)?;
            return Ok(PasswordManagerBackend::MacOsKeychain);
        }
        anyhow::bail!("`security` command not found; macOS Keychain unavailable");
    }

    #[cfg(target_os = "linux")]
    {
        if command_exists("secret-tool") {
            store_master_linux_secret_service(path, wallet)?;
            return Ok(PasswordManagerBackend::LinuxSecretService);
        }
        anyhow::bail!(
            "no supported password manager backend found (expected `secret-tool` for Secret Service)"
        );
    }

    #[cfg(target_os = "windows")]
    {
        if command_exists("cmdkey") {
            store_master_windows_credential_manager(path, wallet)?;
            return Ok(PasswordManagerBackend::WindowsCredentialManager);
        }
        anyhow::bail!("`cmdkey` not found; Windows Credential Manager unavailable");
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = path;
        let _ = wallet;
        anyhow::bail!("no supported password manager backend for this OS");
    }
}

fn command_exists(cmd: &str) -> bool {
    Command::new(cmd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn wallet_password_labels(
    path: &Path,
    wallet: &RgbWallet,
) -> anyhow::Result<(String, String, String)> {
    let wallet_id = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string();
    let fingerprint = wallet
        .fingerprint()
        .context("failed to derive fingerprint for password manager storage")?;
    Ok((wallet_id, fingerprint, "harmoniis".to_string()))
}

#[cfg(target_os = "macos")]
fn store_master_macos_keychain(path: &Path, wallet: &RgbWallet) -> anyhow::Result<()> {
    let (wallet_id, fingerprint, service_prefix) = wallet_password_labels(path, wallet)?;
    let master_mnemonic = wallet
        .export_recovery_mnemonic()
        .context("failed to export mnemonic for keychain storage")?;
    let master_entropy_hex = wallet
        .export_master_key_hex()
        .context("failed to export entropy hex for keychain storage")?;

    store_macos_keychain_secret(
        &format!("{service_prefix}.wallet:{wallet_id}:mnemonic"),
        "harmoniis mnemonic",
        &fingerprint,
        &master_mnemonic,
    )?;
    store_macos_keychain_secret(
        &format!("{service_prefix}.wallet:{wallet_id}:entropy-hex"),
        "harmoniis entropy hex",
        &fingerprint,
        &master_entropy_hex,
    )?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn store_macos_keychain_secret(
    service: &str,
    label: &str,
    account: &str,
    secret: &str,
) -> anyhow::Result<()> {
    // Note: `security` accepts `-w` via argv, which can be visible to local process
    // inspection briefly. This still avoids plaintext-at-rest copies in project files.
    let status = Command::new("security")
        .args([
            "add-generic-password",
            "-U",
            "-a",
            account,
            "-s",
            service,
            "-l",
            label,
            "-w",
            secret,
        ])
        .status()
        .with_context(|| format!("failed to execute `security` for service {service}"))?;
    if !status.success() {
        anyhow::bail!("`security add-generic-password` failed for service {service}");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn store_master_linux_secret_service(path: &Path, wallet: &RgbWallet) -> anyhow::Result<()> {
    let (wallet_id, fingerprint, service_prefix) = wallet_password_labels(path, wallet)?;
    let master_mnemonic = wallet
        .export_recovery_mnemonic()
        .context("failed to export mnemonic for secret-service storage")?;
    let master_entropy_hex = wallet
        .export_master_key_hex()
        .context("failed to export entropy hex for secret-service storage")?;

    store_secret_tool_value(
        &format!("harmoniis:{wallet_id}:mnemonic"),
        &service_prefix,
        &wallet_id,
        "mnemonic",
        &fingerprint,
        &master_mnemonic,
    )?;
    store_secret_tool_value(
        &format!("harmoniis:{wallet_id}:entropy-hex"),
        &service_prefix,
        &wallet_id,
        "entropy-hex",
        &fingerprint,
        &master_entropy_hex,
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn store_secret_tool_value(
    label: &str,
    service: &str,
    wallet_id: &str,
    kind: &str,
    account: &str,
    value: &str,
) -> anyhow::Result<()> {
    let mut child = Command::new("secret-tool")
        .args([
            "store", "--label", label, "service", service, "wallet", wallet_id, "kind", kind,
            "account", account,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("failed to run secret-tool for {kind}"))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("failed to open secret-tool stdin for {kind}"))?;
        stdin
            .write_all(value.as_bytes())
            .with_context(|| format!("failed writing secret-tool payload for {kind}"))?;
    }
    let status = child
        .wait()
        .with_context(|| format!("failed waiting secret-tool for {kind}"))?;
    if !status.success() {
        anyhow::bail!("secret-tool failed storing {kind}");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn store_master_windows_credential_manager(path: &Path, wallet: &RgbWallet) -> anyhow::Result<()> {
    let (wallet_id, fingerprint, service_prefix) = wallet_password_labels(path, wallet)?;
    let master_mnemonic = wallet
        .export_recovery_mnemonic()
        .context("failed to export mnemonic for credential-manager storage")?;
    let master_entropy_hex = wallet
        .export_master_key_hex()
        .context("failed to export entropy hex for credential-manager storage")?;

    store_cmdkey_value(
        &format!("{service_prefix}.wallet:{wallet_id}:mnemonic"),
        &fingerprint,
        &master_mnemonic,
    )?;
    store_cmdkey_value(
        &format!("{service_prefix}.wallet:{wallet_id}:entropy-hex"),
        &fingerprint,
        &master_entropy_hex,
    )?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn store_cmdkey_value(target: &str, account: &str, secret: &str) -> anyhow::Result<()> {
    let status = Command::new("cmdkey")
        .args([
            &format!("/generic:{target}"),
            &format!("/user:{account}"),
            &format!("/pass:{secret}"),
        ])
        .status()
        .with_context(|| format!("failed to execute cmdkey for target {target}"))?;
    if !status.success() {
        anyhow::bail!("cmdkey failed storing target {target}");
    }
    Ok(())
}

// ── Remove / check credential store ──────────────────────────────────────────

pub fn remove_master_from_password_manager(
    path: &Path,
    wallet: &RgbWallet,
) -> anyhow::Result<PasswordManagerBackend> {
    #[cfg(target_os = "macos")]
    {
        if command_exists("security") {
            remove_master_macos_keychain(path, wallet)?;
            return Ok(PasswordManagerBackend::MacOsKeychain);
        }
        anyhow::bail!("`security` command not found; macOS Keychain unavailable");
    }

    #[cfg(target_os = "linux")]
    {
        if command_exists("secret-tool") {
            remove_master_linux_secret_service(path, wallet)?;
            return Ok(PasswordManagerBackend::LinuxSecretService);
        }
        anyhow::bail!(
            "no supported password manager backend found (expected `secret-tool` for Secret Service)"
        );
    }

    #[cfg(target_os = "windows")]
    {
        if command_exists("cmdkey") {
            remove_master_windows_credential_manager(path, wallet)?;
            return Ok(PasswordManagerBackend::WindowsCredentialManager);
        }
        anyhow::bail!("`cmdkey` not found; Windows Credential Manager unavailable");
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = path;
        let _ = wallet;
        anyhow::bail!("no supported password manager backend for this OS");
    }
}

pub fn check_master_in_password_manager(path: &Path, wallet: &RgbWallet) -> anyhow::Result<bool> {
    #[cfg(target_os = "macos")]
    {
        if !command_exists("security") {
            return Ok(false);
        }
        return check_master_macos_keychain(path, wallet);
    }

    #[cfg(target_os = "linux")]
    {
        if !command_exists("secret-tool") {
            return Ok(false);
        }
        return check_master_linux_secret_service(path, wallet);
    }

    #[cfg(target_os = "windows")]
    {
        if !command_exists("cmdkey") {
            return Ok(false);
        }
        return check_master_windows_credential_manager(path, wallet);
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = path;
        let _ = wallet;
        Ok(false)
    }
}

#[cfg(target_os = "macos")]
fn remove_master_macos_keychain(path: &Path, wallet: &RgbWallet) -> anyhow::Result<()> {
    let (wallet_id, fingerprint, service_prefix) = wallet_password_labels(path, wallet)?;
    delete_macos_keychain_secret(
        &format!("{service_prefix}.wallet:{wallet_id}:mnemonic"),
        &fingerprint,
    )?;
    delete_macos_keychain_secret(
        &format!("{service_prefix}.wallet:{wallet_id}:entropy-hex"),
        &fingerprint,
    )?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn delete_macos_keychain_secret(service: &str, account: &str) -> anyhow::Result<()> {
    let status = Command::new("security")
        .args(["delete-generic-password", "-a", account, "-s", service])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("failed to execute `security` for service {service}"))?;
    if !status.success() {
        anyhow::bail!("credential not found for service {service} (nothing to remove)");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn check_master_macos_keychain(path: &Path, wallet: &RgbWallet) -> anyhow::Result<bool> {
    let (wallet_id, fingerprint, service_prefix) = wallet_password_labels(path, wallet)?;
    let status = Command::new("security")
        .args([
            "find-generic-password",
            "-a",
            &fingerprint,
            "-s",
            &format!("{service_prefix}.wallet:{wallet_id}:mnemonic"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("failed to execute `security`")?;
    Ok(status.success())
}

#[cfg(target_os = "linux")]
fn remove_master_linux_secret_service(path: &Path, wallet: &RgbWallet) -> anyhow::Result<()> {
    let (wallet_id, fingerprint, service_prefix) = wallet_password_labels(path, wallet)?;
    clear_secret_tool_value(&service_prefix, &wallet_id, "mnemonic", &fingerprint)?;
    clear_secret_tool_value(&service_prefix, &wallet_id, "entropy-hex", &fingerprint)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn clear_secret_tool_value(
    service: &str,
    wallet_id: &str,
    kind: &str,
    account: &str,
) -> anyhow::Result<()> {
    let status = Command::new("secret-tool")
        .args([
            "clear", "service", service, "wallet", wallet_id, "kind", kind, "account", account,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("failed to run secret-tool clear for {kind}"))?;
    if !status.success() {
        anyhow::bail!("secret-tool clear failed for {kind} (credential may not exist)");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn check_master_linux_secret_service(path: &Path, wallet: &RgbWallet) -> anyhow::Result<bool> {
    let (wallet_id, fingerprint, service_prefix) = wallet_password_labels(path, wallet)?;
    let output = Command::new("secret-tool")
        .args([
            "lookup",
            "service",
            &service_prefix,
            "wallet",
            &wallet_id,
            "kind",
            "mnemonic",
            "account",
            &fingerprint,
        ])
        .output()
        .context("failed to run secret-tool lookup")?;
    Ok(output.status.success() && !output.stdout.is_empty())
}

#[cfg(target_os = "windows")]
fn remove_master_windows_credential_manager(path: &Path, wallet: &RgbWallet) -> anyhow::Result<()> {
    let (wallet_id, _fingerprint, service_prefix) = wallet_password_labels(path, wallet)?;
    delete_cmdkey_value(&format!("{service_prefix}.wallet:{wallet_id}:mnemonic"))?;
    delete_cmdkey_value(&format!("{service_prefix}.wallet:{wallet_id}:entropy-hex"))?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn delete_cmdkey_value(target: &str) -> anyhow::Result<()> {
    let status = Command::new("cmdkey")
        .args([&format!("/delete:{target}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("failed to execute cmdkey /delete for target {target}"))?;
    if !status.success() {
        anyhow::bail!("cmdkey /delete failed for target {target} (credential may not exist)");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn check_master_windows_credential_manager(
    path: &Path,
    wallet: &RgbWallet,
) -> anyhow::Result<bool> {
    let (wallet_id, _fingerprint, service_prefix) = wallet_password_labels(path, wallet)?;
    let output = Command::new("cmdkey")
        .args([&format!(
            "/list:{service_prefix}.wallet:{wallet_id}:mnemonic"
        )])
        .output()
        .context("failed to execute cmdkey /list")?;
    Ok(output.status.success())
}

// ── Labeled-wallet resolution ─────────────────────────────────────────────
//
// Every wallet family (webcash, bitcoin, voucher, rgb) uses:
//   Canonical DB name:  {label}_{family}.db   (e.g. main_webcash.db)
//   Legacy name (main): {family}.db           (e.g. webcash.db)
//
// `resolve_labeled_db_path` prefers canonical, falls back to legacy for
// the "main" label (existing wallets), defaults to canonical for new ones.

/// Effective label: returns "main" when the user omitted `--label`.
pub fn effective_label(label: Option<&str>) -> &str {
    match label {
        None | Some("main") => "main",
        Some(l) => l,
    }
}

/// Resolve the database path for a labeled wallet with legacy migration.
///
/// If the old `{family}.db` exists but `main_{family}.db` does not,
/// rename it automatically. This migrates v0.1.42 and earlier wallets.
pub fn resolve_labeled_db_path(master_wallet_path: &Path, family: &str, label: &str) -> PathBuf {
    let base_dir = master_wallet_path
        .parent()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| PathBuf::from("."));
    let canonical = base_dir.join(format!("{label}_{family}.db"));

    // Legacy migration for "main" label: {family}.db → main_{family}.db
    if label == "main" {
        let legacy = base_dir.join(format!("{family}.db"));
        if legacy.exists() {
            let legacy_size = std::fs::metadata(&legacy).map(|m| m.len()).unwrap_or(0);
            let canonical_size = std::fs::metadata(&canonical).map(|m| m.len()).unwrap_or(0);

            // Migrate if legacy has data and canonical is missing or empty.
            if legacy_size > canonical_size {
                if canonical.exists() {
                    let _ = std::fs::remove_file(&canonical);
                }
                if let Err(e) = std::fs::rename(&legacy, &canonical) {
                    eprintln!(
                        "Warning: could not migrate {} → {}: {}",
                        legacy.display(),
                        canonical.display(),
                        e
                    );
                    return legacy;
                }
                eprintln!("Migrated {} → {}", legacy.display(), canonical.display());
                return canonical;
            }
        }
    }

    if canonical.exists() {
        return canonical;
    }

    canonical
}

/// Open a webcash wallet for any label (including "main" as default).
pub async fn resolve_webcash_wallet(
    master_wallet_path: &Path,
    wallet: &RgbWallet,
    label: Option<&str>,
) -> anyhow::Result<WebcashWallet> {
    let label = effective_label(label);
    let (secret, _index) = wallet
        .derive_webcash_secret_for_label(label)
        .context("failed to derive webcash wallet")?;
    let db_path = resolve_labeled_db_path(master_wallet_path, "webcash", label);
    let webcash_wallet = WebcashWallet::open(&db_path)
        .await
        .with_context(|| format!("failed to open webcash wallet at {}", db_path.display()))?;
    // Suppress webylib's noisy "Master secret stored" println during store.
    // We print our own context-specific message if needed.
    {
        use std::io::Write;
        let _ = std::io::stdout().flush();
        // Redirect stdout to /dev/null for this call
        #[cfg(unix)]
        let _guard = suppress_stdout();
        webcash_wallet
            .store_master_secret(&secret)
            .await
            .context("failed to store webcash master secret")?;
    }
    Ok(webcash_wallet)
}

/// Open a voucher wallet for any label (including "main" as default).
pub fn resolve_voucher_wallet(
    master_wallet_path: &Path,
    wallet: &RgbWallet,
    label: Option<&str>,
) -> anyhow::Result<VoucherWallet> {
    let label = effective_label(label);
    let (secret, _index) = wallet
        .derive_voucher_secret_for_label(label)
        .context("failed to derive voucher wallet")?;
    let db_path = resolve_labeled_db_path(master_wallet_path, "voucher", label);
    let voucher_wallet = VoucherWallet::open(&db_path)
        .with_context(|| format!("failed to open voucher wallet at {}", db_path.display()))?;
    voucher_wallet
        .store_master_secret(&secret)
        .context("failed to store voucher master secret")?;
    Ok(voucher_wallet)
}

/// Resolve the bitcoin.db path for a labeled wallet.
pub fn resolve_bitcoin_db_path(wallet_path: &Path, label: Option<&str>) -> PathBuf {
    let label = effective_label(label);
    resolve_labeled_db_path(wallet_path, "bitcoin", label)
}

/// Display path for a labeled wallet (for user-facing output).
pub fn labeled_wallet_display_path(
    master_wallet_path: &Path,
    family: &str,
    label: Option<&str>,
) -> PathBuf {
    let label = effective_label(label);
    resolve_labeled_db_path(master_wallet_path, family, label)
}

pub fn extract_webcash_secret(payment_output: &str) -> anyhow::Result<String> {
    harmoniis_wallet::wallet::webcash::extract_webcash_secret(payment_output)
}

pub async fn pay_from_wallet(
    rgb_wallet_path: &Path,
    wallet: &RgbWallet,
    amount: &str,
    memo: &str,
) -> anyhow::Result<String> {
    let webcash_wallet = resolve_webcash_wallet(rgb_wallet_path, wallet, None).await?;
    let parsed_amount = WebcashAmount::from_str(amount)
        .with_context(|| format!("invalid webcash amount '{amount}'"))?;
    let payment_output = webcash_wallet
        .pay(parsed_amount, memo)
        .await
        .with_context(|| format!("failed to create wallet payment for {memo}"))?;
    extract_webcash_secret(&payment_output)
}

pub async fn pay_voucher_from_wallet(
    rgb_wallet_path: &Path,
    wallet: &RgbWallet,
    client: &HarmoniisClient,
    amount_units: u64,
    memo: &str,
) -> anyhow::Result<VoucherSecret> {
    let voucher_wallet = resolve_voucher_wallet(rgb_wallet_path, wallet, None)?;
    voucher_wallet
        .pay(client, amount_units, memo)
        .await
        .map_err(anyhow::Error::from)
}

pub fn make_client(api: &str, direct: bool) -> HarmoniisClient {
    if direct {
        HarmoniisClient::new_direct(api)
    } else {
        HarmoniisClient::new(api)
    }
}

pub fn now_utc() -> String {
    chrono::Utc::now().to_rfc3339()
}

pub fn parse_amount_to_units(amount: &str) -> u64 {
    match amount.trim().parse::<f64>() {
        Ok(f) => (f * 1e8).round() as u64,
        Err(_) => 0,
    }
}

pub fn parse_keywords_csv(input: Option<&str>) -> Vec<String> {
    input
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn normalize_metadata_tag(input: Option<String>) -> Option<String> {
    input
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty())
}

fn normalize_list(values: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for value in values {
        let tag = value.trim().to_lowercase();
        if tag.is_empty() {
            continue;
        }
        if !out.iter().any(|v| v == &tag) {
            out.push(tag);
        }
    }
    out
}

fn normalize_optional_decimal(input: Option<String>) -> anyhow::Result<Option<String>> {
    let Some(raw) = input else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let parsed = trimmed
        .parse::<f64>()
        .with_context(|| format!("invalid decimal amount '{trimmed}'"))?;
    if parsed <= 0.0 {
        anyhow::bail!("amount must be > 0, got {trimmed}");
    }
    let units = (parsed * 100_000_000.0).round() as u64;
    let whole = units / 100_000_000;
    let frac = units % 100_000_000;
    if frac == 0 {
        Ok(Some(format!("{whole}")))
    } else {
        Ok(Some(format!(
            "{whole}.{}",
            format!("{frac:08}").trim_end_matches('0')
        )))
    }
}

fn attachment_type_for(path: &Path) -> String {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    if ext == "md" {
        "text/markdown".to_string()
    } else {
        "text/plain".to_string()
    }
}

fn read_attachment(path: &Path) -> anyhow::Result<PostAttachment> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed reading attachment file {}", path.display()))?;
    let filename = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid attachment filename: {}", path.display()))?
        .to_string();
    Ok(PostAttachment {
        filename,
        content: Some(content),
        attachment_type: attachment_type_for(path),
        s3_key: None,
        url: None,
        is_public: false,
    })
}

pub fn build_activity_metadata(
    post_type: &str,
    category: Option<String>,
    location: Option<String>,
    location_country: Option<String>,
    remote_ok: bool,
    service_terms: Vec<String>,
    tags_csv: Option<String>,
    price_min: Option<String>,
    price_max: Option<String>,
    currency: Option<String>,
    billing_model: Option<String>,
    billing_cycle: Option<String>,
    invoice_rule: Option<String>,
    unit_label: Option<String>,
) -> anyhow::Result<Option<PostActivityMetadata>> {
    let mut meta = PostActivityMetadata::default();
    meta.category = normalize_metadata_tag(category);
    meta.location = normalize_metadata_tag(location);
    meta.location_country = normalize_metadata_tag(location_country);
    meta.remote_ok = if remote_ok { Some(true) } else { None };
    meta.service_terms = normalize_list(service_terms);
    meta.tags = parse_keywords_csv(tags_csv.as_deref());
    meta.price_min = normalize_optional_decimal(price_min)?;
    meta.price_max = normalize_optional_decimal(price_max)?;
    meta.currency = normalize_metadata_tag(currency);
    meta.billing_model = normalize_metadata_tag(billing_model);
    meta.billing_cycle = normalize_metadata_tag(billing_cycle);
    meta.invoice_rule = normalize_metadata_tag(invoice_rule);
    meta.unit_label = normalize_metadata_tag(unit_label);
    meta.intent = if post_type == "general" {
        None
    } else {
        Some(post_type.to_string())
    };

    if meta.category.is_none() {
        meta.category = match post_type {
            "service_offer" | "service_request" => Some("services".to_string()),
            "product_listing" | "goods_offer" => Some("products".to_string()),
            "job_request" => Some("jobs".to_string()),
            "bid" => Some("contracts".to_string()),
            "provision" => Some("provisioning".to_string()),
            _ => None,
        };
    }
    if meta.currency.is_none() && (meta.price_min.is_some() || meta.price_max.is_some()) {
        meta.currency = Some("webcash".to_string());
    }
    if meta.billing_model.is_none() && is_commercial_listing_post_type(post_type) {
        meta.billing_model = Some("one_time".to_string());
    }
    if meta.billing_model.as_deref() == Some("subscription") {
        if meta.billing_cycle.is_none() {
            meta.billing_cycle = Some("monthly".to_string());
        }
        if meta.invoice_rule.is_none() {
            meta.invoice_rule = Some("monthly_pickup".to_string());
        }
    }

    let has_any = meta.intent.is_some()
        || meta.category.is_some()
        || meta.subcategory.is_some()
        || meta.location.is_some()
        || meta.location_country.is_some()
        || meta.remote_ok.is_some()
        || !meta.delivery_modes.is_empty()
        || !meta.service_terms.is_empty()
        || !meta.tags.is_empty()
        || meta.price_min.is_some()
        || meta.price_max.is_some()
        || meta.currency.is_some()
        || meta.exchange_type.is_some()
        || meta.market_model.is_some()
        || meta.participant_source.is_some()
        || meta.fulfillment_mode.is_some()
        || meta.execution_urgency.is_some()
        || meta.geo_scope.is_some()
        || meta.compliance_domain.is_some()
        || meta.billing_model.is_some()
        || meta.billing_cycle.is_some()
        || meta.invoice_rule.is_some()
        || meta.unit_label.is_some()
        || !meta.extra.is_empty();

    Ok(if has_any { Some(meta) } else { None })
}

pub fn build_post_attachments(
    post_type: &str,
    content: &str,
    terms_file: Option<PathBuf>,
    descriptor_file: Option<PathBuf>,
    attachment_files: Vec<PathBuf>,
) -> anyhow::Result<Vec<PostAttachment>> {
    let mut attachments = Vec::new();
    if let Some(path) = terms_file {
        let mut att = read_attachment(&path)?;
        let lower = att.filename.to_lowercase();
        att.filename = if lower.ends_with(".txt") {
            "terms.txt".to_string()
        } else {
            "terms.md".to_string()
        };
        attachments.push(att);
    }
    if let Some(path) = descriptor_file {
        let mut att = read_attachment(&path)?;
        let default_name = listing_descriptor_filename(post_type);
        let lower = att.filename.to_lowercase();
        att.filename = if lower.ends_with(".txt") {
            default_name.replacen(".md", ".txt", 1)
        } else {
            default_name.to_string()
        };
        attachments.push(att);
    }
    for path in attachment_files {
        attachments.push(read_attachment(&path)?);
    }

    if !attachments.is_empty() {
        return Ok(attachments);
    }

    if is_commercial_listing_post_type(post_type) {
        let descriptor_name = listing_descriptor_filename(post_type);
        let descriptor_title = descriptor_name
            .trim_end_matches(".md")
            .replace(['_', '-'], " ");
        Ok(vec![
            PostAttachment {
                filename: "terms.md".to_string(),
                content: Some(default_terms_markdown()),
                attachment_type: "text/markdown".to_string(),
                s3_key: None,
                url: None,
                is_public: false,
            },
            PostAttachment {
                filename: descriptor_name.to_string(),
                content: Some(format!("# {}\n\n{}", descriptor_title, content)),
                attachment_type: "text/markdown".to_string(),
                s3_key: None,
                url: None,
                is_public: false,
            },
        ])
    } else {
        Ok(vec![PostAttachment {
            filename: "description.md".to_string(),
            content: Some(format!("# Listing\n\n{}", content)),
            attachment_type: "text/markdown".to_string(),
            s3_key: None,
            url: None,
            is_public: false,
        }])
    }
}

pub fn is_commercial_listing_post_type(post_type: &str) -> bool {
    matches!(
        post_type,
        "service_offer"
            | "service_request"
            | "product_listing"
            | "job_request"
            | "provision"
            | "goods_offer"
    )
}

fn listing_descriptor_filename(post_type: &str) -> &'static str {
    match post_type {
        "service_offer" | "service_request" | "job_request" | "provision" => "service.md",
        "product_listing" | "goods_offer" => "product.md",
        _ => "description.md",
    }
}

fn default_terms_markdown() -> String {
    [
        "# Terms",
        "",
        "1. Scope is exactly what is written in the listing descriptor attachment.",
        "2. Buyer and seller must agree on delivery details through contract and bid flow.",
        "3. Payment, arbitration profit, and dispute/refund rules follow Harmoniis contract endpoints.",
    ]
    .join("\n")
}

pub fn next_contract_id() -> String {
    let n: u32 = rand::thread_rng().gen_range(1..999_999);
    format!("CTR_{}_{:06}", chrono::Utc::now().format("%Y"), n)
}

/// Temporarily suppress stdout (redirects fd 1 to /dev/null).
/// Returns a guard that restores stdout on drop.
#[cfg(unix)]
fn suppress_stdout() -> StdoutGuard {
    use std::os::unix::io::AsRawFd;
    let saved_fd = unsafe { libc::dup(1) };
    if let Ok(devnull) = std::fs::File::open("/dev/null") {
        unsafe { libc::dup2(devnull.as_raw_fd(), 1) };
    }
    StdoutGuard { saved_fd }
}

#[cfg(unix)]
struct StdoutGuard {
    saved_fd: i32,
}

#[cfg(unix)]
impl Drop for StdoutGuard {
    fn drop(&mut self) {
        if self.saved_fd >= 0 {
            unsafe {
                libc::dup2(self.saved_fd, 1);
                libc::close(self.saved_fd);
            }
        }
    }
}
