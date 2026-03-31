use std::path::Path;
use std::sync::Mutex;

use anyhow::Context;
use hkdf::Hkdf;
use rusqlite::{params, Connection};
use sha2::Sha256;

use crate::{
    client::HarmoniisClient,
    error::{Error, Result},
    types::VoucherSecret,
};

#[derive(Debug, Clone)]
pub struct VoucherStats {
    pub balance_units: u64,
    pub unspent_outputs: usize,
    pub total_outputs: usize,
    pub spent_outputs: usize,
}

pub struct VoucherWallet {
    conn: Mutex<Connection>,
}

impl VoucherWallet {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| {
                Error::Other(anyhow::anyhow!(
                    "cannot create voucher wallet dir {}: {e}",
                    dir.display()
                ))
            })?;
        }
        let conn = Connection::open(path)
            .map_err(|e| Error::Other(anyhow::anyhow!("open voucher db: {e}")))?;
        Self::init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| Error::Other(anyhow::anyhow!("open in-memory voucher db: {e}")))?;
        Self::init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;

            CREATE TABLE IF NOT EXISTS voucher_metadata (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS voucher_outputs (
                public_hash    TEXT PRIMARY KEY,
                amount_units   INTEGER NOT NULL,
                secret_display TEXT NOT NULL,
                status         TEXT NOT NULL,
                created_at     TEXT NOT NULL,
                updated_at     TEXT NOT NULL
            );
            ",
        )?;
        Ok(())
    }

    pub fn store_master_secret(&self, master_secret_hex: &str) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| Error::Other(anyhow::anyhow!("voucher wallet mutex poisoned")))?;
        conn.execute(
            "INSERT OR REPLACE INTO voucher_metadata (key, value) VALUES ('master_secret_hex', ?1)",
            params![master_secret_hex],
        )?;
        Ok(())
    }

    pub fn insert(&self, secret: VoucherSecret) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let proof = secret.public_proof();
        let conn = self
            .conn
            .lock()
            .map_err(|_| Error::Other(anyhow::anyhow!("voucher wallet mutex poisoned")))?;
        conn.execute(
            "INSERT OR REPLACE INTO voucher_outputs (
                public_hash, amount_units, secret_display, status, created_at, updated_at
             ) VALUES (
                ?1, ?2, ?3, 'live',
                COALESCE((SELECT created_at FROM voucher_outputs WHERE public_hash = ?1), ?4),
                ?4
             )",
            params![
                proof.public_hash,
                i64::try_from(secret.amount_units).map_err(|_| Error::Other(anyhow::anyhow!(
                    "voucher amount {} exceeds i64 range",
                    secret.amount_units
                )))?,
                secret.display(),
                now,
            ],
        )?;
        Ok(())
    }

    pub fn stats(&self) -> Result<VoucherStats> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| Error::Other(anyhow::anyhow!("voucher wallet mutex poisoned")))?;
        let balance_units: i64 = conn.query_row(
            "SELECT COALESCE(SUM(amount_units), 0) FROM voucher_outputs WHERE status = 'live'",
            [],
            |row| row.get(0),
        )?;
        let total_outputs: i64 =
            conn.query_row("SELECT COUNT(*) FROM voucher_outputs", [], |row| row.get(0))?;
        let unspent_outputs: i64 = conn.query_row(
            "SELECT COUNT(*) FROM voucher_outputs WHERE status = 'live'",
            [],
            |row| row.get(0),
        )?;
        let spent_outputs = total_outputs.saturating_sub(unspent_outputs);
        Ok(VoucherStats {
            balance_units: u64::try_from(balance_units.max(0)).unwrap_or_default(),
            unspent_outputs: usize::try_from(unspent_outputs.max(0)).unwrap_or_default(),
            total_outputs: usize::try_from(total_outputs.max(0)).unwrap_or_default(),
            spent_outputs: usize::try_from(spent_outputs.max(0)).unwrap_or_default(),
        })
    }

    pub fn balance(&self) -> Result<u64> {
        Ok(self.stats()?.balance_units)
    }

    pub async fn check(&self, client: &HarmoniisClient) -> Result<VoucherStats> {
        let live = self.list_live_outputs()?;
        for batch in live.chunks(100) {
            let proofs: Vec<String> = batch
                .iter()
                .map(|secret| secret.public_proof().display())
                .collect();
            let response = client.voucher_check(&proofs).await?;
            let results = response
                .get("results")
                .and_then(|v| v.as_object())
                .cloned()
                .unwrap_or_default();
            for secret in batch {
                let proof = secret.public_proof().display();
                if let Some(entry) = results.get(&proof) {
                    let is_live = entry
                        .get("spent")
                        .and_then(|v| v.as_bool())
                        .map(|spent| !spent)
                        .unwrap_or(false);
                    self.set_status(
                        &secret.public_proof().public_hash,
                        if is_live { "live" } else { "spent" },
                    )?;
                }
            }
        }
        self.stats()
    }

    pub async fn pay(
        &self,
        client: &HarmoniisClient,
        amount_units: u64,
        _memo: &str,
    ) -> Result<VoucherSecret> {
        if amount_units == 0 {
            return Err(Error::Other(anyhow::anyhow!(
                "voucher payment amount must be > 0"
            )));
        }

        let live = self.list_live_outputs()?;
        let exact = live
            .iter()
            .find(|secret| secret.amount_units == amount_units)
            .cloned();
        if let Some(secret) = exact {
            self.set_status(&secret.public_proof().public_hash, "spent")?;
            return Ok(secret);
        }

        let (inputs, total) = select_inputs(&live, amount_units)?;
        let payment_secret = VoucherSecret::generate(amount_units);
        let mut outputs = vec![payment_secret.clone()];
        let change_amount = total.saturating_sub(amount_units);
        let change_secret = if change_amount > 0 {
            let secret = VoucherSecret::generate(change_amount);
            outputs.push(secret.clone());
            Some(secret)
        } else {
            None
        };

        // Phase 1: record intent BEFORE the remote call so a crash between
        // the server accepting and the local update cannot lose change value.
        {
            let conn = self
                .conn
                .lock()
                .map_err(|_| Error::Other(anyhow::anyhow!("voucher wallet mutex poisoned")))?;
            let tx = conn.unchecked_transaction()?;
            let now = chrono::Utc::now().to_rfc3339();
            for input in &inputs {
                tx.execute(
                    "UPDATE voucher_outputs SET status = 'pending_spend', updated_at = ?2 WHERE public_hash = ?1",
                    params![input.public_proof().public_hash, now],
                )?;
            }
            if let Some(ref change) = change_secret {
                let proof = change.public_proof();
                tx.execute(
                    "INSERT OR REPLACE INTO voucher_outputs (public_hash, amount_units, secret_display, status, created_at, updated_at)
                     VALUES (?1, ?2, ?3, 'pending_change', ?4, ?4)",
                    params![
                        proof.public_hash,
                        i64::try_from(change.amount_units).map_err(|_| Error::Other(
                            anyhow::anyhow!("voucher amount too large for i64")
                        ))?,
                        change.display(),
                        now,
                    ],
                )?;
            }
            tx.commit()?;
        }

        // Phase 2: remote call — if we crash here, recovery can detect
        // pending_spend / pending_change rows and resolve them.
        let replace_result = client.voucher_replace(&inputs, &outputs).await;

        // Phase 3: finalize local state.
        {
            let conn = self
                .conn
                .lock()
                .map_err(|_| Error::Other(anyhow::anyhow!("voucher wallet mutex poisoned")))?;
            let tx = conn.unchecked_transaction()?;
            let now = chrono::Utc::now().to_rfc3339();
            if replace_result.is_ok() {
                for input in &inputs {
                    tx.execute(
                        "UPDATE voucher_outputs SET status = 'spent', updated_at = ?2 WHERE public_hash = ?1",
                        params![input.public_proof().public_hash, now],
                    )?;
                }
                if change_secret.is_some() {
                    // pending_change -> live
                    let change = change_secret.as_ref().unwrap();
                    tx.execute(
                        "UPDATE voucher_outputs SET status = 'live', updated_at = ?2 WHERE public_hash = ?1",
                        params![change.public_proof().public_hash, now],
                    )?;
                }
            } else {
                // Rollback: server rejected — restore inputs to live, remove change.
                for input in &inputs {
                    tx.execute(
                        "UPDATE voucher_outputs SET status = 'live', updated_at = ?2 WHERE public_hash = ?1",
                        params![input.public_proof().public_hash, now],
                    )?;
                }
                if let Some(ref change) = change_secret {
                    tx.execute(
                        "DELETE FROM voucher_outputs WHERE public_hash = ?1 AND status = 'pending_change'",
                        params![change.public_proof().public_hash],
                    )?;
                }
            }
            tx.commit()?;
        }

        replace_result?;
        Ok(payment_secret)
    }

    pub async fn reinsert_if_live(
        &self,
        client: &HarmoniisClient,
        secret: &VoucherSecret,
    ) -> Result<bool> {
        let is_live = client.voucher_is_live(&secret.public_proof()).await?;
        if !is_live {
            return Ok(false);
        }
        self.insert(secret.clone())?;
        Ok(true)
    }

    pub async fn merge(&self, client: &HarmoniisClient, group: usize) -> Result<String> {
        let live = self.list_live_outputs()?;
        if live.len() < 2 {
            return Ok("Voucher merge skipped: fewer than 2 live outputs.".to_string());
        }
        let target_group = group.max(2).min(live.len());
        let inputs = live.into_iter().take(target_group).collect::<Vec<_>>();
        let total: u64 = inputs.iter().map(|secret| secret.amount_units).sum();
        let merged = VoucherSecret::generate(total);

        // Phase 1: record intent before remote call.
        {
            let conn = self
                .conn
                .lock()
                .map_err(|_| Error::Other(anyhow::anyhow!("voucher wallet mutex poisoned")))?;
            let tx = conn.unchecked_transaction()?;
            let now = chrono::Utc::now().to_rfc3339();
            for input in &inputs {
                tx.execute(
                    "UPDATE voucher_outputs SET status = 'pending_spend', updated_at = ?2 WHERE public_hash = ?1",
                    params![input.public_proof().public_hash, now],
                )?;
            }
            let proof = merged.public_proof();
            tx.execute(
                "INSERT OR REPLACE INTO voucher_outputs (public_hash, amount_units, secret_display, status, created_at, updated_at)
                 VALUES (?1, ?2, ?3, 'pending_change', ?4, ?4)",
                params![
                    proof.public_hash,
                    i64::try_from(merged.amount_units).map_err(|_| Error::Other(
                        anyhow::anyhow!("voucher amount too large for i64")
                    ))?,
                    merged.display(),
                    now,
                ],
            )?;
            tx.commit()?;
        }

        // Phase 2: remote call.
        let replace_result = client
            .voucher_replace(&inputs, std::slice::from_ref(&merged))
            .await;

        // Phase 3: finalize.
        {
            let conn = self
                .conn
                .lock()
                .map_err(|_| Error::Other(anyhow::anyhow!("voucher wallet mutex poisoned")))?;
            let tx = conn.unchecked_transaction()?;
            let now = chrono::Utc::now().to_rfc3339();
            if replace_result.is_ok() {
                for input in &inputs {
                    tx.execute(
                        "UPDATE voucher_outputs SET status = 'spent', updated_at = ?2 WHERE public_hash = ?1",
                        params![input.public_proof().public_hash, now],
                    )?;
                }
                tx.execute(
                    "UPDATE voucher_outputs SET status = 'live', updated_at = ?2 WHERE public_hash = ?1",
                    params![merged.public_proof().public_hash, now],
                )?;
            } else {
                for input in &inputs {
                    tx.execute(
                        "UPDATE voucher_outputs SET status = 'live', updated_at = ?2 WHERE public_hash = ?1",
                        params![input.public_proof().public_hash, now],
                    )?;
                }
                tx.execute(
                    "DELETE FROM voucher_outputs WHERE public_hash = ?1 AND status = 'pending_change'",
                    params![merged.public_proof().public_hash],
                )?;
            }
            tx.commit()?;
        }

        replace_result?;
        Ok(format!(
            "Merged {} outputs into {} credits.",
            inputs.len(),
            crate::types::voucher_format_decimal(merged.amount_units)
        ))
    }

    /// Recover from incomplete pay/merge operations that crashed between the
    /// remote call and the local database update.  Checks the server for the
    /// real status of any pending outputs and finalizes them.
    pub async fn recover_pending(&self, client: &HarmoniisClient) -> Result<String> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| Error::Other(anyhow::anyhow!("voucher wallet mutex poisoned")))?;

        // Find pending_spend inputs and pending_change outputs.
        let mut stmt = conn.prepare(
            "SELECT public_hash, secret_display, status FROM voucher_outputs WHERE status IN ('pending_spend', 'pending_change')",
        )?;
        let rows: Vec<(String, String, String)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(stmt);

        if rows.is_empty() {
            return Ok("No pending voucher operations to recover.".to_string());
        }

        let now = chrono::Utc::now().to_rfc3339();
        let mut recovered = 0usize;

        for (public_hash, secret_display, status) in &rows {
            let secret = VoucherSecret::parse(secret_display)?;
            let is_live = client
                .voucher_is_live(&secret.public_proof())
                .await
                .unwrap_or(false);

            let new_status = match status.as_str() {
                "pending_spend" => {
                    if is_live {
                        "live"
                    } else {
                        "spent"
                    }
                }
                "pending_change" => {
                    if is_live {
                        "live"
                    } else {
                        "lost"
                    }
                }
                _ => continue,
            };

            conn.execute(
                "UPDATE voucher_outputs SET status = ?2, updated_at = ?3 WHERE public_hash = ?1",
                params![public_hash, new_status, now],
            )?;
            recovered += 1;
        }

        Ok(format!(
            "Recovered {} pending voucher operations.",
            recovered
        ))
    }

    pub fn recover_from_wallet(&self, gap_limit: usize) -> Result<String> {
        let master_secret = self.metadata_value("master_secret_hex")?;
        if master_secret.is_none() {
            return Err(Error::Other(anyhow::anyhow!(
                "voucher wallet has no deterministic master secret"
            )));
        }
        let _ = derive_deterministic_secret(master_secret.unwrap().as_str(), gap_limit as u64)?;
        Ok(
            "Voucher deterministic recovery is not supported by the current protocol because voucher proofs are amount-tagged. Reinsert held voucher secrets with `hrmw voucher insert`."
                .to_string(),
        )
    }

    pub fn list_live_outputs(&self) -> Result<Vec<VoucherSecret>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| Error::Other(anyhow::anyhow!("voucher wallet mutex poisoned")))?;
        let mut stmt = conn.prepare(
            "SELECT secret_display FROM voucher_outputs WHERE status = 'live' ORDER BY amount_units ASC, created_at ASC",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let display = row?;
            out.push(VoucherSecret::parse(&display)?);
        }
        Ok(out)
    }

    fn set_status(&self, public_hash: &str, status: &str) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| Error::Other(anyhow::anyhow!("voucher wallet mutex poisoned")))?;
        conn.execute(
            "UPDATE voucher_outputs SET status = ?2, updated_at = ?3 WHERE public_hash = ?1",
            params![public_hash, status, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    fn metadata_value(&self, key: &str) -> Result<Option<String>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| Error::Other(anyhow::anyhow!("voucher wallet mutex poisoned")))?;
        let mut stmt = conn.prepare("SELECT value FROM voucher_metadata WHERE key = ?1")?;
        let mut rows = stmt.query(params![key])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        Ok(Some(row.get(0)?))
    }
}

fn select_inputs(live: &[VoucherSecret], amount_units: u64) -> Result<(Vec<VoucherSecret>, u64)> {
    let mut total = 0u64;
    let mut inputs = Vec::new();
    for secret in live.iter().rev() {
        if total >= amount_units {
            break;
        }
        total = total.saturating_add(secret.amount_units);
        inputs.push(secret.clone());
    }
    if total < amount_units {
        return Err(Error::Other(anyhow::anyhow!(
            "insufficient voucher balance: need {} credits, have {}",
            crate::types::voucher_format_decimal(amount_units),
            crate::types::voucher_format_decimal(total)
        )));
    }
    Ok((inputs, total))
}

fn derive_deterministic_secret(master_secret_hex: &str, index: u64) -> Result<String> {
    let ikm = hex::decode(master_secret_hex)
        .with_context(|| format!("invalid voucher master secret hex '{master_secret_hex}'"))
        .map_err(Error::Other)?;
    let hk = Hkdf::<Sha256>::new(Some(b"harmoniis-voucher-wallet-v1"), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(&index.to_be_bytes(), &mut okm)
        .map_err(|e| Error::Other(anyhow::anyhow!("voucher hkdf expand failed: {e}")))?;
    Ok(hex::encode(okm))
}
