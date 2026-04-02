//! Persistent configuration and state for cloud mining instances.
//!
//! Stored at `~/.harmoniis/cloud/config.toml` and `~/.harmoniis/cloud/state.toml`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Persisted user configuration.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CloudConfig {
    pub vast_api_key: Option<String>,
    #[serde(default = "default_label")]
    pub default_label: String,
}

fn default_label() -> String {
    "cloudminer".to_string()
}

/// Persisted state for a running cloud mining instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceState {
    pub instance_id: u64,
    pub offer_id: u64,
    pub label: String,
    pub ssh_host: String,
    pub ssh_port: u16,
    pub gpu_name: String,
    pub num_gpus: u32,
    pub cost_per_hour: f64,
    pub started_at: String,
}

fn cloud_dir() -> PathBuf {
    dirs_next::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".harmoniis")
        .join("cloud")
}

fn config_path() -> PathBuf {
    cloud_dir().join("config.toml")
}

fn state_path() -> PathBuf {
    cloud_dir().join("state.toml")
}

pub fn ssh_key_path() -> PathBuf {
    cloud_dir().join("id_ed25519")
}

pub fn ssh_pubkey_path() -> PathBuf {
    cloud_dir().join("id_ed25519.pub")
}

pub fn load_config() -> Result<CloudConfig> {
    let path = config_path();
    if !path.exists() {
        return Ok(CloudConfig::default());
    }
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))
}

pub fn save_config(cfg: &CloudConfig) -> Result<()> {
    let dir = cloud_dir();
    std::fs::create_dir_all(&dir)?;
    let text = toml::to_string_pretty(cfg)?;
    std::fs::write(config_path(), text)?;
    Ok(())
}

pub fn load_state() -> Result<Option<InstanceState>> {
    let path = state_path();
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let state: InstanceState =
        toml::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(Some(state))
}

pub fn save_state(state: &InstanceState) -> Result<()> {
    let dir = cloud_dir();
    std::fs::create_dir_all(&dir)?;
    let text = toml::to_string_pretty(state)?;
    std::fs::write(state_path(), text)?;
    Ok(())
}

pub fn clear_state() -> Result<()> {
    let path = state_path();
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

/// Resolve the API key from config, env, or prompt.
pub fn resolve_api_key(cfg: &CloudConfig) -> Result<String> {
    if let Some(key) = &cfg.vast_api_key {
        if !key.is_empty() {
            return Ok(key.clone());
        }
    }
    if let Ok(key) = std::env::var("VAST_API_KEY") {
        if !key.is_empty() {
            return Ok(key);
        }
    }
    anyhow::bail!(
        "Vast.ai API key not configured.\n\
         Set it with: hrmw webminer cloud config set vast-api-key <KEY>\n\
         Or export VAST_API_KEY=<KEY>"
    )
}
