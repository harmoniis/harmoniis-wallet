//! Vast.ai REST API client.
//!
//! Reference: <https://docs.vast.ai/api-reference/introduction>
//! Auth: `Authorization: Bearer {api_key}` on all requests.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const API_BASE: &str = "https://console.vast.ai/api/v0";

pub struct VastClient {
    api_key: String,
    http: reqwest::Client,
}

/// A GPU offer from Vast.ai search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Offer {
    pub id: u64,
    pub gpu_name: String,
    pub num_gpus: u32,
    pub total_flops: f64,
    pub dph_total: f64,
    pub reliability: f64,
    pub cuda_max_good: f64,
    pub inet_down: f64,
    pub flops_per_dphtotal: f64,
}

impl Offer {
    /// Total FLOPS (Vast.ai reports in TFLOPS directly for some offers).
    pub fn tflops(&self) -> f64 {
        self.total_flops
    }

    /// FLOPS per dollar per hour (from Vast.ai, pre-computed).
    pub fn flops_per_dollar(&self) -> f64 {
        self.flops_per_dphtotal
    }

    /// Composite score: efficiency first, speed as tiebreaker.
    /// Formula: FLOPS/$ * (1 + TFlops/1000)
    /// The TFlops/1000 term adds ~10-60% bonus for faster GPUs
    /// without letting raw speed dominate cost efficiency.
    pub fn composite_score(&self) -> f64 {
        if self.dph_total <= 0.0 {
            return 0.0;
        }
        let efficiency = self.flops_per_dollar();
        let speed_bonus = 1.0 + self.tflops() / 1000.0;
        efficiency * speed_bonus
    }
}

/// Instance details from Vast.ai.
#[derive(Debug, Clone, Deserialize)]
pub struct Instance {
    #[serde(default)]
    pub id: u64,
    pub actual_status: Option<String>,
    pub ssh_host: Option<String>,
    pub ssh_port: Option<u16>,
    pub public_ipaddr: Option<String>,
    pub gpu_name: Option<String>,
    pub num_gpus: Option<u32>,
    pub dph_total: Option<f64>,
    pub ports: Option<Value>,
}

impl Instance {
    /// Extract the SSH host and port from instance data.
    pub fn ssh_connection(&self) -> Option<(String, u16)> {
        // Try ports map first (direct port mapping)
        if let Some(ports) = &self.ports {
            if let Some(tcp22) = ports.get("22/tcp") {
                if let Some(arr) = tcp22.as_array() {
                    if let Some(entry) = arr.first() {
                        if let Some(host_port) = entry.get("HostPort").and_then(|v| v.as_str()) {
                            if let Ok(port) = host_port.parse::<u16>() {
                                let host = self
                                    .public_ipaddr
                                    .clone()
                                    .unwrap_or_else(|| "localhost".to_string());
                                return Some((host, port));
                            }
                        }
                    }
                }
            }
        }
        // Fallback to ssh_host/ssh_port
        if let (Some(host), Some(port)) = (&self.ssh_host, self.ssh_port) {
            return Some((host.clone(), port));
        }
        None
    }

    pub fn is_running(&self) -> bool {
        self.actual_status.as_deref() == Some("running")
    }
}

impl VastClient {
    pub fn new(api_key: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            http: reqwest::Client::new(),
        }
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.api_key)
    }

    /// Search for GPU offers, sorted by best TFlops/$/hr.
    pub async fn search_offers(&self, num_gpus: u32, limit: u32) -> Result<Vec<Offer>> {
        let body = json!({
            "num_gpus": {"eq": num_gpus},
            "cuda_max_good": {"gte": 12.0},
            "verified": {"eq": true},
            "rentable": {"eq": true},
            "rented": {"eq": false},
            "reliability": {"gte": 0.95},
            "inet_down": {"gte": 200},
            "order": [["flops_per_dphtotal", "desc"]],
            "limit": limit,
            "type": "on-demand"
        });

        let resp = self
            .http
            .post(format!("{API_BASE}/bundles/"))
            .header("Authorization", self.auth_header())
            .json(&body)
            .send()
            .await
            .context("Vast.ai search request failed")?;

        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("Vast.ai search failed (HTTP {status}): {text}");
        }

        let data: Value = serde_json::from_str(&text)?;
        let offers_raw = data
            .get("offers")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut offers = Vec::new();
        for raw in offers_raw {
            let id = raw.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
            let gpu_name = raw
                .get("gpu_name")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string();
            let num_gpus = raw.get("num_gpus").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let total_flops = raw
                .get("total_flops")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let dph_total = raw.get("dph_total").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let reliability = raw
                .get("reliability2")
                .or_else(|| raw.get("reliability"))
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let cuda_max_good = raw
                .get("cuda_max_good")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let inet_down = raw.get("inet_down").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let flops_per_dphtotal = raw
                .get("flops_per_dphtotal")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);

            offers.push(Offer {
                id,
                gpu_name,
                num_gpus,
                total_flops,
                dph_total,
                reliability,
                cuda_max_good,
                inet_down,
                flops_per_dphtotal,
            });
        }
        Ok(offers)
    }

    /// Find top offers across 2x, 4x, 8x GPU configs (max 8 GPUs).
    /// Returns up to 20 offers sorted by composite score.
    pub async fn find_best_offers(&self) -> Result<Vec<Offer>> {
        let (o2, o4, o8) = tokio::try_join!(
            self.search_offers(2, 8),
            self.search_offers(4, 8),
            self.search_offers(8, 8),
        )?;

        let mut candidates: Vec<Offer> = o2
            .into_iter()
            .chain(o4.into_iter())
            .chain(o8.into_iter())
            .collect();

        candidates.sort_by(|a, b| {
            b.composite_score()
                .partial_cmp(&a.composite_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        candidates.truncate(20);
        Ok(candidates)
    }

    /// Create an instance from an offer ID using the popular CUDA template.
    pub async fn create_instance(&self, offer_id: u64, onstart_script: &str) -> Result<u64> {
        let body = json!({
            "client_id": "me",
            "image": "nvidia/cuda:12.0.1-devel-ubuntu20.04",
            "template_hash_id": "fd2e982e4facaf7b2918006939d1e06e",
            "disk": 16,
            "label": "hrmw-cloud-mining",
            "onstart": onstart_script,
        });

        let resp = self
            .http
            .put(format!("{API_BASE}/asks/{offer_id}/"))
            .header("Authorization", self.auth_header())
            .json(&body)
            .send()
            .await
            .context("Vast.ai create instance failed")?;

        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("Vast.ai create instance failed (HTTP {status}): {text}");
        }

        let data: Value = serde_json::from_str(&text)?;
        let instance_id = data
            .get("new_contract")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("No instance ID in response: {text}"))?;

        Ok(instance_id)
    }

    /// Get instance details.
    pub async fn get_instance(&self, instance_id: u64) -> Result<Instance> {
        let resp = self
            .http
            .get(format!("{API_BASE}/instances/{instance_id}/?owner=me"))
            .header("Authorization", self.auth_header())
            .send()
            .await
            .context("Vast.ai get instance failed")?;

        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("Vast.ai get instance failed (HTTP {status}): {text}");
        }

        let data: Value = serde_json::from_str(&text)?;
        // Response is { "instances": { ...fields... } } — the object IS the instance
        let instance_val = if let Some(inner) = data.get("instances") {
            if inner.is_object() && inner.get("actual_status").is_some() {
                // "instances" is the instance object itself
                let mut obj = inner.clone();
                // Inject "id" from the URL if missing
                if obj.get("id").is_none() {
                    obj["id"] = serde_json::json!(instance_id);
                }
                obj
            } else if inner.is_array() {
                let mut first = inner
                    .as_array()
                    .and_then(|a| a.first().cloned())
                    .unwrap_or(data.clone());
                if first.get("id").is_none() {
                    first["id"] = serde_json::json!(instance_id);
                }
                first
            } else {
                data.clone()
            }
        } else {
            data
        };

        let instance: Instance = serde_json::from_value(instance_val)?;
        Ok(instance)
    }

    /// Destroy an instance.
    pub async fn destroy_instance(&self, instance_id: u64) -> Result<()> {
        let resp = self
            .http
            .delete(format!("{API_BASE}/instances/{instance_id}/"))
            .header("Authorization", self.auth_header())
            .json(&json!({}))
            .send()
            .await
            .context("Vast.ai destroy instance failed")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await?;
            anyhow::bail!("Vast.ai destroy failed (HTTP {status}): {text}");
        }
        Ok(())
    }

    /// Upload an SSH public key to the account.
    pub async fn upload_ssh_key(&self, pubkey: &str) -> Result<()> {
        let resp = self
            .http
            .post(format!("{API_BASE}/ssh/"))
            .header("Authorization", self.auth_header())
            .json(&json!({ "ssh_key": pubkey }))
            .send()
            .await
            .context("Vast.ai SSH key upload failed")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await?;
            // Ignore "already exists" errors
            if !text.contains("already") {
                anyhow::bail!("Vast.ai SSH key upload failed (HTTP {status}): {text}");
            }
        }
        Ok(())
    }
}
