//! Lazy installer for the CUDA Toolkit's NVRTC subpackage on Linux.
//!
//! The CUDA mining backend (`miner::cuda`) needs `libnvrtc.so` to compile
//! its SHA-256 kernel at runtime. The NVIDIA driver alone does not ship
//! NVRTC — only the toolkit does. This module provides:
//!
//! - distro detection (Debian/Ubuntu apt repo metadata),
//! - driver CUDA-version detection (parsed from `nvidia-smi`),
//! - a presence check for `libnvrtc.so`,
//! - and an idempotent installer that adds NVIDIA's CUDA apt repo and
//!   installs `cuda-nvrtc-X-Y` matching the driver.
//!
//! Interactive prompting lives in the CLI; this module is pure
//! orchestration so it can be reused by both `hrmw webminer start` and
//! `miner::cloud::provision` (the latter runs the same shell commands
//! over SSH on a Vast.ai instance).

use std::process::Command;

/// Apt-based Linux distribution descriptor used to build the NVIDIA repo URL.
///
/// `id` is the `/etc/os-release` ID (e.g. "ubuntu", "debian"). `version_id`
/// is the same field's `VERSION_ID` with dots stripped (NVIDIA's repo
/// layout: `ubuntu2404`, `debian12`). `arch` is mapped to NVIDIA's repo
/// arch token (`x86_64`, `sbsa`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AptDistro {
    pub id: String,
    pub version_id: String,
    pub arch: String,
}

impl AptDistro {
    /// `ubuntu2404`, `debian12`, etc. — exactly what NVIDIA's repo layout
    /// uses as a path segment.
    pub fn repo_segment(&self) -> String {
        format!("{}{}", self.id, self.version_id)
    }
}

/// Detect the running distro from `/etc/os-release`. Returns `None` on
/// non-Linux, on read failure, or when the distro isn't apt-based
/// (NVIDIA only ships apt repos for Ubuntu/Debian/WSL-Ubuntu).
pub fn detect_apt_distro() -> Option<AptDistro> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let release = std::fs::read_to_string("/etc/os-release").ok()?;
    let mut id = None;
    let mut id_like = String::new();
    let mut version_id = None;
    for line in release.lines() {
        let (k, v) = line.split_once('=')?;
        let v = v.trim_matches('"').trim();
        match k {
            "ID" => id = Some(v.to_string()),
            "ID_LIKE" => id_like = v.to_string(),
            "VERSION_ID" => version_id = Some(v.replace('.', "")),
            _ => {}
        }
    }
    let id = id?;
    let version_id = version_id?;

    // NVIDIA's apt repo names: ubuntu2204, ubuntu2404, debian11, debian12.
    let supported = matches!(id.as_str(), "ubuntu" | "debian")
        || id_like
            .split_whitespace()
            .any(|t| t == "ubuntu" || t == "debian");
    if !supported {
        return None;
    }

    // Map dpkg arch → NVIDIA repo arch.
    let dpkg = Command::new("dpkg")
        .arg("--print-architecture")
        .output()
        .ok()?;
    let arch = String::from_utf8(dpkg.stdout).ok()?;
    let arch = match arch.trim() {
        "amd64" => "x86_64",
        "arm64" => "sbsa",
        other => other, // pass through; NVIDIA may add more later
    }
    .to_string();

    Some(AptDistro {
        id,
        version_id,
        arch,
    })
}

/// Read the driver's reported CUDA major version from `nvidia-smi`.
/// Returns `None` if the driver isn't installed (no nvidia-smi binary or
/// it errors), which means there is no point installing the toolkit.
pub fn driver_cuda_major() -> Option<u32> {
    let out = Command::new("nvidia-smi")
        .arg("--query")
        .arg("--display=COMPUTE")
        .output()
        .ok()?;
    if !out.status.success() {
        // Older smi versions: try `nvidia-smi` plain and grep.
        let plain = Command::new("nvidia-smi").output().ok()?;
        let s = String::from_utf8_lossy(&plain.stdout);
        return parse_smi_cuda_version(&s);
    }
    let s = String::from_utf8_lossy(&out.stdout);
    parse_smi_cuda_version(&s)
}

fn parse_smi_cuda_version(s: &str) -> Option<u32> {
    // nvidia-smi prints `CUDA Version: 13.0` (header) or `CUDA Version : 13.0`
    // (query mode). Match either spacing.
    let needle = "CUDA Version";
    let pos = s.find(needle)?;
    let rest = &s[pos + needle.len()..];
    let rest = rest.trim_start_matches(|c: char| c == ':' || c.is_whitespace());
    let major: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    major.parse().ok()
}

/// Cheap presence check — runs `ldconfig -p | grep -q libnvrtc.so` style
/// without spawning a shell. Linux only.
pub fn nvrtc_present() -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    let out = Command::new("ldconfig").arg("-p").output();
    let Ok(out) = out else {
        return false;
    };
    String::from_utf8_lossy(&out.stdout).contains("libnvrtc.so")
}

/// Apt-get install command tail (the part after `apt-get install -yqq`).
/// Tries the driver-matching package first, then falls back through known
/// NVRTC subpackage names. Shared with the cloud-provision SSH path so
/// both surfaces stay in sync.
pub fn nvrtc_install_command(driver_major: u32) -> String {
    let primary = match driver_major {
        13 => "cuda-nvrtc-13-0",
        12 => "cuda-nvrtc-12-6",
        _ => "cuda-nvrtc-13-0",
    };
    format!(
        "apt-get update -qq && \
         DEBIAN_FRONTEND=noninteractive apt-get install -yqq {primary} 2>/dev/null || \
         DEBIAN_FRONTEND=noninteractive apt-get install -yqq cuda-nvrtc-13-0 2>/dev/null || \
         DEBIAN_FRONTEND=noninteractive apt-get install -yqq cuda-nvrtc-12-6 2>/dev/null || \
         DEBIAN_FRONTEND=noninteractive apt-get install -yqq cuda-nvrtc-12-4 2>/dev/null || \
         DEBIAN_FRONTEND=noninteractive apt-get install -yqq cuda-nvrtc-12-0 2>/dev/null || \
         DEBIAN_FRONTEND=noninteractive apt-get install -yqq libnvrtc12 2>/dev/null || true"
    )
}

/// Self-contained bash script for installing NVRTC on a remote Ubuntu host
/// over SSH. Unlike [`nvrtc_install_command`], this also bootstraps NVIDIA's
/// CUDA apt repository if missing — fresh cloud instances ship with the
/// NVIDIA driver but no apt source for `cuda-nvrtc-*` packages, so the
/// fallback chain in [`nvrtc_install_command`] alone silently fails (every
/// `apt-get install` returns "package not found", final `|| true` swallows
/// the failure, and `hrmw webminer list-devices` later reports "No mining
/// devices found" — observed on RTX 4080S vast.ai / runpod images).
///
/// The script detects the Ubuntu release on the remote and picks the
/// matching repo segment (ubuntu2404 / ubuntu2204 / ubuntu2004), then
/// installs the keyring deb only if not already present (idempotent), and
/// finally runs the same fallback chain.
pub fn nvrtc_remote_install_script(driver_major: u32) -> String {
    let install_tail = nvrtc_install_command(driver_major);
    format!(
        "set -e; \
         if [ ! -f /usr/share/keyrings/cuda-archive-keyring.gpg ] && \
            ! ls /etc/apt/sources.list.d/ 2>/dev/null | grep -q cuda; then \
           tmp=$(mktemp -d); \
           release=$(lsb_release -rs 2>/dev/null | tr -d .); \
           case \"$release\" in \
             24*) seg=ubuntu2404 ;; \
             22*) seg=ubuntu2204 ;; \
             20*) seg=ubuntu2004 ;; \
             *) seg=ubuntu2204 ;; \
           esac; \
           curl -fsSL --retry 3 -o \"$tmp/cuda-keyring.deb\" \
             \"https://developer.download.nvidia.com/compute/cuda/repos/${{seg}}/x86_64/cuda-keyring_1.1-1_all.deb\"; \
           dpkg -i \"$tmp/cuda-keyring.deb\"; \
           rm -rf \"$tmp\"; \
         fi; \
         {install_tail}"
    )
}

/// Add NVIDIA's CUDA apt repo (idempotent — skips if the keyring file
/// already exists) and install the NVRTC package matching the driver.
///
/// Runs through `sudo` unless already euid 0. Returns Err on any step
/// failure with stderr captured for the caller to surface.
#[cfg(target_os = "linux")]
pub fn install_nvrtc(distro: &AptDistro, driver_major: u32) -> anyhow::Result<()> {
    use anyhow::{anyhow, Context};

    let keyring_installed = std::path::Path::new("/usr/share/keyrings/cuda-archive-keyring.gpg")
        .exists()
        || std::fs::read_dir("/etc/apt/sources.list.d")
            .map(|d| {
                d.flatten()
                    .any(|e| e.file_name().to_string_lossy().contains("cuda"))
            })
            .unwrap_or(false);

    let segment = distro.repo_segment();
    let arch = &distro.arch;
    let keyring_url = format!(
        "https://developer.download.nvidia.com/compute/cuda/repos/{segment}/{arch}/cuda-keyring_1.1-1_all.deb"
    );

    let install_tail = nvrtc_install_command(driver_major);

    let script = if keyring_installed {
        install_tail
    } else {
        format!(
            "set -e; \
             tmp=$(mktemp -d); \
             curl -fsSL --retry 3 -o \"$tmp/cuda-keyring.deb\" '{keyring_url}'; \
             dpkg -i \"$tmp/cuda-keyring.deb\"; \
             rm -rf \"$tmp\"; \
             {install_tail}"
        )
    };

    run_privileged_script(&script).context("CUDA NVRTC install failed")?;

    if !nvrtc_present() {
        return Err(anyhow!(
            "apt completed but libnvrtc.so still not visible to ldconfig — \
             the package may not match your driver's CUDA major version ({driver_major}). \
             See https://developer.nvidia.com/cuda-toolkit-archive"
        ));
    }
    Ok(())
}

/// Run a shell script with root privileges. Uses sudo unless already root,
/// which keeps it ergonomic in containers (root, no sudo) and on user
/// laptops (sudo with cached credentials).
#[cfg(target_os = "linux")]
fn run_privileged_script(script: &str) -> anyhow::Result<()> {
    use anyhow::bail;
    let is_root = unsafe { libc::geteuid() } == 0;
    let mut cmd = if is_root {
        let mut c = Command::new("sh");
        c.arg("-c").arg(script);
        c
    } else {
        let mut c = Command::new("sudo");
        c.arg("-E").arg("sh").arg("-c").arg(script);
        c
    };
    let status = cmd.status()?;
    if !status.success() {
        bail!("privileged command exited with {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_smi_header_format() {
        let s = "+-----------------------------------------------------------------------------+\n\
                 | NVIDIA-SMI 550.127.05   Driver Version: 550.127.05   CUDA Version: 13.0     |\n\
                 |-------------------------------+----------------------+----------------------+\n";
        assert_eq!(parse_smi_cuda_version(s), Some(13));
    }

    #[test]
    fn parses_smi_query_format() {
        let s = "==============NVSMI LOG==============\n\nCUDA Version : 12.6\n";
        assert_eq!(parse_smi_cuda_version(s), Some(12));
    }

    #[test]
    fn ignores_garbage() {
        assert_eq!(parse_smi_cuda_version("nothing relevant here"), None);
    }

    #[test]
    fn install_command_picks_matching_package_first() {
        let cmd = nvrtc_install_command(13);
        let pos_13 = cmd.find("cuda-nvrtc-13-0").unwrap();
        let pos_12 = cmd.find("cuda-nvrtc-12-6").unwrap();
        assert!(pos_13 < pos_12);
    }

    #[test]
    fn distro_repo_segment_is_concatenated() {
        let d = AptDistro {
            id: "ubuntu".to_string(),
            version_id: "2404".to_string(),
            arch: "x86_64".to_string(),
        };
        assert_eq!(d.repo_segment(), "ubuntu2404");
    }
}
