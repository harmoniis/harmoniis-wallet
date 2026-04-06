//! Runtime CUDA capability detection.
//!
//! Scans the system for CUDA libraries and makes them discoverable
//! before cudarc tries to load them. This decouples the build-time
//! CUDA version pin from the runtime CUDA version.
//!
//! Call `ensure_cuda_libraries()` once at startup, before any cudarc calls.

use std::path::{Path, PathBuf};

/// Scan the system for CUDA libraries and ensure they're on the library
/// search path. Returns the detected CUDA version string (e.g. "13.0") or None.
pub fn ensure_cuda_libraries() -> Option<String> {
    let mut version = None;

    // 1. Detect driver CUDA version first (determines which toolkit is compatible).
    let driver_version = detect_cuda_version_from_smi();
    let driver_major = driver_version
        .as_ref()
        .and_then(|v| v.split('.').next())
        .and_then(|s| s.parse::<u32>().ok());

    if let Some(ref v) = driver_version {
        eprintln!("CUDA detect: driver reports CUDA {v}");
    }

    // 2. Find CUDA toolkit directories
    let cuda_dirs = find_cuda_directories();
    eprintln!("CUDA detect: scanning {} directories...", cuda_dirs.len());
    for dir in &cuda_dirs {
        eprintln!("CUDA detect:   dir: {}", dir.display());
    }

    // 3. Find NVRTC libraries, preferring the one matching the driver version.
    let mut all_found: Vec<(PathBuf, String, u32)> = Vec::new(); // (dir, version, major)
    for dir in &cuda_dirs {
        if let Some((ver, major)) = find_nvrtc_in_with_major(dir) {
            eprintln!("CUDA detect:   found NVRTC {ver} (major={major}) in {}", dir.display());
            all_found.push((dir.clone(), ver, major));
        }
    }

    if !all_found.is_empty() {
        // Prefer the version matching the driver, then newest available.
        if let Some(dm) = driver_major {
            all_found.sort_by(|a, b| {
                let a_match = (a.2 == dm) as u8;
                let b_match = (b.2 == dm) as u8;
                b_match.cmp(&a_match).then(b.2.cmp(&a.2))
            });
            let best = &all_found[0];
            if best.2 != dm {
                eprintln!(
                    "CUDA detect: WARNING — toolkit NVRTC is v{}, but driver only supports CUDA {}.x",
                    best.1, dm,
                );
                eprintln!(
                    "CUDA detect: install CUDA {dm}.x toolkit, or update GPU driver to support CUDA {}",
                    best.1,
                );
            }
        }
        let (dir, ver, _) = &all_found[0];
        eprintln!("CUDA detect: selected NVRTC {ver} from {}", dir.display());
        version = Some(ver.clone());
        prepend_library_path(dir);
    } else if let Some(ref v) = driver_version {
        eprintln!("CUDA detect: no NVRTC library found in any scanned directory");
        // List nvrtc-related files in scanned dirs to help debug
        for dir in &cuda_dirs {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_lower = name.to_string_lossy().to_lowercase();
                    if name_lower.contains("nvrtc") {
                        eprintln!("CUDA detect:   candidate: {}/{}", dir.display(), name.to_string_lossy());
                    }
                }
            }
        }
        if let Some(dm) = driver_major {
            eprintln!(
                "CUDA detect: install CUDA {dm}.x toolkit from https://developer.nvidia.com/cuda-toolkit-archive"
            );
        }
        version = Some(v.clone());
    } else {
        eprintln!(
            "CUDA detect: no CUDA driver or libraries found (searched {} dirs)",
            cuda_dirs.len()
        );
    }

    version
}

/// Find directories that may contain CUDA libraries.
fn find_cuda_directories() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    // Environment variables
    for var in [
        "CUDA_PATH",
        "CUDA_HOME",
        "CUDA_ROOT",
        "CUDA_TOOLKIT_ROOT_DIR",
        "NVRTC_DLL",
    ] {
        if let Ok(val) = std::env::var(var) {
            eprintln!("CUDA detect: {var}={val}");
            let p = PathBuf::from(&val);
            // CUDA Toolkit: bin/ has DLLs on Windows, lib64/ has .so on Linux
            let bin = p.join("bin");
            let lib64 = p.join("lib64");
            let lib_x64 = p.join("lib").join("x64");
            let lib = p.join("lib").join("x86_64-linux-gnu");
            if bin.is_dir() {
                dirs.push(bin);
            }
            if lib64.is_dir() {
                dirs.push(lib64);
            }
            if lib_x64.is_dir() {
                dirs.push(lib_x64);
            }
            if lib.is_dir() {
                dirs.push(lib);
            }
            if p.is_dir() {
                dirs.push(p);
            }
        }
    }

    // Platform-specific well-known locations
    #[cfg(windows)]
    {
        // Scan all installed CUDA Toolkit versions (prefer newest first).
        let bases = [
            r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA",
            r"C:\Program Files\NVIDIA\CUDA",
        ];
        for base in bases {
            if let Ok(entries) = std::fs::read_dir(base) {
                // Collect and sort descending so v13.0 is tried before v12.0.
                let mut versions: Vec<_> = entries.flatten().collect();
                versions.sort_by(|a, b| b.file_name().cmp(&a.file_name()));
                for entry in versions {
                    let bin = entry.path().join("bin");
                    if bin.is_dir() {
                        dirs.push(bin);
                    }
                    let lib_x64 = entry.path().join("lib").join("x64");
                    if lib_x64.is_dir() {
                        dirs.push(lib_x64);
                    }
                }
            }
        }
        // NVIDIA driver directory — nvrtc forwarding DLLs live here.
        if let Ok(sysroot) = std::env::var("SystemRoot") {
            let sys32 = PathBuf::from(&sysroot).join("System32");
            if sys32.is_dir() {
                dirs.push(sys32);
            }
        }

        // Scan Windows PATH — CUDA installer adds toolkit bin/ to PATH.
        // This catches installations at non-standard locations.
        if let Ok(path) = std::env::var("PATH") {
            for entry in path.split(';') {
                let p = PathBuf::from(entry.trim());
                if p.is_dir() && !dirs.contains(&p) {
                    // Only add dirs that look CUDA-related (performance: don't
                    // scan every PATH directory on the system).
                    let lower = entry.to_lowercase();
                    if lower.contains("cuda") || lower.contains("nvrtc") || lower.contains("nvidia") {
                        dirs.push(p);
                    }
                }
            }
        }
    }

    #[cfg(unix)]
    {
        let known = [
            "/usr/local/cuda/lib64",
            "/usr/local/cuda/lib",
            "/usr/local/cuda/targets/x86_64-linux/lib",
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib64",
        ];
        for d in known {
            let p = PathBuf::from(d);
            if p.is_dir() {
                dirs.push(p);
            }
        }
        // Scan /usr/local/cuda-* versioned installs
        if let Ok(entries) = std::fs::read_dir("/usr/local") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if name.to_string_lossy().starts_with("cuda-") {
                    let lib = entry.path().join("lib64");
                    if lib.is_dir() {
                        dirs.push(lib);
                    }
                }
            }
        }
    }

    dirs
}

/// Check if a directory contains an NVRTC library. Returns (version, major).
fn find_nvrtc_in_with_major(dir: &Path) -> Option<(String, u32)> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut best: Option<(u32, String)> = None;

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();

        #[cfg(windows)]
        {
            // Versioned: nvrtc64_130_0.dll, nvrtc64_120_0.dll, nvrtc64_112_0.dll
            if name.starts_with("nvrtc64_") && name.ends_with(".dll") {
                let ver = name.trim_start_matches("nvrtc64_").trim_end_matches(".dll");
                if let Some(major_minor) = parse_nvrtc_version(ver) {
                    let major = ver
                        .split('_')
                        .next()
                        .and_then(|s| {
                            if s.len() >= 2 {
                                s[..s.len() - 1].parse::<u32>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    if best
                        .as_ref()
                        .map_or(true, |(best_maj, _)| major > *best_maj)
                    {
                        best = Some((major, major_minor));
                    }
                }
            }
            // Unversioned: nvrtc64.dll (some toolkit installs)
            if best.is_none() && (name == "nvrtc64.dll" || name == "nvrtc.dll") {
                // Can't determine version from filename — try to infer from path.
                // e.g. C:\...\CUDA\v13.0\bin\nvrtc64.dll → major=13
                let major = dir
                    .components()
                    .filter_map(|c| {
                        let s = c.as_os_str().to_string_lossy();
                        s.strip_prefix('v')
                            .and_then(|v| v.split('.').next())
                            .and_then(|m| m.parse::<u32>().ok())
                    })
                    .last()
                    .unwrap_or(0);
                let display = if major > 0 {
                    format!("{major}.x")
                } else {
                    "unknown".to_string()
                };
                best = Some((major, display));
            }
        }

        #[cfg(unix)]
        {
            // libnvrtc.so.12, libnvrtc.so.13, libnvrtc.so.12.0.76, etc.
            if name.starts_with("libnvrtc.so.") {
                let ver = name.trim_start_matches("libnvrtc.so.");
                let major_str = ver.split('.').next().unwrap_or(ver);
                let major = major_str.parse::<u32>().unwrap_or(0);
                let display = format!("{major}.x");
                if best
                    .as_ref()
                    .map_or(true, |(best_maj, _)| major > *best_maj)
                {
                    best = Some((major, display));
                }
            }
        }
    }
    best.map(|(major, display)| (display, major))
}

/// Parse NVRTC DLL version string: "130_0" → "13.0", "120_0" → "12.0"
#[allow(dead_code)]
fn parse_nvrtc_version(s: &str) -> Option<String> {
    // Format: MMm_p or MMm  (e.g. "130_0" or "120")
    let num_part = s.split('_').next()?;
    if num_part.len() >= 2 {
        let major = &num_part[..num_part.len() - 1];
        let minor = &num_part[num_part.len() - 1..];
        Some(format!("{major}.{minor}"))
    } else {
        None
    }
}

/// Add a directory to the runtime library search path.
fn prepend_library_path(dir: &Path) {
    let dir_str = dir.to_string_lossy();

    #[cfg(unix)]
    {
        let key = "LD_LIBRARY_PATH";
        let current = std::env::var(key).unwrap_or_default();
        if !current.contains(&*dir_str) {
            let new_val = if current.is_empty() {
                dir_str.to_string()
            } else {
                format!("{dir_str}:{current}")
            };
            std::env::set_var(key, &new_val);
        }
    }

    #[cfg(windows)]
    {
        let key = "PATH";
        let current = std::env::var(key).unwrap_or_default();
        if !current.contains(&*dir_str) {
            let new_val = format!("{dir_str};{current}");
            std::env::set_var(key, &new_val);
        }
    }
}

/// Detect CUDA version from nvidia-smi output.
fn detect_cuda_version_from_smi() -> Option<String> {
    // Try PATH first, then well-known Windows location.
    let candidates = if cfg!(windows) {
        vec![
            "nvidia-smi".to_string(),
            r"C:\Windows\System32\nvidia-smi.exe".to_string(),
            r"C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe".to_string(),
        ]
    } else {
        vec!["nvidia-smi".to_string()]
    };

    for cmd in &candidates {
        if let Ok(output) = std::process::Command::new(cmd).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if let Some(pos) = line.find("CUDA Version:") {
                    let ver = line[pos + 14..].trim();
                    let ver = ver.split_whitespace().next().unwrap_or(ver);
                    return Some(ver.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nvrtc_dll_versions() {
        assert_eq!(parse_nvrtc_version("130_0"), Some("13.0".to_string()));
        assert_eq!(parse_nvrtc_version("120_0"), Some("12.0".to_string()));
        assert_eq!(parse_nvrtc_version("120"), Some("12.0".to_string()));
        assert_eq!(parse_nvrtc_version("90"), Some("9.0".to_string()));
    }
}
