# harmoniis-wallet

Reference CLI wallet for the Harmoniis marketplace and Webcash miner.

It provides:
- RGB-style contract/certificate custody via Witness secrets.
- Local wallet state in SQLite.
- Webcash wallet operations (`info`, `insert`, `pay`, `check`, `recover`, `merge`).
- Webcash mining with backends: `CUDA -> Vulkan/wgpu -> CPU`.

## Install

### crates.io (recommended)

```bash
cargo install harmoniis-wallet
hrmw --version
```

### Fresh Ubuntu (install Rust first)

```bash
curl https://sh.rustup.rs -sSf | sh -s -- -y
source ~/.cargo/env
cargo install harmoniis-wallet
hrmw --version
```

## Default Paths

- Main wallet DB: `~/.harmoniis/rgb.db`
- Webcash wallet DB: `~/.harmoniis/webcash.db`
- Miner log (daemon mode): `~/.harmoniis/miner.log`
- Miner status JSON: `~/.harmoniis/miner_status.json`
- Pending accepted keeps: `~/.harmoniis/miner_pending_keeps.log`

Important: `hrmw webcash ... --wallet` expects the **main wallet path** (`rgb.db`), not `webcash.db`.

## Quick Start

```bash
# One-time setup
hrmw setup

# Wallet summary
hrmw info

# Register identity
hrmw identity register --nick alice

# Webcash basics
hrmw webcash info
hrmw webcash insert "e1.0:secret:..."
hrmw webcash check
```

## Webminer (Production)

### Foreground run (recommended while validating)

```bash
hrmw webminer run --accept-terms
```

This prints active backend, GPU/CPU setup, speed, ETA, and accepted solutions in real time.

### Background daemon mode

```bash
hrmw webminer start --accept-terms
hrmw webminer status
hrmw webminer stop
```

### Backend selection

```bash
# Auto: CUDA -> Vulkan/wgpu -> CPU
hrmw webminer run --backend auto --accept-terms

# GPU-only policy (CUDA preferred)
hrmw webminer run --backend gpu --accept-terms

# CPU-only policy
hrmw webminer run --backend cpu --cpu-threads 8 --accept-terms
```

### Local benchmark

```bash
hrmw webminer bench --cpu-threads 8
```

Benchmark numbers are hardware/driver/thermal dependent.

## Mining Safety and Recovery

- Accepted mining rewards are claimed with Webcash `replace` + wallet `insert`, so old secrets are invalidated.
- If claim/insert fails after server acceptance, keep secrets are written to `~/.harmoniis/miner_pending_keeps.log`.

Replay pending keeps:

```bash
cat ~/.harmoniis/miner_pending_keeps.log | xargs -n 1 hrmw webcash insert
```

Recover deterministic Webcash chains:

```bash
hrmw webcash recover --wallet ~/.harmoniis/rgb.db --gap-limit 20
```

## Backup (Recommended)

Backup the full wallet directory, not a single DB:

```bash
tar -C ~ -czf harmoniis_backup_$(date +%Y%m%d_%H%M%S).tar.gz .harmoniis
```

Restore:

```bash
tar -C ~ -xzf harmoniis_backup_YYYYMMDD_HHMMSS.tar.gz
```

## Build and Test

```bash
cargo build --release
cargo test --test unit_tests
```

## Publish

```bash
cargo publish
```

Requires crates.io authentication and a verified crates.io email.
