<p align="center">
<pre>
 _                          _          _ _      _
| |__  _ __ _ __ _____      ___ _ __ | | | ___| |_
| '_ \| '__| '_ ` _ \ \ /\ / / / _ \| | |/ _ \ __|
| | | | |  | | | | | \ V  V /| |  __/| | |  __/ |_
|_| |_|_|  |_| |_| |_|\_/\_/ |_|\___||_|_|\___|\__|
</pre>
</p>

<p align="center">
<em>Smart-contract wallet for the Harmoniis decentralised marketplace — RGB contracts, Webcash fees, Bitcoin/ARK settlement</em>
</p>

<p align="center">
<a href="https://crates.io/crates/harmoniis-wallet"><img src="https://img.shields.io/crates/v/harmoniis-wallet.svg" alt="crates.io"></a>
<a href="https://github.com/harmoniis/harmoniis-wallet/actions/workflows/ci.yml"><img src="https://github.com/harmoniis/harmoniis-wallet/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
</p>

---

## Install

**macOS / Linux / FreeBSD:**

```bash
curl --proto '=https' --tlsv1.2 -sSf https://harmoniis.com/wallet/install | sh
```

**Windows (PowerShell):**

```powershell
iwr https://harmoniis.com/wallet/install.ps1 -UseB | iex
```

**From source (requires Rust 1.86+):**

```bash
cargo install harmoniis-wallet
```

## Quick Start

```bash
hrmw setup
hrmw info

hrmw identity register --nick alice
# alias: hrmw identity claim --nick alice
hrmw webcash info
```

## Upgrade

```bash
hrmw upgrade
```

## Uninstall

**macOS / Linux / FreeBSD:**

```bash
curl -fsSL https://github.com/harmoniis/harmoniis-wallet/releases/latest/download/uninstall.sh | sh
```

**Windows (PowerShell):**

```powershell
iwr https://github.com/harmoniis/harmoniis-wallet/releases/latest/download/uninstall.ps1 -UseB | iex
```

Wallet data at `~/.harmoniis/` is **never removed** by the uninstaller.

## Mining

```bash
hrmw webminer bench                     # benchmark CPU + GPU
hrmw webminer run --accept-terms        # foreground mining
hrmw webminer start --accept-terms      # background mining
hrmw webminer status                    # check miner status
hrmw webminer stop                      # stop background miner
```

GPU auto-detection: CUDA (NVIDIA) > Vulkan/DX12 (AMD/Intel) > CPU fallback.

## Contract Usage

Buyer flow:

```bash
hrmw contract buy --post POST_ID --amount 1.0 --type service
hrmw contract bid --post POST_ID --contract CONTRACT_ID
```

Seller/holder flow:

```bash
hrmw contract insert 'n:CONTRACT_ID:secret:<hex>'
hrmw contract accept --id CONTRACT_ID
hrmw contract deliver --id CONTRACT_ID --text 'delivered work'
```

Transfer custody safely:

```bash
hrmw contract replace --id CONTRACT_ID
```

`replace` rotates witness state: the old secret is invalid after replacement.

## Webcash Usage

```bash
hrmw webcash info
hrmw webcash insert 'e1.0:secret:<hex>'
hrmw webcash pay --amount 0.2 --memo 'payment'
hrmw webcash check
hrmw webcash recover --gap-limit 20
hrmw webcash merge --group 20
```

## Voucher Usage

```bash
hrmw voucher info
hrmw voucher insert 'v10:secret:<hex>'
hrmw voucher pay --amount 3 --memo 'payment'
hrmw voucher check
hrmw voucher recover --gap-limit 20
hrmw voucher merge --group 20
```

- Voucher outputs are bearer secrets; keep exported voucher secrets if you may need to rebuild the voucher wallet.
- `hrmw voucher recover` reports the current deterministic voucher-proof recovery limitation.

## Payment Rails

- Payment for paid commands is sourced from the local wallet automatically.
- Webcash rail uses `X-Webcash-Secret` with `wats`.
- Voucher rail uses `X-Voucher-Secret` with `credits`.
- Bitcoin rail uses `X-Bitcoin-Secret` with `sats`.
- In ARK mode, `X-Bitcoin-Secret` must be `ark:<vtxo_txid>:<amount_sats>`.
- Backend ARK mode verifies incoming VTXOs via ASP/wallet state before settlement.
- Clients may send `X-Payment-Rail` on the unpaid probe; `402` responses publish `payment.rail_details`, and `/api/info` mirrors the same acquisition metadata under `payment_rails`.
- Rail lock is strict per listing inception rail:
  - comments on a post must pay with that post rail,
  - ratings on a post must pay with that post rail,
  - contract buy must pay with the reference post rail.
- Contract pickup is free and does not take a payment header.
- Wrong rail on paid descendants returns HTTP `402` with `code: payment_rail_mismatch`.
- Client API exposes payment-header abstractions so either rail can be used cleanly.

CLI rail flags:

```bash
# default (webcash)
hrmw --payment-rail webcash timeline post --content "hello"

# voucher rail from local wallet
hrmw --payment-rail voucher timeline post --content "hello"

# bitcoin rail from local ARK wallet
hrmw --payment-rail bitcoin timeline post --content "hello"
```

ARK helper commands (Arkade ASP):

```bash
hrmw bitcoin ark info
hrmw bitcoin ark deposit
hrmw bitcoin ark boarding
hrmw bitcoin ark balance
hrmw bitcoin ark send <ark_address> <amount_sats>
hrmw bitcoin ark settle <amount_sats> [--index 0]
hrmw bitcoin ark settle-address <btc_address> <amount_sats>
hrmw bitcoin ark verify-proof 'ark:<vtxo_txid>:<amount_sats>'
```

Command semantics:
- `deposit`: show the ARK deposit address (send on-chain BTC here).
- `boarding`: finalize deposited on-chain BTC into ARK offchain balance.
- `settle`: settle ARK offchain sats back to this wallet on-chain address.
- `settle-address`: settle ARK offchain sats to any on-chain BTC address.

## Generic 402 Requests

`hrmw` can perform custom paid requests against Harmoniis or another HTTP 402 service:

```bash
hrmw --payment-rail webcash req \
  --url https://harmoniis.com/api \
  --endpoint /timeline \
  --method POST \
  --json '{"author_fingerprint":"<fp>","author_nick":"agent_ops","content":"hello","signature":"<pgp_signature>"}'
```

Alias: `hrmw 402 ...`

Inspection and safety commands:
- `hrmw req losses`
- `hrmw req blacklist list`
- `hrmw --payment-rail bitcoin req blacklist clear --url https://harmoniis.com/api --endpoint /timeline --method POST`

## Deterministic Bitcoin Wallet

The wallet derives a deterministic Bitcoin slot (`bitcoin[0]`) from the root key and exposes:
- Taproot (`BIP86`) as the primary receive path.
- SegWit (`BIP84`) as compatibility fallback for payers without Taproot support.

```bash
# show descriptors + deterministic address and sync balances
hrmw bitcoin info

# explicit sync settings
hrmw bitcoin sync --network bitcoin --stop-gap 40 --parallel-requests 8

# deterministic taproot address at index N
hrmw bitcoin address --network bitcoin --kind taproot --index 0

# deterministic segwit fallback address at index N
hrmw bitcoin address --network bitcoin --kind segwit --index 0
```

Notes:
- This is deterministic reconstruction support (no separate seed file needed).
- `hrmw bitcoin info` and `hrmw bitcoin sync` report both Taproot and SegWit next receive addresses.
- On-chain addresses are funding rails; ARK tokens are settlement inputs and must be backend-verified.
- Default esplora endpoints are auto-selected by network and can be overridden with `--esplora`.

## Mining

Foreground (recommended for live logs):

```bash
hrmw webminer run --accept-terms
```

Backend order in `auto`: `CUDA -> Vulkan/wgpu -> CPU`.

Examples:

```bash
hrmw webminer run --backend auto --accept-terms
hrmw webminer run --backend gpu --accept-terms
hrmw webminer run --backend cpu --cpu-threads 8 --accept-terms
hrmw webminer bench --cpu-threads 8
```

Accepted mined keeps are inserted into wallet with replace semantics (old secret invalidated).
If insert fails after acceptance, pending keeps are stored in `miner_pending_keeps.log`.

## Key Model

The wallet stores one BIP39 master mnemonic/entropy pair and derives every slot using hardened BIP32 paths:

- `RGB identity key` (wallet contract identity)
- `Webcash master secret`
- `Bitcoin deterministic slot key`
- `Generic vault root slot` (for app-scoped vault key derivation)
- `PGP-style signing identities` (multiple, labeled, selectable)

PGP identities are managed with labels:

```bash
hrmw identity pgp-list
hrmw identity pgp-new --label ops-signing
hrmw identity pgp-use --label ops-signing
```

`hrmw identity register` signs with the active PGP label by default.

Master key backup / restore:

```bash
hrmw key export --format mnemonic
hrmw key export --format hex --output ./master.hex
hrmw key import --mnemonic "word1 word2 ... word12"
hrmw key fingerprint
```

Password manager storage:

```bash
# During initial setup
hrmw setup --password-manager required

# Change setting on an existing wallet (idempotent — safe to re-run)
hrmw setup --password-manager off        # remove credentials from OS store
hrmw setup --password-manager required   # (re-)store credentials in OS store
hrmw setup --password-manager best-effort
```

Modes:

- `required` (default): fails if no supported password manager is available.
- `best-effort`: continue if password-manager storage fails.
- `off`: remove credentials from OS store (or skip storage on first run).

Re-running `hrmw setup` on an existing wallet is safe: it never destroys key material, contracts, or identities. It only updates the password manager setting. To re-import a master key, use `hrmw key import --force` instead.

After switching to `off`, back up your master key immediately:

```bash
hrmw key export --format mnemonic
```

Supported credential stores:

| Platform | Backend |
|----------|---------|
| macOS | Keychain (with optional iCloud sync) |
| Linux | Secret Service (`secret-tool`) |
| Windows | Credential Manager (`cmdkey`) |

Deterministic slot map:

- `pgp[i]` for `i=0..999` (identity scan range)
- `webcash[0]` deterministic webcash master
- `rgb[0]` deterministic RGB identity root
- `bitcoin[0]` deterministic Bitcoin slot seed material
- `vault[0]` deterministic vault root seed material (backward-compatible alias: `harmonia-vault[0]`)

This allows reconstruction from only the master mnemonic (or entropy hex) plus server discovery.

Derived vault material (for any consumer app) is exposed by `src/vault.rs`:

```rust
use harmoniis_wallet::{wallet::RgbWallet, VaultRootMaterial};

let wallet = RgbWallet::open(std::path::Path::new(\"~/.harmoniis/master.db\"))?;
let root = VaultRootMaterial::from_wallet(&wallet)?;
let aead_key = root.derive_aead_key_bytes(\"my-app\")?;
let mqtt_seed = root.derive_mqtt_tls_seed_bytes(\"default\")?;
```

Database model:

- `master.db` stores root material metadata, slot registry, and PGP identity registry.
- `rgb.db` stores wallet-level contract/certificate/local timeline state.
- `webcash.db` stores Webcash balance state.
- `bitcoin.db` stores Bitcoin/ARK wallet persistence (including ARK boarding outputs).

Important:

- RGB contract state is wallet-scoped (`rgb.db`), not partitioned by active PGP key label.
- PGP identities are signing keys derived from master key slots; switching active PGP label does not switch to a different RGB state database.

## Default Paths

All wallet data lives under `~/.harmoniis/`:

| File | Purpose |
|------|---------|
| `~/.harmoniis/master.db` | Root material metadata, slot registry, PGP identity registry |
| `~/.harmoniis/rgb.db` | Wallet-level contract, certificate, and local timeline state |
| `~/.harmoniis/webcash.db` | Webcash balance state |
| `~/.harmoniis/bitcoin.db` | Bitcoin/ARK wallet persistence (including ARK boarding outputs) |
| `~/.harmoniis/miner.log` | Miner daemon log |
| `~/.harmoniis/miner_status.json` | Miner status snapshot |
| `~/.harmoniis/miner_pending_keeps.log` | Pending mined keeps (fallback if insert fails) |

## Backup and Restore

Backup the entire wallet directory:

```bash
tar -C ~ -czf harmoniis_backup_$(date +%Y%m%d_%H%M%S).tar.gz .harmoniis
```

Restore:

```bash
tar -C ~ -xzf harmoniis_backup_YYYYMMDD_HHMMSS.tar.gz
```

Then validate:

```bash
hrmw info
hrmw webcash recover --wallet ~/.harmoniis/master.db --gap-limit 40
hrmw recover deterministic --pgp-start 0 --pgp-end 999
```

If you accidentally pass `--wallet .../webcash.db`, `hrmw` now auto-corrects to the sibling `master.db` path.

For deterministic restore on a new machine:

```bash
hrmw setup
hrmw key import --mnemonic "word1 word2 ... word12" --force
hrmw recover deterministic --pgp-start 0 --pgp-end 999
```

## Module Structure

```
src/
  lib.rs                   # public API, re-exports, backward-compat shims
  config.rs                # WalletConfig (centralized configuration)
  wallet/
    mod.rs                 # WalletCore (was RgbWallet)
    schema.rs              # SQLite schema / migrations
    identities.rs          # PGP identity management
    payments.rs            # payment rail logic
    contracts.rs           # RGB contract operations
    snapshots.rs           # JSON snapshot import/export
    webcash.rs             # re-exports from webylib (SecretWebcash, Amount, etc.)
    storage.rs             # S3 wallet backup (behind s3-storage feature)
  marketplace/
    mod.rs                 # HarmoniisClient (was client/)
    identities.rs          # identity registration
    posts.rs               # timeline posting
    storage.rs             # marketplace storage helpers
    timeline.rs            # timeline queries
    ...
  actors/
    mod.rs                 # actix actor infrastructure (behind actix-actors feature)
    wallet_actor.rs
    webcash_actor.rs
    payment_ledger_actor.rs
```

Backward-compatible re-exports in `lib.rs`:
- `pub type RgbWallet = WalletCore` -- existing code continues to compile.
- `pub mod client = marketplace` -- old import paths still work.

### Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `bundled-sqlite` | on | Compile SQLite from source |
| `securities` | off | Dormant Phase 3 security types |
| `actix-actors` | off | Actix actor wrappers for wallet, webcash, and payment ledger |
| `s3-storage` | off | S3 wallet backup + AWS Secrets Manager integration |

### Configuration

`WalletConfig` centralizes runtime settings (API base URL, wallet path, network, payment rail preferences) and is threaded through constructors instead of scattered env reads.

## Build and Test

```bash
cargo build --release
cargo test --test unit_tests
```

## Credits

- Webminer architecture/perf direction inspired by [`maaku/webminer`](https://github.com/maaku/webminer).
- RGB smart-contract model built on [`RGB-WG/rgb`](https://github.com/RGB-WG/rgb) with Harmoniis witness-backed bearer state and arbitration service.
- Witness custody/replace flow inspired by Webcash server semantics (replace invalidates old secret).
