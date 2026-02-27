# harmoniis-wallet

Reference CLI wallet for Harmoniis contracts plus Webcash mining.

## Credits

- Webminer architecture/perf direction inspired by [`maaku/webminer`](https://github.com/maaku/webminer).
- RGB model inspired by [`RGB-WG/rgb`](https://github.com/RGB-WG/rgb).
- Witness custody/replace flow inspired by Webcash server semantics (replace invalidates old secret).

## Key Model (Current)

One root private key is stored in the wallet and deterministically derives separate key material:

- `RGB identity key` (wallet contract identity)
- `Webcash master secret`
- `Bitcoin deterministic slot key` (reserved for Bitcoin rail integration)
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
hrmw key import --mnemonic "word1 word2 ... word24"
hrmw key fingerprint
```

Deterministic slot map:

- `pgp[i]` for `i=0..999` (identity scan range)
- `webcash[0]` deterministic webcash master
- `rgb[0]` deterministic RGB identity root
- `bitcoin[0]` deterministic Bitcoin slot seed material

This allows reconstruction from only the root key export plus server discovery.

## Install

### 1) Install Rust

Ubuntu/Debian:

```bash
curl https://sh.rustup.rs -sSf | sh -s -- -y
source ~/.cargo/env
```

macOS:

```bash
curl https://sh.rustup.rs -sSf | sh -s -- -y
source "$HOME/.cargo/env"
```

Windows (PowerShell):

```powershell
winget install Rustlang.Rustup
rustup default stable
```

FreeBSD:

```sh
pkg install -y rust cargo
```

NetBSD:

```sh
pkgin -y install rust cargo
```

### 2) Install `harmoniis-wallet`

```bash
cargo install harmoniis-wallet
hrmw --version
```

## Default Paths

- Main wallet DB: `~/.harmoniis/rgb.db`
- Webcash DB: `~/.harmoniis/webcash.db`
- Miner log (daemon): `~/.harmoniis/miner.log`
- Miner status JSON: `~/.harmoniis/miner_status.json`
- Pending mined keeps: `~/.harmoniis/miner_pending_keeps.log`

## Quick Start

```bash
hrmw setup
hrmw info

# Optional: create/select additional labeled signing keys
hrmw identity pgp-new --label team-main --active
hrmw identity pgp-list

hrmw identity register --nick alice
hrmw webcash info
```

## RGB Contract Usage

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

## Payment Rails

- Active settlement rail today: **Webcash** (`X-Webcash-Secret`).
- `X-Bitcoin-Secret` is supported when backend enables Bitcoin mode (`HARMONIIS_BITCOIN_PAYMENT_MODE`).
- Client API exposes payment-header abstractions so Bitcoin/ARK can be enabled without breaking existing Webcash flows.

CLI rail flags:

```bash
# default (webcash)
hrmw --payment-rail webcash timeline post --content "hello"

# bitcoin header mode (requires explicit secret and backend support)
hrmw --payment-rail bitcoin --bitcoin-secret "<vtxo-or-ark-secret>" timeline post --content "hello"

# or via env
HRMW_BITCOIN_SECRET="<vtxo-or-ark-secret>" hrmw --payment-rail bitcoin timeline post --content "hello"
```

## Deterministic Bitcoin Wallet (Taproot + SegWit Fallback)

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
- Current backend settlement remains Webcash-first; Bitcoin payment header plumbing is present for staged rollout.
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
hrmw webcash recover --wallet ~/.harmoniis/rgb.db --gap-limit 40
hrmw recover deterministic --pgp-start 0 --pgp-end 999
```

If you accidentally pass `--wallet .../webcash.db`, `hrmw` now auto-corrects to the sibling `rgb.db` path.

For deterministic restore on a new machine:

```bash
hrmw setup
hrmw key import --mnemonic "word1 word2 ... word24" --force
hrmw recover deterministic --pgp-start 0 --pgp-end 999
```

## Build and Test

```bash
cargo build --release
cargo test --test unit_tests
```
