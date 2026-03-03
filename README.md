# harmoniis-wallet

Reference CLI wallet for Harmoniis contracts plus Webcash mining.

## Credits

- Webminer architecture/perf direction inspired by [`maaku/webminer`](https://github.com/maaku/webminer).
- RGB model inspired by [`RGB-WG/rgb`](https://github.com/RGB-WG/rgb).
- Witness custody/replace flow inspired by Webcash server semantics (replace invalidates old secret).

## Key Model (Current)

The wallet stores one BIP39 master mnemonic/entropy pair and derives every slot using hardened BIP32 paths:

- `RGB identity key` (wallet contract identity)
- `Webcash master secret`
- `Bitcoin deterministic slot key`
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

Password manager storage at setup time:

```bash
hrmw setup --password-manager required
```

Modes:

- `required` (default): setup fails if no supported password manager is available.
- `best-effort`: continue setup if password-manager storage fails.
- `off`: skip password-manager storage.

On macOS, this stores in Keychain under a `harmoniis` service label. If iCloud Keychain sync is enabled in macOS settings, those entries sync; `hrmw` cannot force iCloud sync from CLI.

Deterministic slot map:

- `pgp[i]` for `i=0..999` (identity scan range)
- `webcash[0]` deterministic webcash master
- `rgb[0]` deterministic RGB identity root
- `bitcoin[0]` deterministic Bitcoin slot seed material

This allows reconstruction from only the master mnemonic (or entropy hex) plus server discovery.

Database model:

- `master.db` stores root material metadata, slot registry, and PGP identity registry.
- `rgb.db` stores wallet-level contract/certificate/local timeline state.
- `webcash.db` stores Webcash balance state.
- `bitcoin.db` stores Bitcoin/ARK wallet persistence (including ARK boarding outputs).

Important:

- RGB contract state is wallet-scoped (`rgb.db`), not partitioned by active PGP key label.
- PGP identities are signing keys derived from master key slots; switching active PGP label does not switch to a different RGB state database.

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

- Master wallet DB: `~/.harmoniis/master.db`
- RGB DB: `~/.harmoniis/rgb.db`
- Webcash DB: `~/.harmoniis/webcash.db`
- Bitcoin DB: `~/.harmoniis/bitcoin.db`
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

## Payment Rails

- Both rails are supported; backend config controls which rails are enabled.
- Webcash rail uses `X-Webcash-Secret` with `wats`.
- Bitcoin rail uses `X-Bitcoin-Secret` with `sats`.
- In ARK mode, `X-Bitcoin-Secret` must be `ark:<vtxo_txid>:<amount_sats>`.
- Backend ARK mode verifies incoming VTXOs via ASP/wallet state before settlement.
- Client API exposes payment-header abstractions so either rail can be used cleanly.

CLI rail flags:

```bash
# default (webcash)
hrmw --payment-rail webcash timeline post --content "hello"

# bitcoin header mode (requires explicit secret and backend support)
hrmw --payment-rail bitcoin --bitcoin-secret "<vtxo-or-ark-secret>" timeline post --content "hello"

# or via env
HRMW_BITCOIN_SECRET="<vtxo-or-ark-secret>" hrmw --payment-rail bitcoin timeline post --content "hello"
```

ARK helper commands (Arkade ASP):

```bash
hrmw bitcoin ark info
hrmw bitcoin ark boarding-start
hrmw bitcoin ark boarding-end
hrmw bitcoin ark balance
hrmw bitcoin ark send <ark_address> <amount_sats>
hrmw bitcoin ark settle <amount_sats> [--index 0]
hrmw bitcoin ark settle-address <btc_address> <amount_sats>
hrmw bitcoin ark verify-proof 'ark:<vtxo_txid>:<amount_sats>'
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

Project test wallets (Alice/Bob with recovery verification):

```bash
cd harmoniis-wallet
./scripts/prepare_project_test_wallets.sh
```

This creates `wallets/mainnet-test/{alice,bob}` and recovered verification wallets under the project root.

Full mnemonic rebuild proof (root + RGB + Webcash + Bitcoin + ARK + PGP identities):

```bash
cd harmoniis-wallet
./scripts/prove_mnemonic_rebuild.sh
```

This writes `wallets/rebuild-proof/RESULT.txt` plus source/restored snapshots for parity checks.

## Build and Test

```bash
cargo build --release
cargo test --test unit_tests
```
