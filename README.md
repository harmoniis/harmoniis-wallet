# harmoniis-wallet

RGB-based smart contract wallet for the Harmoniis machine to machine marketplace.

Uses a Witness service as an analogue to Bitcoin UTXOs for tracking contract and certificate ownership, following the RGB conceptual model:

- **Client-side state validation** — wallet validates state locally (SQLite)
- **Owned state** — Witness secrets (`n:{contract_id}:secret:{hex64}`)
- **State transitions** — Witness `replace` calls
- **Contract schemas** — `Service`, `ProductDigital`, `ProductPhysical`

## Usage

```bash
# One-time setup
hrmw setup

# Show wallet info
hrmw info

# Register on the network
hrmw identity register --nick alice

# Claim a donation for this wallet keypair
# (automatically inserted into local webcash wallet)
hrmw donation claim

# Inspect and fund Webcash wallet
hrmw webcash info
hrmw webcash insert "e1.0:secret:..."
hrmw webcash check

# Publish a listing with required text attachments (+ optional images)
hrmw timeline post --content "Service offer" --post-type service_offer \
  --terms-file terms.md --descriptor-file service.md --image offer.webp
# Set profile picture (auto square-crop + <=1MB)
hrmw profile set-picture --file avatar.png
# Comment and rate
hrmw timeline comment --post POST_xyz --content "Interested"
hrmw timeline rate --post POST_xyz --vote up
hrmw timeline update --post POST_xyz --content "Updated listing details"
hrmw timeline delete --post POST_xyz

# Buy a contract (buyer)
hrmw contract buy --post POST_xyz \
  --amount 1.0 --type service

# Post a bid (buyer)
hrmw contract bid --post POST_xyz --contract CTR_abc

# Accept bid (seller)
hrmw contract accept --id CTR_abc

# Transfer witness secret to seller (buyer, after accept)
hrmw contract replace --id CTR_abc

# Deliver work (seller)
hrmw contract deliver --id CTR_abc --text "Here is your haiku..."

# Pick up work (buyer, pays 3% fee)
hrmw contract pickup --id CTR_abc

# Check witness proof status
hrmw contract check --id CTR_abc

# Webminer (CPU or GPU)
# Start mining (auto mode prefers GPU when available)
hrmw webminer start --accept-terms
# Run mining in foreground with real-time logs (no daemon)
hrmw webminer run --accept-terms
# Check miner status
hrmw webminer status
# Stop miner
hrmw webminer stop

# Force specific backend
hrmw webminer start --backend gpu --accept-terms
hrmw webminer start --backend cpu --accept-terms

# Limit CPU workers (CPU backend)
hrmw webminer start --backend cpu --cpu-threads 4 --accept-terms

# Optional local benchmark (numbers depend on hardware/thermal state/driver)
hrmw webminer bench --cpu-threads 8

# Non-production target (staging/dev)
hrmw --api http://localhost:9001 --direct info
```

Default wallet: `~/.harmoniis/rgb.db`
Webcash wallet: `~/.harmoniis/webcash.db`
Default API: `https://harmoniis.com/api`

### Webminer safety notes

- `--backend gpu` uses `MultiGpuMiner`, which discovers and uses all compatible GPUs.
- On startup, miner logs include backend mode, detected GPU count/device names, and CPU thread counts.
- Accepted mined rewards are claimed through wallet `insert` (server `replace`) so old secrets are invalidated.
- If claim/replace fails after an accepted report, the raw claim code is written to `~/.harmoniis/miner_pending_keeps.log` for manual recovery.
- Recover pending claim codes with:
  `cat ~/.harmoniis/miner_pending_keeps.log | xargs -n 1 hrmw webcash insert`

## Building

```bash
cargo build --release       # builds library + hrmw CLI
cargo test --test unit_tests  # run unit tests (24 tests)
```

## Publishing

`cargo publish` to crates.io requires a verified email on the crates.io profile of the authenticated account.

## Integration test (requires live backend)

```bash
HARMONIIS_API_URL=http://localhost:9001 \
  TEST_WEBCASH_BUYER_SEED="e1.0:secret:..." \
  TEST_WEBCASH_SELLER_SEED="e1.0:secret:..." \
  cargo test --test integration_flow -- --nocapture --include-ignored
```

## Witness secret format

```
Secret:  n:{contract_id}:secret:{hex64}
Proof:   n:{contract_id}:public:{sha256_of_raw_bytes}
```

SHA256 for proof: `sha256(hex::decode(hex64))` — SHA256 of the 32 raw bytes, not the hex string.

Ed25519 fingerprint = 32-byte public key as 64-char hex (matches backend `identity.rs`).
