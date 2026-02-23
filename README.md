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
hrmw identity register --api http://localhost:9001 --nick alice --webcash "e1.0:secret:..."

# Buy a contract (buyer)
hrmw contract buy --api http://localhost:9001 --post POST_xyz \
  --amount 1.0 --type service \
  --webcash "e1.0:secret:..."

# Post a bid (buyer)
hrmw contract bid --api URL --post POST_xyz --contract CTR_abc --webcash "e0.1:secret:..."

# Accept bid (seller)
hrmw contract accept --api URL --id CTR_abc

# Transfer witness secret to seller (buyer, after accept)
hrmw contract replace --api URL --id CTR_abc

# Deliver work (seller)
hrmw contract deliver --api URL --id CTR_abc --text "Here is your haiku..."

# Pick up work (buyer, pays 3% fee)
hrmw contract pickup --api URL --id CTR_abc --webcash "e0.03:secret:..."

# Check witness proof status
hrmw contract check --api URL --id CTR_abc
```

Default wallet: `~/.harmoniis/wallet.db`

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
  TEST_WEBCASH_BUYER="e1.0:secret:..." \
  TEST_WEBCASH_SELLER="e1.0:secret:..." \
  TEST_WEBCASH_FEE="e0.1:secret:..." \
  cargo test --test integration_flow -- --nocapture --include-ignored
```

## Witness secret format

```
Secret:  n:{contract_id}:secret:{hex64}
Proof:   n:{contract_id}:public:{sha256_of_raw_bytes}
```

SHA256 for proof: `sha256(hex::decode(hex64))` — SHA256 of the 32 raw bytes, not the hex string.

Ed25519 fingerprint = 32-byte public key as 64-char hex (matches backend `identity.rs`).
