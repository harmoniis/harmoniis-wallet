# Changelog

All notable changes to `harmoniis-wallet` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

_Nothing yet._

---

## [0.1.2] — 2026-02-24

### Added

- Timeline payload attachments in `PublishPostRequest`.
- CLI auto-adds markdown attachments for:
  - `hrmw timeline post` (`description.md`)
  - `hrmw timeline comment` (`comment.md`)
  - `hrmw contract bid` (`bid.md`)

### Fixed

- `hrmw timeline post` now satisfies backend marketplace policy requiring descriptive `.md/.txt`
  attachment for commercial listings.

---

## [0.1.1] — 2026-02-24

### Added

- CLI: `hrmw donation claim` to call `POST /api/v1/donations` with wallet signature (`donation-request`).
- CLI: `hrmw timeline post` for public timeline posting.
- CLI: `hrmw timeline comment` for comment publishing via `parent_id`.
- CLI: `hrmw timeline rate` for post/comment voting (`up`/`down`).
- Client: `claim_donation` and `rate_post` API wrappers.

### Fixed

- `contract bid --post <id>` now correctly uses `parent_id=<id>` in timeline payload.

---

## [0.1.0] — 2026-02-21

### Added

**Library**

- `witnessSecret` — RGB21 bearer secret (`n:{contract_id}:secret:{hex64}`), zeroize-on-drop.
- `witnessProof` — RGB21 public proof (`n:{contract_id}:public:{sha256_of_raw_bytes}`).
- `StablecashSecret` — RGB20 bearer secret (`u{amount_units}:{contract_id}:secret:{hex64}`),
  zeroize-on-drop. **Sandbox only** until Phase 2 is released.
- `StablecashProof` — RGB20 public proof.
- `Identity` — Ed25519 key pair; `fingerprint()` equals the hex-encoded public key (64 chars).
- `RgbWallet` — SQLite-backed local wallet:
  - Persistent on-disk (default `~/.harmoniis/wallet.db`).
  - In-memory mode (`open_memory()`) for tests.
  - Stores `contracts`, `certificates`, and `wallet_metadata`.
  - JSON snapshot export/import.
- `HarmoniisClient` — async HTTP client for the Harmoniis API:
  - `new(base_url)` — routes through the Cloudflare proxy at `harmoniis.com/api/…` (default).
  - `new_direct(backend_url)` — connects directly to a local or Lambda backend.
  - witness methods: `witness_check`, `witness_is_live`, `witness_replace`, `witness_replace_rgb20`.
  - Arbitration methods: `buy_contract`, `get_contract`, `contract_status`, `accept_contract`,
    `deliver`, `pickup`, `refund`, `request_release`.
  - Timeline methods: `register_identity`, `publish_post`, `publish_encrypted_reply`.
- `SecurityDeed` (feature = `securities`) — **Dormant Phase 3** types for
  `ContractBasket`, `Bond`, and `RevenueShare`. Off by default; do **not** enable in production.

**CLI (`hrmw`)**

- Global flags: `--wallet <path>`, `--api <URL>` (default `https://harmoniis.com`),
  `--direct` (bypass Cloudflare proxy).
- `hrmw setup` — generate a new Ed25519 identity and SQLite wallet.
- `hrmw info` — display fingerprint, nickname, and contract summary.
- `hrmw identity register` — register on the Harmoniis timeline.
- `hrmw contract list|get|buy|bid|accept|replace|deliver|pickup|refund|check`.
- `hrmw certificate list|get|insert|check`.

**Tests**

- 24 unit tests covering `crypto`, `types`, and `wallet`.
- 6 local-simulation tests (no live backend required) that mirror DynamoDB witness logic.
- 1 ignored integration test (`tests/integration_flow.rs`) for end-to-end validation against
  a live or local backend.

**Build**

- Feature `bundled-sqlite` (default on) — compiles SQLite from source; no system `libsqlite3`.
- Feature `securities` (off by default) — dormant Phase 3 security types.
- `rustls-tls` on `reqwest` — no OpenSSL dependency; cross-platform (`cargo install` works
  on Linux, macOS, and Windows).

---

[Unreleased]: https://github.com/harmoniis/harmoniis-wallet/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/harmoniis/harmoniis-wallet/releases/tag/v0.1.2
[0.1.1]: https://github.com/harmoniis/harmoniis-wallet/releases/tag/v0.1.1
[0.1.0]: https://github.com/harmoniis/harmoniis-wallet/releases/tag/v0.1.0
