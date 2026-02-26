# Changelog

All notable changes to `harmoniis-wallet` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

_Nothing yet._

---

## [0.1.14] — 2026-02-26

### Added

- Added CUDA mining backend support (single and multi-device) using NVRTC via `cudarc`.

### Changed

- Backend auto-selection order is now `CUDA -> Vulkan/wgpu -> CPU`.
- `--backend gpu` now prefers CUDA first and falls back to Vulkan/wgpu.

---

## [0.1.13] — 2026-02-25

### Changed

- Removed hybrid mining mode completely; supported webminer backends are now `auto|gpu|cpu`.
- Updated CLI/docs/bench output to CPU+GPU only and removed all hybrid references.

---

## [0.1.12] — 2026-02-25

### Added

- CPU miner now includes AVX2 SIMD hashing path with runtime feature detection on `x86_64`.
- Added unit coverage for multi-GPU nonce range splitting and miner pending-claim logging.
- Added webminer benchmark command guidance and mining safety notes to README.

### Changed

- Webminer startup diagnostics continue to print active setup details (backend mode, GPU devices, CPU threads, chunk size).

### Fixed

- Accepted mining rewards are now claimed using wallet `insert` (`replace`) semantics so mined secrets are rotated and old secrets become invalid.
- If claim/replace fails after accepted mining report, raw claim codes are persisted to `~/.harmoniis/miner_pending_keeps.log` for manual recovery.

---

## [0.1.11] — 2026-02-25

### Added

- Webminer backend selection now supports explicit `--backend auto|gpu|cpu`.
- Webminer now supports `--cpu-threads <N>` for CPU worker control.
- Added `Multi-GPU` backend support that discovers and uses all compatible adapters concurrently.
- Miner startup now prints setup diagnostics (backend mode, CPU threads, GPU device info, nonce chunking).

### Changed

- Miner backend trait now supports range-based mining with structured attempt/elapsed reporting.
- GPU miner dispatch is now range-driven (`nonce_offset` + `nonce_count`) instead of hard-coded single-range execution.
- Daemon hash rate and ETA now use actual attempted nonce counts returned by backends.
- `BackendChoice::Auto` now prefers GPU backend.

---

## [0.1.10] — 2026-02-24

### Changed

- `contract accept` now follows the current backend flow: seller decrypts
  `witness_secret_encrypted_for_seller`, rotates custody via `witness/replace`,
  and stores the seller-held witness secret locally.

### Fixed

- Added support for decrypting `sealed_v2_x25519_chacha20poly1305` witness envelopes in CLI.
- Removed outdated accept guidance that required buyer-side replace after seller acceptance.

---

## [0.1.9] — 2026-02-24

### Changed

- Internal CLI refactor for clearer module boundaries (`hrmw` + helper module split).

### Fixed

- Prevented accidental Webcash spending on non-payment API errors by enforcing 402-only retry.
- Improved `contract buy` payment fallback behavior to align with requested amount.

---

## [0.1.4] — 2026-02-24

### Changed

- CLI production default API is now `https://harmoniis.com/api` (no `--api` needed for normal usage).
- Proxy and direct URL handling now accepts explicit API bases:
  - proxy client accepts `https://harmoniis.com/api` and `https://harmoniis.com`
  - direct client accepts `.../api/v1` or backend root URLs
- README examples now use default production configuration and show `--api` only for staging/dev.

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
  - Persistent on-disk (default `~/.harmoniis/rgb.db`).
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

[Unreleased]: https://github.com/harmoniis/harmoniis-wallet/compare/v0.1.12...HEAD
[0.1.12]: https://github.com/harmoniis/harmoniis-wallet/releases/tag/v0.1.12
[0.1.11]: https://github.com/harmoniis/harmoniis-wallet/releases/tag/v0.1.11
[0.1.10]: https://github.com/harmoniis/harmoniis-wallet/releases/tag/v0.1.10
[0.1.9]: https://github.com/harmoniis/harmoniis-wallet/releases/tag/v0.1.9
[0.1.4]: https://github.com/harmoniis/harmoniis-wallet/releases/tag/v0.1.4
[0.1.2]: https://github.com/harmoniis/harmoniis-wallet/releases/tag/v0.1.2
[0.1.1]: https://github.com/harmoniis/harmoniis-wallet/releases/tag/v0.1.1
[0.1.0]: https://github.com/harmoniis/harmoniis-wallet/releases/tag/v0.1.0
