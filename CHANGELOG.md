# Changelog

All notable changes to `harmoniis-wallet` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [0.1.61] — 2026-04-15

### Fixed

- **CI**: crates.io check sends a **`curl` User-Agent** (403 without it).

## [0.1.60] — 2026-04-15

### Changed

- **CI**: Fail fast unless the **webylib** version in `Cargo.toml` is already published on crates.io (release webylib before tagging).

## [0.1.59] — 2026-04-15

### Changed

- **webylib**: Require **0.2.6+** (published on crates.io). Release **webylib** before this crate.

## [0.1.58] — 2026-04-15

### Fixed

- **Clippy / hygiene**: Resolve new `clippy` lints (including `-D warnings` cleanups)
  across library, miner, marketplace, and tests; document allowed lints for the large CLI surface in `Cargo.toml`.
- **Async**: `recover_pending` no longer holds the SQLite `MutexGuard` across `.await`.

## [0.1.57] — 2026-04-15

### Changed

- **Naming (webcash)**: Prefer **secret** / **secret webcash string** over “token”
  for bearer `e…:secret:…` values. `extract_webcash_token` is replaced by
  `extract_webcash_secret` (library + CLI). Payment CLI output label updated.
- **Internal**: `rail_token` identifiers in the paid-request engine renamed to
  `rail_key` (payment rail label, not webcash).
- **Metadata helpers**: `normalize_token` renamed to `normalize_metadata_tag` in
  CLI support (category/location tags, unrelated to webcash).

## [0.1.55] — 2026-04-14

### Added

- **iOS and Android library targets**: `aarch64-apple-ios`, `aarch64-apple-ios-sim`,
  `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`.
  Built as static/dynamic libraries for SDK integration.
- **Difficulty-aware cloud instance selection**: Offers that exceed server
  reporting capacity at the current difficulty are filtered out and rejected.
  Prevents renting GPUs that would lose solutions.
- **Background wallet insertion thread**: Keep secrets are inserted into the
  webcash wallet on a separate OS thread immediately after each mining report,
  without blocking the reporter pipeline.
- **Drain-before-shutdown**: Monitored drain with progress display and 600s
  timeout. Wallet insertion completes before exit.
- **Queue depth monitoring**: `pending=N` in periodic stats line. Warns when
  reporters fall behind.

### Changed

- **Single reporter thread**: Server processes reports sequentially (~6s each).
  Multiple clients provided zero throughput and wasted CPU. Now 1 reporter + 1
  wallet thread = 3 OS threads total (was 6-16).
- **wgpu MAX_BATCH 8→64, pipeline_depth 4→32**: +50% mining speed on wgpu
  (390→587 MH/s on AMD RX 580). Matches CUDA batch size.
- **Roofline hashrate estimation**: `min(TFLOPS × 0.267, mem_bw × 0.016)` GH/s
  per GPU. Generic formula — works across Pascal, Ampere, Ada without per-GPU
  hardcoding. Correctly estimates RTX 4090 (14.4 vs 14.5 actual), Titan X
  Pascal (3.2 vs 3.2 actual).
- **Lazy wallet runtime**: Tokio runtime for wallet insertion only created when
  first solution is accepted. Zero overhead during pure mining.
- **Webcash pricing (backend)**: Updated to roofline model with server reporting
  cap (600 solutions/hr max). Overcapacity offers filtered from pricing average.
- Upgraded webylib 0.1→0.2 (fixes iOS compilation).
- Branding: "marketplace for agents and robots" (not "decentralised marketplace").

### Fixed

- Cloud stop: waits up to 10 min for solution drain before destroying instance.
- Stale `pending_solutions.log` cleared after drain (prevents "Bad timestamp"
  errors on collect).
- UNIQUE constraint on wallet insert handled gracefully (skip, don't error).
- Removed broken `collect --watch` from cloud start (wallet insertion is built-in).
- SSH wait increased to 5 min for slow CUDA Docker boot on vast.ai.

## [0.2.0] — 2026-03-29

### Changed

- **Breaking module reorganization** (public API preserved via re-exports):
  - `wallet.rs` split into `wallet/` module with focused files: `mod.rs`,
    `schema.rs`, `identities.rs`, `payments.rs`, `contracts.rs`, `snapshots.rs`.
  - `client/` renamed to `marketplace/` with `timeline.rs` split out from the
    monolithic client module.
  - Core wallet type renamed `WalletCore`; `RgbWallet` remains as a type alias.
  - `pub mod client` shim re-exports `marketplace` for backward compatibility.

### Added

- New `config.rs` with `WalletConfig` for centralized runtime configuration
  (API base, wallet path, network, payment rail preferences).
- New `wallet/webcash.rs` re-exporting webylib types (`SecretWebcash`, `Amount`,
  `PublicWebcash`, etc.) so downstream crates no longer need a direct webylib
  dependency.
- New `actors/` module behind `actix-actors` feature flag with `WalletActor`,
  `WebcashActor`, and `PaymentLedgerActor`.
- New `wallet/storage.rs` behind `s3-storage` feature flag for S3 wallet backup
  and AWS Secrets Manager integration.

## [0.1.39] — 2026-03-26

### Added

- `hrmw setup` is now idempotent: re-running on an existing wallet updates
  settings (e.g. `--password-manager off`) without destroying key material.
- Password manager credentials can now be removed post-setup via
  `hrmw setup --password-manager off`.
- Release binaries for Linux, macOS, and Windows now include GPU mining support
  (wgpu: DX12/Vulkan/Metal). Previously GPU was compile-time only for source builds.
- Added `install.ps1` PowerShell installer for first-time Windows users.

### Changed

- CI/CD overhauled to follow Harmonia patterns:
  - FreeBSD builds use native VM via `cross-platform-actions` instead of `cross-rs`.
  - Windows builds use MSVC environment setup (`ilammy/msvc-dev-cmd`).
  - All native platform releases compiled with GPU support.
  - FreeBSD aarch64 dropped; FreeBSD x86_64 now uses native VM builds.

### Fixed

- Fixed `GPU: feature-disabled [MISS]` on Windows — release binaries now include
  the wgpu GPU backend which auto-selects DX12 or Vulkan for AMD and NVIDIA GPUs.
- Fixed inability to change password manager setting after initial wallet setup.

## [0.1.38] — 2026-03-18

### Fixed

- Published the current request-engine and accounting-compatible wallet surface as a new release so Harmonia can consume a versioned `harmoniis-wallet` crate in CI and release automation instead of relying on an unpublishable sibling-only checkout.

## [0.1.37] — 2026-03-18

### Fixed

- Corrected paid-request compatibility for multi-rail `HTTP 402` flows, including proper rail/header selection and challenge-id echoing for settlement correlation.
- Restored the wallet request-engine regression coverage so the release test suite catches 402/client compatibility drift before publishing.

## [0.1.36] — 2026-03-17

### Fixed

- Added the `CARGO_REGISTRY_TOKEN` release secret and cut a clean patch release from a committed lockfile so the automated crates.io publish step can run.

## [0.1.35] — 2026-03-17

### Fixed

- Formatted the wallet-owned 402 engine and voucher support changes so the release CI passes `cargo fmt --check`.

## [0.1.34] — 2026-03-17

### Added

- Added a shared wallet-owned HTTP 402 request engine for:
  - `identity register` / `identity claim`
  - `timeline post`
  - `timeline comment`
  - `timeline rate`
  - `contract buy`
  - `contract bid`
- Added generic paid-request execution via `hrmw req` with `hrmw 402` alias.
- Added paid-request loss and blacklist inspection:
  - `hrmw req losses`
  - `hrmw req blacklist list`
  - `hrmw req blacklist clear`
- Added first-class voucher wallet persistence and automatic voucher-funded retries.

### Changed

- Paid requests now acquire Webcash, Voucher, and ARK Bitcoin value from local wallet state instead of manual payment-secret flags.
- `402` retry flow now uses `payment.rail_details` / `/api/info` acquisition metadata and sends `X-Payment-Rail` on unpaid probes.
- README and skill docs now describe the local-wallet payment flow, generic paid requests, voucher behavior, and free pickup semantics.

### Fixed

- Webcash and Voucher secrets are reinserted locally after post-payment service errors when still live.
- Unrecoverable paid-request failures are now logged and auto-blacklisted after repeated endpoint losses.

## [0.1.33] — 2026-03-10

### Added

- Added wallet-derived vault identity signing support to `hrmw` so Harmonia
  broker, remote config, and push flows can sign requests directly from labeled
  vault-derived identities.
- Added CLI support for labeled vault-derived identity management, including
  creation, listing, export, and signing.

### Changed

- Extended wallet vault identity handling so derived identities can carry stable
  labels and be used cleanly for MQTT/TLS and Harmonia remote-config flows.
- Added PKCS#8 PEM export for wallet-derived Ed25519 identities used by the
  Harmonia MQTT certificate flow.

## [0.1.26] — 2026-03-07

### Added

- Added generic vault derivation module `src/vault.rs`:
  - `VaultRootMaterial` for deterministic domain-separated key derivation from `vault[0]`.
  - `derive_aead_key_bytes`, `derive_mqtt_tls_seed_bytes`, `derive_signing_key`, and public identity helpers.
- Added first-class `vault` slot family support (`vault[0]`) with deterministic test vectors.
- Added wallet APIs:
  - `derive_vault_master_key_hex()`
  - backward-compatible alias `derive_harmonia_vault_master_key_hex()`.

### Changed

- Wallet slot registry now persists `vault[0]` at initialization.
- CLI fingerprint output now shows `Vault slot` preview.
- Deterministic recovery path validates vault slot derivation along with rgb/webcash/bitcoin.
- README expanded with generic vault slot and derivation usage.

---

## [0.1.25] — 2026-03-04

### Changed

- Clarified rail-aware CLI help text:
  - `hrmw contract buy --amount` now documents decimal units by listing rail
    (webcash or bitcoin), not webcash-only wording.
  - `hrmw timeline post --price-min/--price-max` now documents decimal values
    as `--currency`-dependent (defaulting to webcash when omitted).

---

## [0.1.24] — 2026-03-04

### Changed

- Removed legacy ARK CLI aliases from `hrmw bitcoin ark` help output to keep
  the canonical operation names only:
  - `deposit` (on-chain -> ARK entry start),
  - `boarding` (on-chain -> ARK offchain finalization),
  - `settle` / `settle-address` (ARK offchain -> on-chain exits).

---

## [0.1.23] — 2026-03-04

### Changed

- Clarified ARK flow terminology in docs and CLI guidance:
  - `deposit` (show ARK deposit address)
  - `boarding` (finalize on-chain deposit into ARK offchain)
  - `settle` / `settle-address` (move ARK offchain back on-chain)
- Added explicit rail-lock behavior in docs:
  wrong rail now documented as `HTTP 402` with `payment_rail_mismatch`.
- Added `verify-proof` usage guidance for ARK proof validation format
  `ark:<vtxo_txid>:<amount_sats>`.

---

## [0.1.16] — 2026-02-26

### Changed

- Added backend-level multi-workunit mining interface with pipeline depth hints.
- Multi-CUDA backend now mines independent full work units concurrently across GPUs.
- Daemon mining loop now supports pipelined multi-workunit cycles and per-workunit submission handling.

---

## [0.1.15] — 2026-02-26

### Changed

- Optimized CUDA mining hot path with atomic best-result reduction and persistent device result buffers.
- Reduced CUDA kernel pressure by switching to a rolling 16-word SHA256 schedule.
- Improved multi-CUDA dispatch path by removing unused nonce table cloning in worker tasks.

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

[Unreleased]: https://github.com/harmoniis/harmoniis-wallet/compare/v0.1.55...HEAD
[0.1.55]: https://github.com/harmoniis/harmoniis-wallet/compare/v0.1.54...v0.1.55
[0.2.0]: https://github.com/harmoniis/harmoniis-wallet/compare/v0.1.39...v0.2.0
[0.1.39]: https://github.com/harmoniis/harmoniis-wallet/releases/tag/v0.1.39
[0.1.12]: https://github.com/harmoniis/harmoniis-wallet/releases/tag/v0.1.12
[0.1.11]: https://github.com/harmoniis/harmoniis-wallet/releases/tag/v0.1.11
[0.1.10]: https://github.com/harmoniis/harmoniis-wallet/releases/tag/v0.1.10
[0.1.9]: https://github.com/harmoniis/harmoniis-wallet/releases/tag/v0.1.9
[0.1.4]: https://github.com/harmoniis/harmoniis-wallet/releases/tag/v0.1.4
[0.1.2]: https://github.com/harmoniis/harmoniis-wallet/releases/tag/v0.1.2
[0.1.1]: https://github.com/harmoniis/harmoniis-wallet/releases/tag/v0.1.1
[0.1.0]: https://github.com/harmoniis/harmoniis-wallet/releases/tag/v0.1.0
# Release 0.1.28
