# Changelog

All notable changes to `harmoniis-wallet` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [0.1.41] — 2026-03-29

### Fixed

- **Multi-GPU mining**: the subprocess GPU probe used adapter enumeration
  indices which are not stable across process boundaries.  With 2 physical
  GPUs (e.g. RX 590 + RX 580), only 1 was usable.  Fixed by identifying
  adapters by `(vendor, device, backend)` identity triple instead of index.
  Both GPUs now mine in parallel with proportional work distribution.

## [0.1.40] — 2026-03-29

### Added

- **Bitcoin wallet persistence**: BDK file-store backend saves UTXO cache,
  address indices, and sync state to `bitcoin.taproot.dat` / `bitcoin.segwit.dat`.
  Subsequent syncs load cached state.  Fully recoverable from master key.
- **Subprocess GPU probe**: GPU pipeline creation is tested in a child process
  before use.  If the GPU driver segfaults (known AMD Vulkan issue on Polaris),
  the adapter is skipped and the next one (e.g. DX12) is tried automatically.
  RX 580 now mines at ~485 Mh/s via DX12 fallback.
- **CUDA on Windows**: the `cuda` feature now compiles on all platforms (was
  Linux-only).  `cudarc` loads the NVIDIA driver at runtime via
  `fallback-dynamic-loading`; gracefully falls back to wgpu when unavailable.
  Zero change to existing CUDA behaviour on Linux.
- **Wallet key protection**: `RgbWallet::open()` now refuses to generate new
  keys if existing key material is missing — returns `KeyMaterialMissing` error
  instead of silently replacing the wallet.  Prevents accidental money loss from
  metadata corruption.
- **Windows self-update fix**: `hrmw upgrade` on Windows now renames the running
  binary aside (`.old.exe`) before replacing it, avoiding the "access denied"
  error from the OS file lock.
- **Interactive `--accept-terms` prompt**: `webminer run` and `webminer start`
  now prompt the user to accept terms interactively when the flag is not passed.
  Declining exits cleanly.
- `uninstall.sh` (Linux/macOS/FreeBSD) and `uninstall.ps1` (Windows) — remove
  the binary and PATH entry.  Wallet data at `~/.harmoniis/` is never touched.

### Changed

- **WGSL shader optimised** to match CUDA performance:
  - Rolling 16-word message schedule (was 64-word; 4x less register pressure).
  - Packed 3-word atomic output (was 11); host re-verifies hash from nonce,
    eliminating a TOCTOU race condition in the shader output.
  - Pre-allocated input/result GPU buffers (eliminates per-dispatch allocations).
- OpenGL backend removed from wgpu enumeration — only Vulkan, DX12, and Metal
  are used for compute.
- `split_assignments_for_weights()` extracted to shared `miner::mod` — was
  duplicated in `multi_gpu.rs` and `multi_cuda.rs`.
- Witness secret generation upgraded from `thread_rng()` to `OsRng` (OS CSPRNG)
  for defence-in-depth; matches root key and identity key entropy source.
- Self-update error messages now platform-appropriate (no "sudo" on Windows).
- `install.ps1` uses Windows native `tar.exe` (avoids MSYS2 tar path conflicts)
  and broadcasts `WM_SETTINGCHANGE` so open shells pick up PATH immediately.

### Fixed

- **Voucher pay/merge atomicity**: three-phase commit prevents money loss if the
  process crashes between server acceptance and local database update.  Pending
  operations are recovered on next wallet open via `recover_pending()`.
- **Windows miner daemon**: `is_running()` now verifies process alive via
  `tasklist` (was trusting stale PID file); `start()` detaches child with
  `CREATE_NO_WINDOW | DETACHED_PROCESS`; `stop()` terminates via `taskkill`
  (was "not implemented on this platform").
- **CUDA panic catch**: `cudarc` panics when CUDA DLLs are missing;
  `catch_unwind` around `CudaContext::device_count()` prevents crash on
  AMD-only systems.  Falls through to wgpu gracefully.
- Voucher insert amount overflow now returns error instead of silently clamping
  to `i64::MAX`.

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

[Unreleased]: https://github.com/harmoniis/harmoniis-wallet/compare/v0.1.39...HEAD
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
