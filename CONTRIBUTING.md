# Contributing to harmoniis-wallet

Thank you for your interest in contributing! This guide covers everything you need
to submit a high-quality pull request.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Setup](#development-setup)
4. [Running Tests](#running-tests)
5. [Commit Format](#commit-format)
6. [Pull Request Process](#pull-request-process)
7. [Design Principles](#design-principles)
8. [Feature Phases](#feature-phases)

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
By participating you agree to uphold it.

---

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork:
   ```sh
   git clone https://github.com/YOUR-USERNAME/harmoniis-wallet.git
   cd harmoniis-wallet
   ```
3. **Add the upstream remote:**
   ```sh
   git remote add upstream https://github.com/harmoniis/harmoniis-wallet.git
   ```
4. **Create a branch** from `main`:
   ```sh
   git checkout -b fix/my-bug-description
   ```

Branch naming conventions:
- `fix/<description>` — bug fix
- `feat/<description>` — new feature
- `docs/<description>` — documentation only
- `refactor/<description>` — internal restructuring, no behaviour change
- `test/<description>` — tests only

---

## Development Setup

Minimum Rust version: **1.85** (MSRV — enforced in CI).

```sh
# Install Rust via rustup if needed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Check toolchain
rustc --version   # must be >= 1.70

# Build (default features: bundled-sqlite)
cargo build

# Build with dormant securities feature (for maintainers only)
cargo build --features securities

# Build without bundled SQLite (links against system libsqlite3)
cargo build --no-default-features
```

No external system dependencies are required with the default feature set.
`rustls-tls` is used instead of OpenSSL for cross-platform compatibility.

---

## Running Tests

```sh
# All tests (unit + local-simulation + doc tests)
cargo test

# With securities feature (runs 3 additional internal tests)
cargo test --features securities

# Unit tests only
cargo test --test unit_tests

# Local simulation tests (no backend required)
cargo test --test local_sim

# Integration test — requires a running backend
# (ignored by default; run explicitly)
HARMONIIS_API_URL=http://localhost:9001 \
  TEST_WEBCASH_BUYER="e1.0:secret:..." \
  TEST_WEBCASH_SELLER="e1.0:secret:..." \
  TEST_WEBCASH_FEE="e0.1:secret:..." \
  cargo test --test integration_flow -- --ignored --nocapture

# Linting and formatting (required to pass CI)
cargo clippy -- -D warnings
cargo fmt --check
```

All of the following must pass before a PR is merged:
- `cargo build` (stable + MSRV 1.85)
- `cargo test` (Linux, macOS, Windows)
- `cargo clippy -- -D warnings`
- `cargo fmt --check`

---

## Commit Format

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <short summary>

[optional body]

[optional footer(s)]
```

**Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `perf`

**Scope** (optional): `types`, `wallet`, `client`, `cli`, `crypto`, `identity`, `securities`

**Examples:**

```
feat(wallet): add snapshot import validation

fix(client): correct witness_check response parsing (keyed object, not array)

docs: add CLI quick-start examples to README

test(types): add round-trip test for StablecashSecret

chore: bump rusqlite to 0.37
```

- Use the imperative mood: "add", not "added" or "adds".
- Keep the summary line under 72 characters.
- Reference issues with `Closes #42` or `Fixes #42` in the footer.

---

## Pull Request Process

1. **Keep PRs focused** — one logical change per PR. Large refactors should be
   discussed in an issue first.
2. **Update CHANGELOG.md** under `[Unreleased]` using the Keep a Changelog format.
3. **Add or update tests** for any new behaviour. Coverage of the changed code paths
   is expected.
4. **Run the full test suite** locally before pushing.
5. **Fill out the PR template** completely.
6. A maintainer will review your PR within a few business days. Address all requested
   changes; resolved threads will be marked.
7. PRs are merged via **squash-and-merge** — your individual commits are consolidated
   into one commit on `main`.

---

## Design Principles

These principles mirror the RGB protocol's philosophy and must be preserved:

| Principle | Guidance |
|-----------|----------|
| **Client-side validation** | The wallet verifies state locally; the server is untrusted. |
| **Bearer secrets** | Ownership = possession of `witnessSecret`. No account model. |
| **Zeroize on drop** | All secret material (`witnessSecret`, `StablecashSecret`, `Identity`) must be cleared from memory when dropped. Use `zeroize`. |
| **No OpenSSL** | `rustls-tls` only. Cross-platform `cargo install` must work without system libraries. |
| **Phase discipline** | Phase 1 (RGB21 contracts) is live. Phase 2 (Stablecash) is sandbox. Phase 3 (Securities) is dormant behind a feature flag. Do not promote phases without a maintainer decision. |
| **MSRV 1.85** | Do not use language features or API surface introduced after Rust 1.85. |
| **Minimal dependencies** | Every new dependency must be justified. Prefer the standard library. |

---

## Feature Phases

```
Phase 1 (LIVE)     — RGB21 Contract + Certificate
Phase 2 (SANDBOX)  — RGB20 Stablecash / USDH
Phase 3 (DORMANT)  — Securities (ContractBasket, Bond, RevenueShare)
                     compiled only with --features securities
```

Changes to Phase 3 code may be accepted even while dormant, but the feature must
not be enabled in the default build, and no production-backend integration may be
added until Phase 3 is officially released.
