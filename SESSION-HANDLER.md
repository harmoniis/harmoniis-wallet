# Session Handler: Webcash GPU Mining Development & Deployment

## Target Instance

**Vast.ai Type #33453597** — Sichuan, CN
- **GPUs**: 4x RTX 4090 (24GB VRAM each)
- **Compute**: 325.6 TFLOPS
- **Host**: #124072, verified
- **CPU**: AMD EPYC 7542 32-Core (64 threads)
- **RAM**: 387 GB
- **Storage**: 2593 GB NVMe
- **Network**: 61 Mbps down / 308 Mbps up
- **PCIe**: 4.0 x16, 19.6 GB/s
- **CUDA**: Max 12.4
- **Template**: `cuda:12.0.1-devel-ubuntu20.04` (ID: `fd2e982e4facaf7b2918006939d1e06e`)
- **Expected mining speed**: ~40 GH/s (4 GPUs, scaling from 100 GH/s on 10x RTX 4090)
- **Cost**: ~$0.55/hr

---

## What Needs To Be Implemented

### `hrmw webminer cloud start --machine <id> --env dev`

A new `--env dev` flag on the cloud start command. When set:

1. **Provision**: Create vast.ai instance on the specified machine using the CUDA 12.0.1 template
2. **Install dependencies over SSH** (instead of uploading a pre-built binary):
   ```bash
   # Essential build tools
   apt update && apt install -y build-essential pkg-config libssl-dev git gcc-10 g++-10
   
   # Rust toolchain
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
   source ~/.cargo/env
   
   # Clone repo
   git clone https://github.com/harmoniis/harmoniis-wallet.git /root/hw
   cd /root/hw
   
   # Build release (use gcc-10 for aws-lc-sys compatibility on Ubuntu 20.04)
   CC=gcc-10 CXX=g++-10 cargo build --release
   
   # Install
   cp target/release/hrmw /root/.local/bin/hrmw
   ```
3. **Do NOT start mining automatically** — dev mode is for manual testing
4. **Print SSH command** so the developer can log in and run manually:
   ```
   ssh -i ~/.harmoniis/cloud/id_ed25519 -p <port> root@<host>
   cd /root/hw && /root/.local/bin/hrmw webminer start -f --accept-terms --server https://webcash.org
   ```

**Why dev mode exists**: The production `cloud start` uploads a pre-built binary and starts mining immediately. Dev mode clones the repo so the developer can edit code directly on the GPU server, rebuild in ~1.5 minutes, and test changes without the local→push→pull→rebuild round-trip that wastes GPU rental money.

**Key difference from production mode**: In dev mode, all code changes happen on the remote machine. `cargo build --release` runs remotely. The developer SSHs in, edits, rebuilds, and tests interactively.

### Build Requirements on Ubuntu 20.04

- **gcc-10/g++-10**: Required because `aws-lc-sys` (dependency of `rustls`) has a bug detection check that rejects gcc-9. Ubuntu 20.04 ships gcc-9 by default.
  ```bash
  apt install -y gcc-10 g++-10
  CC=gcc-10 CXX=g++-10 cargo build --release
  ```
- **Rust 1.86+**: The crate requires `rust-version = "1.86"`.
- **CUDA toolkit**: Provided by the container image. NVRTC compiles the SHA256 kernel at runtime via `cudarc`.

---

## Historic Challenges & Failures

### 1. Mining Speed: 72 GH/s → 100 GH/s (SOLVED)

**Baseline**: 72 GH/s on 10x RTX 4090 (vast.ai), measured live: `speed=72.29 Gh/s`. Benchmark showed 133 GH/s raw GPU capability (`cuda_total_estimate=132939.99 Mh/s`) — 45% wasted on CPU dispatch overhead.

**Root cause**: Each mining cycle has ~150μs of CPU overhead (JoinSet task spawning, work unit creation, stats). With pipeline_depth=40 (4x per GPU), the GPU computed for only 420μs per cycle. Overhead fraction: 150/570 = 26%.

**Fix (committed on `main`)**:
- Pipeline depth 4x → 32x (320 midstates for 10 GPUs, 32 per GPU)
- GPU computes ~2.5ms per cycle, overhead stays ~150μs → 6% overhead
- MAX_BATCH: 8 → 64 (supports deeper pipeline)
- Pipeline clamp: 64 → 1024
- CUDA kernel: `lop3.b32` for ch/maj (1 instruction vs 3-5), `__umulhi` fast division
- Kernel self-init: block 0 thread 0 zeroes out_best (eliminates host memset_zeros per kernel)

**Result**: 100 GH/s measured live on 10x RTX 4090: `speed=101.77 Gh/s` (mine=2316μs cycle=2779μs). Pipeline depth confirmed at 320. Expected ~40 GH/s on 4x RTX 4090 (linear scaling, untested).

### 2. In-Process Reporter Threads Kill GPU Speed (CRITICAL LESSON)

**Every attempt to add HTTP reporting threads inside the mining process destroyed GPU performance:**

| Attempt | Threads | Speed | Root Cause |
|---------|---------|-------|------------|
| 3 threads, Arc\<Mutex\<Receiver\>\> (v0.1.52) | 3 | ~72-75 GH/s | **WORKS** — only proven pattern. Cost ~3 GH/s vs 0 threads |
| 64 threads, Arc\<Mutex\<Receiver\>\> | 64 | →31 GH/s | Mutex contention on receiver |
| 64 threads, tokio runtimes | 64 | →25 GH/s | Tokio runtime contention with main runtime |
| 64 threads, per-worker mpsc | 64 | →22 GH/s | TLB shootdowns from reqwest malloc/free |
| std::thread::scope GPU dispatch | N/A | →25 GH/s | Thread create/destroy overhead per cycle |
| \_\_launch\_bounds\_\_(256, 5) | N/A | →44 GH/s | Register spilling on some GPUs |

**Why**: `reqwest::blocking::Client` internally spawns a tokio runtime per client. Memory allocation/deallocation in those threads causes TLB shootdowns (Inter-Processor Interrupts) that stall CUDA API calls on the GPU dispatch cores. Even idle threads cause this.

**The 3-thread pattern from v0.1.52 is the only one that works acceptably.** It uses ONE shared `reqwest::blocking::Client` created eagerly in the constructor, shared via `Arc<MiningProtocol>`. The 3 threads pull from `Arc<Mutex<mpsc::Receiver>>`. Cost: ~3 GH/s on the old 4x pipeline. With 32x pipeline, the cost should be even lower because cycles are longer.

### 3. Subprocess Reporter (FAILED — DNS Error)

**Attempt**: Spawn `hrmw webminer report-worker` as a child process. Solutions piped via stdin. 64 threads in separate address space.

**What worked**: Mining speed was unaffected (100 GH/s maintained). The pipe communication worked. The child process spawned and ran.

**What failed**: Zero solutions were submitted. The subprocess's HTTP client could not resolve DNS:
```
Submit failed: error sending request for url (https://webcash.org/api/v1/mining_report): error trying to connect: dns error: failed to lookup address information: nodename nor servname provided, or not known
```

**Details**: The subprocess created 8 `MiningProtocol` instances (each with `reqwest::blocking::Client`). These clients internally spawn tokio runtimes. In the subprocess context, DNS resolution failed for all of them. On the vast.ai Linux instance, errors showed "operation timed out" instead of DNS errors, making it look like the server was down (it wasn't).

**Why v0.1.52 works**: The blocking client is created EAGERLY in `MiningProtocol::new()` (called in the main process's async context). The client is shared to threads via `Arc<MiningProtocol>`. DNS resolution happens through the main process's networking stack, which works.

**The subprocess approach may still be viable** if the DNS issue is resolved (e.g., pre-resolve the IP, or create the client differently). But it is NOT working as implemented and was fully reverted.

### 4. Solution Reporting Time Constraint (UNSOLVED — PRIMARY CHALLENGE)

**User requirement**: "we truly need multiple parallel reporting at least 64 reportings parallel if not more but with absolute no downside for CPU. Each report takes 7 sec and we mine much faster than reporting. It should be max additional 10-20 sec after stopping mining to collect the remaining ones."

**User's core insight**: "reporting is a simple HTTP req that waits 7 sec for server to respond back. This is not hard CPU, it's a problem of understanding the architecture, processes, Rust, UNIX, and kernel very well."

#### Server-Side Timing Constraints (from webcash server source code)

| Constraint | Limit | Impact |
|------------|-------|--------|
| **Timestamp window** | ±2 hours from server receipt | Solutions are valid for 2 hours. NOT the real bottleneck. |
| **Difficulty validation** | Hash leading zeros must be >= server's CURRENT difficulty | **THE REAL BOTTLENECK** — if difficulty increases, ALL queued solutions are instantly invalid |
| **Committed difficulty** | Preimage `difficulty` field must be >= current server difficulty | Same — difficulty increase kills pending solutions |
| **Difficulty adjustment** | Every 128 mining reports, ±1 bit | At target rate (10s/report), adjustment every ~21 minutes |
| **Mining amount** | Must exactly match server's current `mining_amount` | Epoch change (every 525,000 reports) invalidates all pending solutions |
| **Unique preimage** | Duplicate preimages rejected (server stores hash) | Can't resubmit; each solution is one-shot |

**Why fast reporting matters**: The 2-hour timestamp window is generous. The REAL danger is **difficulty adjustment**. If difficulty increases by 1 bit (from 36 to 37) while solutions are queued, every queued solution mined at difficulty 36 is REJECTED — the hash doesn't have enough leading zeros for difficulty 37. At 100 GH/s mining ~1.5 solutions/sec, a 5-minute reporting backlog means ~450 solutions lost if difficulty bumps.

**The math (updated with difficulty risk)**:
- Mining: ~1.5 solutions/sec at 100 GH/s, difficulty 36
- 3 threads × (1 report / 7 seconds) = 0.43 reports/sec
- **Deficit: 1.07 solutions/sec accumulating in buffer**
- After 1 minute: ~90 found, ~26 reported, ~64 pending
- After 5 minutes: ~450 found, ~129 reported, ~321 pending
- If difficulty bumps at 5 minutes: **321 solutions LOST**
- Time to drain 321 pending with 3 threads: 321/0.43 = **12.5 minutes** (unacceptable)
- Time to drain with 64 threads: 321/(64/7) = **35 seconds** (close to target)

#### How maaku's C++ Webminer Handles This

The C++ webminer (`maaku/webminer`) uses a simpler pattern:
- **1 background thread** for ALL network I/O (submission + settings refresh)
- Mining threads push solutions to a shared deque (`g_solutions`) under mutex
- Background thread pops solutions FIFO, submits synchronously (7s each)
- **On network error**: solution pushed back to FRONT of deque, thread sleeps and retries
- **On difficulty change**: background thread checks if queued solution still meets current difficulty; if not, logged to orphan file and skipped
- **No pre-building**: each mining thread builds its own work unit inline

This works for the C++ miner because it runs at ~500 MH/s (CPU-only), finding ~0.007 solutions/sec at difficulty 36. One thread at 1/7s = 0.14 reports/sec — 20x headroom. At 100 GH/s, we need 200x more reporting throughput.

#### Proposed Architecture: Non-Blocking Pre-Emptive Reporter

The user's vision: "make it work like a perfect loop machine without ever blocking the miner and make it wait for anything." Key principles:

1. **The mining loop must NEVER wait on I/O** — zero blocking, zero allocation in the hot path
2. **Pre-emptively prepare everything in background** — DNS resolution, TLS handshake, connection keep-alive, JSON serialization
3. **During mining: N threads submit continuously** (N chosen to not hurt GPU)
4. **On shutdown: spawn burst threads for rapid drain** (GPU is off, TLB shootdowns irrelevant)

**Design (to be implemented):**

```
MINING PHASE (GPU active):
  Mining loop → mpsc::channel (non-blocking send) → 3 submitter threads
  │                                                   │
  │  reqwest::blocking::Client (shared, keep-alive)   │
  │  TLS session cached, DNS pre-resolved             │
  │  HTTP/1.1 persistent connections                  │
  └───────────────────────────────────────────────────┘
  
  Submitter threads during mining:
  - 3 threads (proven safe for GPU speed)
  - Shared client with connection pool (reuse TLS sessions)
  - On success: record_accepted, write keep, wallet insert
  - On error: push to retry deque (front, like maaku)
  - On difficulty mismatch: log to orphan, skip (don't waste 7s)

SHUTDOWN PHASE (GPU stopped, SIGINT received):
  1. Stop mining loop (set shutdown flag)
  2. Drain channel into Vec<SolutionReport>
  3. Check each against current difficulty (skip stale ones)
  4. Spawn 30-60 additional submitter threads
  5. Distribute remaining solutions round-robin to all threads
  6. Each thread uses clone of the SAME reqwest::blocking::Client
     (connection pool shared, TLS sessions reused)
  7. Wait for all threads to complete (max 20s timeout)
  8. Any remaining unsent: write to overflow file for collect --watch

PRE-EMPTIVE OPTIMIZATIONS (background, zero GPU impact):
  - DNS: resolve once at startup, cache IP
  - TLS: first request establishes session; subsequent requests reuse
  - Connection: HTTP keep-alive (reqwest default)
  - Serialization: preimage is already base64; work decimal computed once
  - No allocation in send path: channel send is a pointer move
```

**Why this solves the problem:**
- During mining: 3 threads = 0.43 reports/sec. Buffer grows but solutions are <2 hours old.
- Difficulty check before submission: skip stale solutions instantly (don't waste 7s on guaranteed rejection)
- On shutdown: 60 threads = 8.6 reports/sec. Drain 100 solutions in 12s.
- Connection reuse: subsequent requests skip DNS + TLS = faster than 7s each.
- Zero GPU impact: mining loop does one non-blocking `channel.send()` per solution.

### 5. The Webcash Server Is NOT Broken (AGENT ERROR — USER CORRECTED)

**The agent spent hours falsely blaming the webcash.org server**, claiming the POST `/mining_report` endpoint was "down globally." The agent ran curl tests from both the vast.ai server and the local Mac, all showing timeouts, and concluded the server was broken. The agent even searched GitHub issues and declared the project "unmaintained since March 2023."

**The user called this out directly:**
- "is not the webcash server that is broken"
- "you lie, I saw in the v0.1.52 how the solutions worked"
- "you did something wrong, the speed works good but the report mining is not working"

**The user was right.** When v0.1.52 was restored, the server responded immediately:
```
[submitter-0] accepted in 7138ms
Mining report accepted! keep=e185.546875:secret:c0b87732...
📥 Response status: 200 OK
📥 Response body: {"status": "success"}
```

**What actually happened**: The agent's code changes broke the HTTP client. The subprocess reporter couldn't resolve DNS. The `collect --watch` and curl tests may have been affected by the many failed connection attempts saturating something. Once the original v0.1.52 code was restored, everything worked.

**WARNING TO NEXT AGENT**: Do NOT blame the webcash.org server. It works. If submissions fail, the bug is in YOUR code. Test with the v0.1.52 binary first to confirm the server is up, then bisect to find what you broke.

**The root cause**: The lazy `Option<reqwest::blocking::Client>` pattern + subprocess process context = DNS resolution failure. The v0.1.52 eager creation in the main process context works reliably.

---

## Current Architecture (v0.1.53 on `main`)

### Mining Pipeline
```
tokio async runtime
  ├── Target refresher (background, every 15s)
  ├── Work unit creator (rayon, overlapped with GPU mining)
  └── Main loop:
       1. Create 320 WorkUnits (rayon parallel, overlapped)
       2. mine_work_units() → JoinSet spawns 1 task per GPU
          Each GPU: mine_batch(32 midstates, difficulty)
            → fire 32 kernels back-to-back on CUDA stream
            → single stream.synchronize()
            → read 32 results
       3. Collect results, record stats
       4. For each solution: persist to file + send to submitter channel
```

### Solution Submission (v0.1.52 pattern, restored)
```
Mining loop → mpsc::channel → Arc<Mutex<Receiver>>
  ├── submitter-0 ─┐
  ├── submitter-1 ──┤── reqwest::blocking::Client (shared via Arc<MiningProtocol>)
  └── submitter-2 ─┘   POST /api/v1/mining_report (~7s per report)
                        On success: record_accepted() + write keep to file + wallet insert
```

### Key Files
| File | Purpose |
|------|---------|
| `src/miner/daemon.rs` | Main mining loop, submitter threads, shutdown drain |
| `src/miner/multi_cuda.rs` | Multi-GPU dispatch (JoinSet, round-robin) |
| `src/miner/cuda.rs` | Single GPU: mine_batch (fire N kernels, sync once) |
| `src/miner/shader/sha256_mine.cu` | CUDA kernel (lop3.b32, umulhi fast div) |
| `src/miner/protocol.rs` | HTTP client (async + blocking), mining_report submission |
| `src/miner/collect.rs` | Batch collect + watch mode (separate process reporter) |
| `src/miner/cloud/provision.rs` | Vast.ai provisioning, SSH deployment |
| `src/miner/cloud/config.rs` | API keys, instance state, config persistence |

### GPU Optimization Constants
| Constant | Value | Location | Purpose |
|----------|-------|----------|---------|
| `MAX_BATCH` | 64 | cuda.rs | Result buffer slots per GPU |
| `pipeline_depth` | `gpu_count * 32` | multi_cuda.rs | Work units per mining cycle |
| `pipeline_clamp` | 1024 | daemon.rs | Upper bound on pipeline depth |
| `CUDA_BLOCK_SIZE` | 256 | cuda.rs | Threads per CUDA block |
| `NONCE_SPACE_SIZE` | 1,000,000 | mod.rs | Nonces per work unit |
| `SUBMITTER_THREADS` | 3 | daemon.rs | In-process HTTP reporter threads |

---

## Measured Results (from live logs, not estimates)

### 10x RTX 4090 (vast.ai, 2026-04-10/11)

| Metric | Value | Source |
|--------|-------|--------|
| Baseline speed (v0.1.52 code, 4x pipeline) | 72.29 GH/s | `speed=72.29 Gh/s ... (mine=431μs cycle=540μs)` |
| Optimized speed (32x pipeline, lop3 kernel) | 101.77 GH/s | `speed=101.77 Gh/s ... (mine=2511μs cycle=2798μs)` |
| Benchmark raw GPU | 132.94 GH/s | `cuda_total_estimate=132939.99 Mh/s` |
| Pipeline depth (optimized) | 320 | `workunit_pipeline_depth=320` |
| Solution submission time | 7138ms | `[submitter-0] accepted in 7138ms` (v0.1.52 pattern) |
| Server response | 200 OK | `📥 Response body: {"status": "success"}` |
| With 64 in-process threads | 22 GH/s | `speed=22.03 Gh/s ... (mine=4126μs cycle=4134μs)` |
| With 3 duplicate miners | 27 GH/s | `speed=27.17 Gh/s` (3 processes fighting for GPU) |
| With launch_bounds(256,5) | 44 GH/s | `speed=44.38 Gh/s` (GPU1/2 at 2.5% share) |

### Local Mac (AMD RX 580, 2026-04-11)

| Metric | Value | Source |
|--------|-------|--------|
| v0.1.52 mining speed | ~500 MH/s | `speed=500.74 Mh/s` |
| v0.1.52 submission | 7512ms | `[submitter-0] accepted in 7512ms` |
| Latest (main) mining speed | ~500 MH/s | `speed=501.48 Mh/s` (unchanged) |
| Latest (main) submission | DNS error | `dns error: failed to lookup address information` (subprocess reporter) |
| Latest (main, v0.1.52 submitters restored) | 7512ms | `[submitter-0] accepted in 7512ms` ✓ |

### Speed measurements NOT from live logs (from commit messages only)
- 75 GH/s: claimed in commit `2f3f28b` message ("fixes 75→25 GH/s regression") — no raw log evidence
- 31 GH/s with 64 Mutex threads: claimed in commit `4e23c57` — no raw log
- 30 GH/s with sync_channel: claimed in commit `a07e19c` — no raw log

---

## What To Test on 4x RTX 4090

### 1. Mining Speed (~40 GH/s target)
```bash
# Start miner in foreground
hrmw webminer start -f --accept-terms --server https://webcash.org
# Expected: speed=~40 Gh/s (4/10 of 100 GH/s)
# Watch: mine=Xμs cycle=Yμs — cycle should be <2x mine
```

### 2. Solution Reporting (must work at full speed)
```bash
# Watch for:
# [submitter-N] accepted in ~7000ms — confirms server responds
# solutions=X/Y where Y > 0 — confirms solutions accepted
# Mining speed stays at ~40 GH/s while reporting
```

### 3. Shutdown Drain (max 10-20 seconds)
```bash
# Mine for 2 minutes, then Ctrl+C
# Watch: "Drained pending submissions in Xs"
# X must be < 20 seconds
# All buffered solutions must be reported before exit
```

### 4. Solution Rate vs Report Rate
```bash
# At 40 GH/s, difficulty 36: ~0.6 solutions/sec
# 3 threads × (1/7s) = 0.43 reports/sec
# Marginal — may need to increase to 6 submitter threads
# If solutions accumulate faster than reported:
#   Increase SUBMITTER_THREADS from 3 to 6-8
#   Test that GPU speed stays at ~40 GH/s
```

---

## Challenges To Investigate

### Challenge 1: Optimal Submitter Thread Count During Mining
On 4x RTX 4090, 3 threads may not be enough. With ~0.6 solutions/sec and 7s per report, 3 threads handle 0.43/sec — deficit of 0.17/sec. After 5 minutes: ~51 unreported.

**Test**: Try 3, 6, 8, 12 threads. For each, measure:
- GPU speed (must stay at ~40 GH/s)
- Submission success rate
- Buffer growth rate (solutions found - solutions reported)

The goal is to find the maximum thread count where GPU speed is unaffected. On the 10x RTX 4090 system, 3 threads cost ~3 GH/s. With the 32x pipeline (longer cycles), thread interference is proportionally smaller.

### Challenge 2: Pre-Emptive Stale Difficulty Check
The maaku C++ miner checks difficulty BEFORE submitting. If a queued solution's hash doesn't meet current difficulty, it's logged to orphan file and skipped — saving 7 seconds of wasted HTTP wait.

**Implement**: Before each submission, compare `solution.difficulty_achieved` against the shared `target.difficulty`. If `achieved < current`, skip and log. This is critical because difficulty adjustments invalidate ALL queued solutions at once.

### Challenge 3: Burst Drain on Shutdown (10-20 Second Target)
When SIGINT fires:
1. Set shutdown flag (stops mining loop)
2. GPU work completes (last cycle, ~3ms)
3. **Now GPU is idle — spawn 60 additional threads**
4. All threads share the SAME `Arc<MiningProtocol>` (same connection pool)
5. Each thread clones the `Arc`, pulls from the channel
6. With 63 threads × 7s per report: 9 reports/sec → drain 100 solutions in 11s
7. Timeout at 20s; any remaining → overflow file for `collect`

The key insight: spawning threads AFTER GPU stops is safe. TLB shootdowns only matter during CUDA dispatch. Once mining is done, the CPU can do whatever it wants.

### Challenge 4: Remove Local Collection Workaround
Currently, `hrmw webminer cloud watch` runs locally and syncs solutions from remote via SSH every 30 seconds. This was a workaround for unreliable remote reporting.

**Goal**: All solution reporting happens on the remote machine. The local machine only monitors status. On `cloud stop`:
1. Send SIGINT to remote miner
2. Miner stops mining, enters burst drain (60 threads, 20s max)
3. All solutions reported on the remote
4. Only after drain completes: destroy instance
5. **No SSH solution download, no local collection**

### Challenge 5: Connection Reuse for Maximum Throughput
`reqwest::blocking::Client` maintains an internal connection pool with HTTP keep-alive. First request does DNS + TLS (~200ms). Subsequent requests reuse the connection (~0ms overhead).

**Design rules:**
- ONE shared `reqwest::blocking::Client` for ALL threads (created eagerly in `MiningProtocol::new()`)
- Shared via `Arc<MiningProtocol>` — Arc clone is a pointer increment
- NOT separate clients per thread (64 clients = 64 DNS lookups = 64 TLS handshakes = failure)
- `reqwest` handles connection pool internally — no manual pooling needed
- HTTP/1.1 keep-alive is default — connections persist between requests

### Challenge 6: Zero-Blocking Mining Loop Architecture
The mining loop must NEVER wait on I/O. Current architecture already achieves this:
```
Mining loop:
  1. GPU mines (2.5ms)
  2. Check solutions (μs)
  3. For each solution: channel.send() — NON-BLOCKING (mpsc unbounded)
  4. Repeat
```
`mpsc::channel::send()` is a pointer swap — nanoseconds, no allocation, no I/O. The submitter threads on the other end of the channel do all the heavy lifting (HTTP, file I/O, wallet insert) independently.

**What must NOT be in the mining loop:**
- HTTP calls (7s blocking)
- DNS resolution
- TLS handshake
- File open/write (solutions are written with `let _ =` to ignore errors — never blocks)
- Mutex contention with submitters (channel send doesn't lock; submitters lock the receiver)

**Pre-emptive preparation (already done by reqwest internally):**
- DNS resolved on first request, cached for connection pool lifetime
- TLS session established once, resumed for all subsequent connections
- TCP connection kept alive (no SYN/SYN-ACK per request)
- HTTP pipelining handled by the keep-alive connection

---

## Release Process

### Building on Remote (Dev Mode)
```bash
ssh -i ~/.harmoniis/cloud/id_ed25519 -p <port> root@<host>
cd /root/hw
git pull origin main
CC=gcc-10 CXX=g++-10 cargo build --release  # ~1.5 minutes
cp target/release/hrmw /root/.local/bin/hrmw
```

### Building Locally (Production)
```bash
cd ~/workspace/harmoniis/marketplace/harmoniis-wallet
cargo build --release  # ~3 minutes on Mac
cargo install --path . --force  # installs to ~/.cargo/bin/hrmw
```

### Deploying to Remote (Production Mode)
```bash
hrmw webminer cloud start --offer <machine_id>
# Automatically: uploads binary, starts miner, starts reporter
```

### Version Bump
```bash
# Edit Cargo.toml version
# Commit with: bump vX.Y.Z
# Tag: git tag vX.Y.Z && git push --tags
```

### Testing Checklist Before Release
- [ ] `cargo check` — compiles clean
- [ ] `cargo test` — all tests pass
- [ ] Local miner test (30s) — mines and reports solutions
- [ ] Remote 4x GPU test — ~40 GH/s, solutions reported at speed
- [ ] Shutdown drain test — all solutions reported within 20s of stopping
- [ ] No in-process thread regressions — speed doesn't drop with submitters active

---

## Vast.ai API Reference

### Authentication
```
Authorization: Bearer <api_key>
```
API key stored in `~/.harmoniis/cloud/config.toml`.

### Key Endpoints
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v0/bundles/` | POST | Search GPU offers (JSON filter body) |
| `/api/v0/asks/{offer_id}/` | PUT | Create instance |
| `/api/v0/instances/{id}/` | GET | Instance status |
| `/api/v0/instances/{id}/` | DELETE | Destroy instance |
| `/api/v0/ssh/` | POST | Upload SSH public key |

### Instance Creation Payload
```json
{
  "client_id": "me",
  "image": "cuda:12.0.1-devel-ubuntu20.04",
  "disk": 40,
  "label": "harmoniis-dev-4gpu",
  "runtype": "ssh ssh_proxy"
}
```

### SSH Key
Stored at `~/.harmoniis/cloud/id_ed25519` (Ed25519). Must be uploaded to vast.ai account before creating instances.

---

## Key Invariants (NEVER VIOLATE)

1. **Never add 64 in-process HTTP threads to the mining process** — kills GPU from 100 to 22 GH/s. Tested 4 times, failed every time.
2. **3 in-process submitter threads is the ONLY proven pattern** — v0.1.52 pattern with eagerly-created shared blocking client. Do not change this without measuring GPU speed impact.
3. **Never use lazy blocking client (Option\<reqwest::blocking::Client\>)** — the `ensure_blocking_client()` pattern caused DNS failures when used in subprocess context. Use eager creation in MiningProtocol::new().
4. **Do NOT blame the webcash.org server** — it works (7s response). If submissions fail, the bug is in your code. Always test with v0.1.52 binary first.
5. **Always use gcc-10+ on Ubuntu 20.04** — gcc-9 has memcmp bug that breaks aws-lc-sys
6. **Always kill ALL hrmw processes before deploying** — multiple miners split GPU time (observed: 7 processes → 19 GH/s instead of 72 GH/s)
7. **Pipeline depth must match MAX_BATCH** — gpu_count * multiplier per GPU, MAX_BATCH >= multiplier
8. **More submitter threads can be spawned ONLY after mining stops** — for the shutdown drain phase when GPU is idle, TLB shootdowns don't matter
9. **The user requires 32-64 parallel reporters without speed loss + 10-20s drain** — this is unsolved. Do not claim it's done until measured on real GPUs.
