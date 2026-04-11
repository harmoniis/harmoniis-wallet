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

**Baseline**: 72 GH/s on 10x RTX 4090 (vast.ai). Benchmark showed 130 GH/s raw GPU capability — 45% wasted on CPU dispatch overhead.

**Root cause**: Each mining cycle has ~150μs of CPU overhead (JoinSet task spawning, work unit creation, stats). With pipeline_depth=40 (4x per GPU), the GPU computed for only 420μs per cycle. Overhead fraction: 150/570 = 26%.

**Fix (committed on `main`)**:
- Pipeline depth 4x → 32x (320 midstates for 10 GPUs, 32 per GPU)
- GPU computes ~2.5ms per cycle, overhead stays ~150μs → 6% overhead
- MAX_BATCH: 8 → 64 (supports deeper pipeline)
- Pipeline clamp: 64 → 1024
- CUDA kernel: `lop3.b32` for ch/maj (1 instruction vs 3-5), `__umulhi` fast division
- Kernel self-init: block 0 thread 0 zeroes out_best (eliminates host memset_zeros per kernel)

**Result**: 100 GH/s on 10x RTX 4090. Expected ~40 GH/s on 4x RTX 4090.

### 2. In-Process Reporter Threads Kill GPU Speed (CRITICAL LESSON)

**Every attempt to add HTTP reporting threads inside the mining process destroyed GPU performance:**

| Attempt | Threads | Speed | Root Cause |
|---------|---------|-------|------------|
| 3 threads, Arc\<Mutex\<Receiver\>\> | 3 | 75→72 GH/s | Acceptable but not ideal |
| 64 threads, Arc\<Mutex\<Receiver\>\> | 64 | →31 GH/s | Mutex contention on receiver |
| 64 threads, tokio runtimes | 64 | →25 GH/s | Tokio runtime contention with main runtime |
| 64 threads, per-worker mpsc | 64 | →22 GH/s | TLB shootdowns from reqwest malloc/free |
| std::thread::scope GPU dispatch | N/A | →25 GH/s | Thread create/destroy overhead per cycle |
| \_\_launch\_bounds\_\_(256, 5) | N/A | →44 GH/s | Register spilling on some GPUs |

**Why**: `reqwest::blocking::Client` internally spawns a tokio runtime per client. Memory allocation/deallocation in those threads causes TLB shootdowns (Inter-Processor Interrupts) that stall CUDA API calls on the GPU dispatch cores. Even idle threads cause this.

**The 3-thread pattern from v0.1.52 is the only one that works acceptably.** It uses ONE shared `reqwest::blocking::Client` created eagerly in the constructor, shared via `Arc<MiningProtocol>`. The 3 threads pull from `Arc<Mutex<mpsc::Receiver>>`. Cost: ~3 GH/s on the old 4x pipeline. With 32x pipeline, the cost should be even lower because cycles are longer.

### 3. Subprocess Reporter DNS Failure (FAILED APPROACH)

**Attempt**: Spawn `hrmw webminer report-worker` as a child process. Solutions piped via stdin. 64 threads in separate address space — zero TLB interference.

**Failure**: The subprocess could not resolve DNS:
```
dns error: failed to lookup address information: nodename nor servname provided, or not known
```

**Why**: `reqwest::blocking::Client` created in a subprocess with multiple client pools (8 pools × 8 threads each) failed DNS resolution. The exact cause is unclear — possibly macOS mDNSResponder issues with many concurrent resolution requests from a spawned process, or the `reqwest::blocking::Client::builder().build()` behaving differently in subprocess context.

**The v0.1.52 in-process pattern does NOT have this issue** because the blocking client is created in the main process and shared via Arc to threads. DNS resolution happens through the main process's resolver.

### 4. Solution Reporting Time Constraint (UNSOLVED CHALLENGE)

**The problem**: Each solution submission to webcash.org takes ~7 seconds (server-side proof-of-work verification). At 100 GH/s and difficulty 36, the miner finds ~1.5 solutions/second. With 3 submitter threads, throughput is 3/7 = 0.43 solutions/second — **the reporter can't keep up**.

**The math**:
- Mining: ~1.5 solutions/sec at 100 GH/s, difficulty 36
- 3 threads × (1 report / 7 seconds) = 0.43 reports/sec
- Deficit: 1.5 - 0.43 = 1.07 solutions/sec accumulating in buffer
- After 1 minute of mining: ~90 solutions found, ~26 reported, ~64 pending
- Time to drain 64 pending after stopping: 64/0.43 = ~149 seconds (2.5 minutes!)

**The requirement**: After stopping the miner, ALL remaining buffered solutions must be reported within 10-20 seconds. This requires ~64 / 15 seconds = 4.3 solutions/sec = 30 concurrent threads.

**The tension**: 30+ threads in-process kill GPU speed, but we need them for the drain phase AFTER mining stops. Possible solution: the 3 threads run during mining, then on shutdown the miner spawns additional threads for rapid drain (GPU is already stopped, so TLB shootdowns don't matter).

**Alternative**: The `collect --watch` mode (separate process) handles overflow. But it uses 200ms file polling which adds latency. It should be upgraded to more threads and faster polling during drain.

### 5. The Webcash Server Is NOT Broken (FALSE DIAGNOSIS)

During this session, the mining_report endpoint appeared to time out from all locations. This was incorrectly diagnosed as a server-side issue. **The actual cause was the subprocess reporter's DNS failure** — the subprocess couldn't resolve webcash.org, so all submissions hung until timeout. Meanwhile, the `collect --watch` process (which also uses reqwest::blocking) had similar issues.

**Proof**: When v0.1.52 was restored (in-process submitters with eagerly-created blocking client), the server responded in 7 seconds and accepted the solution:
```
[submitter-0] accepted in 7138ms
Mining report accepted! keep=e185.546875:secret:...
📥 Response status: 200 OK
📥 Response body: {"status": "success"}
```

**Lesson**: Always test with the known-working code path before blaming external services. The blocking client initialization method matters: eager creation in the main process context works; lazy creation in subprocess context fails.

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

### Challenge 1: Optimal Submitter Thread Count
On 4x RTX 4090, 3 threads may not be enough. With ~0.6 solutions/sec and 7s per report, 3 threads handle 0.43/sec — deficit of 0.17/sec. After 5 minutes: ~51 unreported solutions.

**Test**: Try 3, 6, 8 threads. Measure GPU speed impact for each. Find the sweet spot where reporting keeps up without killing mining speed.

### Challenge 2: Fast Shutdown Drain
When the miner stops, buffered solutions must be drained in 10-20 seconds. With N threads and 7s per report:
- 3 threads: can drain ~4 solutions in 10s
- 10 threads: can drain ~14 solutions in 10s
- 30 threads: can drain ~43 solutions in 10s

**Solution**: On SIGINT/SIGTERM, BEFORE draining:
1. Stop mining (GPU freed)
2. Spawn additional submitter threads (30-60) for rapid drain
3. GPU is stopped so TLB shootdowns don't matter
4. Drain all pending solutions with maximum parallelism

### Challenge 3: Remove Local Collection Workaround
Currently, `hrmw webminer cloud watch` runs locally and syncs solutions from the remote via SSH every 30 seconds. This is a workaround for unreliable remote reporting. If remote reporting works reliably, this can be removed.

**Goal**: All solution reporting happens on the remote machine. The local machine only monitors status. On `cloud stop`:
1. Send SIGINT to remote miner
2. Miner drains all buffered solutions (10-20s)
3. Only after all solutions reported: destroy instance

### Challenge 4: Connection Pooling for Multiple Reporters
The webcash.org server may rate-limit connections per IP. With 30+ threads hitting the same endpoint:
- Use a shared `reqwest::blocking::Client` (internal connection pool)
- NOT separate clients per thread (64 separate clients caused timeouts)
- The v0.1.52 pattern already does this correctly (one client, shared via Arc)

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

1. **Never add 64 in-process HTTP threads to the mining process** — kills GPU from 100 to 22 GH/s
2. **Never use lazy blocking client creation** — causes DNS failures in subprocesses
3. **Always use gcc-10+ on Ubuntu 20.04** — gcc-9 has memcmp bug that breaks aws-lc-sys
4. **Always kill ALL hrmw processes before deploying** — multiple miners split GPU time
5. **Pipeline depth must match MAX_BATCH** — gpu_count * multiplier per GPU, MAX_BATCH >= multiplier
6. **Server responds to webcash.org POST /mining_report in ~7 seconds** — do not blame the server without testing with the v0.1.52 proven code path first
7. **3 in-process submitter threads is the proven safe number** — more threads can be spawned ONLY after mining stops (for drain)
