# Session Handler: Webcash GPU Mining Development & Deployment

## ABSOLUTE RULES — READ BEFORE TOUCHING ANYTHING

### Rule 1: reqwest::blocking::Client MUST Be Created EAGERLY in the Main Process

**This is the #1 cause of failure in this project. It has happened THREE TIMES.**

`reqwest::blocking::Client` created in a subprocess, lazy `Option<>`, or any context other than the main process's `MiningProtocol::new()` call **DOES NOT WORK**. The server receives the request but never responds (0 bytes returned, looks like server is down — but it isn't).

**What works (v0.1.52 pattern, proven on every test):**
```rust
// In MiningProtocol::new() — called once at startup in the main process:
let http_blocking = reqwest::blocking::Client::builder()
    .timeout(Duration::from_secs(60))
    .build()?;
```

**What breaks (EVERY TIME, tested 3 times):**
```rust
// In a subprocess (fork+exec): BROKEN
let client = reqwest::blocking::Client::builder().build()?;  // looks OK, compiles, runs — but server never responds

// Lazy creation in Option<>: BROKEN
http_blocking: Option<reqwest::blocking::Client>  // commit a9ade36 introduced this, caused cascade failure

// In report-worker subprocess with pre-resolved IP: STILL BROKEN
reqwest::blocking::Client::builder().resolve("webcash.org", addr).build()?;  // DNS is NOT the issue
```

**The symptom**: curl to `mining_report` from the same machine ALSO times out. It looks exactly like the server is down. But `/api/v1/target` works fine. When you restore v0.1.52 code, the server responds in 7 seconds immediately.

**Why it happens**: Unknown at the low level. The blocking client internally spawns a tokio runtime. Something about the runtime initialization or connection establishment in a non-main-process context produces a client that establishes TCP + TLS but sends malformed or incomplete HTTP requests that the server's Python/Tornado backend hangs on indefinitely. The many hanging connections then block the server's `/mining_report` handler for ALL clients (including curl), while `/target` uses a different handler and works fine.

**The git history that proves this:**
- `a9ade36`: Changed from eager to lazy `Option<>` — broke everything
- `72c2a06`, `1926201`: Various attempts with different client patterns — all broken
- `ab55786`: Subprocess reporter with pipe — clients created in subprocess — broken
- `a9958c1`: Reverted to v0.1.52 eager pattern — immediately worked
- `01a00d1`, `de3bfba`: New subprocess attempt with pre-resolved DNS — still broken
- `a414ebd`: **Current fix**: N clients created EAGERLY in main process — to be tested

### Rule 2: NEVER Open More Than 8 Concurrent Connections to mining_report

The webcash.org server uses nginx as reverse proxy with a ~60s gateway timeout. The backend processes mining reports at ~7s each. Opening more than ~8 concurrent connections causes:
1. Connections 9+ get 504 Gateway Timeout (nginx kills them at 60s)
2. The hanging connections poison the backend — ALL subsequent requests to `/mining_report` hang
3. Even curl from the same machine stops working
4. `/api/v1/target` continues working (different handler)
5. The server may need operator restart to recover

**Measured on 2026-04-11:** 60 concurrent connections caused total `/mining_report` endpoint failure. Even single curl requests returned 0 bytes. Server was dead for hours.

### Rule 3: NEVER Blame the webcash.org Server

Every time submissions fail, the bug is in OUR code. The server works. This has been proven three times:
1. Agent blamed server → user corrected → v0.1.52 restored → server responded instantly
2. Agent blamed server overload → user corrected → it was broken client creation
3. Agent blamed nginx gateway timeout → user corrected → it was broken client creation flooding

**Test protocol**: If submissions fail, FIRST restore v0.1.52 binary and test. If v0.1.52 submits successfully, the bug is in your new code. Bisect from there.

### Rule 4: The Preimage Format Is Correct

The preimage construction in `work_unit.rs` is verified by unit tests and matches the C++ reference webminer (maaku/webminer) exactly. The hash-to-decimal conversion in `protocol.rs` is correct. The JSON submission format is correct. If reports fail, the issue is the HTTP client, not the data.

---

## Target Instances

### Dev Testing: 4x RTX 4090
**Vast.ai Type #33453597** — Sichuan, CN (or France equivalent)
- **GPUs**: 4x RTX 4090, PCIe 4.0 x16
- **Expected speed**: ~42-50 GH/s
- **Cost**: ~$1.07/hr
- **Use**: `hrmw webminer cloud start --env dev --offer <id>`

### Production: 10x RTX 4090
- **Expected speed**: ~100 GH/s
- **Solution rate at difficulty 36**: ~1.46 solutions/sec (100e9 / 2^36)
- **Required reporting throughput**: 1.46 × 7 = 10.2 concurrent connections minimum

---

## Current State (as of 2026-04-12, commit `a414ebd` on `main`)

### What Is Implemented and Working
- **Mining at 42-50 GH/s on 4x RTX 4090** — verified on vast.ai France instance
- **`--env dev` cloud provisioning** — clones repo, builds from source, prints SSH command
- **vast.ai `cur_state` API fix** — instance status detection works
- **Stale difficulty check** — skips solutions below current difficulty before submission
- **Overflow file** — unsent solutions saved to `miner_overflow_solutions.log`
- **`hrmw webminer collect`** — retries pending + overflow solutions offline

### What Is Implemented BUT UNTESTED
- **N eagerly-created clients** (commit `a414ebd`) — N separate `reqwest::blocking::Client` instances created in the main process, each with its own TCP connection, distributed to N in-process submitter threads via per-client mpsc channels
- Auto-scaling: N = gpu_count + 2, clamped 3..8
- This is the v0.1.52 pattern scaled from 1 client to N clients
- **NEEDS TESTING** — the webcash.org server was killed by our 60-connection flood and needs to recover before we can test

### What Is NOT Working
- **Solution reporting at full speed** — 3 threads (v0.1.52) can't keep up at 100 GH/s. The N-client architecture should fix this but is untested.
- **Subprocess reporter** — BROKEN. Creating reqwest clients in subprocess context produces dead clients. This approach is DEAD. Do not attempt again.

---

## Measured Results (from live logs on 2026-04-11)

### 4x RTX 4090 (vast.ai France, instance 34644238)

| Metric | Value | Notes |
|--------|-------|-------|
| Mining speed (0 submitter threads) | ~50 GH/s | Subprocess reporter was running but broken |
| Mining speed (3 in-process threads) | 42 GH/s | v0.1.52 pattern, proven |
| Mining speed (6 in-process threads) | 43-48 GH/s | No GPU regression vs 3 threads |
| Submission time (3 threads, shared client) | 7-16s | Server queuing on 1 TCP connection |
| Submission time (6 threads, shared client) | 34-37s | Worse queuing on 1 connection |
| Submission time (6 threads, per-thread client) | 43-54s | Even worse (6 tokio runtimes overhead) |
| Throughput (3 threads, shared client) | 0.37 reports/sec | Best measured |
| Throughput (6 threads, shared client) | 0.29 reports/sec | Worse than 3 threads |
| Solutions found in 2.5 min | 189 | ~1.26 solutions/sec at 42 GH/s |
| Solutions accepted in 2.5 min | 43 | 0.29 reports/sec — buffer growing |
| 60 concurrent connections | 10 accepted, 11 timeout, server killed | NEVER DO THIS |

### Key Insight from Testing

**One shared client (v0.1.52) serializes all requests on one TCP connection.** With 3 threads: thread 0 takes 7s, thread 1 waits → 13s, thread 2 waits → 16s. All requests queue on the SAME connection.

**Multiple separate clients each get their own TCP connection.** Server can process multiple connections in parallel (nginx dispatches to backend). BUT: clients MUST be created eagerly in the main process.

**Server capacity**: ~8 concurrent connections before nginx 504s. Beyond that, the `/mining_report` endpoint dies.

---

## Architecture (Current on main)

### Mining Pipeline
```
tokio async runtime
  ├── Target refresher (background, every 15s)
  ├── Work unit creator (rayon, overlapped with GPU mining)
  └── Main loop:
       1. Create pipeline_depth WorkUnits (rayon parallel, overlapped)
       2. mine_work_units() → JoinSet spawns 1 task per GPU
       3. Collect results, record stats
       4. For each solution: persist to file + dispatch to client channel
```

### Solution Submission (N-client pattern, commit a414ebd)
```
Main process startup (BEFORE mining):
  Create N reqwest::blocking::Client instances EAGERLY
  Each: own connection pool = own TCP connection

Mining loop:
  Solution found → round-robin dispatch to client[i % N]

N submitter threads (1 per client):
  client-0: rx.recv() → submit with client[0] → ~7s → next
  client-1: rx.recv() → submit with client[1] → ~7s → next
  ...
  client-N: rx.recv() → submit with client[N] → ~7s → next

Server sees N independent miners, processes in parallel.
Throughput: N/7 reports/sec (with N ≤ 8 to avoid nginx 504s)
```

### Key Files
| File | Purpose |
|------|---------|
| `src/miner/daemon.rs` | Mining loop, N eagerly-created clients, submitter threads |
| `src/miner/protocol.rs` | HTTP client, `submit_report_with_client()` static method |
| `src/miner/work_unit.rs` | Preimage construction (verified correct) |
| `src/miner/collect.rs` | Offline retry, `report_worker()` (BROKEN — do not use) |
| `src/miner/cloud/provision.rs` | Vast.ai provisioning, `start_dev()` for dev mode |

### Constants
| Constant | Value | Location | Purpose |
|----------|-------|----------|---------|
| `MAX_BATCH` | 64 | cuda.rs | Result buffer slots per GPU |
| `pipeline_depth` | `gpu_count * 32` | multi_cuda.rs | Work units per mining cycle |
| `num_clients` | `gpu_count + 2` (3..8) | daemon.rs | Reporter client connections |
| `NONCE_SPACE_SIZE` | 1,000,000 | mod.rs | Nonces per work unit |

---

## What the Next Session Must Do

### Step 1: Wait for webcash.org mining_report to Recover

Test with curl:
```bash
curl -s --max-time 15 -X POST https://webcash.org/api/v1/mining_report \
  -H "Content-Type: application/json" \
  -d '{"preimage": "test", "work": 0, "legalese": {"terms": true}}'
```
Expected: 500 Internal Server Error (bad data, but server responds). If it times out with 0 bytes, the server is still hung from the 60-connection flood on 2026-04-11.

### Step 2: Provision 4x RTX 4090 with --env dev

```bash
hrmw webminer cloud start --env dev --offer <offer_id>
# SSH in, verify 4 GPUs detected
```

### Step 3: Test N-Client Architecture (commit a414ebd)

```bash
# Start miner (auto-creates 6 clients for 4 GPUs)
hrmw webminer start -f --accept-terms --server https://webcash.org

# Watch for:
# 1. "reporter_clients=6 (created eagerly in main process)"
# 2. [client-0] accepted in ~7000ms  (NOT 34000ms — that means shared connection)
# 3. [client-1] accepted in ~7000ms  (each client should be ~7s independently)
# 4. speed=42+ Gh/s (must not regress)
# 5. solutions=X/Y where X tracks Y closely (not falling behind)
```

**Critical check**: Each `[client-N]` must show ~7s accept time. If they show 30-50s, the clients are sharing a connection (wrong). If they show 0 bytes / timeout, the client creation is broken (see Rule 1).

### Step 4: Test Shutdown Drain

```bash
# Mine for 2 minutes, then Ctrl+C
# Watch: "Drained in Xs" — should be fast (N clients drain in parallel)
# Check: solutions_found ≈ solutions_accepted (nothing lost)
```

### Step 5: Scale to 10x RTX 4090

Only after 4x works perfectly:
```bash
hrmw webminer cloud start --offer <10x_offer>
# Expected: ~100 GH/s, 8 clients (clamped), ~1.14 reports/sec
# May need HRMW_REPORTER_CLIENTS=8 override if auto-calc is too low
```

**If 8 clients isn't enough** (solutions accumulate), increase carefully: 8→10→12. NEVER above 8 without first verifying the previous count works. Each increase risks 504 cascade.

---

## The Root Cause Explained — For the Next Agent

The central mystery of this project: why does `reqwest::blocking::Client` work in the main process but fail in subprocesses?

**What happens when you create a blocking client:**
1. `reqwest::blocking::Client::builder().build()` internally creates a `reqwest::Client` (async)
2. The async client creates a tokio runtime
3. The tokio runtime spawns worker threads for DNS resolution, connection pooling, etc.
4. The blocking wrapper parks the calling thread and runs requests on the async runtime

**In the main process**, this tokio runtime initializes correctly — it inherits the process's networking stack, DNS configuration, and event loop. Requests work.

**In a subprocess (fork+exec)**, the new process gets a fresh address space. The tokio runtime initializes in this fresh context. Something about this initialization (likely the interaction between the internal tokio runtime and the parent's networking state, or the way reqwest establishes TLS sessions) produces a client that can establish TCP connections but sends HTTP requests that the Python/Tornado server hangs on instead of processing.

The **symptom** is indistinguishable from "server is down" — zero bytes received, curl also hangs. The **fix** is always the same: create the client in the main process.

**To scale N clients**, create all N in the main process BEFORE mining starts, then distribute to N in-process threads. The TLB cost of N threads (maybe 3-5 GH/s) is acceptable — it's far better than losing solutions.

**DO NOT** attempt to work around this with:
- Pre-resolved DNS (`.resolve()`) — the issue is NOT DNS
- `ureq` or other HTTP libraries — untested, may have same issue
- Raw `TcpStream` + manual HTTP — fragile, untested
- `fork()` without `exec()` — unsafe in multi-threaded process

The ONLY proven pattern: `reqwest::blocking::Client::builder().build()` in the main process.

---

## Git History Reference

| Commit | What | Outcome |
|--------|------|---------|
| `a414ebd` | N eagerly-created clients in main process | **CURRENT — untested** |
| `ea137a3` | Auto-scale clients to nginx limit | Part of current |
| `de3bfba` | Subprocess reporter with N clients | BROKEN (subprocess client creation) |
| `c76113d` | Burst drain tuning | Superseded by N-client approach |
| `4703e42` | Vast.ai cur_state fix | Working |
| `01a00d1` | Burst drain + stale check + --env dev | Partially working |
| `a9958c1` | Restore v0.1.52 pattern | THE WORKING BASELINE |
| `cd0b6d8` | 32x pipeline + kernel opts | Working (GPU optimizations) |
| `ab55786` | Subprocess reporter (pipe-based) | BROKEN (subprocess client) |
| `334e162` | collect --watch (file-tailing reporter) | BROKEN (same root cause) |
| `c410809` | Remove all submitters (file-only) | Mining works, no reporting |
| `72c2a06` | 64 blocking submitter threads | BROKEN (TLB shootdowns → 22 GH/s) |
| `a9ade36` | Lazy Option\<Client\> | **THE COMMIT THAT BROKE EVERYTHING** |

The pattern: `a9ade36` introduced lazy client creation. Every subsequent attempt inherited this broken pattern. `a9958c1` restored eager creation and everything worked. `a414ebd` (current) uses eager creation with N separate clients — the correct approach, just untested.
