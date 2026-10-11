# Cold-start IBD: handshake starvation during header verification

**Status:** design / proposal (2026-10-11). Root cause CONFIRMED on a public fleet host.
**Scope:** testnet; consensus-adjacent IBD path. Any change lands on its own branch,
fully tested + soaked, and is NOT fleet-deployed until proven.

## Symptom

A fresh node joining the testnet is slow to form its peer mesh, so Initial Block
Download barely starts:
- The **first** peer completes its handshake and connects **instantly**.
- Peers **2..N** complete Noise but then take **~15-30s each** to reach
  `PeerState::Connected` — so the 3-peer `MESH_FLOOR_PEERS` floor takes tens of
  seconds to form, and on a slow / NAT'd node it may never form.

Measured on a public (non-NAT) fleet host: `outbound` climbs 1 → (stall) →
6 only across ~60s, with the stall window matching the header-verify time.

## Root cause (confirmed)

Two independent contributors — the first is fixed, the second is this doc:

1. **Dial cadence (FIXED, PR #280):** the outbound connector dialed on a fixed
   10s interval (~1 peer / ~20s). Fixed by an adaptive cadence (2s under the mesh
   floor, 10s once meshed). This made dialing fast but did NOT fix the completion
   lag below.

2. **Single message processor blocked by header verification (THIS DOC):**
   - All peers' inbound messages funnel through **one** `mpsc` channel into **one**
     `spawn_message_processor` task that calls `process_message` **sequentially**
     (`src/network/node/runtime.rs:218,264,294`; `mpsc::channel(8)`).
   - When that single task processes a `Headers` message it runs
     `validate_header_batch` — **~2000 sequential RandomX verifies, ~24-46s in
     light mode — directly on the processor task**, NOT offloaded
     (`src/network/node/dispatch/headers.rs:615`). (#184 already moved this OFF
     the ChainSync write lock, but it still runs inline on the processor.)
   - For that entire ~24-46s window the processor cannot handle ANY other peer's
     `Version` / `Verack`. Their messages queue behind the headers batch (and the
     cap-8 channel backs up), so their handshakes stall — exactly the observed
     ~15-30s completion lag.

`block_in_place` / `spawn_blocking` **alone do not fix this**: the processor is a
single task; while it is blocked (or awaiting) on this one `Headers` message it
does not `recv()` the next message, so other peers' handshakes still wait.

## The fix

Make header verification **not occupy the single message processor**: verify the
batch off-task and apply the result without the processor blocking, so it keeps
servicing other peers' handshake messages.

**Chosen approach — detached verify + apply:**
In `handle_headers`, after the cheap read-lock nonce gate (keep in the processor),
spawn a task that:
1. runs `validate_header_batch` via `tokio::task::spawn_blocking` (CPU pool, frees
   the worker thread), then
2. re-acquires the ChainSync write lock, re-checks `validate_header_nonce` (consume),
   and runs the existing apply (`update_peer_height*`, `queue_headers_from_peer`).
The processor returns immediately and processes the next message.

### Refactor required (the real work)
`process_message` and `handle_headers` currently take the dispatch context **by
reference** (`&RwLock<ChainSync>`, `&DashMap`, `&SharedBlockchain`, `&RwLock<PeerScorer>`),
but the processor loop holds them as `Arc`s (`processor_sync.as_ref()`, …). A
`'static` spawned task needs **owned `Arc` clones**, so:
- thread the needed `Arc`s (sync, chain, peers, scorer) to `handle_headers` as
  owned clones (either change the header path's params to `Arc<…>` or pass clones
  alongside the existing refs), and
- clone them into the spawned task.
This is a broad-ish signature change along the header dispatch path + its tests.

### Safety / ordering analysis (must hold)
- **Nonce single-use:** keep the cheap `is_header_nonce_outstanding` read-lock gate
  in the processor (rejects cross-peer / stale before spawning). The spawned task
  re-checks + consumes `validate_header_nonce` under the write lock, so a batch that
  timed out (>60s) or was superseded during verify is discarded — same invariant as
  today, just moved into the task. Keep tests
  `handle_headers_cross_peer_nonce_is_rejected_without_consuming` /
  `..._valid_nonce_is_single_use` green.
- **Overlapping batches:** IBD keeps one outstanding header nonce at a time, but a
  >60s verify + driver re-request could make two verify concurrently. The write-lock
  apply + nonce consume serialize the apply; `queue_headers_from_peer` must remain
  idempotent against duplicate hashes (it already dedups via `pending_headers`
  membership — verify). Consider a per-"one-verify-in-flight" guard if needed.
- **Back-pressure:** with the processor no longer stalled, the cap-8 channel no
  longer backs up during IBD; revisit whether the channel cap still wants bumping.
- **No ChainSync-lock regression:** verification stays off the write lock (#184).

### Alternative considered (not chosen)
Handle `Version`/`Verack` inline in the per-connection read loop
(`connection.rs`) so handshakes never route through the busy central processor,
leaving only heavy messages (Headers/Blocks) central. Smaller blast radius on the
consensus path, but splits the dispatch in two and duplicates handshake plumbing.
Keep as a fallback if the detached-verify refactor proves too invasive.

## Test + rollout plan (do NOT shortcut)
1. Full lib suite green (currently 2188/2188) + the handle_headers nonce tests.
2. Public-host cold-start re-verify (the `coldstart-verify` harness): expect the
   mesh to reach `outbound>=3` within a few seconds of dialing (not ~60s) AND the
   chain tip to start advancing — i.e. handshakes no longer wait on header verify.
3. Single-node soak against the live fleet (fresh data-dir) to full sync, watching
   for any sync-wedge / fork / EMERGENCY-TIER-3 regressions.
4. Only then build pristine, fingerprint-verify (`d312f6ee…`, network-layer only),
   and `safe-deploy.sh` roll to the fleet.

## References
- `src/network/node/runtime.rs` (`spawn_message_processor`, single `msg_rx` loop)
- `src/network/node/dispatch/headers.rs:615` (`validate_header_batch` inline)
- `src/network/node/dispatch/control.rs` (`handle_version` / `handle_verack`,
  `Connecting → VersionReceived → Connected`)
- `#184` (verify off the ChainSync lock); PR #280 (adaptive dial cadence).
