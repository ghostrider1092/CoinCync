# Cold-start IBD: handshake starvation during header verification

**Status:** IMPLEMENTED (2026-10-11). Root cause confirmed on a public fleet host.
Shipped as: adaptive dial cadence (PR #280), RandomX key-epoch hold (PR #285), and
a dedicated handshake lane with inline verify (PR #287) — all merged to `main` and
deployed to the fleet (network-layer only; consensus fingerprint `d312f6ee…`
unchanged). An intermediate detached-verify attempt (PR #283) was superseded; see
"The fix (shipped)".
**Scope:** testnet; consensus-adjacent IBD path. Each change landed on its own
branch, fully tested + soaked, and was not fleet-deployed until proven.

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

## The fix (shipped)

The goal is to keep the single processor from starving handshakes during a header
verify. Two approaches were tried; the second shipped.

### First attempt — detached verify (PR #283, superseded)
`handle_headers` was moved OFF the processor: it spawned a task that ran
`validate_header_batch` via `spawn_blocking` and applied the result (this needed
the `Arc`-ification of `process_message`'s `peers`/`sync`/`scorer` so a `'static`
task could own clones). It unblocked handshakes — **but** it let the header verify
run **concurrently with block application** across a RandomX key-epoch boundary.
Light mode keeps a single cache slot keyed per epoch, so the spawned verify (new
epoch) and the inline block-apply (old epoch) ping-ponged the cache: a fresh-node
soak measured **78 "Building RandomX cache" rebuilds** (vs ~4-8 with #285's
key-epoch hold alone). The unblock-handshakes goal was met, but at the cost of
re-introducing the thrash #285 had just removed. Superseded by #287.

### Shipped approach — dedicated handshake lane (PR #287)
Keep header verify **inline** on the single processor (so it serializes with
block-apply and never flips the cache slot concurrently — the no-thrash invariant),
and take **handshakes off that processor** via a dedicated lane:
- A second `mpsc` channel + its own consumer task
  (`runtime::spawn_handshake_processor`). The connection read loop
  (`connection.rs`) routes `Version`/`Verack` there instead of the shared
  processor. Because it is a separate task, tokio schedules it independently, so a
  peer's handshake completes even while the main processor is parked in a verify.
- `handle_headers` runs inline again (reverting #283's `tokio::spawn`); the RandomX
  batch still runs via `spawn_blocking` so it never pins an async worker.
- `dispatch::process_handshake` services the two handshake types (peer-activity /
  byte accounting mirrored from `process_message`). The H-3 pre-handshake gate is
  unaffected: it *ignores* (never penalizes) early non-handshake messages, so the
  cross-lane race (a peer's `GetHeaders` arriving before its `Verack` is serviced)
  is safe — the early message is dropped and re-requested, no misbehavior score.

This is the "alternative" the first revision of this doc listed as *not chosen*. It
turned out to be the right call: it keeps verify serialized (no thrash) **and**
handshakes unblocked, where the detached-verify could only get one of the two.

### Companion fix (PR #285)
The thrash-freeness of inline verify depends on #285's **key-epoch hold** (the IBD
download window does not cross a RandomX epoch boundary before the tip reaches it),
which keeps verify and block-apply on the same epoch key. Measured: #287 inline
verify *without* #285 ≈ 114 rebuilds; *with* #285, **6**.

### Safety / ordering analysis (held)
- **Nonce single-use / off the ChainSync lock:** `handle_headers` is unchanged here
  — the `is_header_nonce_outstanding` read-lock gate, the `spawn_blocking` verify
  off the write lock (#184), and the `validate_header_nonce` consume under the write
  lock all remain. Tests `handle_headers_cross_peer_nonce_is_rejected_without_consuming`
  / `..._valid_nonce_is_single_use` stay green.
- **Cross-lane ordering:** handshake messages (`Version`/`Verack`) only ever precede
  `Connected`; after `Connected` no handshake messages arrive. A data message that
  races ahead of its peer's `Verack` hits the H-3 gate and is ignored (not scored),
  so splitting the lanes introduces no new penalty or corruption.
- **No concurrent verify/apply:** both run on the one main processor task, one
  message at a time → never concurrent → no epoch-boundary cache thrash.

## Test + rollout (completed)
1. Full lib suite green (2190/2190 with #285+#287; 2188/2188 for #287 on `main`
   without #285) + the `handle_headers` nonce tests.
2. Public-host cold-start soak (fresh data-dir, fleet VPS): mesh reached
   `outbound>=3` within ~10s of dialing (not ~60s), **6** RandomX cache rebuilds
   (vs 78 for the detached-verify attempt), 0 orphans, 0 EMERGENCY-TIER /
   fork / panic / deadlock, full sync to the fleet tip.
3. Pristine build, fingerprint-verified (`d312f6ee…`, network-layer only), rolled to
   all 6 fleet nodes via `safe-deploy.sh` — each re-meshed to 6-7 peers and
   re-synced cleanly after its restart.

> NOTE: a fresh IBD node cannot complete header-batch delivery on a NAT'd dev box
> (the bulk Headers response stalls), so cold-start soaks/demos must run on a
> public fleet VPS, not behind WSL NAT.

## References
- `src/network/node/runtime.rs` (`spawn_message_processor`, `spawn_handshake_processor`)
- `src/network/node/connection.rs` (read-loop lane split: `Version`/`Verack` → handshake lane)
- `src/network/node/dispatch/mod.rs` (`process_handshake`; inline `Headers` arm)
- `src/network/node/dispatch/headers.rs` (`validate_header_batch` via `spawn_blocking`)
- `src/network/node/dispatch/control.rs` (`handle_version` / `handle_verack`,
  `Connecting → VersionReceived → Connected`)
- `#184` (verify off the ChainSync lock); PR #280 (adaptive dial); PR #283
  (detached verify, superseded); PR #285 (key-epoch hold); PR #287 (handshake lane).
