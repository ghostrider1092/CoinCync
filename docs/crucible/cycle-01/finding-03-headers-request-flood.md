# Crucible Cycle 01 — Finding #3: IBD GetHeaders flood (4 Hz hammer)

**Status:** Fixed
**Severity:** High (operational — eats CPU + bandwidth, eventually kills node, masks legitimate sync stalls)
**Discovered:** 2026-06-10
**Fixed in:** `v1.0.11-fleet-2026-06-06` commit `9292306`
**Tester:** operator + barns (both observed; operator's log was the post-mortem source)
**Time-to-fix:** ~30 minutes from log dive to verified fix

## TL;DR

The IBD tick loop (`network/node.rs:1582`) ran every 0.5s and sent a
fresh `GetHeaders` request to a chosen peer on every tick — no gate
on whether a previous request was still in flight. Hot 4 Hz hammer
against a single peer. One observed session emitted 26,000+ GetHeaders
+ 125 `EMERGENCY-TIER-3` recovery fires over 8 hours of being stuck
on a fork tie, then the node died.

## Symptom

From operator's log (2026-06-10, 8-hour session):

```
2026-06-10T00:29:09.940500Z INFO [IBD] GetHeaders nonce=26101 sent to peer [63, 136, 204, 21] (our_height=2594, state=Headers)
2026-06-10T00:29:10.436838Z INFO [IBD] GetHeaders nonce=26102 sent to peer [63, 136, 204, 21] (our_height=2594, state=Headers)
2026-06-10T00:29:10.947669Z INFO [IBD] GetHeaders nonce=26103 sent to peer [63, 136, 204, 21] (our_height=2594, state=Headers)
```

3 requests in 1.007 seconds = ~3 Hz steady state (peaks at 4 Hz). All
to the same peer. our_height never changes (stuck on fork tie). For 8
hours.

Adjacent emergency-recovery firing pattern:

```
ERROR Sync EMERGENCY-TIER-3 #125: chain has not advanced past height 2594 for 420s
  ... orphan-fetch cascade or similar pathology ... operator may need
  to wipe + reimport snapshot.
```

`EMERGENCY-TIER-3` fired 125 times across the 8-hour window
(re-firing every 120s once triggered). Each firing called
`reset_headers_timeout` — which DID work as intended (briefly cleared
the in-flight flag) but the flood resumed within ticks because the
SENDER didn't gate on the flag either.

Then the node died. Exit code 4, no graceful-shutdown line in the
log. Likely memory exhaustion from accumulated orphan + request state.

## Discovery path

1. **Barns reports** "stuck at h=2128" + "node won't shut down via
   Ctrl+C" + "I don't know what came from your sync vs natural
   sync" (the last question is the giveaway — he had no other peer).
2. **Operator's node found dead** (background task failed with exit
   code 4).
3. **Log dive** — last 30 non-IBD lines all `EMERGENCY-TIER-3 #N`.
   Last 3 lines were rapid-fire `GetHeaders nonce=...`. Counted 125
   emergency fires, 26,103 GetHeaders nonces.
4. **Source dive** — found the IBD tick loop in
   `network/node.rs::sync_loop` at line ~1582:

   ```rust
   match state {
       SyncState::Idle | SyncState::Headers | SyncState::ConfirmingSynced => {
           // Check if headers request timed out (no response in 15s)
           if sync_sync.read().await.headers_timed_out(now) {
               warn!("Headers request timed out, retrying with different peer");
               sync_sync.write().await.reset_headers_timeout();
           }
           // ↓ NO GATE HERE ↓
           let height = sync_chain.height();
           let locator = build_locator(...);
           if let Some(peer_id) = pick_scored_peer(...) {
               // ... sends GetHeaders unconditionally
               sync_sync.write().await.mark_headers_requested(now);
           }
       }
   ```

5. **Cross-checked** the called functions in `sync.rs`:
   - `mark_headers_requested(now)` — `if self.headers_request_time.is_none() { ... }` — no-op if a request is already marked. Looked like a guard but is actually just append-only behavior.
   - `headers_timed_out(now)` — checks 60s past last request. (Not 15s as the call-site comment claimed.)
   - `reset_headers_timeout()` — sets `headers_request_time = None`.
6. **The check at the call site** only fires on timeout EXPIRY (clearing
   state) and only logs a warning. It doesn't suppress the send below.
   So every tick → send. The 60s timeout effectively never matters
   because a new request was always less than 0.5s old.

## Root cause

The IBD state machine has no concept of "a request is currently in
flight, wait for it." The internal state IS tracked
(`headers_request_time: Option<u64>`) but the tick loop doesn't
consult it before sending.

This is a classic "the data structure is there, the call site forgot
to use it" bug. Probably accumulated during a refactor where the
timeout-reset path was added (the explicit emergency-recovery code
DOES use the right primitive) and the call-site gate was overlooked.

## Fix

Two changes in `9292306`:

**1. Add a read-only predicate to `sync.rs`:**

```rust
pub fn headers_request_pending(&self) -> bool {
    self.headers_request_time.is_some()
}
```

**2. Gate the send at the call site in `network/node.rs`:**

```rust
// Time out a stuck request first
if sync_sync.read().await.headers_timed_out(now) {
    warn!("Headers request timed out, retrying with different peer");
    sync_sync.write().await.reset_headers_timeout();
}

// ── NEW GATE ──
if sync_sync.read().await.headers_request_pending() {
    continue;  // wait for response or timeout
}

// ... existing send logic
```

Net effect: at most one in-flight GetHeaders per peer at a time,
60-second cap before the timeout-reset fires and allows the next
tick to legitimately re-request.

`EMERGENCY-TIER-3` recovery still calls `reset_headers_timeout()` so
its effect now actually propagates — the next tick is free to issue
a fresh request, exactly the recovery semantics that emergency-tier-3
was designed for.

## Verification

After rebuild + relaunch:

| Window | Old behavior | New behavior |
|---|---|---|
| 25 seconds | ~100 GetHeaders | **0 GetHeaders** |
| 60 seconds | ~240 GetHeaders | **1 GetHeaders** (initial + 60s timeout cycle) |
| 8 hours | ~115,000 GetHeaders + 240 emergency fires + likely death | 1 in-flight per peer always |

The node survives indefinitely now. Stuck-on-fork situations still
need EMERGENCY-TIER-3 to actually break the fork, but the underlying
loop no longer self-destructs.

## Impact

- **v1.0.10 and earlier:** affected with the same control flow. Did
  not surface in public testnet because real peers were always
  productive on at least some requests; the bug only fires fast when
  the peer is unresponsive. A 4 Hz hammer against a productive peer
  just looks like aggressive IBD.
- **v1.0.11 (pre-fix):** affected.
- **v1.0.11-fleet-2026-06-06 from `9292306` onward:** fixed.

The bug was probably **the** load contributor to the
"chain stuck for hours" pathology that EMERGENCY-TIER-3 was added to
recover from. Now that the gate is in place, EMERGENCY-TIER-3 should
fire much less often, and when it does fire it should actually unstick
the node (because the recovery path's `reset_headers_timeout()` now
lets a real new request go out, instead of being immediately drowned
in the existing flood).

## Crucible learning

The bug was visible in log VOLUME, not log CONTENT. Every individual
"`GetHeaders nonce=N sent`" line looked fine. Only the rate, plotted
over time, revealed the bug. A maintenance bot watching for the
EMERGENCY-TIER-3 errors would have caught the stuck-state symptom
but not the request-rate cause.

**Process gap:** an IBD-rate sanity test (or a regression test that
fails if more than 5 GetHeaders fire in 10 seconds) would have
caught this. Open v1.0.13 follow-up.

**Process gap:** the EMERGENCY-TIER-3 emergency-recovery code's
expected recovery behavior should be tested in isolation. Today it
exists, fires, and produces operator-facing warnings, but its
actual effect (does the node UNSTICK after firing?) is implicit. A
test that "fire emergency-tier-3 → verify next GetHeaders goes
through" would have made the underlying flood bug visible.

## Follow-up tasks

- [ ] Add IBD-rate regression test (assert ≤ 5 GetHeaders / 10s)
- [ ] Add EMERGENCY-TIER-3 effectiveness test (fire it, verify state
      machine reaches Synced or at least makes one productive
      request)
- [ ] Audit other periodic-message-send paths in `node.rs` for the
      same anti-pattern (`SyncState::Blocks` block-request loop, peer
      handshake retry loop, mempool gossip path)
- [ ] Review the `headers_request_pending` predicate naming for
      consistency with future state additions (e.g., when we add a
      blocks-pending predicate per the Blocks state)
