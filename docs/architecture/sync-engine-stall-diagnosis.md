# Diagnosis: sync-engine "idle-while-behind" stall

## ROOT CAUSE FOUND (2026-07-09) + FIX SHIPPED

Live inspection of the wedged node (seed1) resolved this: the node's **only**
log output was, every 10 s:

```
eclipse-defense: significant drift — subnet_sum=11 but outbound_count=1 (diff=10)
```

The **eclipse-defense per-/16 outbound slot counters had leaked** to 11 while
only 1 outbound connection was actually live. Those leaked counters sit at
`MAX_OUTBOUND_PER_SUBNET` (2) for the fleet's /16s, so
`try_track_outbound_subnet_owned` **refuses new outbound** to every fleet
subnet → the node is pinned at 1 outbound → it cannot peer with enough nodes to
sync → `peer_heights` stays empty → the state machine + recovery (below) never
fire. The `is_synced`/`target_height` disagreement described further down is the
*downstream* symptom; the **eclipse slot leak is the primary cause.** The leak
accumulates under reconnect churn (RAII `OutboundSubnetSlot` Arcs held past
their connection's life), and the periodic check only *warned* about the drift
without correcting it.

**Fix (shipped, tested):** `ConnectionTracker::reconcile_outbound_subnets()` —
on a detected drift of ≥2 the maintenance tick rebuilds the per-/16 counters
from the live outbound connection set, freeing the phantom slots so the node can
dial the fleet again. A security-critical counter must be reconcilable against
ground truth; RAII across async task boundaries proved structurally
insufficient. Tests: `reconcile_frees_leaked_outbound_slots`,
`reconcile_with_empty_live_set_zeroes_all_counters` (connection_tracker.rs).

The `is_synced` robustness items below remain worthwhile secondary hardening
(so a node behind a live peer requests regardless of the manager's internal
state), but they are no longer the primary fix.

---

**Status:** DIAGNOSIS for offline fix design. Observed repeatedly during the
2026-07-08/09 fleet incident (seed1, randomx2, and earlier randomx2 IBD). This
is a **pre-existing** sync-engine bug — independent of the Phase 2 work and the
rolled-back `retain_connected_peers` (whose call is removed; it does not run).

## Symptom

A node knows it is behind and is well-peered, yet sends **no** sync requests:

```
seed1  height=10042  target_height=10444  peer_count=8  synced=false
       (5 minutes of logs: zero GetHeaders / GetBlocks / orphan / stall lines)
```

The tip is actually at 10522 (a mining node), so seed1 is ~480 blocks behind
with 8 peers, and simply does nothing. A restart clears it only transiently.

## Root cause: two disagreeing notions of "the network tip"

There are **two** best-known-height values, and they can diverge:

1. **`chain.peer_target_height`** (atomic, surfaced as RPC `target_height`).
   Written only by `set_sync_info(synced, target)`, which is called only from
   `set_chain_state` — i.e. **only on a local tip advance.**
2. **`ChainSync.true_best_height()`** = `best_known_height.max(max(peer_heights))`
   in the sync manager, recomputed on every peer-height mutation.

The recovery path and the request path both key off the **manager** value:

- The maintenance loop's **EMERGENCY-TIER-3** deep-recovery is gated on
  `!sync_sync.is_synced()` where manager `is_synced()` = `local_height >=
  true_best_height()` ([node.rs:1662], [sync.rs:451]).
- The state machine only enters **`Headers`** (which sends `GetHeaders`) when
  `update_peer_height_for` sees a peer height **> local** ([sync.rs:314]).

**The wedge:** when the manager's `peer_heights` map is empty or all ≤ local,
`true_best_height() == local` → manager `is_synced() == true`. Then:

- EMERGENCY-TIER-3 never fires (gated on `!is_synced()`), and
- the state machine never enters `Headers` (no peer height > local was
  recorded),

so the node is **idle**. But `chain.peer_target_height` still holds a stale
higher value (10444, set earlier and never refreshed because a tip advance
never happens while wedged). RPC therefore reports `synced=false, target=10444`
while the engine believes it is fully synced. The two views are inconsistent
and nothing reconciles them.

## The sub-question: why does `peer_heights` go empty?

`peer_heights` is populated only by `update_peer_height_for`, called on:
Version handshake `start_height`, `InvBlock` announcements, and (Phase 2)
`ChainWork`. It is pruned on local advance (`prune_stale_peer_heights`),
disconnect (`remove_peer_height`), and the ≤-local drop path.

If a peer connected while its (and our) height was low and then the peer's
subsequent tip announcements do not reach us — or reach us but are not routed
into `update_peer_height_for` — the entry never climbs to the peer's real
height. With 8 connected peers all at 10522, `peer_heights` should hold 10522;
that it apparently holds nothing needs **live packet/log inspection** to pin
down (which is why this is deferred to a calm session, not hot-patched):

- Are peers sending `InvBlock` for new tips, and is seed1's dispatch feeding
  those into `update_peer_height_for`?
- Does the periodic tip re-announce reach a node that isn't itself advancing?
- Did a burst of ≤-local drops (during the 10042-rollback window) evict entries
  that were never re-added?

## Fix direction (design offline, test, then ship)

Two complementary changes; neither should be rushed onto the live fleet:

1. **Make deep-recovery key off ground truth, not the manager's `is_synced`.**
   EMERGENCY-TIER-3 (and the "should I be requesting?" decision) must fire when
   the node is **demonstrably behind a connected peer** — e.g. `chain.height()
   < max(height advertised by any currently-connected peer)` — regardless of
   the manager's internal `is_synced()`. A node that is provably behind a live
   peer must request from it, full stop. This breaks the "both notions say
   synced-ish so we idle" deadlock even if `peer_heights` is momentarily stale.

2. **Keep the two tip-views reconciled.** Either refresh
   `chain.peer_target_height` from the manager on every maintenance tick (not
   only on tip advance), or drive both from a single source. Today they can
   silently diverge, which is what makes the RPC report and the engine's
   behavior contradict each other.

3. **Root the `peer_heights` emptiness** (the live-inspection item above) so
   the manager's `true_best_height` reflects reality in the first place — the
   cleanest fix, since with correct `peer_heights` the existing state machine
   and recovery both work.

## Interaction with the phantom-target redesign

This is closely related to the rolled-back `retain_connected_peers` work:
both are about `peer_heights` not reflecting the live peer set/heights. A single
careful redesign should cover both — a peer-height model driven by **liveness +
current advertisements** (prune on sustained silence, refresh from real
announcements) rather than the current populate-once / prune-on-local-advance
scheme that both over-retains stale highs (phantom target) and under-populates
real highs (this stall).
