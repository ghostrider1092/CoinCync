# Runtime mesh-floor + anchor durability

**Status:** implemented (observability + durability; mining behavior unchanged)
**Idea family:** "small hidden things" — a dam's seepage gauges and its
anchored foundation bolts.

## Background

`scripts/deploy-node-binary.sh` gates a rolling restart on `peer_count >= 3`,
and the REST readiness probe uses the same floor — but those are **external and
instantaneous**. The node itself had no *sustained* notion of "I have been
under-meshed for a while," only the per-request health band in `crate::vitals`.
Separately, Bitcoin-style **anchor peers** already exist in this tree
(`peer_manager::{save,load}_anchors_to_disk`, `AddressManager::set_anchors`,
anchor-first dialing) but with two gaps: the set was unbounded, and it was only
persisted by a periodic 60s timer — never on graceful shutdown, because the
binary exits without calling `P2PNode::stop()`.

## What this adds

### Runtime mesh-floor (observability)
- `P2PNode.mesh_degraded: AtomicBool`, updated once per 30s heartbeat by
  `update_mesh_floor`. It counts consecutive heartbeats with **connected** peers
  below `MESH_FLOOR_PEERS` (3, matching the deploy/REST floor); after
  `MESH_FLOOR_SUSTAIN_TICKS` (3 ≈ 90s) it sets `mesh_degraded`. Recovery is
  immediate on the first heartbeat back at/above the floor (slow in, fast out —
  hysteresis against transient blips).
- Exposed via `network_stats().mesh_degraded`, and as `mesh_degraded` in both
  `get_info` and the versioned `get_vitals` (`ChainVitals`).

**This is observational.** It does **not** change mining or peering by itself.
That is deliberate: the live bootstrap seed currently mines solo with
`peer_count = 1`, so a mesh-floor that *paused mining* by default would halt the
testnet. The natural next step — an **opt-in** flag that pauses the solo miner
while `mesh_degraded` (so a real ≥3-node mesh refuses to mine on a partition,
while the bootstrap seed leaves it off) — is left as a follow-up and must default
**off**. The `mesh_degraded` signal is the primitive that makes that safe to add
later; a monitor or miner can already read and act on it today.

### Anchor durability
- `save_anchors_to_disk` now keeps only the `ANCHOR_MAX` (2) **longest-lived**
  connected outbound peers (sorted by `connected_at`), instead of every
  momentarily-connected one — the stable core an eclipse attacker can't easily
  displace.
- Anchors are now persisted on graceful shutdown: `P2PNode::save_anchors()` is
  called in the binary's SIGTERM/Ctrl-C sequence, closing the "up to 60s of
  anchor loss on a clean stop" gap.

## Why it's testnet-safe / no consensus impact

No block validation, serialization, genesis, or hash-locked file is touched.
The mesh-floor is a read-only counter; the anchor changes affect only which
outbound peers are re-dialed first after a restart. Default mining behavior is
unchanged.

## Portability (help other chains)

A *sustained* under-mesh signal with hysteresis (distinct from an instantaneous
"low peers" band) is a small, generic primitive any P2P chain can expose so
monitors, load balancers, and (opt-in) miners react to a real partition instead
of flapping on momentary peer churn. Bounded, longevity-ranked anchors persisted
on shutdown are standard eclipse hygiene that many young chains skip.
