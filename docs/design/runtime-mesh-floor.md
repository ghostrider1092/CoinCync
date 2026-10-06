# Runtime mesh-floor + anchor durability

**Status:** implemented (observability + durability + re-bootstrap-on-isolation;
mining behavior unchanged)
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

### Re-bootstrap on isolation (#147)

The mesh-floor above is *observational*; this is the *active recovery* that
pairs with it. The outbound connector (`peer_manager::spawn_outbound_connector`)
retries known addresses indefinitely — the `AddressManager` tried-set
self-clears once every address has been tried — but it had no path back once the
**address book itself drained to empty**. A long-running node can reach that
state: each peer that fails `FAILURE_PURGE_THRESHOLD` times is *purged* from the
book entirely, so a node that loses connectivity long enough purges every known
address, after which `get_next()` returns `None` forever. The startup bootstrap
(`Node::start`) only re-queries DNS when the book *starts* empty, so nothing
re-resolved the seeds after it drained — the node stayed isolated until a manual
restart (the "never re-dials" half of #147; see @Rastonite in #126).

The connector now re-bootstraps when it finds itself isolated:

- **Trigger** — on a tick where `get_next()` returns `None` (nothing dialable)
  **and** `outbound_count < MESH_FLOOR_PEERS` (3). The floor matters: with a
  healthy outbound set, addr-relay gossip refills the book without a DNS query,
  so re-bootstrap is reserved for genuine under-mesh.
- **Action** — re-run `Bootstrapper::get_peers_with_proxy` (honoring
  onion-only / proxy-DNS exactly as startup does) and `AddressManager::add` the
  results. Purged addresses are gone from `tried`/`known_addrs` too, so re-added
  seeds are immediately dialable on the next tick.
- **Backoff** — first retry fires immediately; subsequent retries while
  re-resolution yields **no new** addresses back off exponentially
  (`REBOOTSTRAP_BACKOFF_MIN` 60s → ×2 → `REBOOTSTRAP_BACKOFF_MAX` 30min), and
  reset to the floor the moment a re-bootstrap adds any address. A persistent DNS
  outage therefore settles at one query per 30min, not one per 10s tick.
- **Seedless guard** — skipped entirely when the bootstrap config has no DNS
  seeds and no hardcoded seeds (e.g. regtest), so an isolated single-node regtest
  miner does not log a no-op re-bootstrap every interval.

The isolation gate and backoff schedule are factored into two pure helpers
(`should_rebootstrap`, `next_rebootstrap_backoff`) with direct unit tests, so the
decision logic is verified without driving the async connector loop.

## Why it's testnet-safe / no consensus impact

No block validation, serialization, genesis, or hash-locked file is touched.
The mesh-floor is a read-only counter; the anchor changes affect only which
outbound peers are re-dialed first after a restart; and the re-bootstrap path
only re-queries the same DNS/hardcoded seeds the node already uses at startup and
adds the results to the address book. No peer is dialed that startup wouldn't
have dialed. Default mining behavior is unchanged.

## Portability (help other chains)

A *sustained* under-mesh signal with hysteresis (distinct from an instantaneous
"low peers" band) is a small, generic primitive any P2P chain can expose so
monitors, load balancers, and (opt-in) miners react to a real partition instead
of flapping on momentary peer churn. Bounded, longevity-ranked anchors persisted
on shutdown are standard eclipse hygiene that many young chains skip.
