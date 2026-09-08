# Colony live actuator — design sketch

**Status:** design only. Nothing here is built. This is the reviewed plan for
replacing the dry-run `LoggingActuator` (see [`colony-status.md`](colony-status.md))
with a real actuator that lets the colony *steer* peer selection — while keeping
the node the final authority over its own topology.

Prerequisite reading: [`colony.md`](colony.md) (design + Prime Privacy
Invariant), [`colony-status.md`](colony-status.md) (what's built), and the guard
layer in `src/colony/guard/`.

---

## 1. Goal and non-goals

**Goal.** Give the `coincync-tick` sidecar's Act pipeline a `ColonyActuator`
implementation (`RpcActuator`) that turns an authorized caste action into an
**advisory RPC call** to the local node, so the colony can actually improve peer
diversity, cover traffic, and partition recovery — not just log intent.

**Non-goals.**

- The colony does **not** get direct control of the peer set. Every advisory
  call is a *hint*; the node validates it, caps it, keeps its anchors, and may
  ignore it.
- No change to consensus, the mempool, or Dandelion++. The actuator touches peer
  **selection/topology and cover traffic only** — the same public-signal surface
  the castes already reason about.
- The colony never *originates* a penalty against a peer (see the tarpit rule in
  §5). It can only reinforce a judgement the node already reached on its own.

**The one-line invariant:** *a caste may add margin; it may never remove a
guarantee.* The node's own eclipse protection (/16 diversity), anchor set, and
diversity floor remain authoritative and are never weakened by colony advice.

---

## 2. Two independent enforcement layers (defense in depth)

Advice must pass **two** gates that share no state, so neither the sidecar nor a
single bug can narrow the node's topology dangerously:

| Layer | Where | What it decides |
|-------|-------|-----------------|
| **Colony guards** | sidecar (`ColonyGuards`) | whether to *send* advice at all — kill switch, diversity floor, per-action rate limits (already built + tested) |
| **Node admission** | node (`AdvisoryInbox`) | whether to *apply* received advice — independent validation, caps, its own rate limits, its own kill switch |

The node treats the sidecar as **semi-trusted infrastructure**: authenticated
(bearer) but not obeyed. A compromised or buggy sidecar is contained by the node
layer; a compromised node RPC is contained by the fact that advisory methods can
only *add diverse peers / cover traffic*, never disconnect honest peers or drop
below the node's own floors (§5).

There are therefore **two kill switches**: the colony's (sidecar,
`COINCYNC_COLONY_ACT_ENABLED`, already built) and the node's
(`COINCYNC_NODE_ACCEPT_COLONY_ADVICE`, new). Both must be armed for any advice to
take effect. The node's defaults OFF.

---

## 3. Identity: address by netgroup, never by internal PeerId

The crux that kept this out of the node before. The sidecar knows peers as
`FleetPeer { name, rpc_url }`; the node knows them as `PeerId = [u8; 32]` plus a
`SocketAddr`. Bridging those directly is fragile.

**Design:** advice is addressed by **routable network identity** both sides can
independently observe — the peer's P2P address and its derived `/16`-style
netgroup — never a node-internal `PeerId`. The sidecar derives the address from
the fleet peer (it already computes `netgroup_of(rpc_url)` for the diversity
census). The node resolves the advertised address to one of *its* connected
peers; if it can't resolve it, it **ignores the advice** (fail-closed). This
also means advice carries no more identifying information than the node already
has from the connection itself.

---

## 4. The seam: advisory RPC methods

A small set of mutating, bearer-authed, node-rate-limited methods registered on
the existing `jsonrpsee` server (alongside `submit_block` / `send_raw_transaction`,
the only other mutating methods today). Each maps one `ColonyActuator` method to
one node effect. Handlers are **cheap**: they validate shape, then push a typed
message onto a bounded `AdvisoryInbox` channel and return. The node's own
maintenance/peer-manager loop drains the inbox and applies each item with full
state access and the §5 rules — so application runs on the node's thread, never
in the RPC handler.

| Actuator method | Advisory RPC | Node effect (after validation) |
|-----------------|--------------|--------------------------------|
| `prefer_peers` | `colony_prefer_peers([addr])` | bias `relay_scores` toward these + mark eviction-protected, **capped**, additive, decays on its own |
| `open_bridges` | `colony_request_bridges([addr])` | dial toward these diverse addresses via the existing outbound connector, subject to `max_outbound` and the node's `/16` diversity |
| `set_relay_legs` | `colony_relay_hint([addr])` | advisory block-relay leg preference (centipede); node caps and may ignore |
| `set_swarm_mode` | `colony_swarm_mode(mode)` | adjust relay aggressiveness / padding within fixed bounds |
| `tarpit_peer` | `colony_tarpit(addr, secs)` | apply a slow-hold **only if the node's own scorer already flags this peer** (§5) |
| `cover_pulse` | `colony_cover_pulse()` | emit one padding burst via the existing `TrafficShaper` |
| `assert_wire_profile` | — | no RPC; the node already enforces the canonical wire shape. Kept as a sidecar-side assertion/metric only |
| `schedule_housekeep` | — | node-local timing; stays a sidecar concern, not an RPC |

The sidecar side is a `RpcActuator` implementing `ColonyActuator`, calling these
over the existing `RpcClient` (same bearer as `get_info`). It replaces
`LoggingActuator` in `colony_act_report`; the guard layer in front of it is
unchanged.

---

## 5. Node-side admission rules (the safety core)

Every inbox item is applied by the node only under these rules. They are the
reason a compromised sidecar cannot hurt the network:

1. **Anchors are untouchable.** No advice can disconnect, deprioritize, or
   tarpit a peer in the node's anchor set.
2. **Never below the node's own floors.** `colony_request_bridges` only *adds*
   outbound connections and only while doing so preserves the node's `/16`
   diversity and `max_outbound`. It cannot cause a disconnect.
3. **Tarpit reinforces, never originates (ban-consistency rule D.5).**
   `colony_tarpit` is applied **only if** the node's own `PeerScorer`
   independently already considers the peer misbehaving. Advice on an
   honest-looking peer is dropped and counted. The colony can shorten the leash
   on a peer the node already distrusts; it can never put an honest peer on one.
4. **Additive and reversible.** `prefer` / relay hints are bounded biases that
   decay via the existing relay-score evaporation — no permanent state.
5. **Node rate limits, independent of the sidecar's.** Each advisory kind has
   its own token bucket on the node, so a sidecar ignoring its own limiter still
   can't flood the node.
6. **Audit everything.** Every item is logged as applied / capped / ignored
   (with reason) and exposed as a metric, so the operator can see exactly what
   the colony changed.
7. **Node kill switch wins.** With `COINCYNC_NODE_ACCEPT_COLONY_ADVICE` unset,
   handlers accept the call, log it, and drop it — the node runs fully
   autonomous regardless of the sidecar.

---

## 6. Wiring

- **New:** `src/network/node/colony_advice.rs` — the `AdvisoryInbox` (bounded
  `tokio::mpsc`), the typed advice enum, and the drain-and-apply function that
  enforces §5. Owned by the node, given a clone of the seams it needs
  (`relay_scores`, `conn_tracker`, `AddressManager`/connector dial request,
  `TrafficShaper`, `PeerScorer`).
- **RPC:** register the §4 methods in `src/rpc/server.rs`; each pushes onto the
  inbox. The RPC `state` gains an `Option<AdvisoryInbox>` handle (None → methods
  return "advice disabled").
- **Drain:** a dedicated branch in the peer-manager loop (not the safety-critical
  ping/dandelion maintenance loop) drains the inbox each tick and applies items.
- **Sidecar:** `RpcActuator` in the tick crate implementing `ColonyActuator`;
  `colony_act_report` selects `RpcActuator` when a new `--colony-act-live` flag
  is set (and the env kill switch is armed), else keeps `LoggingActuator`.

No change to the colony core (`ColonyActor`, guards, castes) — this is purely a
new actuator behind the existing trait.

---

## 7. Staged rollout (each step separately reviewed)

0. **Path-proving.** Methods exist; node kill switch OFF → accept-log-drop. Proves
   the RPC/inbox path end-to-end with zero effect (the node-side mirror of the
   current sidecar dry-run).
1. **Additive only.** Enable `colony_prefer_peers` + `colony_cover_pulse` on a
   two-node testnet. Safest — purely additive, reversible.
2. **Partition recovery.** Enable `colony_request_bridges`. Watch it heal an
   induced partition without ever narrowing diversity.
3. **Defensive, last.** Enable `colony_tarpit` — most consequential, and gated by
   the node-corroboration rule (§5.3). Only after 1–2 are proven stable.

Each stage: metrics + audit log reviewed, kill switch tested, rollback = unset
the node env var.

---

## 8. Testing

- **Node admission unit tests** (the safety core): an anchor is never dropped; a
  bridge request that would breach `/16` diversity or `max_outbound` is capped/
  refused; `colony_tarpit` on a peer the scorer likes is ignored and counted;
  advice with the node kill switch off is dropped; per-kind node rate limits
  hold. Mock the seams; assert on the applied/ignored outcome.
- **`RpcActuator` tests** against a mock RPC: each authorized action issues the
  right call with address-keyed identity; a transport error is swallowed
  (advisory, best-effort) and never panics the tick.
- **End-to-end (two-node testnet)**: induce a partition, arm both kill switches,
  confirm the colony's bridge advice is applied within node limits and the
  partition heals; confirm disarming either kill switch stops all effect.

---

## 9. Failure modes

| Scenario | Containment |
|----------|-------------|
| Sidecar down | Node gets no advice and runs fully autonomous — no degradation |
| Sidecar buggy (bad advice) | Node validation (§5) caps/ignores; worst case is a few redundant diverse dials |
| Sidecar compromised | Bearer-authed, but advice can still only *add* diverse peers / cover traffic; node kill switch + admission rules bound the blast radius; **cannot** disconnect honest peers or narrow topology |
| Node RPC compromised | Advisory methods are strictly less powerful than the existing `submit_block` / `send_raw_transaction`; same bearer surface, additive-only effects |

**Bottom line:** the live actuator is worth building only if it cannot make the
network *worse* than a node with no colony at all. The two-kill-switch,
node-validates-independently, additive-only, tarpit-reinforces-never-originates
design is what buys that property. Until it is built and staged per §7, the Act
host stays dry-run.
