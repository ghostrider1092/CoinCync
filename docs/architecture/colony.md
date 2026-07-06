# colony — ant/termite swarm agents for network resilience

> Status: **DESIGN (Phase 0)** — this document. No code. Extends the
> [`tick`](tick.md) agent framework from lone agents into a swarm.
>
> Prime thesis: **a swarm can harden a privacy chain's network without
> weakening its privacy — if, and only if, the swarm forages exclusively
> on public signals and never observes the transaction graph.** This
> document's central job is to prove that boundary holds for every caste.

## Executive summary

`tick` gave CoinCync lone parasitic agents (RescueTick, HealthTick,
PropagationTick) that quest, latch, and feed. `colony` is the next layer:
**many simple, stateless agents whose local behavior produces emergent,
resilient network health with no central controller** — the way an ant
colony finds food or a termite mound repairs itself.

Nature solves three problems CoinCync's P2P layer also has:

| Insect behavior | CoinCync problem it maps to |
|---|---|
| Ant foraging + pheromone trails (ACO) | Slow / fragile **block** propagation paths |
| Ant scouting from many sources | Peer discovery that a single poisoned source can dominate (eclipse) |
| Termite stigmergic mound repair | Network partitions / eclipse; no self-healing today |

The colony runs in the **`coincync-tick` sidecar** (separate process — a
swarm bug cannot wedge the node) and is **purely advisory**: it observes
public network signals and *recommends* peer/relay actions to the node
over a bounded RPC. The node's peer manager remains the sole authority and
can rate-limit or ignore any advice. Nothing the colony does is
consensus-critical; nothing it does touches a transaction.

## Why this makes CoinCync unique

Most chains optimize their P2P layer for speed. Most **privacy** chains
deliberately *don't* — any network optimization risks leaking metadata
(which peer, which path, which timing), and metadata is how privacy chains
actually get de-anonymized. So privacy networks tend to stay deliberately
"dumb": fixed relay, no path learning, manual peer management.

CoinCync's angle is to have both: **a self-healing, swarm-optimized P2P
layer that is provably privacy-safe because it forages only on public
signals (blocks, topology) and is structurally incapable of touching the
transaction graph.** That combination — emergent network resilience *with*
an explicit, auditable privacy boundary — is the differentiator. It is
also honest: the uniqueness is not "we made routing smart" (many chains
claim that); it is "we made routing smart on a privacy chain *without*
giving the network a way to see who sent what," and this document is the
proof of that claim. Overclaiming here would be self-defeating (Standing
Principle: privacy claims must be provable), so the boundary is stated as
an invariant with a per-caste proof, not a slogan.

## The colony vs. tick

`tick` agents are **vertical**: one agent runs a Quest→Latch→Feed state
machine against a target. `colony` agents are **horizontal**: many
identical foragers each doing a trivial probe, with coordination emerging
from a shared local "environment" (the pheromone map), not from any agent
talking to another. The tick sidecar hosts both. HealthTick (already
built, read-only) is the colony's sensory organ; the colony adds
*advisory action* on top of that sensing — but only on the public network
layer.

## The four castes

### 1. Forager ants — block-relay path scoring

**Job:** continuously score the node's peers by how fast and reliably they
deliver **blocks** (public data), and recommend that the node prefer
high-pheromone peers for block relay and keep them as long-lived
connections.

**Mechanism (Ant Colony Optimization, adapted):**
- Each observed block arrival deposits "pheromone" on the peer that
  delivered it first, weighted by how far ahead of the pack it was.
- Pheromone **evaporates** over time, so stale-good peers decay and the
  map tracks *current* conditions (and resists a peer that was fast once).
- The node's relay/connection preference reads the map as one input.

**Output:** a peer→score table (block-relay latency, reliability,
liveness). Advisory only.

### 2. Scout ants — swarm peer discovery

**Job:** many independent light scouts discover and vet candidate peers
from *diverse* sources (DNS seeds, addr gossip, peer snapshots, hardcoded
anchors), so **no single source can dominate the peer set** (D.3, eclipse
resistance).

**Mechanism:** each scout draws candidates from a different source, probes
them for a real handshake + a valid recent header (cheap PoW check, reusing
`verify_peer_header_pow`), and only then nominates them. A candidate must
be corroborated by scouts from ≥2 independent sources before the colony
recommends adoption — a single poisoned DNS response or addr flood cannot
seed the peer set alone.

### 3. Termite workers — self-healing mesh

**Job:** sense **network partitions** and **eclipse pressure** from public
topology facts and recommend re-wiring the peer graph to heal splits —
without an operator.

**Stigmergy:** termites coordinate by modifying and sensing a shared
environment, not by messaging. Here the "environment" is the local view of
peer connectivity + tip divergence (from HealthTick's
`aggregate_fleet_health`). Signals that trigger healing:
- tip height/difficulty divergence across peers beyond a threshold
  (possible partition),
- peer-set concentration in one IP range / ASN (eclipse pressure),
- collapse in reachable-peer diversity.

**Response (advisory, bounded):** recommend dialing corroborated peers
from under-represented sources to restore diversity. **Anchor rule:** the
colony may *add* diversity but may never recommend dropping the node's
long-lived anchor peers — so a manipulated colony cannot use "healing" to
evict good peers and eclipse the node (see Attacks).

### 4. Colony ops — the shared substrate

Not a network caste: the plumbing. The tick sidecar hosts the pheromone
map, runs the forager/scout/termite loops on intervals, and exposes the
resulting advice. It reuses HealthTick for sensing and the existing
`CoincyncAdapter` RPC surface for probing. Fleet-mode (optional) shares
**only public aggregate metrics** between operator-owned hosts — never
per-transaction anything (see Privacy).

---

## The Prime Privacy Invariant

> **The colony forages only on public signals. It never observes, records,
> scores, times, or routes an individual transaction or any stem-phase
> traffic. Transaction propagation remains 100% under the node's existing
> Dandelion++ logic, unmodified.**

Everything below is the enforcement of that one sentence. On a privacy
chain this is not a guideline; it is the feature's license to exist. A
swarm that optimizes the path a *transaction* takes, or that records which
peer relayed which tx, is a de-anonymization engine — exactly the
"node that records pre-cut-through transactions" that rule **P3.5**
forbids and a direct violation of **P4.1** (never deviate from stem-phase
relay).

### The public/private line, drawn explicitly

| Signal the colony MAY use | Why it's safe |
|---|---|
| Block arrival timing per peer | Blocks are broadcast to everyone; a block reveals no sender |
| Peer liveness / handshake success | Connection state is public by definition |
| Peer-reported tip height/difficulty | Already public via `get_info`; validated, never trusted blindly |
| Peer IP / ASN diversity | Observable to any node; used only to *increase* diversity |

| Signal the colony MUST NEVER touch |
|---|
| Any individual transaction, its hash, size, or timing |
| Which peer a transaction arrived from or was relayed to |
| Mempool / stem-pool contents or ordering |
| Dandelion++ stem routing, epochs, fluff timing, per-edge mapping |
| The node's *own* originated-transaction egress (Dandelion owns this) |

### Per-caste privacy proof

- **Forager ants** score on **block** relay only. Blocks carry no sender
  identity; making block relay faster on some paths leaks nothing about
  who sent what. The forager never sees a transaction — it subscribes only
  to block-arrival events.
- **Scout ants** probe handshakes + public headers. Discovery touches no
  transaction data; a vetted peer is just an address + a valid header.
- **Termite workers** act on **topology** facts (connectivity, tip
  divergence, IP/ASN spread) — all publicly observable — and change only
  *which peers exist*, never *how transactions flow* through them.
- **Colony ops / fleet mode** shares only aggregate public metrics
  (counts, latencies, tip divergence). No per-tx field exists in the
  substrate to leak.

### The critical non-interaction with Dandelion++

Block-relay optimization is safe; transaction-relay optimization is fatal.
The colony's advice applies to **block relay and peer topology only**. The
node's transaction path — stem selection, epoch mapping, fluff probability,
timing — stays entirely inside the existing Dandelion++ implementation and
is **not an input to, nor an output of, the colony.** The colony cannot
"speed up" a transaction; it does not know transactions exist.

Metadata caveat honestly stated: changing peer topology changes *whom a
node is connected to*, which is itself observable. The colony therefore
moves topology toward **more** diversity, never toward a distinctive
fingerprint, and never in response to transaction activity (which would
couple topology to tx timing). Topology changes are driven by block/peer
signals on the colony's own clock, decoupled from any tx event.

## Advisory-only architecture (isolation + safety)

The colony **recommends**; the node **decides**. The sidecar computes
advice from public signals and submits it over a bounded RPC (e.g.
`suggest_peer` / `peer_preference` — additive to the existing
addnode-style surface). The node's peer manager:
- rate-limits and caps how much advice it will act on per epoch,
- keeps its anchor peers regardless of advice,
- validates every suggested peer itself (handshake + PoW header) before
  dialing — never trusts the colony's word (D.4).

Consequences: a buggy or fully-compromised colony can at worst waste some
outbound dials against validated peers; it can never force the node to
drop good peers, accept an invalid peer, or alter consensus/tx behavior.

## Trust and verification model — attacks

- **Pheromone poisoning (Sybil fast-relay):** an attacker floods fast
  blocks to attract pheromone, then eclipses. *Countered by:* evaporation
  (transient advantage decays), the anchor rule (can't evict good peers),
  ≥2-source corroboration for adoption, and the node re-validating every
  peer. Attracting pheromone yields at most a *candidate*, still subject to
  diversity caps.
- **Eclipse-via-healing:** attacker induces a fake "partition" to trigger
  healing toward attacker peers. *Countered by:* healing may only *add*
  diversity from under-represented sources, never drop anchors; total
  advice acted-on per epoch is capped.
- **Scout source poisoning:** one bad DNS/addr source. *Countered by:*
  multi-source corroboration + per-source dominance caps (D.3).
- **Advice-channel DoS:** colony spams suggestions. *Countered by:* the
  node rate-limits/caps the advisory RPC like any other (D.2).
- **Privacy exfiltration via the colony:** *structurally impossible* —
  there is no transaction-derived field anywhere in the pheromone map or
  the advisory RPC to exfiltrate.

## Consensus, DoS, and reorg posture

- **CONSENSUS IMPACT: none.** The colony is an ops/network-advisory layer.
  It never validates blocks, never changes chain selection, never touches
  consensus-locked files. `FORK RISK: none`.
- **DOS SURFACE:** bounded — probing costs are the colony's own; the
  advisory RPC is rate-limited/capped by the node; pheromone state is
  O(peers), tiny. A malicious peer can waste at most one validated dial.
- **REORG BEHAVIOR:** n/a — the colony holds no chain state; tip divergence
  is read-only sensing.
- **PRIVACY IMPACT:** designed to be **none** by the Prime Invariant;
  every caste's proof above is the argument. `CRYPTO REVIEW NEEDED: no`
  (no crypto is authored — reuses `verify_peer_header_pow`).

## Configuration (sketch)

```toml
# /etc/coincync-tick/colony.toml  (loaded by the sidecar; off by default)
[colony]
enabled = false                 # master switch; ships OFF
mode = "advise"                 # "observe" (log only) | "advise" (send RPC)

[forager]
evaporation_half_life_secs = 600
max_relay_preference_peers = 8

[scout]
min_corroborating_sources = 2
max_peers_per_source_pct = 25   # no single source dominates (D.3)

[termite]
partition_divergence_blocks = 100
anchor_peers_protected = true   # never recommend dropping anchors
max_new_dials_per_epoch = 4
```

## Phased implementation plan

- **Phase 0 — this design doc.** No code. Establishes the Prime Invariant
  and the advisory-only boundary for review before anything is built.
- **Phase 1 — pheromone substrate + Forager (observe mode).** Build the
  peer→score map from block-arrival events; `mode = "observe"` logs
  recommendations only, sends nothing. Zero network effect — pure
  measurement, safe on the fleet.
- **Phase 2 — advisory RPC + Forager (advise mode).** Add the bounded,
  rate-limited `peer_preference` RPC; node treats it as one input, keeps
  anchors. Two-node test first (F.5).
- **Phase 3 — Scout ants.** Multi-source discovery with corroboration.
- **Phase 4 — Termite self-healing.** Partition/eclipse sensing +
  diversity-only healing. Most careful phase; adversarial + partition
  tests mandatory (F.1) before any fleet use.
- **Phase 5 — fleet-mode shared substrate** (optional; public aggregates
  only).

Each phase is off by default and independently revertible. RescueTick-style
active intervention (feeding chains) is **out of scope** for the colony —
that stays in `tick`.

## Non-goals

- **Not** a transaction router, mixer, or Dandelion replacement/optimizer.
- **Not** a consensus participant — no voting, no chain selection.
- **Not** a gossip protocol change — it advises the *existing* peer
  manager; it does not add a new wire protocol between nodes (fleet mode
  shares metrics over the operator's own channel, not the P2P network).
- **Not** in-process in the node — isolation is a feature.

## Rejected alternatives

- **Pheromone on transaction propagation** — rejected: de-anonymization
  engine (P3.5). This rejection is the whole reason the design is
  block/topology-only.
- **In-node swarm** — rejected: a swarm bug could wedge consensus; the
  sidecar keeps failure contained.
- **Forced peer re-wiring** — rejected: lets a poisoned colony eclipse the
  node. Advisory + anchors + node-side validation instead.
- **Gossiping the pheromone map over P2P** — rejected: it adds a new
  wire-protocol attack surface and a fingerprint. Each node keeps a local
  map; fleet mode uses the operator's private channel with public
  aggregates only.

## Forking hazards — why correct wiring is load-bearing

This section is honest documentation, not a threat. Its first job is to
protect CoinCync from wiring the colony wrong; its second, incidental job
is to explain why a careless fork of this code breaks *their* chain, not
ours. The moat here is **understanding, not obfuscation** — the code is
public and copyable; the privacy reasoning is what has to be re-derived,
and a team that skips it burns its own users.

The rule everywhere in this document is: **incorrect wiring must fail
loudly at build/test time, never silently at runtime.** A privacy or
consensus break that only manifests in production is unacceptable (a
fragile chain is a dead chain). Each hazard below therefore names the
guard that catches it *before* it ships.

### Hazard 1 — wiring the forager to transactions (the fatal one)

The "obvious optimization" a non-privacy engineer reaches for is to score
peers by **transaction** propagation, not block propagation. Do that and
the pheromone map becomes a **transaction-origin map** — a
de-anonymization engine that traces who-sent-what (violates P3.5, P4.1).
On a privacy chain this is catastrophic and *silent*: the crypto still
works, the chain still runs, and users are being traced with no error.

- **Enforced by construction:** the colony's only inputs are
  `BlockRelayEvent` and `PeerLivenessEvent` types. **There is no code path
  from a transaction to a pheromone deposit** — feeding one requires adding
  a new input type, a visible, reviewable change.
- **Enforced by test:** a privacy test asserts the forager subscribes to
  block/peer events only and that no colony type carries a tx-derived
  field (F.8). Wire a tx in → the test goes red → CI (branch protection)
  blocks the merge. The break is loud, at build time, and never reaches a
  user. A fork that deletes this test to "make it compile" is deleting the
  thing that was keeping their users safe.

### Hazard 2 — removing advisory-only (letting the colony act directly)

If a fork lets the colony *force* peer re-wiring instead of *advising* the
node, a poisoned colony can eclipse the node (isolate it, feed it a false
chain). *Guard:* the node validates every suggested peer itself and keeps
its anchors; the colony has no direct socket authority. Removing that
indirection is a conspicuous architectural change, not an accident.

### Hazard 3 — dropping the anchor rule

If "healing" is allowed to evict long-lived anchor peers, an attacker
induces a fake partition to force connections onto attacker peers
(eclipse-via-healing). *Guard:* healing may only *add* diversity, capped
per epoch; anchors are protected. Tested with a partition/eclipse
adversarial suite (F.1) before any fleet use.

### Hazard 4 — gossiping the pheromone map over P2P

Broadcasting the map turns a local optimization into a new wire protocol —
extra attack surface and a fingerprint. *Guard:* each node keeps a
**local** map; fleet mode shares only public aggregates over the
operator's private channel, never the P2P network.

### Why this is a durable, honest moat

A fork can copy the four castes in an afternoon. To run them safely they
must reproduce, for *their* stack: the type-level tx/colony separation, the
privacy test suite that enforces it, the advisory boundary, the anchor
rule, and the adversarial partition tests — i.e. the entire correctness
apparatus this document specifies. Skip any of it and the failure is
either **loud** (their CI breaks, if they kept the guards) or **their
users' privacy** (if they didn't). Neither outcome touches CoinCync. The
defensibility is that privacy-safe swarm networking is *hard to get right*,
this document is the map, and the map is the work.

## References

- [`tick`](tick.md) — the agent framework this extends.
- Dorigo & Stützle, *Ant Colony Optimization* (2004) — foraging/pheromone.
- Grassé (1959) — *stigmergy* (termite coordination via the environment).
- CoinCync AI Development Rules — D.3 (eclipse/Sybil), P3.5 / P4.1
  (transaction-propagation privacy), C.2 (metadata), G.2 (no crypto churn).
