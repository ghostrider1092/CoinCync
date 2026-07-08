# The Insectarium — CoinCync's biomimetic resilience suite

> Status: **DESIGN (Phase 0)** — umbrella architecture. Catalogs every
> biomimetic caste, the invariants that bind them, and how they compose.
> Deep-dive docs live per caste ([`tick`](tick.md), [`colony`](colony.md),
> and the standalone castes below as they are written).

## Why biomimicry (thesis)

Insect colonies survive with **no central controller, on cheap local
rules, under constant damage.** That is precisely the operating condition
of a decentralized privacy chain's network layer: no coordinator, hostile
environment, nodes joining and dying. CoinCync borrows the *strategies*
evolution already tuned — foraging, stigmergy, synchronization,
redundancy, ambush — and maps each to a real network/ops/privacy job.

This is an identity **and** a moat. The moat is not the metaphor (anyone
can name a module "ant"); it is that each caste is **privacy-safe by
construction on a chain where that is hard**, proven per-caste, and wired
so that copying the code without the reasoning breaks the copier's chain,
not ours (see each caste's *forking hazards*). Privacy claims are stated as
invariants with proofs, never as slogans (Standing Principle).

## The five shared invariants (bind EVERY caste)

These are load-bearing. A caste that violates one is not a CoinCync caste.

- **I1 — Non-consensus.** No caste changes block validation, chain
  selection, difficulty, emission, serialization, or **consensus
  timestamps**. Anything time-based (Firefly) drives only non-consensus
  timing — cover traffic, gossip rounds — never block time (B.2
  determinism). `FORK RISK: none` for the entire suite.
- **I2 — No transaction observation.** No caste observes, records, scores,
  times, or routes an individual transaction or stem-phase traffic. Every
  caste that touches the network operates on **public signals only**
  (blocks, topology, peer liveness). Transaction propagation stays 100%
  inside the existing Dandelion++ logic (P3.5, P4.1, C.2).
- **I3 — Advisory + isolated.** Castes run in the `coincync-tick` sidecar
  (separate process — a caste bug cannot wedge the node) and **advise**;
  the node's peer/relay manager decides, validates, rate-limits, and keeps
  its anchors. No caste has direct authority over consensus or sockets.
- **I4 — Fail loud, at build/test time.** Incorrect wiring must break the
  build or a test, never silently break the chain at runtime. Each caste's
  privacy/consensus invariant is enforced by type separation + tests + CI
  (branch protection), so a wrong wire is caught before it ships.
- **I5 — Off by default, phased, revertible.** Every caste ships disabled,
  activates in staged phases (observe → advise → act), each phase
  independently revertible, none reaching mainnet unproven (H.3).

If a proposed caste can't satisfy all five, it is marketing, not a
feature, and does not get built.

## The catalog

Legend — **Layer**: Priv(acy) · Net-def(ense) · Resil(ience) · Ops.
**Form**: standalone caste, or a *mode* of another.

### Existing / designed

- **🪳 tick** — *lone parasitic agents.* Quest→Latch→Feed. RescueTick
  (chain recovery), HealthTick (read-only monitoring, shipped as the
  `coincync-tick` sidecar), PropagationTick. Layer: Resil/Ops.
  Doc: [`tick`](tick.md).
- **🐜 colony** — *ant/termite swarm.* Forager ants (block-relay path
  **scoring** — efficiency), scout ants (multi-source peer discovery),
  termite workers (self-healing mesh). Layer: Net-def/Resil.
  Doc: [`colony`](colony.md). PR #207.

### Privacy caste (CoinCync's core edge)

- **🔦 firefly** — *synchronized cover traffic.* Pulse-coupled oscillators
  (Kuramoto) sync the *timing* of cover/dummy traffic so it pulses
  network-wide in unison — cover that blends globally defeats timing
  correlation far better than per-node jitter. Extends traffic shaping.
  **I1 is the sharp edge:** syncs cover-traffic/gossip timing, **never
  block time.** Layer: Priv. *Form: standalone.*
- **🦗 cicada** — *prime-interval anti-correlation scheduling.* Prime/quasi
  cycles (13/17-yr emergence) so predators can't lock the rhythm. Schedules
  churn, key rotation, rebroadcast on unpredictable intervals so observers
  can't correlate them. Hardens auto-churn. Layer: Priv. *Form: standalone.*
- **🥢 stick-insect** — *protocol camouflage.* Mimicry. Normalizes wire
  fingerprint (user-agent, sizes, timing quirks) so every node looks
  identical — uniformity is anonymity (C.6). Layer: Priv.
  *Form: mode of traffic shaping.*

### Network-defense caste

- **🦎 mantis** — *tarpit ambush.* Ambush predator. Detects a misbehaving
  peer and slows it to a crawl, burning attacker resources instead of a
  clean ban. Turns DoS attempts into wasted attacker effort. Must be
  ban-consistent (D.5): only proven-malice peers are tarpitted, never
  honest slow ones. Layer: Net-def. *Form: standalone.*
- **🕷️ spider** — *sentinel web.* Reads "vibrations": sentinel connections
  sense attack signatures (eclipse pressure, partition onset, flood
  patterns) and feed the colony's termite-healing. Layer: Net-def
  (detection). *Form: mode of colony (its sensory organ).*

### Resilience caste

- **🐛 centipede** — *multipath redundant propagation.* Many legs; lose
  some and keep moving. Sends **blocks** along multiple independent paths
  at once, so a censoring/partitioning adversary can't stop propagation by
  killing one path. The **complement** to ants: ants optimize the single
  fastest path (efficiency); the centipede uses many paths (redundancy).
  **I2 is the sharp edge:** multipath applies to **blocks only** — multipath
  on a *transaction* would shatter Dandelion's single-stem design (P4.1).
  Layer: Resil/anti-censorship. *Form: standalone.*
- **🦗 locust** — *density-adaptive mode.* Solitary↔gregarious by crowding.
  A node shifts relay aggressiveness by load/attack density — conservative
  when calm, aggressive swarm-relay under congestion/attack. Layer: Resil.
  *Form: standalone (or a mode toggle shared across castes).*
- **🐜 army-ant** — *living-bridge partition recovery.* Self-assembles a
  relay path across a split. Layer: Resil. *Form: mode of colony (termite)
  healing — not standalone.*

## How the suite composes (sensing → deciding → acting)

The castes are not a pile of gadgets; they form a control loop:

1. **Sense** — HealthTick + spider read public network state (health, tip
   divergence, attack signatures).
2. **Decide** — colony (ants/termites) turns signals into peer/relay advice;
   locust picks the aggressiveness mode.
3. **Act (advisory)** — the node applies vetted advice: prefer fast peers
   (ant), keep redundant paths (centipede), heal diversity (termite),
   tarpit attackers (mantis).
4. **Protect** — firefly, cicada, stick-insect run continuously underneath,
   keeping the *timing and shape* of all this traffic non-correlatable.

Efficiency (ant) and redundancy (centipede) are a deliberate pair; sensing
(spider) and healing (termite) are a pair; the privacy castes are the
substrate everything else runs on top of.

## Roadmap

- **Shipped:** tick (HealthTick sidecar), colony (#207).
- **Built (pure cores + observe-mode wiring in `coincync-tick --castes-observe`):**
  all eight standalone castes — [cicada](caste-cicada.md),
  [mantis](caste-mantis.md), [firefly](caste-firefly.md),
  [centipede](caste-centipede.md), [stick-insect](caste-stick-insect.md),
  [spider](caste-spider.md), [locust](caste-locust.md),
  [army-ant](caste-army-ant.md). Each has its own design doc + unit tests.
  spider/locust/centipede/army-ant are driven by real adapter signals in
  observe mode; mantis/firefly are armed pending a node-adapter feed.
- Implementation of any caste follows I5: observe → advise → act, off by
  default, two-node + adversarial tests before fleet, never to mainnet
  unproven.

## Non-goals & honest limits

- **Not** consensus. The suite is an ops/network/privacy layer; it never
  touches the consensus-locked files or monetary policy.
- **Not** a transaction system. No caste sees transactions; Dandelion++ is
  untouched by all of them.
- **Not** naming for naming's sake. A caste that can't satisfy the five
  invariants and do a real job is cut. Overclaiming any of these as a
  privacy guarantee without its proof is forbidden — the proofs live in the
  per-caste docs, and a caste without one stays in "observe" mode only.

## References

- [`tick`](tick.md), [`colony`](colony.md) — the two anchor docs.
- Kuramoto (1975) — coupled-oscillator synchronization (firefly).
- Dorigo & Stützle (2004) — Ant Colony Optimization (colony).
- Grassé (1959) — stigmergy (termite/colony).
- CoinCync AI Development Rules — B.2 (determinism), C.2/C.6 (metadata,
  uniformity), D.2/D.3/D.5 (DoS, eclipse, ban consistency), P3.5/P4.1
  (transaction-propagation privacy), H.3 (testnet-before-mainnet).
