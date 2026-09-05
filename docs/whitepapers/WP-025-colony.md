# WP-025 · The Colony
### Biomimetic network resilience, bounded by an enforced privacy invariant

**Status:** Shipped (non-consensus) — **2 castes live in observe mode; 9 are pure
decision cores, unwired** · **Layer:** Sidecar / Advisory · **Series:**
[CoinCync Whitepapers](README.md)

---

## 1. Motivation

Network-layer defenses in most chains are a pile of independent heuristics: a ban
score here, a peer rotation there, a rate limit somewhere else. Each is written
for one attack, tuned by hand, and interacts with the others in ways nobody has
modelled.

Insects solve the same class of problem — foraging under uncertainty, defending
without a commander, staying unremarkable to predators — with many small agents
following simple local rules and no central controller. The colony is an attempt
to organise CoinCync's network resilience the same way: a set of small,
independently testable **castes**, each imitating one survival trick.

The design constraint that makes this safe rather than reckless is that a swarm of
autonomous agents adjusting a privacy network's behaviour is an *enormous* attack
surface. Most of this paper is about the boundaries drawn to contain it.

---

## 2. Threat addressed

| Attack | Assumption it needs | What we removed |
|---|---|---|
| **Eclipse / flood / partition** | Attack patterns are invisible without central analysis | `spider` classifies inbound-rate, netgroup concentration, and dup-churn signatures locally |
| **Drop-and-retry churn** — a banned peer rotates IP and reconnects immediately | Disconnecting is the strongest response | `mantis` **tarpits** on an escalating slow-hold; a fast drop just says "rotate IP and retry" |
| **Re-eclipse during partition repair** | Any reachable peer is a good bridge | `army_ant` picks **netgroup-diverse, recently-seen** bridge peers |
| **Single-path block suppression** | One relay path is enough | `centipede` relays each block over several netgroup-diverse legs (**blocks only, never transactions**) |
| **Relay-mode flapping** under oscillating load | A threshold is enough | `locust` phase-switches with **hysteresis** |
| **Periodic-housekeeping phase-lock** | A fixed housekeeping interval is harmless | `cicada` spaces housekeeping on **prime-varied** intervals (13/17), so nothing can phase-lock |
| **Cover traffic that hides nothing** | Uncoordinated padding suffices | `firefly` synchronises network-wide cover bursts under a bandwidth cap, so a real transaction hides inside a global flash |
| **Wire fingerprinting** | Node identity strings are harmless | `stick_insect` snaps user-agent, banner, and sizes to one canonical form (WP-011) |
| **The colony itself becoming a deanonymisation oracle** | An advisory agent can be trusted with transaction data | **Capability-level exclusion — see §3** |

---

## 3. The Prime Privacy Invariant

This is the load-bearing part of the design, and it comes before the castes.

> Every caste forages only on **public** signals — block relay, chain tip, peer
> liveness, connection and topology shape. The colony **cannot** observe, score,
> or route an individual transaction or any stem-phase (Dandelion++) traffic.
> Transaction propagation stays entirely under the node's own Dandelion++ logic.

A swarm that could see transactions would be the single best deanonymisation tool
on the network: it observes peer behaviour continuously, correlates across the
fleet, and adapts. Whatever the intent, the capability would exist.

**It rests on enforced boundaries, not a promise.** The colony module is only ever
handed public-signal types — `ChainTipState` and `AggregateFleetHealth` (heights,
tip ages, peer counts, difficulty) — and **no capability or handle to transaction
or stem-phase data crosses into the module**. A caste has nothing to score
transaction activity *with*, even if its code tried.

The invariant holds exactly as long as two boundaries are kept: **module isolation**
of the caste code, and **the absence of any tx/stem capability in the types it
receives**. Weakening either is a defense regression, not a refactor.

This phrasing is deliberate and was tightened after review. "The colony does not
look at transactions" is a behavioural claim about current code. "The colony is
handed no capability with which to look at transactions" is a structural claim
that survives someone changing the code carelessly. **Prefer structural claims;
they are the ones that stay true.**

The second structural boundary: the colony is **advisory-only and non-consensus**.
It never signs, orders, or validates a block, and **cannot alter consensus
validity**. It runs in the `coincync-tick` sidecar, not in the node's consensus
path.

---

## 4. Design

### 4.1 Castes

Eleven castes across four functions. Each imitates one insect trick, and each is
built as a **pure decision core**: a deterministic, unit-tested function over
public-signal inputs.

**Sensing** — `spider` (attack-signature classification), `sensor` (fleet-health
state), `forager` (peer scoring by relay quality and tip freshness), `pheromone`
(the ant-colony-optimisation trail map: deposit on good relayers, **evaporate**
each round so scores track *now* rather than accumulating history).

**Defense** — `mantis` (escalating tarpit), `army_ant` (diverse bridge selection
on suspected partition).

**Relay resilience** — `centipede` (multi-leg netgroup-diverse block relay),
`locust` (density-adaptive relay with hysteresis).

**Privacy camouflage** — `cicada` (prime-varied housekeeping intervals),
`firefly` (synchronised cover flashes, bounded coupling, attacker pulses
rate-limited so a pulse flood can neither drive nor amplify our timing),
`stick_insect` (canonical wire fingerprint).

`stick_insect`'s size-bucket ladder is the model for the live wire normalisation
in `traffic_shaping.rs` / `framing.rs` (WP-011 §3.4, WP-012 §3.2) — the caste
holds the *policy* as one audited definition; the network layer does the sending.

### 4.2 Honest status

| Phase | State |
|---|---|
| **Phase 1 — Observe** | **Live today.** `forager` and `sensor` measure public signals and log rankings and state. They send nothing and change no node behaviour — safe on the live fleet. |
| **Phase 2 — Advise** | Castes surface recommendations (bridge peers, relay legs, tarpit holds); the node remains the sole actor. Not built. |
| **Phase 3 — Act / heal** | Self-healing acts on sensor signatures. **Designed, not built.** |

The pure decision cores for the act-phase castes exist and are tested. The sidecar
wiring that would let them *act* is deliberately gated. **Nine of eleven castes
change nothing on a live network today**, and this paper says so rather than
describing designed behaviour in the present tense.

### 4.3 Act-phase guards, specified in advance

Any Act-phase behaviour is gated on four hard guards before it may change node
behaviour:

- **Diversity floors** — never collapse peer or netgroup diversity below a
  minimum. An autonomous agent optimising for relay quality would otherwise
  converge on a small set of "best" peers, which is a self-inflicted eclipse.
- **Per-action rate limits** — bound how fast the colony can change anything.
- **A global kill switch** — an operator must be able to stop it.
- **Untrusted-telemetry handling** — every peer-supplied signal is treated as
  adversarial input, never trusted at face value. Otherwise an attacker feeds the
  colony the observations that make it act against its own network.

Specifying these *before* building the act phase is the point. Guards retrofitted
onto an autonomous system are guards designed around what was already built.

---

## 5. Security analysis

**What holds.** The colony cannot affect consensus, and cannot observe transaction
or stem-phase traffic — both by structure rather than by policy. The two live
castes only measure and log.

**What this does not protect against.**

- **The invariant is only as strong as its two boundaries** (§3). No test
  currently *fails* if someone passes a transaction-bearing type into the module;
  the boundary is maintained by review. Making it a compile-time capability check
  would be strictly better.
- **Observe mode still consumes resources** and still derives information, even if
  it acts on none of it. Logged rankings are a local artifact worth thinking about
  in a forensic-seizure threat model.
- **Act phase is unanalysed in practice.** The guards in §4.3 are specified, not
  implemented or tested. An autonomous network-adaptation system is a genuinely
  hard safety problem and nothing here should be read as claiming it is solved.
- **Biomimetic framing is an organising metaphor, not evidence.** That a mechanism
  resembles an insect behaviour says nothing about whether it works against an
  adversary. Each caste's rule must stand on its own analysis; the metaphor is how
  the code is organised, not why it is correct.
- **Advisory signals could still be gamed** once wired, which is exactly what the
  untrusted-telemetry guard is for.

---

## 6. Implementation

| Component | Location |
|---|---|
| Caste modules (11) | `src/colony/*.rs` |
| Map and honest status table | `src/colony/README.md` |
| Full design | `docs/architecture/biomimetic.md`, `docs/architecture/colony.md` |
| Host sidecar | `src/bin/coincync-tick.rs`, `src/tick_adapter/` |
| Live wire normalisation derived from `stick_insect` | `src/network/traffic_shaping.rs`, `src/network/framing.rs` |

---

## 7. Known limits

- Nine of eleven castes are unwired decision cores (§4.2).
- The privacy invariant's boundaries are review-enforced, not compiler-enforced
  (§5).
- Act-phase guards are specified but unbuilt.
- No adversarial evaluation of any caste's rule against a live attacker.
- Advisory value is currently unmeasured — we do not know how much the observe-mode
  signals would improve decisions if acted upon.

---

## 8. References

- Dorigo et al. — ant colony optimisation, the basis for `pheromone` / `forager`.
- Mirollo & Strogatz (1990) — pulse-coupled oscillator synchronisation, the basis
  for `firefly`.
- Heilman et al. (2015) — eclipse attacks, the threat `spider` and `army_ant`
  target (see WP-022).
- Internal: [WP-011 Uniformity](WP-011-transaction-uniformity.md),
  [WP-012 Traffic shaping](WP-012-traffic-shaping.md),
  [WP-020 Dandelion++](WP-020-dandelion.md),
  [WP-022 Peer eviction](WP-022-relative-peer-eviction.md).
