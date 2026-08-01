# The Colony — biomimetic swarm agents

Emergent, no-central-controller **network resilience and metadata privacy**,
built from many small agents ("castes") that each imitate one insect's survival
trick. The colony is hosted by the `coincync-tick` sidecar and is
**advisory-only** and **non-consensus** — it never signs, orders, or validates a
block, and **cannot alter consensus validity**.

For the full design see [`docs/architecture/biomimetic.md`](../../docs/architecture/biomimetic.md)
(the umbrella) and [`docs/architecture/colony.md`](../../docs/architecture/colony.md).
This README is the map; those are the territory.

---

## Prime Privacy Invariant (read this first)

> **Every caste forages only on _public_ signals** — block relay, chain tip,
> peer liveness, connection/topology shape. The colony **cannot** observe,
> score, or route an individual transaction or any stem-phase (Dandelion++)
> traffic — a boundary that must be **enforced at the module and capability
> level**, not left to convention. Transaction propagation stays 100% under the
> node's own Dandelion++ logic.

This rests on enforced boundaries, not a promise. The colony module is only ever
handed public-signal types — `ChainTipState` / `AggregateFleetHealth` (heights,
tip ages, peer counts, difficulty) — and **no capability or handle to transaction
or stem-phase data crosses into the module**, so a caste has nothing to score
transaction activity *with*, even if its code tried. The invariant holds exactly
as long as those two boundaries are kept enforced: module isolation of the caste
code, and the absence of any tx/stem capability in the types it receives. Treat
weakening either as a defense regression (B.3).

---

## The castes

Grouped by what they do. **Status** is honest: most castes are implemented as
**pure decision cores** (deterministic, unit-tested functions) whose *act/advise*
wiring into the sidecar is designed but not fully built. Only `forager` and
`sensor` run today, in **observe mode** (measure + log, change nothing).

### 🕸️ Sensing — feel the shape of the traffic

| Caste | Insect trick | What it senses | Rule | Status |
|---|---|---|---|---|
| [`spider`](spider.rs) | reads web vibrations, doesn't chase | inbound-rate, netgroup concentration, dup-churn → **eclipse / flood / partition** signatures | D.2, D.3 | pure core |
| [`sensor`](sensor.rs) | spider/termite sensory layer | classifies `AggregateFleetHealth` (tip divergence, stalled hosts) into a coarse network state | — | **observe** |
| [`forager`](forager.rs) | ant colony optimization | scores peers by block-relay quality + tip freshness | — | **observe (live-safe)** |
| [`pheromone`](pheromone.rs) | ACO trail map | peer→score table: deposit on good relayers, **evaporate** each round so scores track *now* | B.2 | infrastructure |

### 🐜 Defense — make abuse expensive

| Caste | Insect trick | What it does | Rule | Status |
|---|---|---|---|---|
| [`mantis`](mantis.rs) | motionless *hold* | **tarpits** misbehaving peers on an escalating slow-hold instead of a fast drop (drop just says "rotate IP and retry") | D.2 | pure core |
| [`army_ant`](army_ant.rs) | link bodies into a living bridge | on suspected partition, picks **netgroup-diverse, recently-seen** bridge peers to re-span the split without re-eclipsing | D.3 | pure core |

### 🐛 Relay resilience — keep blocks moving

| Caste | Insect trick | What it does | Rule | Status |
|---|---|---|---|---|
| [`centipede`](centipede.rs) | keeps moving on many legs | relays each block over **several netgroup-diverse legs** so it survives slow/dead/adversarial paths (**blocks only, never txs**) | D.2, D.3 | pure core |
| [`locust`](locust.rs) | solitary ↔ gregarious phase switch | density-adaptive relay: calm when quiet, **swarm-relay** under attack/partition, with **hysteresis** so the mode can't flap | D.4 | pure core |

### 🦗 Privacy camouflage — look like everyone else

| Caste | Insect trick | What it does | Rule | Status |
|---|---|---|---|---|
| [`cicada`](cicada.rs) | emerge on **prime** cycles (13/17) so no predator phase-locks | spaces periodic housekeeping (cover bursts, churn, rescans) on **prime-varied** intervals — no single period to lock onto (**never** tx/stem timing) | C.2 | pure core |
| [`firefly`](firefly.rs) | flash in unison (Mirollo–Strogatz pulse coupling) | synchronizes network-wide **cover traffic** under an explicit **bandwidth cap** so a real tx hides inside a global flash; coupling is **bounded** and attacker pulses **rate-limited**, so a pulse flood can neither drive nor amplify our flash timing | C.6, D.2 | pure core |
| [`stick_insect`](stick_insect.rs) | look exactly like every other twig | snaps **wire fingerprint** — user-agent, version banner, message sizes — to one canonical form so every node presents a **canonical observable envelope** | C.6 | pure core |

> **Note:** `stick_insect`'s size-bucket logic is the model for the wire
> size-normalization in **PR #20**, which canonicalizes the observable size of
> **every post-handshake P2P message and Noise record** — not only transactions.
> See `src/network/traffic_shaping.rs` / `src/network/framing.rs`.

---

## Roadmap (honest)

- **Phase 1 — Observe (today):** `forager` + `sensor` measure public signals and
  log rankings/state. They send nothing and change no node behavior — safe to run
  on the live fleet.
- **Phase 2 — Advise:** castes surface recommendations (bridge peers, relay legs,
  tarpit holds) to the node, which stays the sole actor.
- **Phase 3 — Act / heal:** termite-style self-healing acts on spider/sensor
  signatures. Designed, not built. **Any** Act-phase behavior is gated on hard
  guards before it may change node behavior: **diversity floors** (never collapse
  peer/netgroup diversity below a minimum), per-action **rate limits**, a global
  **kill switch**, and **untrusted-telemetry handling** — every peer-supplied
  signal is treated as adversarial input, never trusted at face value.

The pure decision cores for the act-phase castes exist and are tested; the
sidecar wiring that would let them *act* is deliberately gated behind the phases
above so nothing advisory can ever become load-bearing before it's proven.

---

## Invariants every caste keeps

- **Non-consensus.** Advisory only; the node and its consensus rules are always
  the sole authority. A colony bug degrades *margin*, never *validity*.
- **Public signals only.** See the Prime Privacy Invariant above.
- **Deterministic cores (B.2).** Integer/fixed-point, ordered maps, tie-broken by
  key — no float non-determinism; the sidecar layers any CSPRNG jitter on top.
- **Never weaken a defense (B.3).** A caste may add margin; it may not remove an
  existing guarantee.

## Design-rule legend

| Rule | Meaning |
|---|---|
| B.2 | Determinism |
| B.3 | Never weaken an existing defense |
| C.2 | Metadata / timing minimization |
| C.6 | Uniformity is anonymity |
| C.10 | Anonymity-set preservation |
| D.2 | DoS asymmetry (cheap for us, costly for the attacker) |
| D.3 | Eclipse / Sybil resistance (netgroup diversity) |
| D.4 | Hysteresis — no threshold flapping |

## Further reading

- [`docs/architecture/biomimetic.md`](../../docs/architecture/biomimetic.md) — the umbrella model
- [`docs/architecture/colony.md`](../../docs/architecture/colony.md) — the colony in depth
- Per-caste deep dives live in `docs/architecture/caste-*.md` (e.g. `caste-centipede.md`, `caste-firefly.md`).
