# firefly — synchronized cover traffic

> Status: **DESIGN (Phase 0)** — deep-dive for the `firefly` caste of the
> [biomimetic suite](biomimetic.md). No code. Privacy caste.
>
> One-line: nodes synchronize the *timing* of their cover traffic — like
> fireflies flashing in unison — so cover pulses across the network are
> correlated, drowning the inter-node timing correlation a global observer
> uses to trace a transaction's propagation path. It syncs **cover/gossip
> timing only, never block time and never real-transaction timing.**

## The problem: timing correlation on a privacy chain

Cryptography hides *contents*; it does not hide *timing*. A global passive
adversary (someone watching many nodes' network links) doesn't need to
break encryption — they watch the clock:

- **Path-timing correlation:** "a message left A at T, arrived at B at
  T+ε, left B at T+2ε." Chained, this walks a transaction back toward its
  origin even through Dandelion's fluff phase.
- **Per-node jitter is weak against this.** If each node independently
  randomizes its send times, the adversary still sees *uncorrelated* noise
  and can average it out across many observations. Independent randomness
  is exactly what statistics is good at defeating.

Fireflies solve the biological version of this: thousands of them flash on
their own useless rhythm until they **couple** into one synchronized
flash — emergent, no conductor.

## The mechanism: pulse-coupled oscillators (decentralized sync)

Each node runs a phase oscillator (Mirollo–Strogatz / Kuramoto model).
When a node's phase completes a cycle it **fires**: emits a cover pulse
(indistinguishable padding traffic, `MessageType::Padding`, already used by
traffic shaping). When a node *observes* peers' pulses, it nudges its own
phase slightly toward them. With even weak coupling the network converges
to firing **in unison** — no central clock, no coordinator, no consensus.

Why synchronization is the point: once cover pulses are network-wide
**correlated**, path-timing correlation drowns. The adversary sees every
node emit at once; "A emitted then B emitted" carries no information when
*everyone* emitted. Real messages riding the synchronized carrier inherit
its anonymity. This is the crowd-timing complement to Dandelion's
crowd-routing.

## The hard invariant (I1 + I2): what firefly must NEVER couple to

> The oscillator drives **cover-traffic and gossip-round timing only.** It
> **never** influences block timestamps, difficulty, validation, or chain
> selection (I1), and it **never delays, reschedules, or observes a real
> transaction** (I2). Real transaction egress stays 100% under Dandelion++.

Two ways to get this fatally wrong, both forbidden:

1. **Coupling consensus time to the oscillator.** Block timestamps are a
   consensus input with their own rules (median-time-past, future limit).
   The firefly phase is a *local, non-consensus* signal; nodes disagreeing
   on phase must have **zero** consensus effect. Wire the oscillator into
   `block.timestamp` and you have a non-deterministic consensus input
   (B.2) — a fork. Firefly never touches it.
2. **Rescheduling real transactions onto the pulse.** Tempting ("send real
   txs at pulse time so they blend"), but delaying a real tx to align with
   the clock **couples that tx's timing to the firefly phase** — now the
   phase is a *signal about the transaction*, observable, and a
   deanonymization vector. Firefly only ever adds **cover**; real traffic
   flows on Dandelion's schedule, untouched. Real txs blend in *if they
   happen to coincide*, but are never *made* to coincide.

The correct picture: firefly raises the network-wide cover floor in a
correlated way. Dandelion decides when/where real transactions go. The two
never share a clock.

## Privacy analysis (honest)

**Protects against:** a global passive adversary doing *path-timing
correlation* across the fluff phase and general relay. Synchronized cover
injects network-correlated noise that this attack cannot average away.

**Does not protect against (stated plainly, per Standing Principle):**
- A **global active** adversary who can drop/delay links to create timing
  gaps — firefly raises cost, not immunity.
- **Origin** protection at the stem — that is Dandelion's job; firefly is
  complementary, not a replacement (P4.1 untouched).
- An adversary with a **node inside** the pulse group still learns only
  public pulse timing, never transaction contents or the tx schedule.

Firefly is a **cost-raiser against traffic analysis**, documented as such —
not a claim of unlinkability. Overclaiming here would violate the Standing
Principle (privacy claims must be provable).

## Bandwidth is a real, honest cost (C.9)

Cover traffic consumes bandwidth, and *synchronized* cover risks a
thundering-herd spike (all nodes pulsing at once). This is a genuine
privacy-for-bandwidth trade and must be **opt-in and bounded**:
- pulse payload size capped; total cover bandwidth rate-limited per node,
- pulses jittered within a small window around the sync point (keeps
  correlation while smoothing the spike),
- on a small/young network (e.g. a 6-node testnet) the anonymity-set
  benefit is limited — firefly ships **off by default** and is most
  valuable as the network grows (anonymity-set awareness, C.10).

## DoS and attack analysis

- **Desync attack** (adversary disrupts coupling): worst case the network
  falls back to *per-node* cover jitter — still safe, just weaker. Sync is
  a bonus, never a dependency.
- **Phase poisoning** (adversary floods fake pulses to drag the phase):
  coupling per observed pulse is capped and the phase update is bounded, so
  a flood shifts phase slowly at most; pulse sources are rate-limited like
  any peer message (D.2). No node's real traffic is ever tied to phase, so
  a shifted phase leaks nothing.
- **Cover-as-DoS** (amplification): cover volume is hard-capped per node
  regardless of pulses; firefly can never be driven to exceed the operator's
  configured bandwidth ceiling.

## Consensus & reorg posture

`CONSENSUS IMPACT: none` — the oscillator is a local non-consensus timer;
`FORK RISK: none`. `REORG BEHAVIOR: n/a` — holds no chain state.
`CRYPTO REVIEW NEEDED: no` — no crypto authored (cover payloads reuse the
existing `MessageType::Padding` path).

## Configuration (sketch)

```toml
# /etc/coincync-tick/firefly.toml  (or node config); ships OFF
[firefly]
enabled = false
mode = "observe"              # observe | jitter | sync
cover_bandwidth_kbps_max = 32 # hard ceiling per node
pulse_window_ms = 250         # jitter window around the sync point
coupling_strength = 0.05      # weak coupling; slow, poison-resistant
max_phase_nudge_per_pulse = 0.02
```

## Phased plan

- **Phase 0 — this doc.** Establishes the never-couple-to-consensus/tx
  invariant for review.
- **Phase 1 — observe.** Measure real inter-node timing correlation on the
  fleet; emit *no* cover. Pure measurement; quantifies whether firefly
  helps *this* network before spending bandwidth.
- **Phase 2 — per-node jitter.** Independent cover jitter (no coupling).
  Safe baseline; establishes the cover-traffic path + bandwidth caps.
- **Phase 3 — pulse-coupled sync.** Add coupling; verify convergence and
  that real-tx timing is provably decoupled (test asserts no code path
  from a transaction to the oscillator).
- **Phase 4 — tuning** on a grown network where the anonymity set makes it
  worthwhile.

Each phase off by default, independently revertible; adversarial
timing-analysis tests before any mainnet use (F.8).

## Forking hazards — why correct wiring is load-bearing

Same doctrine as [colony](colony.md): incorrect wiring must fail loudly at
build/test time, never silently break privacy or consensus at runtime.

- **Hazard 1 — oscillator → `block.timestamp` (consensus fork).** Makes a
  non-deterministic value a consensus input (B.2). *Guard:* the oscillator
  type is confined to the sidecar/traffic layer; it has **no path** to the
  block builder or validator; a consensus-determinism test rejects any
  non-deterministic timestamp input. Wrong wire → CI red.
- **Hazard 2 — oscillator → real-tx scheduling (deanonymization).** Delays
  real txs onto the pulse, coupling tx timing to a public signal. *Guard:*
  the firefly emitter only produces `Padding`; there is **no code path**
  from the mempool/tx egress to the oscillator; a privacy test asserts real
  transaction send-timing is independent of firefly phase. Wrong wire → CI
  red, before any user is de-anonymized.
- **Hazard 3 — unbounded cover (self-DoS / bandwidth blowout).** *Guard:*
  the per-node bandwidth ceiling is enforced below the pulse logic; sync
  can never raise total cover above it.

The moat, honestly: decentralized-sync cover traffic that is provably
decoupled from both consensus time and transaction time is *hard to get
right on a privacy chain*. A fork that lifts the code without reproducing
the decoupling guards either fails loudly (kept the tests) or de-anonymizes
its own users (dropped them). Neither touches CoinCync.

## Non-goals

- **Not** a Dandelion replacement — complementary; stem routing untouched.
- **Not** a consensus clock — never influences block time or ordering.
- **Not** a transaction scheduler — it emits cover, never moves real txs.
- **Not** valuable on a tiny network — honest about anonymity-set limits;
  off by default until the crowd is large enough to hide in.

## References

- Mirollo & Strogatz (1990) — *Synchronization of pulse-coupled biological
  oscillators.*
- Kuramoto (1975) — coupled-oscillator model.
- [biomimetic suite](biomimetic.md), [colony](colony.md).
- CoinCync AI Development Rules — B.2 (determinism), C.2 (metadata), C.9
  (privacy/perf trades), C.10 (anonymity set), P4 (network-layer privacy),
  D.2 (DoS).
