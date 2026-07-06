# centipede — multipath redundant block propagation

> Status: **DESIGN (Phase 0)** — deep-dive for the `centipede` caste of the
> [biomimetic suite](biomimetic.md). No code. Resilience / anti-censorship.
>
> One-line: a centipede has many legs and keeps moving if it loses some. The
> centipede caste relays each **block** along multiple independent paths at
> once, so a censoring or partitioning adversary can't stop propagation by
> killing one path. **Blocks only — never transactions.**

## The problem: single-path relay is fragile

Efficient relay tends toward a *single* fast path (that's what the
[forager](colony.md) ant optimizes). But a single path is a single point of
failure against an *adversary*:

- **Censorship:** a peer (or a small set) that silently drops a specific
  block can stall its propagation to everything downstream of them.
- **Partition:** if the one fast route crosses a link that goes down, the
  block stops at the gap.
- **Eclipse-adjacent:** a node whose few relay paths all lead through
  attacker-influenced peers can be fed a stalled or selective view.

Efficiency and resilience pull in opposite directions. The ant gives us the
first; the centipede gives us the second, and they compose.

## The mechanism: many legs, coordinated

For each block the node relays, the centipede sends it over **N independent
legs** — N distinct peers chosen to be *diverse* (different peers, ideally
different IP ranges / ASNs / relay directions), not just the single fastest.
Losing legs (dropped, slow, partitioned) does not stop the block: the other
legs carry it. Redundancy, not speed, is the goal.

**Metachronal coordination (the leg-wave).** Real centipedes move their legs
in a staggered wave, not all at once. The caste mirrors this: legs are
*staggered* over a short window rather than fired simultaneously, so
redundancy doesn't become a synchronized bandwidth spike. Diversity of paths
with smoothed egress.

**Complement to the ant, not a rival.** The forager scores peers by
block-relay quality; the centipede *selects several* of the best-and-diverse
as legs. Ant = which peers are good; centipede = use more than one of them.
Together: fast **and** hard to censor.

## The hard invariant (I2): blocks only, never transactions

> The centipede relays **blocks** — public data broadcast to everyone.
> Multipath relay of a **transaction** is forbidden: it would shatter
> Dandelion++'s single-stem design, which deliberately sends a stem
> transaction down **one** path to protect its origin (P4.1). Sending a
> transaction down many paths at once is the textbook way to *reveal* an
> origin (the source is the common node of all the paths).

So the centipede applies strictly to **block** propagation and to nothing in
the transaction/stem path. A block reveals no sender; multipathing it leaks
nothing. This is the same public-signals-only boundary as the rest of the
suite, and it is not optional — it is the difference between a censorship
defense and a de-anonymization engine.

## Advisory + non-consensus

Like the colony, the centipede is **advisory**: it recommends a relay
fan-out (which legs, how many) to the node's block-relay logic; the node
decides, validates peers, and enforces caps. It does **not** change what a
valid block is, how blocks are chosen, or any consensus rule
(`CONSENSUS IMPACT: none`, `FORK RISK: none`). It changes only *how many
copies* of an already-valid block go out, and *to whom*.

## Bandwidth is the honest cost (C.9, W4.4)

Redundancy costs bandwidth: N legs means up to N× the egress for a block.
This is a real trade and must be **bounded and configured**:
- **Fan-out cap** (`max_legs`, small — e.g. 3) — redundancy is cheap
  insurance at low N; it is not "flood every peer."
- **Diversity, not volume** — the value is *independent* paths, so 3 diverse
  legs beat 8 legs that share a bottleneck. Legs are chosen for path
  independence, capping the useful N low.
- Block size already bounds per-relay cost (`MAX_BLOCK_SIZE`); N× that is
  the worst case, and N is small.
- On a small/young network the marginal resilience may not justify the
  bandwidth — ships **off by default**, most valuable as the topology grows.

## DoS and attack analysis

- **Amplification (multipath as a bandwidth-DoS):** an attacker who could
  drive us to relay many blocks over many legs. *Countered by:* the fan-out
  cap and the existing block-relay rate limits — total egress is bounded
  regardless of leg count; N is a small constant.
- **Leg-poisoning (attacker wants to be chosen as a leg to then drop):**
  choosing an attacker as *one* leg is harmless precisely because there are
  *other* legs — that's the whole point. Redundancy defends itself. Legs are
  also drawn from forager-vetted peers.
- **Diversity spoofing (Sybil peers pretending to be independent paths):**
  legs are chosen for observable diversity (distinct peers / address
  ranges); a future integration with the scout ants' corroboration further
  hardens this. Worst case degrades to fewer *truly* independent legs, never
  to unsafety.

## Consensus & reorg posture

`CONSENSUS IMPACT: none` — relays already-valid blocks more redundantly;
never validates, orders, or selects. `REORG BEHAVIOR: n/a` — holds no chain
state. `PRIVACY IMPACT: none` — blocks are public; transactions are never
multipathed (I2). `CRYPTO REVIEW NEEDED: no`.

## Configuration (sketch)

```toml
# ships OFF
[centipede]
enabled = false
mode = "observe"        # observe (log intended legs) | advise | act
max_legs = 3            # fan-out cap; small — diversity over volume
leg_stagger_ms = 150    # metachronal wave: smooth the egress spike
require_path_diversity = true   # prefer independent IP ranges / ASNs
```

## Phased plan

- **Phase 0 — this doc.**
- **Phase 1 — observe.** For each relayed block, *log* the legs the
  centipede *would* have used (peers + diversity), send normally. Pure
  measurement of the resilience the fan-out would add; zero extra bandwidth.
- **Phase 2 — advise.** Recommend the fan-out to the node's relay path;
  node applies within its caps. Two-node + partition tests first (F.2, F.5).
- **Phase 3 — act, tuned** on a grown topology; measure censorship/partition
  resilience against a simulated dropping peer before any mainnet use.

Off by default, revertible per phase.

## Forking hazards — why correct wiring is load-bearing

Same doctrine as [colony](colony.md) / [firefly](caste-firefly.md): wrong
wiring must fail loudly at build/test time.

- **Hazard 1 — multipathing a *transaction* (deanonymization).** The single
  fatal mistake: applying the centipede's fan-out to stem/tx relay. Sending a
  transaction down many paths reveals its origin as the common source
  (P4.1). *Guard:* the centipede's input is a **block** type only; there is
  **no code path** from a transaction (or the stem-pool) into the leg
  selector, and a privacy test asserts the fan-out is invoked only on block
  relay. Wrong wire → CI red, before any origin leaks.
- **Hazard 2 — unbounded fan-out (self-DoS / bandwidth blowout).** *Guard:*
  `max_legs` is enforced below the relay call; the node's egress rate limit
  is the backstop. Redundancy can never exceed the configured ceiling.
- **Hazard 3 — treating Sybil peers as independent legs.** *Guard:*
  diversity is required and scored; worst case is fewer independent legs,
  never a false sense of redundancy that the code relies on.

The moat, honestly: censorship-resistant multipath relay that is provably
*blocks-only* is hard to get right on a privacy chain — a naive fork applies
it to transactions and de-anonymizes its users. The blocks-only guard is the
work.

## Non-goals

- **Not** a transaction relay/mixer — blocks only; Dandelion++ untouched.
- **Not** a flood protocol — bounded, diverse fan-out, not "send to all."
- **Not** a consensus change — same valid blocks, just more copies.
- **Not** worthwhile on a tiny topology — off by default until paths are
  actually independent enough to matter.

## References

- Real centipede locomotion — metachronal (leg-wave) gait; segmental
  redundancy.
- [biomimetic suite](biomimetic.md), [colony](colony.md) (the forager it
  complements), [firefly](caste-firefly.md).
- CoinCync AI Development Rules — P4.1 (stem single-path privacy), C.9
  (privacy/perf trades), C.10 (anonymity set), D.2/D.3 (DoS, eclipse),
  W4.4 (block relay / bandwidth trade-offs).
