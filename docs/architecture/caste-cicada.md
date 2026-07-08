# cicada — prime-interval anti-correlation scheduling

> Status: **BUILT (pure core + observe wiring)** — caste of the
> [biomimetic suite](biomimetic.md). Code: `src/colony/cicada.rs`. Privacy caste.
>
> One-line: paces **node-local housekeeping** (churn, key rotation, rebroadcast,
> rescans) on *prime-varied* intervals so a passive observer can't phase-lock
> onto a fixed rhythm and re-identify the node. Schedules housekeeping timing
> only — **never transaction or stem-phase timing.**

## The problem: fixed periods are a fingerprint

Any recurring node activity that leaves the box on a fixed clock is a rhythm.
A passive observer who sees "this node does X every 300 s" can use that period
to fingerprint the node across sessions and networks, or to correlate two
observations as the same node. A naive scheduler hands the observer exactly one
thing to lock onto: a single period equal to the base interval.

Periodical cicadas (*Magicicada*) evolved the biological answer: they emerge on
**prime**-numbered year cycles — 13 and 17 — specifically so no shorter-cycle
predator can phase-lock onto them.

## The mechanism: prime-varied intervals

`prime_interval_secs(base, counter)` returns `base × prime / REFERENCE_PRIME`,
where `prime` is drawn from a table of primes ([`CICADA_PRIMES`] = 13, 17, 19,
23, 29, 31, 37, 41) walked with a stride coprime to the table length. The
result:

- swings roughly `0.56×` .. `1.78×` around the base — no interval equals the
  base, so there is **no single period to lock onto**;
- visits every prime within one cycle (full spread), in a **non-monotonic**
  order (13→23→37→17…) so it doesn't emerge as a recognisable ramp;
- is fully deterministic in `(base, counter)` — which is what makes it unit-
  testable and free of any RNG/crypto surface.

The residual predictability (the prime walk repeats every 8 steps) is closed
in the **live sidecar**, which adds a CSPRNG jitter term on top of this base
interval before sleeping. That randomness is deliberately *out* of the pure
core to keep it testable.

## Privacy boundary

Cicada emits only a *delay in seconds*. It has no access to the mempool,
Dandelion++ router, or any transaction, so it is structurally incapable of
pacing tx/stem-phase timing — using it there would be a Prime-Privacy-Invariant
violation. It paces housekeeping only.

## Status

- **Pure core:** built, `src/colony/cicada.rs`, 9 unit tests (determinism,
  bounds, overflow-safety, full-prime-coverage, non-monotonicity, wrap safety).
- **Wiring:** driven in observe mode by `coincync-tick --castes-observe` — logs
  the next prime-varied housekeeping interval each round; paces nothing yet.
- **Next:** let the sidecar's own housekeeping cadence consume the schedule
  (advise → act), with CSPRNG jitter layered on top.
