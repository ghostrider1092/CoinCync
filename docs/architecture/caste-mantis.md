# mantis — adversarial tarpit

> Status: **BUILT (pure core; armed, no live feed)** — caste of the
> [biomimetic suite](biomimetic.md). Code: `src/colony/mantis.rs`. Network-defense caste.
>
> One-line: when a peer misbehaves, don't instant-ban it — **hold** the near-idle
> socket on an *escalating* timer. Cheap for us, expensive for the attacker:
> ties up their connection slot and defeats fast retry-from-a-new-IP loops.

## The problem: an instant ban is a "try again" signal

A praying mantis stays motionless and simply *holds* what wanders into reach.
The defensive analogue: dropping an abusive peer the instant it misbehaves just
tells the attacker "rotate to a fresh IP and retry." The cost asymmetry runs the
wrong way — cheap for them, and they learn nothing is being spent to slow them.

## The mechanism: escalating hold, decaying forgiveness

Per-peer offense count → hold seconds, `hold_secs(offenses) = TARPIT_BASE_SECS ×
2^(offenses-1)`, saturating at [`TARPIT_MAX_SECS`] (300 s):

- **First offense = 2 s.** Trivial — a peer that hiccups once on a flaky link is
  barely affected. Cost grows only for *repeat* offenders (the signature of
  deliberate abuse), satisfying the ban-consistency rule (only proven malice is
  penalised, never honest-but-slow peers).
- `forgive_round()` decays every offense count over time and drops peers that
  reach zero, so a reformed peer is fully forgiven — no permanent mark.
- The map is **capacity-bounded** ([`MAX_TRACKED_PEERS`]); when full, the
  *least-offending* entry is evicted, so an address-rotation flood can't bloat
  memory and the worst actors stay held.

Overflow safety was load-bearing here: a naive `TARPIT_BASE_SECS.checked_shl(n)`
silently returns `Some(0)` on value overflow (checked_shl only guards the shift
*amount*), which would give a heavy offender a **zero** hold. The core builds the
power-of-two via `1u64.checked_shl` + `checked_mul` so overflow pins at the cap.

## Boundary

The core is a pure decision function: peer → offense count → hold seconds. It
does no I/O, holds no sockets, and never inspects message *content* — it only
ever sees "this peer misbehaved," a boolean the caller supplies. The node
applies the hold; deciding *how long* is all the caste does.

## Status

- **Pure core:** built, `src/colony/mantis.rs`, 8 unit tests (escalation, cap,
  overflow, saturation, forgiveness, capacity eviction, read-only `hold_for`).
- **Wiring:** deliberately **armed but not fed** in the read-only HealthTick
  sidecar — that path has no per-peer misbehavior feed, and feeding it merely-
  unreachable (honest) peers would violate ban-consistency. Activates with a
  node-adapter offense feed in a later, reviewed phase.
