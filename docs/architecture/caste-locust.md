# locust — density-adaptive relay mode

> Status: **BUILT (pure state machine + live observe wiring)** — caste of the
> [biomimetic suite](biomimetic.md). Code: `src/colony/locust.rs`. Resilience caste.
>
> One-line: shift **relay aggressiveness** by load/attack density — calm and
> conservative when quiet ("solitary"), aggressive swarm-relay under
> congestion/attack ("gregarious") — with hysteresis so it can't flap.

## The problem: one relay posture doesn't fit all conditions

Locusts live quietly alone until crowding tips them into a gregarious swarm
phase — a genuine density-driven behavioural switch. A node has the same tension:
a fixed relay posture either wastes bandwidth when the network is quiet or is too
timid under a censorship/partition push. It should spend where it matters, cheap
when idle and all-in under attack, without a human flipping a switch.

## The mechanism: two-threshold hysteresis

`Locust::update(density_pct, under_attack)` returns the mode:

- `under_attack` → **Gregarious** immediately (an active attack is the one signal
  we don't sit in a sticky band for).
- Otherwise hysteretic: a **Solitary** node goes gregarious only at
  [`HIGH_DENSITY_PCT`] (70%); a **Gregarious** node relaxes back only once density
  drops all the way to [`LOW_DENSITY_PCT`] (30%). The band between is sticky.

The gap between the two thresholds *is* the hysteresis. Density hovering around a
single threshold would make a naive switch oscillate every tick — itself a
fingerprint and a waste — so the enter and exit thresholds are deliberately
different.

## Boundary

The mode is a *recommendation* about how hard to relay **public** blocks /
announcements. It never touches transaction privacy — Dandelion++ stem behaviour
is not the locust's to change — and changes no consensus rule.

## Status

- **Pure core:** built, `src/colony/locust.rs`, 5 unit tests (start-transitional,
  quiet-solitary, no-flap hysteresis, attack-forces-gregarious, inclusive
  thresholds).
- **Wiring:** **live** in `coincync-tick --castes-observe` — driven by real host
  load from `health_snapshot` with `under_attack` fed from spider; logs the mode
  each round. Acting on the mode (actual relay fan-out) is a later phase.
