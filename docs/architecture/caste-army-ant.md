# army-ant — living-bridge partition recovery

> Status: **BUILT (pure selection core + live observe wiring)** — caste of the
> [biomimetic suite](biomimetic.md). Code: `src/colony/army_ant.rs`. Resilience caste.
>
> One-line: when spider senses a split forming, pick the peers to **reconnect
> toward to bridge it** — netgroup-diverse, freshness-weighted — so the rebuilt
> links span different routable groups and favour peers most likely still alive.

## The problem: reconnecting blindly re-eclipses you

Army ants link their own bodies into a living bridge to span a gap so the colony
keeps moving. For a node, a suspected partition means it needs to re-establish
paths to the far side. Reconnecting blindly — grabbing whatever addresses are
handy — risks rebuilding all links into one hostile netgroup, letting the same
actor that caused the split re-eclipse the node during recovery.

## The mechanism: diversity-first, freshness-weighted selection

`select_bridges(candidates, max)` chooses up to `max` reconnection targets:

- **Round-robin across netgroups** — one bridge per distinct netgroup before any
  group contributes a second, so the rebuilt links span
  `min(max, distinct_netgroups)` different routable groups (the same anti-eclipse
  principle the inbound-eviction logic uses defensively).
- **Freshness within a group** — order by `last_seen_secs_ago`, freshest first,
  because the goal is to re-link *now* and a peer seen 10 s ago is worth far more
  than one seen an hour ago.

Selection is fully deterministic (stable sort, tie-broken by id).

## Relationship to centipede

[`centipede`](caste-centipede.md) fans a *block* across diverse legs during
normal operation; army-ant selects *reconnection targets* during a partition
event. Both value netgroup diversity; army-ant additionally weights freshness.
Neither ever touches a transaction — reconnection and block relay are public
topology, not payload.

## Status

- **Pure core:** built, `src/colony/army_ant.rs`, 7 unit tests (diversity-first,
  freshest-in-group, cap, budget-exceeds-candidates, diverse-before-doubling,
  determinism).
- **Wiring:** **live** in `coincync-tick --castes-observe` — activates *only* when
  spider reports `PartitionOnset`, probes peers for freshness, and logs the
  diverse bridge set it *would* reconnect toward. Sends nothing. Acting on it is
  part of the colony healing phase.
