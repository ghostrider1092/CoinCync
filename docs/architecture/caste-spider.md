# spider — sentinel web (attack-signature detection)

> Status: **BUILT (pure core + live observe wiring)** — caste of the
> [biomimetic suite](biomimetic.md). Code: `src/colony/spider.rs`. Network-defense (detection) caste.
>
> One-line: read "vibrations" in **public** network state — inbound-connection
> rate, netgroup concentration, duplicate-message churn, sentinel reachability —
> and classify them into coarse attack signatures. The suite's sensory organ.

## The problem: attacks have signatures before they have consequences

A spider doesn't chase; it reads the vibrations in its web. Eclipse attempts,
partition onset, and floods all leave *shape* in the traffic — concentration,
rate, dark peers — before they do damage. Something has to feel that shape and
hand it to the parts of the suite that heal (colony/army-ant) and defend
(mantis).

## The mechanism: threshold classifier over public metrics

`assess(&SentinelReading)` returns the set of tripped [`ThreatSignature`]s
(empty = calm):

- **EclipsePressure** — inbound peers concentrated ≥ [`ECLIPSE_NETGROUP_PCT`]
  (50%) in one netgroup. Half of inbound from a single routable group is well
  past what an honest topology produces.
- **FloodPattern** — new inbound connections/min ≥ [`FLOOD_CONN_PER_MIN`], or
  duplicate-message share ≥ [`FLOOD_DUPLICATE_PCT`].
- **PartitionOnset** — unreachable long-lived sentinel peers ≥
  [`PARTITION_UNREACHABLE_PCT`].

Every input is a count or percentage of **connection/topology** facts. The
spider never inspects message *content* and never sees a transaction — it feels
the shape of the traffic, not what it carries.

## Detection ≠ action

A tripped signature is a *hint*, not a verdict. It feeds healing and telemetry;
it is never on its own a ban or tarpit reason. A false positive costs a
redundant reconnect, not a disconnected honest peer.

## Status

- **Pure core:** built, `src/colony/spider.rs`, 7 unit tests (calm, each
  signature, inclusive thresholds, combined-attack ordering).
- **Wiring:** **live** in `coincync-tick --castes-observe` — the sidecar builds a
  `SentinelReading` from real `aggregate_fleet_health` (stalled → partition) and
  `fleet_peers` netgroup concentration (→ eclipse), logs the signatures, and
  feeds `under_attack` to locust and the partition trigger to army-ant.
