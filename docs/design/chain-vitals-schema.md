# Chain-vitals schema (`get_vitals`)

**Status:** implemented (observability only; no consensus impact)
**Idea family:** "small hidden things" — the dam's instrumentation panel: a
standard set of gauges anyone can read the same way.

## Problem

`get_info` is the node's kitchen-sink diagnostic endpoint — dozens of fields,
back-compat aliases, and it grows over time. Monitoring tools, load-balancer
health checks, and the partition detector (`scripts/check-fleet-partition.sh`)
only need a handful of health signals, but they read them out of `get_info` with
`// default on missing` fallbacks and no stability contract. There is also no
version marker, so a consumer cannot tell which shape it is parsing.

## Design

`src/vitals.rs` — a small, dependency-free module:

- `HealthStatus` — the node's self-assessed band (`syncing` / `no-peers` /
  `stalled` / `low-peers` / `healthy`) with a stable `as_str()` label and a
  `score()` in `[0.0, 1.0]`. `HealthStatus::from_signals(synced, peer_count,
  tip_age_secs)` is now the **single source of truth** for the band; `get_info`
  was refactored to call it (identical labels/scores/thresholds as before —
  `STALL_TIP_AGE_SECS = 300`, `MIN_HEALTHY_PEERS = 2`, unreadable clock ⇒
  stalled), so there is no behavior change to `get_info`, just de-duplication.
- `ChainVitals` — a versioned record (`schema_version`, `network`, `height`,
  `tip_hash`, `tip_age_secs`, `is_synced`, `peer_count`, `difficulty`,
  `mempool_size`, `status`, `health_score`). `VITALS_SCHEMA_VERSION = 1`.
  Additive optional fields don't bump the version; removals/renames/retypes do.

- New RPC method **`get_vitals`** returns `ChainVitals`. Registered on the
  JSON-RPC server next to `get_info`, and added to the REST allowlist
  (`RPC_ALLOWED_METHODS`) so a load balancer / health checker can hit it on the
  public REST layer. Read-only and non-sensitive.

`get_info` keeps every field it had (nothing is removed) — `get_vitals` is
additive.

## Why it's testnet-safe / no consensus impact

Pure read-side observability. No block validation, serialization, genesis, or
hash-locked file is touched. The health band is computed from already-exposed
signals.

## Portability (help other chains)

`HealthStatus` + `ChainVitals` carry nothing CoinCync-specific. Publishing the
schema (with its `schema_version`) lets cross-chain tooling — dashboards,
`check-fleet-partition`-style detectors, LB health probes — speak one vocabulary
instead of re-learning each chain's bespoke `get_info` shape. The schema version
is the forward-compat hinge that makes that contract safe to depend on.
