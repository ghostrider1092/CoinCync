# Difficulty / block-interval health telemetry

**Status:** implemented (observability only; NO consensus change)
**Idea family:** "small hidden things" — the dam's flow gauges.

## Why telemetry, not an algorithm change

`docs/design/difficulty-oscillation-analysis.md` already concluded that the
testnet's idle-collapse / overshoot is a **calibration** problem, not an ASERT
algorithm problem — simulated param forks did not help. So the right move is not
to touch the consensus difficulty rule, but to make the **observable** that
actually predicts trouble — block-production regularity — first-class, so an
operator sees a stall or an oscillation forming and can react (e.g. keep the
miner continuously online, retune `TESTNET_INITIAL_DIFFICULTY`).

## Design

- **`consensus::difficulty::interval_stats(&[DifficultyBlock]) -> IntervalStats`**
  — a pure function computing inter-block interval `samples / mean / stddev /
  min / max / last` (seconds) over a window, with saturating subtraction so a
  non-monotonic timestamp (possible under the +1s rule / MTP) yields a 0
  interval instead of underflowing. Never panics; a <2-block window returns
  `IntervalStats::EMPTY`. Unit-tested for regular spacing, degenerate/
  non-monotonic input, and variance on irregular spacing.

- The already-present-but-**unwired** `estimate_hashrate(&[DifficultyBlock])` is
  now surfaced (it had no caller anywhere).

- **New RPC `get_difficulty_health`** composes both over the existing
  `get_difficulty_blocks(height+1)` window (144 blocks, DB-sourced,
  deterministic) and returns a versioned blob: `difficulty`,
  `total_difficulty`, `target_block_time_secs` (120), `estimated_hashrate`,
  `tip_age_secs`, and the `interval` stats, plus a coarse `assessment`
  (`warming` / `stalled` / `oscillating` / `slow` / `fast` / `healthy`) derived
  from the stats vs `TARGET_BLOCK_TIME`. Added to the REST allowlist for
  monitoring. It is its **own** method (not folded into `get_info`) precisely
  because it scans a block window — `get_info` stays a cheap per-tick call.

## Why it's testnet-safe / no consensus impact

`interval_stats`/`estimate_hashrate` are f64 informational math over historical
timestamps; nothing feeds back into block validation, difficulty targeting,
genesis, or any hash-locked file. Purely read-side.

## Portability (help other chains)

"Expose block-interval mean/variance + a hashrate estimate + a coarse
production-health assessment, versioned" is a small, generic telemetry contract.
Most chains expose only instantaneous difficulty; the *variance* of block
spacing is the early-warning signal for a single-miner or mis-calibrated network,
and it costs nothing to compute from data every full node already stores.

## Deferred (noted, not done)

`metrics::record_block_interval` (a Prometheus histogram) exists but has no call
site; wiring it into the block-accept path would give a time-series view. Left
out here to keep this change read-only and off the hot path.
