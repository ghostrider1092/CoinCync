# Wave 1 hardening — version fingerprint, graceful shutdown, boot canary, mempool health

**Status:** implemented (all non-consensus, testnet-safe); part of the second
"small hidden things" batch, stacked on `dd17bfc`.

Four net-new features, plus an honest finding that three proposed ideas were
**already covered** by existing infrastructure (documented below so we don't
build duplicates).

## Built

1. **`--version` consensus fingerprint** (`src/bin/node.rs` `long_version_string`)
   — `--version` now prints the crate version plus this binary's consensus-rules
   fingerprint (from #1 of batch one) for testnet and mainnet. Lets an operator
   confirm every fleet host was built from the same consensus rules **without
   starting a node**. Verified: prints `consensus-fingerprint testnet: …` /
   `mainnet: …`.

2. **Complete graceful shutdown** (`src/bin/node.rs` shutdown seq) — the binary
   now calls `P2PNode::stop().await` on SIGTERM/Ctrl-C (previously it exited
   without it, so peers were dropped abruptly and the address book / ban list
   were only ever persisted by their periodic timers). Still inside the
   second-Ctrl-C `select!` so a stuck store flush can be force-aborted.
   Supersedes the anchor-only save from batch-one #4 (`stop()` saves anchors,
   address book, and bans, then disconnects cleanly).

3. **Boot integrity canary** (`Blockchain::boot_integrity_check`, wired into
   `start_node`) — cross-checks, for a non-genesis chain, that the tip block is
   retrievable and the height→hash index agrees with the tip; fatal on mismatch
   (refuse to serve a corrupt store), soft-warn on an empty UTXO set at height
   > 0. Logs a one-line integrity summary. Unit-tested on genesis + a
   seeded height-50 chain.

4. **Mempool health schema** (`get_mempool_health` RPC) — versioned mempool-side
   analog of `get_vitals`: `tx_count`, `bytes`/`max_bytes`, `utilization`,
   `total_fees`, `min_fee_per_byte`, fee-rate percentiles, and oldest pending tx
   age. Added to the REST allowlist. Read-only.

## Already covered (not rebuilt — noted for the record)

- **Reorg telemetry (idea #4):** reorgs already record `ChainEventType::Reorg`
  with `reorg_depth` + `fork_point` (queryable via `get_chain_events`) and feed
  `metrics::record_reorg` (Prometheus). No redundant getter added.
- **Anonymity-set (idea #6):** `get_info` already returns `anonymity_set`. A
  time-series "growth" view is a Prometheus scrape of that gauge, not a new RPC.
- **Tip-stall (idea #7):** `get_difficulty_health` (`assessment="stalled"`) and
  `get_vitals` (`status="stalled"`) already surface an accurate, tip-age-based
  stall on the read path. A proactive maintenance-loop detector was rejected:
  `ChainStateReader` exposes only `(height, hash)` (no timestamp), and a
  height-delta detector would false-positive on the live seed's normal 2–4 min
  block gaps.

## Why testnet-safe

No block validation, genesis, serialization, or hash-locked file changes. The
seeding helper used by tests (`seed_linear_chain_for_testing`) is
`#[cfg(any(test, feature = "test-utilities"))]` and never compiled into a
release node.
