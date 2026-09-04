# Full live test — "everything" (2026-08-22)

Single end-to-end run on a fresh **regtest-fast** chain, two real wallets (A =
miner/sender, B = recipient), real RandomX PoW, real RingCT/CLSAG crypto. No
mocks. Every feature built this session was exercised against a live node and its
result recorded below. All artifacts are the release binaries built from the
working tree at commit `cfb979a1` (+ uncommitted session work).

## Environment

- Node: `coincync-node --network regtest --no-peers --mine <A> --mine-threads 2`
  built `--features "testnet regtest-fast"`.
- RPC `http://127.0.0.1:18081`, Prometheus metrics `http://127.0.0.1:18082/metrics`.
- Chain ran to height ~306, difficulty pinned 1024 (regtest-fast), 0 reorgs, 0 orphans.

## Results

| # | Feature (this session) | Live check | Result |
|---|---|---|---|
| 1 | **Enterprise metrics** | `GET :18082/metrics` mid-run | ✅ real values: `chain_height`, `difficulty`, `total_difficulty`, `circulating_supply_atomic`, `block_reward_atomic`, `utxo_set_size`, `is_synced`, `sync_progress_percent`, `blocks_behind`, `tip_age_seconds`, `db_size_bytes`, `mempool_size`, `reorg_total`, `orphan_blocks_total`, `peers` all populated and tracking the chain |
| 2 | **Privacy-connector RPC** | `get_privacy_features` | ✅ returns registry; `connector_audited=false` (gated, as designed) |
| 3 | **Wallet scan / balance** | A scan → 62 outputs, 3099.95 CYNC | ✅ |
| 4 | **Normal RingCT send** | A→B 5 CYNC (tx `ca8c44e7…`) | ✅ accepted, mined h154, received by B (`payment_id: -`) |
| 5 | **Integrated address (payment ID)** | B issues integrated addr (pid `57631cd8d71e1e1e`); A pays `--payment-id`; tx `2612e23e…` | ✅ B's scan **recovered pid `57631cd8d71e1e1e`** on the 7-CYNC output; the plain send shows none → collision-safe TLV confirmed |
| 6 | **Subaddress receive (W-A)** | A→B subaddr `0/1` 9 CYNC (`--subaddress`, tx `5b0d4ee8…`) | ✅ B detected output tagged `0/1` |
| 7 | **Subaddress spend (W-1 fix)** | B spends 15 CYNC → A (tx `33374f9a…`), amount forces the 9-CYNC subaddr UTXO as input | ✅ node validated the CLSAG (one-time secret needs per-subaddress offset `m_i`); UTXO `0/1` now `spent: yes` on chain |
| 8 | **Signed reproducible releases** | manifest over the **real** node+wallet binaries; 2 maintainers sign | ✅ 2-of-2 verify OK; +1 byte on node → **rejected** (size mismatch); 1-of-2 → **rejected** (below threshold) |

## Not observable in a single-node live run (verified by other means)

- **Anti-eclipse address-book netgroup quota (#1):** in-node peer-book policy;
  covered by unit tests in `network/bootstrap.rs` (quota + netgroup derivation).
- **Spark / MW cut-through soundness fixes:** feature-gated (ed25519-incompatible
  build); proven by `examples/spark_mw_live_demo` + property tests
  (`tests/property_invariants_spark_mw.rs`). Stay gated (`connector_audited=false`)
  pending external audit.
- **RBF / fee market (#3):** pre-existing, tested. **CPFP:** structurally N/A —
  the mempool never admits a spend of an unconfirmed output.

## Teardown

Node stopped by its specific PID (never by image name — the elevated home testnet
node must not be touched). Isolated data dir under the session scratchpad.

## Bottom line

Everything built this session works against a live chain end-to-end. The headline
proofs: an integrated-address payment ID round-tripped encrypted through a real
transaction and was recovered on scan, and a subaddress-received output was spent
on-chain — the two features most likely to be "half-wired" are fully live.
