# Method reference

Every JSON-RPC method registered by `src/rpc/server.rs`, with parameters, return shape, and the access level (public via REST allowlist vs local-only).

## Conventions

- **Atomic units**: all amounts are integer atomic units. 1 CYNC = 10^12 atomic units. So `49500000000000` atomic = 49.5 CYNC.
- **Hashes**: 64-char lowercase hex strings (no `0x` prefix).
- **Heights**: u64 starting at 0 (genesis).
- **Timestamps**: u64 unix-epoch seconds.
- **Public**: callable via `https://api.coincync.network/rpc` and `https://explorer.coincync.network/api/...`.
- **Local**: callable only on the local node's jsonrpsee endpoint (`http://127.0.0.1:28081`).

## Node info

### `get_info`  *(public)*

Returns the node's current status — the canonical "health" payload consumed by both TUIs and the embedded explorer.

**Params:** none.

**Returns:**

```json
{
  "version":                 "1.0.0",
  "network":                 "testnet",
  "height":                  12345,
  "target_height":           12345,
  "top_hash":                "26ec6abd...",
  "tip_hash":                "26ec6abd...",
  "tip_timestamp":           1772900000,
  "tip_age_secs":            17,
  "clock_available":         true,
  "difficulty":              "9876543",
  "total_difficulty":        "1234567890",
  "synced":                  true,
  "is_synced":               true,
  "peer_count":              8,
  "tx_pool_size":            3,
  "mempool_size":            3,
  "anonymity_set":           41782,
  "available_outputs":       41782,
  "effective_ring_size":     11,
  "status":                  "healthy",
  "health_score":            1.0,
  "process_count":           1,
  "process_count_available": false,
  "has_zombies":             false,
  "rpc_auth_enabled":        true,
  "metadata_minimized":      true,
  "stratum_public_bind_requested": true,
  "stratum_public_bind_ack": true,
  "stratum_native_tls_enabled": true,
  "stratum_tls_proxy_ack": false,
  "stratum_transport_hardened": true
}
```

`tip_age_secs` is `null` if the system clock is unreadable (in which case `clock_available` is `false`). Consumers should treat `null` as "unknown" — never as `0`. See `src/rpc/server.rs` for the rationale.

Hardening posture fields in `get_info` / `get_blockchain_info`:

- `rpc_auth_enabled`: runtime RPC auth mode.
- `metadata_minimized`: peer metadata redaction posture.
- `stratum_public_bind_requested`: Stratum requested to bind publicly.
- `stratum_public_bind_ack`: explicit public-bind acknowledgement is present.
- `stratum_native_tls_enabled`: native Stratum TLS transport is enabled.
- `stratum_tls_proxy_ack`: operator acknowledged trusted upstream TLS termination.
- `stratum_transport_hardened`: computed safety flag (true when Stratum is not public, or public with password + ack + encrypted transport).

### `get_blockchain_info`  *(public)*

Same idea as `get_info` but with extra accounting fields (`total_supply`, `total_difficulty`).
Both aggregates are decimal strings so clients can preserve their full u128 values.

### `get_network_info`  *(public)*

Peer breakdown. `connections` is the total live peer count. `incoming`, `outgoing`, `white_peers`, `grey_peers` are `null` in the P0 release because the thin `network_stats()` exposes only the total; the per-direction split lands in P1.

```json
{
  "network": "testnet",
  "version": "1.0.0",
  "protocol_version": 1,
  "connections": 8,
  "incoming": null,
  "outgoing": null,
  "white_peers": null,
  "grey_peers": null
}
```

### `get_sync_status`  *(public)*

```json
{
  "synced":        true,
  "height":        12345,
  "target_height": 12345,
  "progress":      1.0,
  "peers":         8
}
```

### `get_anonymity_set`  *(public)*

The most important privacy-coin metric: total unspent outputs (potential decoys) plus average outputs per block.

```json
{
  "anonymity_set":     41782,
  "height":            12345,
  "outputs_per_block": 3
}
```

### `get_chain_events`  *(public)*

Recent reorgs, fork detections, rejects, and checkpoints. Server-capped to 500 entries; the default limit is 100.

**Params:** `[limit: usize]` *(optional)*.

**Returns:** `{ events: [...], count: usize, current_height: u64, current_tip: hex }`. Each event has `event_type`, `height`, `hash`, `timestamp`, and an event-specific `details` object.

## Blocks

### `get_block_by_height`  *(public)*

**Params:** `[height: u64]`.

**Returns:** the rich block payload (see "Rich block payload" below).

### `get_block`  *(public)*

**Params:** `[hash: 64-char hex]`.

**Returns:** the rich block payload (same shape as `get_block_by_height`).

### `get_block_range`  *(public)*

**Params:** `[start: u64, end: u64]`. Server caps the range to 100 blocks per call.

**Returns:** `{ start, end, count, blocks: [...] }` where each block uses the same rich payload.

### Rich block payload

```json
{
  "height":         12345,
  "hash":           "abc123...",
  "prev_hash":      "def456...",
  "tx_root":        "789...",
  "timestamp":      1772900000,
  "nonce":          42,
  "algorithm":      0,
  "algorithm_name": "RandomX",
  "difficulty":     "9876543",
  "target":         "ffffff...",
  "tx_count":       3,
  "size":           4096,
  "reward":         48500000000000,
  "transactions": [
    {
      "hash":    "...",
      "kind":    "coinbase",
      "inputs":  0,
      "outputs": 1,
      "fee":     0
    }
    /* ... */
  ],
  "bytes": "<hex of borsh-serialized block>"
}
```

The `transactions` array carries lightweight per-tx records (`hash`, `kind`, `inputs`, `outputs`, `fee`). For full transaction bodies you currently need to deserialize the `bytes` field — the txid → block index that would let `get_transaction` work as a standalone lookup is a P1 deferred item.

### `get_block_count`  *(forward-compat reservation, not yet registered)*

Reserved in the REST allowlist for future implementation. Currently returns `MethodNotFound`.

## Transactions

### `get_transaction`  *(public, NotImplemented stub)*

Currently returns `-32601 Method not found` with a labelled message:

> `get_transaction is not yet wired in P0: a txid → (block, index) lookup index lands in P1 alongside the wallet RPC. See chain::Blockchain — there is no tx index today, so this method cannot be satisfied without a full chain scan.`

This is intentional. The REST allowlist still includes the method so the explorer's search bar gets a labelled error rather than a generic 403, but the implementation is honest about not being wired yet.

### `submit_block`  *(local only)*

**Params:** `[block_hex: string]`. Borsh-serialized block, hex-encoded.

**Returns:** `{ "accepted": true, "hash": "..." }` or `{ "error": "..." }`.

Used by the standalone `coincync-miner` to submit found blocks. **Blocked from the public REST proxy.**

### `send_raw_transaction`  *(local only)*

**Params:** `[tx_hex: string]`. Borsh-serialized transaction, hex-encoded.

**Returns:** `{ "accepted": true, "hash": "..." }` or `{ "error": "..." }`.

The mempool runs the same crypto verifiers consensus does — no fast path. **Blocked from the public REST proxy.**

## Mempool

### `get_mempool_info`  *(public)*

```json
{
  "size":       3,
  "bytes":      8421,
  "total_fees": 1500000,
  "max_size":   100000
}
```

## Mining

### `get_mining_live`  *(local only — fingerprint-leak risk)*

Returns the running miner state. **Deliberately blocked from the public REST proxy** because it would let observers fingerprint the miner's hashrate / hardware. Available only on the local jsonrpsee endpoint.

```json
{
  "is_mining":        false,
  "hashrate":         0.0,
  "hashes_total":     0,
  "blocks_found":     0,
  "algorithm":        0,
  "algorithm_name":   "RandomX",
  "mining_height":    12346,
  "target_hex":       "",
  "best_hash_hex":    "",
  /* ... */
}
```

A node that isn't mining (just running as a relay) honestly returns `is_mining: false` with zeroed fields.

## Privacy stores

### `get_privacy_stats`  *(public)*

Aggregate Phase 2 store snapshot. Pre-activation, all roots are zero and all sizes are 0 — it's the same payload, just a baseline. Public testnet is currently in this pre-activation mode.

```json
{
  "shielded_root":            "00000000...",
  "shielded_tree_size":       0,
  "spark_root":               "00000000...",
  "spark_accumulator_size":   0,
  "mw_kernel_root":           "00000000...",
  "mw_kernels_kept":          0,
  "mw_pending_candidates":    0,
  "mw_bytes_saved":           0,
  "mw_compression":           0.0,
  "mandatory_confidential":   true,
  "mandatory_stealth":        true
}
```

### `get_shielded_anchor`, `get_spark_anchor`  *(public)*

Returns the current Merkle root that a light wallet should anchor its spend proofs against. Pre-activation, returns the zero anchor.

### `is_nullifier_spent`, `is_spark_serial_spent`  *(public)*

**Params:** `[nullifier_hex: 64-char hex]`.

**Returns:** `{ "spent": true|false, "height": u64|null }`.

Required for recipient-side "is this coin still spendable" checks in light wallets. Public because nullifier sets are public chain state by design.

### `get_decoys`  *(public)*

Selects decoy outputs for ring-signature construction. **Params:** `[count: u32, max_height: u64]`. Returns a list of `(tx_hash, output_index, public_key, commitment)` tuples sampled by the age-weighted decoy selector.

## Asset queries (permanently NotImplemented)

### `get_asset_info`  *(public, NotImplemented stub)*

Returns `-32601 Method not found` with the labelled message:

> `get_asset_info is not implemented: CoinCync 1.0 has no confidential-asset layer (the asset stack was removed in the 2.0 → 1.0 trim). Single-asset CYNC only.`

This is **permanent**, not deferred. CoinCync 1.0 stripped the confidential-asset machinery. Single-asset CYNC only. The endpoint is allowlisted in REST so the explorer's search bar gets a labelled error rather than a 403 when someone types something that isn't a block hash, txid, or height.

## Chain Verification Methods (added v1.0.0-testnet)

These support `scripts/coincync-verify-chain.sh` — a 5-level chain validation tool.

### `get_expected_reward`

Returns the expected block reward at a given height per the emission curve.

| | |
| --- | --- |
| Params | `[height: u64]` |
| Returns | `{ reward, height, in_cync }` |
| Access | Public |

### `verify_keyimage_uniqueness`

Scans the entire chain for duplicate key images (global double-spend check).

| | |
| --- | --- |
| Params | `[]` (no params) |
| Returns | `{ valid, duplicates, duplicate_images, total_checked }` |
| Access | Public |

### `check_zero_commitments_in_range`

Detects zero commitments and zero stealth addresses (burning bug — H-19).

| | |
| --- | --- |
| Params | `[start_height: u64, end_height: u64]` |
| Returns | `{ zero_count, locations }` |
| Access | Public |

### `verify_signatures_in_range`

Re-verifies every CLSAG ring signature in a block range.

| | |
| --- | --- |
| Params | `[start_height: u64, end_height: u64]` |
| Returns | `{ valid, checked, failures, findings }` |
| Access | Public |

### `verify_range_proofs_in_range`

Re-verifies every Bulletproofs+ range proof in a block range.

| | |
| --- | --- |
| Params | `[start_height: u64, end_height: u64]` |
| Returns | `{ valid, checked, failures, findings }` |
| Access | Public |

### `verify_commitment_balance_in_range`

Verifies Pedersen commitment balance for every transaction (no money printing).

| | |
| --- | --- |
| Params | `[start_height: u64, end_height: u64]` |
| Returns | `{ valid, checked, failures, findings }` |
| Access | Public |

### `full_chain_audit`

Runs all verification checks in one call. Merkle roots, rewards, structural validation, CLSAG, range proofs, and balance — everything.

| | |
| --- | --- |
| Params | `[start_height: u64, end_height: u64]` |
| Returns | `{ valid, blocks_checked, txs_checked, findings, details }` |
| Access | Public |

## See also

- [JSON-RPC 2.0](./json-rpc.md) — the protocol envelope
- [REST endpoints](./rest.md) — the higher-level wrapper
- `src/rpc/server.rs` — the canonical method registrations (this page is generated from reading that file by hand; if it diverges, the source is correct)
