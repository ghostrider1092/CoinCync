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

Same idea as `get_info` but with extra accounting fields (`total_supply`, `total_difficulty`). Both aggregates are decimal strings so clients can preserve their full u128 values.

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
  ],
  "bytes": "<hex of borsh-serialized block>"
}
```

The `transactions` array carries lightweight per-tx records (`hash`, `kind`, `inputs`, `outputs`, `fee`). For full transaction bodies you currently need to deserialize the `bytes` field — the txid → block index that would let `get_transaction` work as a standalone lookup is a P1 deferred item.

### `get_block_count`  *(forward-compat reservation, not yet registered)*

Reserved in the REST allowlist for future implementation. Currently returns `MethodNotFound`.

## Transactions

### `get_transaction`  *(public, NotImplemented stub)*

Currently returns `-32601 Method not found` with a labelled message explaining that the txid-to-block index is not wired yet. The REST allowlist still includes the method so the explorer receives a labelled error rather than a generic 403.

### `submit_block`  *(local only)*

**Params:** `[block_hex: string]`. Borsh-serialized block, hex-encoded.

**Returns:** `{ "accepted": true, "hash": "..." }` or `{ "error": "..." }`.

Used by the standalone miner. **Blocked from the public REST proxy.**

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

Returns the running miner state. **Deliberately blocked from the public REST proxy** because it would let observers fingerprint the miner's hashrate or hardware. A node that is not mining returns `is_mining: false` with zeroed fields.

## Privacy stores

### `get_privacy_stats`  *(public)*

Aggregate Phase 2 store snapshot. Pre-activation, all roots are zero and all sizes are 0 — it is the same payload, just a baseline.

### `get_shielded_anchor`, `get_spark_anchor`  *(public)*

Return the current Merkle root that a light wallet should anchor its spend proofs against. Pre-activation, they return the zero anchor.

### `is_nullifier_spent`, `is_spark_serial_spent`  *(public)*

**Params:** `[nullifier_hex: 64-char hex]`.

**Returns:** `{ "spent": true|false, "height": u64|null }`.

Required for recipient-side spendability checks in light wallets. Public because nullifier sets are public chain state by design.

### `get_decoy_distribution`  *(public)*

Returns a snapshot-bound catalog of output counts. The node does not sample outputs and receives no wallet-specific seed.

**Params:** none.

**Returns:**

```json
{
  "snapshot_height": 12345,
  "snapshot_hash": "26ec6abd...",
  "policy_version": 1,
  "heights": [
    { "height": 0, "count": 1 },
    { "height": 1, "count": 3 }
  ]
}
```

Wallets apply the versioned age distribution locally and construct one shuffled covered request that includes every selected real-input locator.

### `get_outputs_by_locators`  *(public)*

Resolves canonical `(height, ordinal)` output locators against a supplied snapshot.

**Params:** `[snapshot_height: u64, snapshot_hash: hash, policy_version: u16, locators: OutputLocator[]]`.

The request is capped at 256 locators and must be duplicate-free. Unknown policy versions, stale or non-canonical snapshots, missing heights, and out-of-range ordinals reject the entire request. Successful responses preserve request order and repeat the supplied snapshot metadata.

Each output includes `locator`, `public_key`, `commitment`, `height`, `is_coinbase`, and `lock_height`.

### `get_decoys`  *(deprecated; not public)*

The node-selected decoy-pool method is removed from the public REST allowlist. Direct JSON-RPC calls return a stable deprecation error. Wallets and explorer clients must use the two locator RPCs above and must not fall back to `get_decoys` after any snapshot or allocation failure.

## Asset queries (permanently NotImplemented)

### `get_asset_info`  *(public, NotImplemented stub)*

Returns a labelled `-32601 Method not found`: CoinCync 1.0 has no confidential-asset layer. This is permanent, not deferred.

## Chain Verification Methods

These support `scripts/coincync-verify-chain.sh`.

### `get_expected_reward`

| | |
| --- | --- |
| Params | `[height: u64]` |
| Returns | `{ reward, height, in_cync }` |
| Access | Public |

### `verify_keyimage_uniqueness`

| | |
| --- | --- |
| Params | `[]` |
| Returns | `{ valid, duplicates, duplicate_images, total_checked }` |
| Access | Public |

### `check_zero_commitments_in_range`

| | |
| --- | --- |
| Params | `[start_height: u64, end_height: u64]` |
| Returns | `{ zero_count, locations }` |
| Access | Public |

### `verify_signatures_in_range`

| | |
| --- | --- |
| Params | `[start_height: u64, end_height: u64]` |
| Returns | `{ valid, checked, failures, findings }` |
| Access | Public |

### `verify_range_proofs_in_range`

| | |
| --- | --- |
| Params | `[start_height: u64, end_height: u64]` |
| Returns | `{ valid, checked, failures, findings }` |
| Access | Public |

### `verify_commitment_balance_in_range`

| | |
| --- | --- |
| Params | `[start_height: u64, end_height: u64]` |
| Returns | `{ valid, checked, failures, findings }` |
| Access | Public |

### `full_chain_audit`

| | |
| --- | --- |
| Params | `[start_height: u64, end_height: u64]` |
| Returns | `{ valid, blocks_checked, txs_checked, findings, details }` |
| Access | Public |

## See also

- [JSON-RPC 2.0](./json-rpc.md) — the protocol envelope
- [REST endpoints](./rest.md) — the higher-level wrapper
- `src/rpc/server.rs` — the canonical method registrations; if this page diverges, the source is correct
