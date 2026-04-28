# REST endpoints

The REST API is a higher-level wrapper around the JSON-RPC surface, served by `src/rpc/rest.rs` (an axum app). It's the right transport for browser-side code that wants typed JSON without managing JSON-RPC envelopes.

## Where it lives

| URL | What it is |
|---|---|
| `https://api.coincync.network/v1/...` | Public REST, testnet (default) |
| `https://api.coincync.network/v1/mainnet/...` | Public REST, mainnet (post-launch) |
| `http://127.0.0.1:28083/api/v1/...` | Local REST when the node is started with `--rest-bind` |

The REST surface is **only** started when the operator passes `--rest-bind <addr>` or `--explorer` to `coincync-node`. It's opt-in. The bare `coincync-node` only runs the JSON-RPC jsonrpsee server.

## Endpoint inventory

```text
GET  /api/v1/health
GET  /api/v1/status
GET  /api/v1/supply

GET  /api/v1/blocks/recent
GET  /api/v1/block/hash/{hash}
GET  /api/v1/block/height/{height}
GET  /api/v1/block/{height}/transactions

GET  /api/v1/transaction/{hash}
POST /api/v1/transaction/submit         (allowlisted out of public proxy)

GET  /api/v1/mempool
GET  /api/v1/mempool/stats

GET  /api/v1/search?q=...
GET  /api/v1/network
GET  /api/v1/anonymity
GET  /api/v1/peers
GET  /api/v1/stats
GET  /api/v1/emission
GET  /api/v1/events
GET  /api/v1/asset/{id}                 (NotImplemented in 1.0)
GET  /api/v1/assets                     (NotImplemented in 1.0)

GET  /api/v1/ws                         (WebSocket upgrade for live events)

POST /rpc                               (raw JSON-RPC passthrough, allowlisted)
```

## CORS

The public REST server allowlists three origins for browser fetch:

- `https://explorer.coincync.network`
- `http://localhost:3000` (dev convenience)
- `http://127.0.0.1:3000` (dev convenience)

Plus any origins set via the `COINCYNC_CORS_ORIGINS` environment variable on the REST host.

This is **deliberately restrictive** — `CorsLayer::permissive()` would let every website on the internet make authenticated browser requests to the API on behalf of the visitor, which is a CSRF-like attack surface even on read-only endpoints (because of cookies, etag-tracking, etc.). The allowlist limits CORS-enabled access to origins under operator control.

## Allowlist

The `POST /rpc` proxy enforces a read-only allowlist over the underlying jsonrpsee surface. The exhaustive list lives in `src/rpc/rest.rs::RPC_ALLOWED_METHODS`:

**Allowed (read-only):**

- `get_info`, `get_blockchain_info`, `get_network_info`, `get_sync_status`
- `get_anonymity_set`, `get_chain_events`, `get_supply_info`
- `get_privacy_stats`, `get_shielded_anchor`, `get_spark_anchor`
- `get_block_by_height`, `get_block`, `get_block_range`
- `get_peers`, `get_mempool_info`
- `is_nullifier_spent`, `is_spark_serial_spent`, `get_decoys`
- `get_transaction`, `get_asset_info` (both currently `NotImplemented` stubs)
- Forward-compat reservations: `health`, `rpc.discover`, `get_block_count`, etc.

**Blocked (write or sensitive):**

- `submit_block`, `send_raw_transaction` — write methods, blocked
- `get_mining_live` — exposes hashrate / hardware fingerprint, blocked
- Any wallet-side methods (`get_balance`, `unlock_wallet`, etc.) — blocked

Verifying the allowlist is enforced is one of the regression tests: `src/rpc/rest.rs::tests::test_rpc_allowlist_blocks_sensitive`.

## Sample requests

```bash
# Health check (always 200 if the node is up)
curl -s https://api.coincync.network/v1/health

# Chain status — height, tip, sync flag, peer count
curl -s https://api.coincync.network/v1/status | jq .

# Latest 10 blocks (paginated)
curl -s 'https://api.coincync.network/v1/blocks/recent?limit=10' | jq .

# A specific block by height
curl -s https://api.coincync.network/v1/block/height/12345 | jq .

# Search bar (block hash, txid, or height)
curl -s 'https://api.coincync.network/v1/search?q=12345' | jq .

# Anonymity set size — privacy coin's most important metric
curl -s https://api.coincync.network/v1/anonymity | jq .

# Recent chain events (reorgs, fork detections, rejects)
curl -s https://api.coincync.network/v1/events | jq .

# Connected peer table
curl -s https://api.coincync.network/v1/peers | jq .

# Live event WebSocket (if your host exposes /v1/ws)
const ws = new WebSocket('wss://api.coincync.network/v1/ws');
ws.onmessage = (e) => console.log('event:', JSON.parse(e.data));
```

`/api/v1/ws` availability depends on deployment and proxy configuration. For clients that need maximum compatibility across hosts, prefer polling REST endpoints and treat WebSocket support as optional.

## Response shapes

Every endpoint returns JSON. Empty responses are `{}` not `null`. Errors are HTTP status codes plus a JSON body of the form `{"error": "..."}`.

The exact shape of each response is documented in `src/rpc/types.rs` (the typed structs that get serialized) and in [Method reference](./methods.md) (the human-readable field-by-field descriptions).

## Why both REST and JSON-RPC?

REST is more browser-friendly:

- One URL per concept — bookmarkable, cacheable, indexable
- Standard HTTP status codes (404 for "block not found" instead of `{ "error": { "code": -32000 } }`)
- GET requests instead of POST for read methods (CDN-cacheable in the rare case CDN ever gets used)
- WebSocket support for live events without per-event polling

JSON-RPC is more backend-friendly:

- One URL for everything — easy to set up RPC clients in any language
- Symmetric request/response envelope
- Method introspection (`rpc.discover` — not yet wired)

The two share the same backend state (chain, mempool, P2PNode), so a wallet can use whichever transport it prefers without consistency surprises.

## See also

- [JSON-RPC 2.0](./json-rpc.md) — the underlying protocol the REST layer wraps
- [Method reference](./methods.md) — every method, parameters, return shape
- [Operations → API host](../operations/api-host.md) — running this in production
