# JSON-RPC 2.0

CoinCync's primary programmatic interface. Spoken by the `coincync-node` daemon's jsonrpsee server (default `127.0.0.1:28081` on testnet, `127.0.0.1:19081` on mainnet) and by the public reverse proxies in front of the production fleet.

This page covers the protocol envelope, transports, and the read-only / write split. The full method inventory with parameters and return values is in [Method reference](./methods.md).

## Endpoints

| Endpoint | What it speaks | When to use |
|---|---|---|
| `http://127.0.0.1:28081` (local node) | Raw JSON-RPC 2.0 | Local development, scripts running on the same host |
| `https://api.coincync.network/rpc` | JSON-RPC 2.0 (testnet, default) | Wallets, SDKs, tooling — anywhere on the public internet |
| `https://api.coincync.network/rpc/mainnet` | JSON-RPC 2.0 (mainnet, post-launch) | Same, but explicitly targeting mainnet |
| `https://explorer.coincync.network/api/testnet` | JSON-RPC 2.0 (testnet) | The explorer's inline JS uses this; you can too |
| `https://explorer.coincync.network/api/mainnet` | JSON-RPC 2.0 (mainnet, post-launch) | Same, mainnet |

The local-node endpoint exposes the **full** RPC surface (including write methods like `submit_block` and `send_raw_transaction`). The public proxies enforce a read-only allowlist (see [REST endpoints](./rest.md) and `src/rpc/rest.rs::RPC_ALLOWED_METHODS`).

## Protocol

Standard JSON-RPC 2.0 over HTTP POST:

```bash
curl -X POST http://127.0.0.1:28081 \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"get_info","params":[]}'
```

Successful response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "version":      "1.0.0",
    "network":      "testnet",
    "height":       12345,
    "top_hash":     "26ec6abd09fd83b0...",
    "tip_hash":     "26ec6abd09fd83b0...",
    "tip_age_secs": 17,
    "synced":       true,
    "peer_count":   8,
    "tx_pool_size": 3,
    "anonymity_set": 41782,
    "effective_ring_size": 11,
    "status":       "healthy",
    "health_score": 1.0
    /* ... */
  }
}
```

Error response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code":    -32601,
    "message": "Method not found"
  }
}
```

## Error codes

| Code | Meaning |
|---|---|
| `-32600` | Invalid request (malformed envelope) |
| `-32601` | Method not found |
| `-32602` | Invalid params (bad type, out-of-range integer, etc.) |
| `-32603` | Internal error |
| `-32000` | Resource not found (e.g. block at unknown height) |
| `-32001` | Block rejected by validator (during `submit_block`) |
| `-32002` | Transaction rejected by mempool (during `send_raw_transaction`) |

## Read-only vs write methods

The public REST proxy in front of the API server enforces an allowlist that blocks every write method. **Wallets cannot submit transactions through `https://api.coincync.network/rpc`** — they must either run their own local node and use `http://127.0.0.1:28081`, or use a separate authenticated submit endpoint (currently not exposed in the P0 deployment).

This is a deliberate security tradeoff:

- **Reads are public, lots of clients, lots of inspection** — the explorer, wallet sync, third-party blockchains analyzers, monitoring dashboards. The allowlist is exhaustive on the read side.
- **Writes are sensitive and per-user** — submitting a transaction to a stranger's node trusts that node to relay rather than censor. Most wallets should submit to a local node they control. The public submit surface is reserved for a future P1 wallet-RPC stack with proper authentication.

See [REST endpoints → allowlist](./rest.md#allowlist) for the full list.

## Rate limiting

The public proxies enforce per-source-IP rate limits. The exact thresholds are documented in `deploy/api/Caddyfile` and `deploy/explorer/Caddyfile`:

- `api.coincync.network`: **30 requests/min/IP**
- `explorer.coincync.network`: **60 requests/min/IP**

A client that hits the limit gets `429 Too Many Requests`. Back off and retry — the limit is per-minute, not per-second, so spreading 30 calls evenly across 60 seconds always works. The primary purpose of these limits is **not** botnet defense — it's making industrial-rate scraping by chain-forensics firms expensive. See [Federation & DDoS](../operations/federation-and-ddos.md).

## Authentication

Public hosted read-only endpoints may be unauthenticated by deployment policy, but self-hosted nodes can require bearer auth by setting `COINCYNC_RPC_API_KEY`.

When bearer auth is enabled:

- JSON-RPC requests must include `Authorization: Bearer <token>`.
- WebSocket upgrade paths must also include the same bearer token.
- Non-upgrade `GET` requests are rejected when auth is enabled.

Even with unauthenticated public read endpoints, the allowlist and rate limits remain the baseline control plane for abuse resistance.

## Choosing a transport

| You want to... | Use this endpoint |
|---|---|
| Build a wallet that submits transactions | A local node at `http://127.0.0.1:28081` (run your own) |
| Build a read-only block explorer | `https://api.coincync.network/rpc` — public, rate-limited, free |
| Build a chain analyzer / indexer | A local node — the public proxies will rate-limit you and the bandwidth bill on your end is significant anyway |
| Embed live chain data in a web page | The explorer's inline JS already does this from `https://explorer.coincync.network/api/testnet` |
| Run a faucet | A local node next to the faucet binary, with the wallet RPC speaking to localhost |

## See also

- [REST endpoints](./rest.md) — the higher-level REST surface that wraps the JSON-RPC for browser-friendly use
- [Method reference](./methods.md) — every method, every parameter, every field
