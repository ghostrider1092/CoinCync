# Public RPC API host

How to run the public JSON-RPC + REST API at `https://api.coincync.network`. Lives in [`/deploy/api/`](https://github.com/CoinCync/Coincync-Testnet-/tree/main/deploy/api).

Architecturally identical to [`/deploy/explorer/`](./explorer.md), with three differences calibrated for an API audience instead of a human-browser audience:

| | `deploy/explorer/` | `deploy/api/` |
| --- | --- | --- |
| Audience | humans (browsers) | machines (wallets, SDKs, bots) |
| Rate limit | 60/min/IP (lenient) | **30/min/IP (strict)** |
| Body shape | HTML + static assets + JSON | JSON-only |
| CORS | required (CDN allowlist) | **none** (server-to-server) |
| Caching | aggressive on static assets | **no caching** |
| Host | RIC (165.245.161.62) | **Toronto (143.110.218.99)** |

The strict per-IP limit is calibrated for machine clients. A wallet polling `get_info` once per block (every 120 seconds) uses 0.5 req/min — two orders of magnitude under the limit. Anything faster than ~30 req/min sustained is either a bug or a chain-analysis scraper, and slowing them down is a feature, not a bug.

## URL surface

| Public URL | Backend | Purpose |
| --- | --- | --- |
| `POST /rpc` | `127.0.0.1:28083` (rest.rs proxy → testnet jsonrpsee) | Default JSON-RPC 2.0, testnet |
| `POST /rpc/mainnet` | `127.0.0.1:19083` (post-launch) | JSON-RPC 2.0, mainnet |
| `GET  /v1/status` | REST | Chain status, height, tip |
| `GET  /v1/blocks/recent` | REST | Latest blocks (paginated) |
| `GET  /v1/block/height/{h}` | REST | Block by height |
| `GET  /v1/block/hash/{hash}` | REST | Block by hash |
| `GET  /v1/anonymity` | REST | Anonymity-set size + ring stats |
| `GET  /v1/peers` | REST | Connected peer list |
| `GET  /v1/supply` | REST | Emission curve + total supply |
| `GET  /v1/events` | REST | Recent reorgs / forks / rejects |
| `GET  /` | inline HTML | Developer landing — points at explorer + curl examples |

Every method is **read-only**. The REST proxy in `src/rpc/rest.rs::RPC_ALLOWED_METHODS` enforces this server-side; `submit_block`, `send_raw_transaction`, `get_mining_live`, and any other write or fingerprint-sensitive method returns 403 Forbidden.

## First-time deploy

On the API host (Toronto, `143.110.218.99`):

```bash
# 1. Pre-flight: cyncd RPC + REST bound to localhost only.
ss -tlnp | grep -E ':(28080|28081|28083) '
# Expect:
#   0.0.0.0:28080      ← P2P (this host is also seed1, so P2P is public)
#   127.0.0.1:28081    ← jsonrpsee, localhost only
#   127.0.0.1:28083    ← REST (rest.rs), localhost only

# 2. Open 80/443 in DigitalOcean firewall. Do NOT open 28081 / 28083 / 19081 / 19083.
# 3. Deploy
cd /opt/coincync
git pull --ff-only
cd deploy/api
docker compose up -d
docker compose logs -f caddy
```

## Verification

```bash
# JSON-RPC works (testnet by default)
curl -sX POST https://api.coincync.network/rpc \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' | jq .

# REST works
curl -s https://api.coincync.network/v1/status | jq .

# Write methods are blocked (allowlist enforced server-side)
curl -sX POST https://api.coincync.network/rpc \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"submit_block","params":["00..."]}' \
     -w '\n%{http_code}\n'
# expect: 403 (or a JSON-RPC error)

# Mainnet pre-launch returns 502 (no upstream until October 2026)
curl -sX POST https://api.coincync.network/rpc/mainnet \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' -w '\n%{http_code}\n'
```

## Mainnet launch (Oct 1, 2026)

The Caddyfile already has the `/rpc/mainnet` upstream pool defined. To activate:

1. Start a `coincync-node --network mainnet --rpc-bind 127.0.0.1:19081 --rest-bind 127.0.0.1:19083` instance on this host.
2. `docker compose restart caddy`.
3. Verify with `curl https://api.coincync.network/rpc/mainnet`.

## Federation

When traffic on the public API outgrows what one Toronto host can handle, the right answer is a second API host with `api2.coincync.network` pointing at it. **Not** a CDN. The full reasoning is in [Federation & DDoS](./federation-and-ddos.md). The Caddyfile is parameterized so a second operator can drop in a new deployment with a different hostname.

## See also

- [Block explorer](./explorer.md) — the parallel deployment for `explorer.coincync.network`
- [Federation & DDoS](./federation-and-ddos.md) — why this isn't behind Cloudflare
- [JSON-RPC reference](../api/json-rpc.md) — what the API actually exposes
