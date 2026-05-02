# Hostname Reference

> **Updated:** May 1, 2026 — miner role moved from ATL to NYC3 alongside the
> consensus-rules redeploy (commit `805c07d` bound RandomX genesis to network).

## Public Hostnames

| Subdomain | Host | IP | Runs |
| --- | --- | --- | --- |
| `explorer.coincync.network` | RIC | 165.245.161.62 | Explorer frontend + `/health/*` RPC proxy |
| `api.coincync.network` | TOR | 143.110.218.99 | Public JSON-RPC + REST API proxy |
| `coincync.network` (apex) | NYC3 | 45.55.32.13 | Landing page + miner |
| `docs.coincync.network` | NYC3 | 45.55.32.13 | Documentation site |

## Testnet Nodes (active 7)

| Host | IP | Role | Services |
| --- | --- | --- | --- |
| NYC1 | 192.34.59.42 | Mempool + relay | coincync-node |
| FRA | 46.101.138.120 | Mempool + relay | coincync-node |
| TOR | 143.110.218.99 | Seed1 + public API | coincync-node, nginx |
| RIC | 165.245.161.62 | Explorer + relay | coincync-node, nginx |
| NYC3 | 45.55.32.13 | Miner + landing + docs | coincync-node, coincync-miner, nginx |
| ATL | 165.245.140.113 | Seed2 + relay | coincync-node |
| AMS | 164.92.153.24 | Seed3 + relay | coincync-node |

## Port Map

| Port | Protocol | Purpose |
| --- | --- | --- |
| 28080 | TCP | P2P (all nodes) |
| 28081 | TCP | RPC (bound to 0.0.0.0 on all nodes) |
| 80 | TCP | HTTP (nginx on explorer/api/landing hosts) |
| 443 | TCP | HTTPS (nginx on explorer/api/landing hosts) |

## Binary Location

All nodes: `/usr/local/bin/coincync-node`, `/usr/local/bin/coincync-miner`

## systemd Services

All nodes use standardized systemd services. See [Deploying a node](./operations/deployment.md).

## nginx Proxy (by role)

- Explorer host (RIC): `/` static explorer, `/api/*` local RPC proxy, `/health/<node>` fleet health proxy
- API host (TOR): `/rpc`, `/rpc/mainnet`, `/v1/*` public API routes
- Landing host (NYC3): `coincync.network`, `docs.coincync.network`, `mirrors.json`
