# Hostname Reference

> **Updated:** April 22, 2026 — reflects 10-node public testnet configuration.

## Public Hostnames

| Subdomain | Host | IP | Runs |
| --- | --- | --- | --- |
| `explorer.coincync.network` | RIC | 165.245.161.62 | Explorer frontend + `/health/*` RPC proxy |
| `api.coincync.network` | TOR | 143.110.218.99 | Public JSON-RPC + REST API proxy |
| `coincync.network` (apex) | NYC3 | 45.55.32.13 | Landing page |
| `docs.coincync.network` | NYC3 | 45.55.32.13 | Documentation site |

## Testnet Nodes (10 total)

| Host | IP | Role | Services |
| --- | --- | --- | --- |
| LON | 138.68.172.80 | Miner | coincync-node, coincync-miner |
| SFO | 64.227.49.44 | Miner | coincync-node, coincync-miner |
| SYD | 170.64.142.146 | Miner | coincync-node, coincync-miner |
| NYC1 | 192.34.59.42 | Seed | coincync-node |
| NYC3 | 45.55.32.13 | Seed | coincync-node |
| FRA | 46.101.138.120 | Seed | coincync-node |
| TOR | 143.110.218.99 | Seed + API | coincync-node, nginx |
| RIC | 165.245.161.62 | Seed + Explorer | coincync-node, nginx |
| ATL | 165.245.140.113 | Seed | coincync-node |
| AMS | 164.92.153.24 | Seed | coincync-node |

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

All nodes use standardized systemd services. See [DEPLOY_RUNBOOK.md](../pages/DEPLOY_RUNBOOK.md).

## nginx Proxy (by role)

- Explorer host (RIC): `/` static explorer, `/api/*` local RPC proxy, `/health/<node>` fleet health proxy
- API host (TOR): `/rpc`, `/rpc/mainnet`, `/v1/*` public API routes
- Landing host (NYC3): `coincync.network`, `docs.coincync.network`, `mirrors.json`
