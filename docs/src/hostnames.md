# Hostname Reference

Public endpoints and the standard layout of a CoinCync node host. Specific
fleet host addresses are operator-only — they live in the private operator
inventory, not in this public doc.

## Public endpoints

| Subdomain | Role |
| --- | --- |
| `coincync.org` / `coincync.network` | Landing page |
| `docs.coincync.network` | Documentation site |
| `explorer.coincync.network` | Block explorer (temporarily offline) |
| `api.coincync.network` | Public JSON-RPC + REST API proxy (temporarily offline) |

The public JSON-RPC / REST and explorer endpoints are temporarily offline while
hosting is brought back up. In the meantime, connect to the P2P seed
(`2.29.34.197:28080`) and use your own node's RPC — see
[Run a node](./getting-started/run-a-node.md).

## Port map

| Port | Protocol | Purpose |
| --- | --- | --- |
| 28080 | TCP | P2P (all nodes) |
| 28081 | TCP | RPC (localhost by default; bearer auth required for POST when bound non-loopback) |
| 80 / 443 | TCP | HTTP / HTTPS (nginx on the explorer / API / landing hosts) |

## Binaries

A node host installs the binaries under `/usr/local/bin/`:

| Binary | Purpose |
| --- | --- |
| `coincync-node` | node daemon (P2P + RPC) |
| `coincync-wallet` | command-line wallet |
| `coincync-rig` | CPU miner (RandomX); live TUI via `run-solo --tui` |

## systemd services

Hosts use standardized systemd units (see [Deploying a node](./operations/deployment.md)):

- `coincync-node.service` — node daemon, auto-restart, RPC bearer key from a drop-in.
- A miner unit (for example `coincync-baseline-miner.service`) on hosts that
  mine. It depends on `coincync-node.service` and needs `COINCYNC_RPC_API_KEY`
  in its environment block to authenticate to the local node's RPC; the value is
  sourced from the matching `coincync-node.service` drop-in.

## Fleet operations

Running and redeploying the fleet is operator-only and requires SSH access to
hosts whose addresses live in the private operator inventory — not in this
public doc. For the public single-host deployment guide, see
[Deploying a node](./operations/deployment.md).
