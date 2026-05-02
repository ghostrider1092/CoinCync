# Hostname Reference

> **Updated:** May 2, 2026 — public testnet relaunched on the new
> consensus rules (`805c07d`). Explorer host moved to LON,
> NYC3 took the active miner role, ATL demoted to seed-only.

## Public Endpoints

| Subdomain | Role |
| --- | --- |
| `explorer.coincync.network` | Block explorer (front-end + RPC proxy) |
| `api.coincync.network` | Public JSON-RPC + REST API proxy |
| `coincync.network` (apex) | Landing page + active miner |
| `docs.coincync.network` | Documentation site |

Resolve any of the above with `dig` to see the host serving it.

## Testnet Fleet (logical names)

Active on the new consensus chain (genesis `41f970df…`):

| Region | Role |
| --- | --- |
| NYC3 | **Active miner** + landing + docs |
| LON | **Public explorer host** |
| TOR | Seed1 + public API |
| RIC | Mirror explorer + relay |
| NYC1 | Mempool + relay |
| FRA | Mempool + relay |
| ATL | Seed2 + relay (former miner) |
| AMS | Seed3 + relay |
| SYD | Relay |

**Excluded from this redeploy (intentional):**

| Region | Reason |
| --- | --- |
| SFO | Divergent local history including a `--no-p2p-encryption` commit. Skipped pending operator review of whether that flag is load-bearing. Stays on its previous binary until decision is made. |

**Mining:** NYC3 runs `coincync-miner.service` with 2 vCPUs, FULL_MEM RandomX.
The service requires `COINCYNC_RPC_API_KEY` in its environment block to
authenticate to the local node's RPC; the value is sourced from the matching
`coincync-node.service` drop-in.

## Port Map

| Port | Protocol | Purpose |
| --- | --- | --- |
| 28080 | TCP | P2P (all nodes) |
| 28081 | TCP | RPC (localhost on production; bearer auth required for all POST when bound non-loopback) |
| 80 | TCP | HTTP (nginx on explorer/api/landing hosts) |
| 443 | TCP | HTTPS (nginx on explorer/api/landing hosts) |

## Binary Locations

All nodes: `/usr/local/bin/coincync-node`, `/usr/local/bin/coincync-wallet`,
`/usr/local/bin/coincync-tui-miner`. Hosts running the headless miner also
have `/usr/local/bin/coincync-miner` (NYC3 currently).

> **Avoid:** the old binary path `/root/coincync-new/target/release/...` is
> deprecated. A `/root/auto-sync.sh` cron used to respawn nodes from that
> path every 30 min; the cron has been disabled fleet-wide as of the
> 2026-05-02 redeploy. Do not re-enable without first updating the script
> to use `/usr/local/bin/`.

## systemd Services

All nodes use standardized systemd services. See [Deploying a node](./operations/deployment.md).

- `coincync-node.service` — node daemon, auto-restart, RPC bearer key from drop-in
- `coincync-miner.service` — headless miner (NYC3 only by default), depends on coincync-node

## nginx Proxy (by role)

- **Explorer host (LON):** `/` static explorer at `/var/www/explorer/`, `/api/testnet` and `/api/mainnet` proxied to local RPC, `/health/<node>` fleet health fan-out with shared bearer key
- **API host (TOR):** `/rpc`, `/rpc/mainnet`, `/v1/*` public API routes
- **Landing host (NYC3):** `coincync.network`, `docs.coincync.network`, `mirrors.json`
- **Mirror explorer (RIC):** Same `/var/www/explorer/` layout as LON; available as a failover endpoint via the operator inventory.

## Redeploy procedure

> Operator-only — requires SSH access to fleet hosts. Specific host addresses
> live in the private operator inventory, not in this public doc.

```bash
# Sync canonical source to a fleet host (operator laptop has SSH key, fleet
# does not need GitHub creds)
git push ssh://root@<host>/opt/coincync main

# On each fleet host (with --rest-bind binding RPC to 0.0.0.0):
SKIP_PULL=1 DATA_DIR=/data/seed1 bash /opt/coincync/deploy/ops/redeploy-fleet.sh

# Frontend HTML deploy is SEPARATE — only needed on the explorer host:
bash /opt/coincync/deploy/explorer/deploy-explorer.sh   # on LON
```

**Known gotcha:** the redeploy script rebuilds Rust binaries via `cargo build`
which assumes `~/.cargo/bin/cargo` exists for the repo owner. Hosts that lack
rustup (FRA, AMS at the time of the 2026-05-02 redeploy) cannot run the
script — instead, SCP the built binary from a working fleet host using SSH
aliases configured in `~/.ssh/config`:

```bash
scp lon:/usr/local/bin/coincync-node fra:/usr/local/bin/coincync-node.new
ssh fra 'mv /usr/local/bin/coincync-node.new /usr/local/bin/coincync-node && \
         chmod +x /usr/local/bin/coincync-node && \
         mv /data/seed1/testnet /data/seed1/testnet.wiped.$(date -u +%Y%m%dT%H%M%SZ) && \
         systemctl restart coincync-node'
```
