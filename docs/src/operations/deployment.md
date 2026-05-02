# Deploying a node

The runbook for putting a CoinCync node into production. Three deployment patterns: **systemd** (the canonical Linux way), **docker compose** (the easier-to-reproduce way), and **manual** (for development). Pick whichever matches your operational style.

## Pre-deployment checklist

Before deploying any node to a public host, confirm:

- [ ] **Hardware**: 2 vCPUs, 4 GB RAM, 80 GB SSD. The chain grows by ~50 MB/day on testnet — provision accordingly.
- [ ] **OS**: Ubuntu 22.04 / Debian 12 / equivalent. CoinCync builds on macOS and Windows but the production deployment story is Linux.
- [ ] **Cloud firewall** (DigitalOcean / AWS / Hetzner / etc.): allow only the ports you intend to expose. Default deny everything else.
  - **P2P port** (28080 testnet / 19080 mainnet) — must be public for the node to accept inbound peer connections
  - **RPC port** (28081 / 19081) — **never** public; bind to 127.0.0.1
  - **REST port** (28083 / 19083, optional) — never public
  - **Metrics port** (9091, optional) — never public; if you want metrics scraped from another host, use SSH tunneling or WireGuard
  - **nginx** (80 + 443) — only on hosts that run public web ingress; see [Block explorer](./explorer.md), [Public RPC API](./api-host.md), or [the landing/docs deployment](./deployment.md#nyc-landing--docs).
- [ ] **DNS** pointing at the host (if you want a public hostname).
- [ ] **Time synchronization**: `chronyd` or `systemd-timesyncd` running. PoW timestamp validation has a 10-minute drift window; a clock that's off by more than that will reject incoming blocks.

## Pattern A: systemd

The canonical production deployment for a single-node host.

### 1. Build the binaries

On your build host (could be the deployment target itself, or a dev machine):

```bash
git clone https://github.com/CoinCync/Coincync-Testnet-.git /opt/coincync
cd /opt/coincync
cargo build --release --features "randomx testnet"
```

For a mainnet host, swap `testnet` for `mainnet`. (Or build with `--features "randomx testnet mainnet"` and select at runtime via `--network`.)

### 2. Install the binaries

```bash
sudo install -m 0755 target/release/coincync-node /usr/local/bin/coincync-node
sudo install -m 0755 target/release/coincync-wallet /usr/local/bin/coincync-wallet
# coincync-miner only on hosts that will mine
```

### 3. Create the service user and data directory

```bash
sudo useradd -r -s /bin/false coincync
sudo mkdir -p /var/lib/coincync
sudo chown coincync:coincync /var/lib/coincync
sudo chmod 0700 /var/lib/coincync
```

### 4. Install the systemd unit

The unit file lives at [`/deploy/coincync-node.service`](https://github.com/CoinCync/Coincync-Testnet-/blob/main/deploy/coincync-node.service):

```bash
sudo install -m 0644 deploy/coincync-node.service /etc/systemd/system/coincync-node.service
sudo systemctl daemon-reload
sudo systemctl enable --now coincync-node
sudo systemctl status coincync-node
```

The unit:

- Runs as the `coincync` system user (no shell, no home directory)
- Writes to `/var/lib/coincync` only — `ProtectSystem=strict`, `ReadWritePaths=/var/lib/coincync`
- Drops capabilities: `NoNewPrivileges`, `PrivateTmp`, `ProtectHome`
- Restarts on failure with a 10-second backoff
- Logs to journald with the `coincync-node` syslog identifier

### 5. Verify

```bash
journalctl -u coincync-node -f
# Watch for: "Node is running. Ctrl-C to stop." (the systemd version doesn't actually want Ctrl-C, just confirms the startup completed)

curl -sX POST http://127.0.0.1:28081 \
     -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' | jq .
```

If `get_info` returns the chain tip, the node is live.

## Pattern B: docker compose

Easier to reproduce, easier to roll back, easier to run multiple variants on the same host. The docker compose file lives at [`/deploy/docker-compose.yml`](https://github.com/CoinCync/Coincync-Testnet-/blob/main/deploy/docker-compose.yml).

```bash
git clone https://github.com/CoinCync/Coincync-Testnet-.git /opt/coincync
cd /opt/coincync
docker compose pull
docker compose up -d
docker compose logs -f node
```

This compose file builds the node from source on first run and caches the image. Updates are `git pull && docker compose up -d --build`.

### Profiles

The compose file ships several optional profiles for hosts that play specific roles:

| Profile | Adds | Run on |
|---|---|---|
| (default) | just the relay node | every node |
| `mining` | the `coincync-miner` daemon | hosts that mine (one is enough; running on every host is wasteful) |
| `faucet` | the testnet faucet HTTP service | one host (the faucet host) |
| `monitoring` | Prometheus + Grafana | one host (the monitoring host) |
| `explorer` | a separate explorer service via [`/deploy/explorer/`](./explorer.md) | the explorer host |

Activate a profile with `docker compose --profile mining up -d`.

## Pattern C: manual (development)

```bash
cd /path/to/Coincync-Testnet-
./target/release/coincync-node --network testnet --data-dir ~/.coincync
```

For development only. Doesn't survive reboot, doesn't restart on crash, doesn't run as an unprivileged user. See [getting-started/run-a-node.md](../getting-started/run-a-node.md) for the developer workflow.

## RPC binding rules

The single most important security rule:

> **The RPC port (28081 / 19081) MUST NOT be bound to a public interface in production.**

Public deployments bind RPC to `127.0.0.1` only. The nginx configs in `deploy/explorer/`, `deploy/api/`, and `deploy/landing/` are the *only* public-facing HTTP services. nginx reverse-proxies allowlisted requests to the localhost RPC.

If you bind RPC publicly, you've defeated the purpose of every ingress security control:

- The REST allowlist that blocks write methods → bypassable by going straight to RPC
- The rate limit → bypassable
- TLS termination → bypassable
- The Cloudflare-like compliance avoidance argument → moot, because everyone can hit your RPC directly

Verify after deployment:

```bash
ss -tlnp | grep -E '28081|19081|28083|19083|9091'
```

Every match should be `127.0.0.1:port`, never `0.0.0.0:port`. The only `0.0.0.0` listeners on a production node should be:

- `28080` / `19080` — P2P port, deliberately public
- `80` / `443` — nginx, on hosts that run public web ingress

## Stratum banlist operations

If you run Stratum (`coincync-miner` pool mode), abuse tracking now persists across restarts.

- Banlist file path:
  - `COINCYNC_STRATUM_BANLIST_PATH=/var/lib/coincync/stratum_bans.json`
  - default if unset: `stratum_bans.json` in the process working directory

Use the built-in maintenance tool:

```bash
# View entries
cargo run --bin stratum_ban_tool -- list --file /var/lib/coincync/stratum_bans.json

# Remove one IP
cargo run --bin stratum_ban_tool -- clear-ip --file /var/lib/coincync/stratum_bans.json --ip 203.0.113.10

# Remove expired bans
cargo run --bin stratum_ban_tool -- clear-expired --file /var/lib/coincync/stratum_bans.json

# Clear all entries
cargo run --bin stratum_ban_tool -- clear-all --file /var/lib/coincync/stratum_bans.json
```

Operational recommendations:

- Keep banlist under the node data dir (`/var/lib/coincync`) with `0600`/`0640`-style permissions.
- Rotate/clear expired bans as part of routine host maintenance.
- If you expose Stratum publicly, keep `COINCYNC_STRATUM_PASSWORD` set and ensure encrypted transport (prefer native TLS; upstream TLS termination is accepted with explicit acknowledgement).

### Stratum hardening env reference

For public Stratum exposure, CoinCync now enforces explicit transport/security intent. Use this as the operator checklist:

- `COINCYNC_STRATUM_PUBLIC_BIND=1`
  - Requests public bind (`0.0.0.0:3333`).
  - If unset, Stratum defaults to loopback-only.
- `COINCYNC_STRATUM_PUBLIC_BIND_ACK=1`
  - Mandatory acknowledgement before any public bind is allowed.
- `COINCYNC_STRATUM_PASSWORD=<strong-secret>`
  - Mandatory for public Stratum; workers must authorize.
- `COINCYNC_STRATUM_TLS_ENABLED=1`
  - Enables native TLS transport inside Stratum.
  - Optional cert/key paths:
    - `COINCYNC_STRATUM_TLS_CERT_PATH=/path/to/cert.pem`
    - `COINCYNC_STRATUM_TLS_KEY_PATH=/path/to/key.pem`
  - If cert/key are not provided, Stratum auto-generates a self-signed pair under:
    - `COINCYNC_STRATUM_TLS_DATA_DIR` (default `.coincync/stratum-tls`)
- `COINCYNC_STRATUM_TLS_PROXY_ACK=1`
  - Use this only when TLS is terminated by a trusted reverse proxy/L4 terminator.
  - Required for public bind when native TLS is not enabled.

Secure combinations:

- **Recommended (native TLS):**
  - `COINCYNC_STRATUM_PUBLIC_BIND=1`
  - `COINCYNC_STRATUM_PUBLIC_BIND_ACK=1`
  - `COINCYNC_STRATUM_PASSWORD=...`
  - `COINCYNC_STRATUM_TLS_ENABLED=1`
- **Accepted (external TLS terminator):**
  - `COINCYNC_STRATUM_PUBLIC_BIND=1`
  - `COINCYNC_STRATUM_PUBLIC_BIND_ACK=1`
  - `COINCYNC_STRATUM_PASSWORD=...`
  - `COINCYNC_STRATUM_TLS_PROXY_ACK=1`

Quick verification:

```bash
curl -sX POST http://127.0.0.1:28081 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' | jq '.result | {
    stratum_public_bind_requested,
    stratum_public_bind_ack,
    stratum_native_tls_enabled,
    stratum_tls_proxy_ack,
    stratum_transport_hardened
  }'
```

`stratum_transport_hardened` should be `true` for production profiles.

### Pool public bind hardening envs

Pool service exposure uses explicit acknowledgements similar to Stratum:

- `COINCYNC_POOL_PUBLIC_BIND_ACK=1`
  - Required before the pool may bind publicly.
- `COINCYNC_POOL_TLS_PROXY_ACK=1`
  - Required for public pool exposure when TLS is terminated by a trusted upstream proxy.

If these are not set, keep pool endpoints loopback-only.

## Network roles

Most production nodes do exactly one of these. Specializing per host limits blast radius.

| Role | What runs there | Public ports | Example host |
|---|---|---|---|
| **Seed node** | cyncd | 28080 (P2P) | seed1, seed2, seed3 |
| **Explorer host** | cyncd + nginx + explorer assets | 80, 443, 28080 | LON (current public host) |
| **API host** | cyncd + nginx (REST/RPC proxy) | 80, 443, 28080 | TOR |
| **Miner** | cyncd + coincync-miner | 28080 | NYC3 |
| **Faucet** | cyncd + faucet HTTP service | 28080, 8080 (faucet UI) | (operator-assigned host) |
| **Landing/docs** | nginx (no cyncd needed) | 80, 443 | NYC3 |
| **Monitoring** | Prometheus + Grafana | (no public DNS) | (operator-assigned host) |

Splitting roles across hosts is the same federation strategy explained in [Federation & DDoS](./federation-and-ddos.md). One host going down only affects one role.

## Updates

```bash
cd /opt/coincync
git fetch
git log HEAD..origin/main --oneline   # review what's about to come in
git pull --ff-only

# systemd:
cargo build --release --features "randomx testnet"
sudo install -m 0755 target/release/coincync-node /usr/local/bin/coincync-node
sudo systemctl restart coincync-node

# docker compose:
docker compose build
docker compose up -d
```

The chain database survives across upgrades — the on-disk format is stable. If a future upgrade ever changes the database format, the upgrade notes will say so explicitly and the node will refuse to start with a clear error rather than corrupting state.

## Backups

Three things to back up:

1. **Wallet files** (`~/.coincync/wallets/*.wallet`) — encrypted, but lose the password and they're gone forever. Back up the *encrypted file* AND the *password*, separately.
2. **Wallet seed phrases** — the 24-word BIP39 mnemonic. Paper, fireproof safe, ideally two copies in different locations.
3. **Node identity** (`~/.coincync/node_key`) — the Noise XX static key that gives this node its persistent peer ID. Optional to back up; if you lose it, the node generates a new one and gets a new peer ID.

The chain database does NOT need backing up — it can always be re-synced from the network.

## Next reading

- [Signed bootstrap manifest](./bootstrap-signed-manifest.md) — authenticated peer bootstrap with Ed25519-signed seed lists
- [Block explorer](./explorer.md) — running the public explorer nginx stack
- [Public RPC API](./api-host.md) — running the public API nginx stack
- [Federation & DDoS](./federation-and-ddos.md) — why each role is on its own host
- [Tor hidden services](./tor.md) — adding `.onion` availability
