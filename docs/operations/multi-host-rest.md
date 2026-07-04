# Multi-host REST + load-balancer failover

## What this document is

The 2026-07-02 outage — 41 hours of `api.coincync.network` returning
HTTP 504 to every public user — happened because the REST layer only
ran on one fleet host (`api`, at 95.179.165.225). When that host's
`coincync-node` process wedged in a silent-hang, the public API had
nowhere to route.

The multi-host REST work (this PR, `feat/multi-host-rest-api`) makes
REST default-on on every node so a load balancer fronting
`api.coincync.network` can health-check every fleet host and route
around a wedged one.

This document covers the operator-facing wiring: what the code changed,
what infra needs to follow, and how to test failover.

## Code changes (this PR)

**1. REST default-on with opt-out.**
`bin/node.rs` now spawns `rpc::rest::run_rest_api` on
`127.0.0.1:<rpc_port + 2>` by default on every node. Precedence:

1. `--rest-disable` — opt out (use on resource-constrained miner boxes)
2. `--rest-bind <addr>` — explicit override
3. default `127.0.0.1:<rpc_port + 2>`

Loopback default means no public exposure without an explicit nginx /
Cloudflare LB wiring. `ufw` is not touched by this change.

**2. Health probe hierarchy.**

| Endpoint | Purpose | Success | Failure |
|---|---|---|---|
| `GET /api/v1/health` | Legacy — kept for backward compat | 200 always | never |
| `GET /api/v1/health/live` | **Liveness** — is the process alive at all? Used by systemd / k8s restart-if-dead deciders. | 200 always | never (only if process fully dead) |
| `GET /api/v1/health/ready` | **Readiness** — is the node healthy enough to serve queries? Used by LB / nginx / Cloudflare route-around-if-broken deciders. | 200 iff `peer_count ≥ 3` AND `tip_age < 600s` AND jsonrpsee backend answers | 503 with JSON body naming the failed check |

Thresholds:

- `MIN_PEERS_FOR_READY = 3` — matches the fleet minimum used elsewhere
  (`sync-fleet-config.sh` peer_count ≥ 3, `feedback_no_bulk_rolling_restart`
  between-restart verification).
- `MAX_TIP_AGE_FOR_READY = 600s` — 5× the target block time (120s), so
  real chain silence gets caught but transient block-arrival gaps don't
  flip nodes out of rotation for 30s.

The readiness handler round-trips a `get_info` call to the jsonrpsee
backend. That proves BOTH REST AND the jsonrpsee event loop are
responsive — a wedged jsonrpsee (the exact 2026-07-02 failure mode) times
out here and fails the check.

**3. Existing endpoints unchanged.**
`/api/v1/status`, `/api/v1/supply`, `/api/v1/blocks/recent`, and every
other REST route works identically. `/rpc` proxy allowlist unchanged.

## Infrastructure follow-up (NOT in this PR)

### 1. Enable REST binding on every fleet host

Every host in `scripts/fleet-config.json` already runs `coincync-node`
via a systemd unit at `/etc/systemd/system/coincync-node.service`. After
this PR merges and the binary rolls out:

- REST spawns automatically on `127.0.0.1:28083` (testnet RPC port is
  28081, so REST port is 28083)
- No systemd unit change needed
- No ufw rule change needed (loopback bind)
- Verify per-host with `curl -s http://127.0.0.1:28083/api/v1/health/ready | jq .`

For miner boxes (`randomx`, `randomx2`) — either leave REST on (memory
cost is ~5MB), or set `RestDisable=true` in a systemd drop-in and pass
`--rest-disable`.

### 2. nginx: proxy from public port to loopback REST

On each host that will serve public traffic (currently just `api`, plan
to add `seed1`, `relay1`, `relay2`), edit `/etc/nginx/sites-enabled/coincync-rest`:

```nginx
upstream coincync_rest_local {
    server 127.0.0.1:28083;
    keepalive 8;
}

server {
    listen 443 ssl http2;
    server_name api.coincync.network;

    # existing SSL config...

    location / {
        proxy_pass http://coincync_rest_local;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 15s;
        proxy_connect_timeout 5s;
    }
}
```

Reload: `systemctl reload nginx`. Test:
`curl -s https://api.coincync.network/api/v1/health/ready | jq .`.

### 3. Cloudflare Load Balancer

Set up a Cloudflare Load Balancer pool including every REST-capable
host:

```
Pool: coincync-rest-testnet
  Origins:
    - api.coincync.network       (95.179.165.225:443)
    - seed1.coincync.internal    (216.128.156.239:443)
    - relay1.coincync.internal   (208.85.17.18:443)
    - relay2.coincync.internal   (70.34.250.31:443)

Health Monitor: coincync-rest-ready
  Type: HTTPS
  Path: /api/v1/health/ready
  Method: GET
  Expected code: 200
  Interval: 30s
  Timeout: 10s
  Retries: 2
  Follow-up interval on failure: 15s
```

When a host's `/api/v1/health/ready` returns 503, Cloudflare removes it
from the origin pool within one health-check interval (30s worst case)
and routes all incoming `api.coincync.network` requests to the healthy
origins.

### 4. Wildcard DNS

Add `A` records for `seed1.coincync.internal`, `relay1.coincync.internal`,
`relay2.coincync.internal` pointing at their respective IPs. Not
strictly required (Cloudflare accepts raw IP origins), but easier to
manage.

## Failover test

After Cloudflare LB is wired:

```bash
# Confirm public API is up
curl -s https://api.coincync.network/api/v1/health/ready | jq .

# Simulate api box failure (SSH to api box, kill node)
ssh root@95.179.165.225 "systemctl stop coincync-node"

# Wait 60s for Cloudflare to see 503 and pull api from pool
sleep 60

# Public API should STILL be up, served by seed1/relay1/relay2
curl -s https://api.coincync.network/api/v1/health/ready | jq .
# Expected: 200 OK with peer_count/tip_age from the surviving host

# Restore api
ssh root@95.179.165.225 "systemctl start coincync-node"

# Wait 60s + healthcheck interval
sleep 90

# Api box back in rotation; Cloudflare re-adds it
curl -s https://api.coincync.network/api/v1/health/ready | jq .
```

## What this closes and what it doesn't

**Closed:**
- Single api-host SPOF for the public RPC surface
- Silent-hang failure mode (readiness catches wedged jsonrpsee)
- No-signal-until-manual-restart pattern (LB pulls the bad host in ≤ 60s)

**NOT closed:**
- Cloudflare itself as SPOF (single CDN provider). Fix: secondary DNS
  at a second provider.
- api.coincync.network domain (single registrar). Fix: multi-registrar
  strategy.
- Faucet is still api-box-only. Fix: separate follow-up work.
- frost-coord is still api-box-only. Fix: separate follow-up work.
- Explorer HTML frontend is still explorer-box-only. Fix: static-site
  build + IPFS mirror in a separate PR.

See the "Fort Knox" architecture note (session 2026-07-04) for the full
list of remaining decentralization work.
