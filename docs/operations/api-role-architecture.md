# `api.coincync.network` — role architecture

**Status:** current as of 2026-06-03
**Owner:** Sebastian (project lead)
**Audience:** fleet operators, future maintainers

## What this document explains

How the public RPC endpoint (`api.coincync.network`) is wired today,
why it changed on 2026-06-03, and how to reproduce or reverse the
change.

## The 2026-06-03 migration in one sentence

The api endpoint used to be served by a coincync-node running locally
on `95.179.165.225` (955 MB Vultr box). That node OOM-looped under
sustained sync activity (RandomX dataset alone is ~2 GB), so the api
role moved to nginx-only: `95.179.165.225` keeps nginx but proxies
RPC requests to `coincync-lon` (`192.248.151.16`, 16 GB), which runs
the actual coincync-node.

## Why

Three OOM events in a single day (2026-06-03) on `95.179.165.225`:

- `Out of memory: Killed process 1235703 (coincync-node)` (dmesg)
- systemd `NRestarts=4` in an hour
- Each restart cycle: fleet briefly served stale-fork data via
  Cloudflare round-robin between healthy backends and this OOM-
  looping one, surfacing as "chain stalled" warnings on the explorer

The 955 MB tier was fundamentally too small. RandomX dataset (~2 GB
when `FLAG_FULL_MEM` is set) cannot fit. Without `FLAG_FULL_MEM`
verification falls back to LIGHT mode which is 50-100× slower per
hash; under sustained network load this also fails to keep up.

Three alternatives were evaluated:

| Option | Cost | Verdict |
|---|---|---|
| Upgrade `95.179.165.225` to a 2-4 GB Vultr tier | +$6-12/mo | Valid but requires budget approval + manual migration |
| Set `COINCYNC_RANDOMX_LIGHT_MODE=1` on the api box | $0 | Band-aid — slower validation, doesn't fully fix |
| Move api role to nginx-only, proxy to a healthy backend | $0 | **Chosen.** Architectural fix, no recurring cost. |

## Current architecture (post-migration)

```
            Cloudflare
                │
   api.coincync.network HTTPS termination
                │
                ▼
    ┌────────────────────────────┐
    │  95.179.165.225 (api box)  │
    │  ┌──────────────────────┐  │
    │  │ nginx (TLS + auth    │  │
    │  │  proxy, CORS, faucet │  │
    │  │  endpoint)           │  │
    │  └────────┬─────────────┘  │
    │           │ injects Bearer  │
    │           │ COINCYNC_RPC_   │
    │           │ API_KEY header  │
    └───────────┼─────────────────┘
                │  HTTP /rpc → port 28081
                │  cross-Vultr-internal
                ▼
    ┌────────────────────────────┐
    │  192.248.151.16            │
    │  (coincync-lon, 16 GB)     │
    │  ┌──────────────────────┐  │
    │  │ coincync-node        │  │
    │  │   --rpc-bind         │  │
    │  │   0.0.0.0:28081      │  │
    │  │   (auth required —   │  │
    │  │    nginx provides)   │  │
    │  └──────────────────────┘  │
    │  │ coincync-baseline-      │
    │  │  miner (2 threads,      │
    │  │  full-mem RandomX)      │
    │  └──────────────────────┘  │
    └────────────────────────────┘
                │
                ▼
        Vultr ufw firewall:
        port 28081 allow from
        95.179.165.225 only
```

## Key configuration

### nginx on `95.179.165.225` (the api box)

File: `/etc/nginx/sites-enabled/coincync-api`

The `proxy_pass` lines changed:

```nginx
# was:
proxy_pass http://127.0.0.1:28081;
# now:
proxy_pass http://192.248.151.16:28081;
```

The bearer-auth header (`set $coincync_rpc_key "<hex>";`) and the
`proxy_set_header Authorization "Bearer $coincync_rpc_key"` lines
are unchanged — they were already injecting the key server-side so
clients never had to know it. The upstream just changed location.

### systemd on `192.248.151.16` (coincync-lon)

File: `/etc/systemd/system/coincync-node.service`

Added:

```ini
Environment=COINCYNC_RPC_API_KEY=<same hex as nginx uses>
ExecStart=/usr/local/bin/coincync-node --network testnet --data-dir /var/lib/coincync \
    --rpc-bind 0.0.0.0:28081 \
    ...
```

The `--rpc-bind 0.0.0.0:28081` change requires the `COINCYNC_RPC_API_KEY`
env to be set — the node refuses to start a non-loopback RPC bind
without authentication (security check in
[src/rpc/server.rs](../../src/rpc/server.rs); good design).

### Firewall on `192.248.151.16`

```bash
ufw allow from 95.179.165.225 to any port 28081 proto tcp comment 'coincync-api proxy'
```

Only the api box can reach lon's RPC port externally. Anyone else
gets refused at the firewall layer. The bearer-auth requirement
inside the node is the second line of defense.

### systemd on `95.179.165.225` (the api box)

```bash
systemctl stop coincync-node coincync-rig coincync-baseline-miner
systemctl disable coincync-node coincync-rig coincync-baseline-miner
```

These services existed on this box for historical reasons. None of
them are needed in the new architecture — the box is RPC frontend
only.

## What still runs on `95.179.165.225`

After the migration:

- `nginx` (RPC proxy + faucet endpoint + TLS)
- `coincync-faucet` (lightweight, ~30 MB RSS)
- `coincync-frost-coord` (lightweight, ~30 MB RSS)
- Standard system services

Memory footprint: ~270 MB used / 687 MB available out of 955 MB
total. Plenty of headroom for the role.

## Operational implications

### Deploy script

`scripts/deploy-node-binary.sh` no longer includes `95.179.165.225`
in its default FLEET list. Future binary deploys should NOT include
this box because it doesn't run coincync-node anymore. If we ever
upgrade its Vultr tier and want it back in the node fleet, add it
back to the FLEET list.

### Public addnode lists

`docs/src/getting-started/run-a-node.md` and
`docs/src/operations/bootstrap-from-snapshot.md` both list
`95.179.165.225:28080` as a fleet seed in the `--addnode` lists.
**Keep these as-is for now** — even though the box doesn't run
coincync-node, the addnode entry just causes a TCP connect failure
which the dialing node handles gracefully. Removing the entries
would be a bigger doc churn for marginal benefit.

If we ever decommission the api box entirely (move faucet +
frost-coord elsewhere too), then prune the addnode lists.

### Single point of failure

The new architecture has `coincync-lon` as a single backend for
the api endpoint. If lon goes down, the api endpoint goes down.

This is acceptable for a testnet but should be addressed before
mainnet (Oct 1, 2026). Two options for HA:

1. **nginx upstream block** with multiple backends + health checks.
   Need >= 2 fleet boxes with exposed RPC + auth.
2. **Cloudflare load balancer** between multiple direct backends.
   Requires Cloudflare LB add-on ($).

Either way, requires expanding the "expose RPC over the network
with auth" pattern to more boxes. Tracked as v1.0.11+ ops work.

## Reverting

If we ever need to revert (e.g., the cross-Vultr-internal hop adds
unacceptable latency, or coincync-lon proves unreliable):

```bash
# On api box (95.179.165.225)
sed -i 's|proxy_pass http://192.248.151.16:28081|proxy_pass http://127.0.0.1:28081|g' \
    /etc/nginx/sites-enabled/coincync-api
nginx -t && systemctl reload nginx

# Restart coincync-node
systemctl enable --now coincync-node

# On coincync-lon: revert RPC to loopback
sed -i 's|--rpc-bind 0.0.0.0:28081|--rpc-bind 127.0.0.1:28081|' \
    /etc/systemd/system/coincync-node.service
systemctl daemon-reload && systemctl restart coincync-node

# Remove ufw rule (optional, leaving it costs nothing)
ufw delete allow from 95.179.165.225 to any port 28081 proto tcp
```

Then re-add `95.179.165.225` to the FLEET list in
`scripts/deploy-node-binary.sh`.

## Related decisions / context

- `[[hybrid-sync-speedup-plan-2026-05-31]]` (the chaindata-tarball
  bootstrap path) is unaffected — nodes still self-host the chain
  data, the api endpoint is just one of many ways operators query
  the network.
- The architectural separation of "node operator" (runs coincync-
  node) vs "service operator" (runs nginx, faucet, etc.) is
  precedent for the v2.0 separation of consensus nodes from
  light-client / API providers.
