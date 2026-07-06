# coincync-tick — deployment runbook

The `coincync-tick` health/colony sidecar. **Additive and read-only:** it
monitors the local node over RPC + `/proc` and reports health; it **never
restarts or touches `coincync-node`.** So this is not a chain/node restart —
it installs a new unit beside the running node.

## Prerequisites

1. **#206 merged to `main`** (the sidecar binary + `deploy/coincync-tick.service`
   + `deploy/coincync-tick.config.example.toml` are on `main`).
2. A **Linux x86_64 build** of `coincync-tick`, produced by the normal prod
   build path (release CI / Linux build host — not the Windows dev box). The
   binary lands in `out/coincync-tick` like the node binary does.
3. Fleet SSH access (`~/.ssh/coincync_fleet`).

## Per host — ONE AT A TIME

For each fleet host `$H` (verify health before moving to the next):

```sh
# 1. Copy the three artifacts to the host's /tmp
scp -i ~/.ssh/coincync_fleet \
  out/coincync-tick \
  deploy/coincync-tick.service \
  deploy/coincync-tick.config.example.toml \
  scripts/install-tick.sh \
  root@$H:/tmp/

# 2. Install (personal mode; use fleet on the ONE aggregator box)
ssh -i ~/.ssh/coincync_fleet root@$H \
  'DEPLOYMENT_MODE=personal bash /tmp/install-tick.sh'

# 3. Verify it is reporting health, THEN move to the next host
ssh -i ~/.ssh/coincync_fleet root@$H \
  'journalctl -u coincync-tick.service -n 15 --no-pager'
```

`install-tick.sh` is idempotent (re-run to upgrade), runs the sidecar as
`User=coincync` (shares the node's RPC token), and **starts only the sidecar
unit — the node service is never restarted.**

## Enabling the colony forager (optional, later)

The colony forager/sensor are **off by default**. To turn on observe-mode
(read-only; logs recommendations, sends nothing), add `--colony-observe` to
`ExecStart` in the service unit and `systemctl restart coincync-tick`.

## Rollback

```sh
ssh -i ~/.ssh/coincync_fleet root@$H \
  'systemctl disable --now coincync-tick.service && rm -f /usr/local/bin/coincync-tick'
```

Removing the sidecar has zero effect on the node (it was never coupled to it).
