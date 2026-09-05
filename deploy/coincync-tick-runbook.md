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

## Enabling the caste suite + act-phase spine (optional, later)

The biomimetic castes and the honeybee→guards spine run under
`--castes-observe`. Like everything in this sidecar it is **log-only**: it logs
each caste's detection and the quorum-gated verdict, and changes no node
behaviour. There is no "act" — the guard decision is printed, never enforced.

The flags stack; each is off by default:

| Flag | What it adds |
|---|---|
| `--colony-observe` | forager scores peers by public block/tip signals, logs the ranking |
| `--colony-advise` | + logs the peer-preference it *would* advise (implies observe) |
| `--castes-observe` | the full caste suite **and the honeybee→guards spine** — logs each caste's detection *and* the quorum-gated verdict |

To enable, add the flag to `ExecStart` and restart:

```
ExecStart=/usr/local/bin/coincync-tick --config /etc/coincync-tick/config.toml --interval 30 --castes-observe
```

Watch the spine's verdict line:

```sh
journalctl -u coincync-tick -f | grep colony/spine
```

- `colony/spine: no threat reached quorum confidence — nothing would act` is the
  normal state, and the whole point: a single caste's detection (which an
  attacker can influence) is deliberately not enough. Confidence only rises with
  **independent, cross-dimension corroboration** beyond the fault budget.
- When a threat *is* corroborated you'll see either
  `WOULD act (not applied; act wiring is a later phase)` or
  `guard withheld the response` with the reason (`WouldBreakDiversityFloor`,
  `RateLimited`, `BelowConfidence`, `KillSwitch`).

**`spider`/`sensor` need a fleet aggregate to produce evidence**, so on a
personal single-host node the spine will almost always log "nothing would act".
Run `deployment_mode = "fleet"` on the aggregator box (with a
`fleet-config.json`) to give it a real aggregate and per-host evidence that can
actually reach quorum.

Rollout: enable `--castes-observe` on your own node first (confirm it runs and
read the format), then on the fleet aggregator, and watch the `colony/spine`
lines over days. Each `WOULD act` is the colony telling you what it would do —
the observe-mode validation set that must look right *before* any future,
separately-reviewed phase is allowed to enforce. Do not enable enforcement
before mainnet; it needs this data plus an adversarial multi-caste interaction
test.

**Off switch:** remove `--castes-observe` and restart, or stop the service. (The
guards' kill switch lives in the core for the future act phase; it is not yet a
runtime operator toggle because nothing enforces today.)

## Rollback

```sh
ssh -i ~/.ssh/coincync_fleet root@$H \
  'systemctl disable --now coincync-tick.service && rm -f /usr/local/bin/coincync-tick'
```

Removing the sidecar has zero effect on the node (it was never coupled to it).
