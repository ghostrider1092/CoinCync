# Deploy runbook — v1.0.13 (non-consensus binary swap)

Copy-paste sequence to build `main` @ **1.0.13** reproducibly and roll it to the
testnet fleet **one host at a time**, leaving chain state intact.

> **Scope check:** this is a *binary swap* — `deploy-node-binary.sh` replaces the
> binary and bounces systemd; it does **not** wipe chain DB. Only valid because
> 1.0.13 changes node behaviour but **not consensus** (no genesis/validation-rule
> change vs what the fleet runs). If a future change touches consensus, use the
> wipe path instead — never here.

---

## 0. Prerequisites (on a Linux box with Docker)

```bash
# Fresh clone of the authoritative repo (NOT OneDrive, NOT Windows).
git clone https://github.com/ghostrider1092/Coincync-Testnet-.git
cd Coincync-Testnet-
git checkout main
git pull

# Confirm you're at 1.0.13 with the 4 PRs merged.
grep -m1 '^version' Cargo.toml           # -> version = "1.0.13"
git log --oneline -6                      # #234/#235/#236/#237 present

# SSH key for the fleet must be present + chmod 600.
ls -l ~/.ssh/coincync_fleet
```

## 1. Reproducible build from `main`

```bash
./scripts/build-in-docker.sh
# Produces:
#   out/coincync          <- the node binary (this is what we deploy)
#   out/coincync-wallet, out/coincync-rig, out/coincync-tui-miner
#   out/SHA256SUMS

# Verify the build's own hashes.
( cd out && sha256sum -c SHA256SUMS )

# Record the node binary hash so you can confirm it landed on each host.
sha256sum out/coincync
```

**Optional (independent proof):** compare `out/SHA256SUMS` against the
`verify-reproducible` CI artifact for the same commit — they must match.

## 2. Name the binary for the deploy script

The build emits `out/coincync`; the deploy script defaults to `./out/coincync-node`.
Reconcile:

```bash
cp out/coincync out/coincync-node
```

## 3. Preview the fleet (no changes)

```bash
bash scripts/deploy-node-binary.sh --dry-run
```
This lists the hosts it would touch (reads `scripts/fleet-config.json`; the
`api` host is auto-skipped — nginx-only).

## 4. Roll one host at a time — lowest blast radius first

Deployable nodes (api excluded):

| Order | `--only` key | role | ip | why this order |
|------:|--------------|------|----|----------------|
| 1 (canary) | `relay1` | relay | 208.85.17.18 | not a seed/miner/explorer — safest to break |
| 2 | `relay2` | relay | 70.34.250.31 | second relay |
| 3 | `randomx2` | miner | 45.32.79.234 | watch block production |
| 4 | `randomx` | miner | 173.199.93.21 | primary miner |
| 5 | `explorer` | explorer | 207.148.6.50 | user-facing, not consensus |
| 6 | `seed3` | seed | 45.32.251.6 | seeds LAST, staggered — never all down |
| 7 | `seed2` | seed | 140.82.57.168 | |
| 8 | `seed1` | seed | 216.128.156.239 | public-facing seed, do last |

For **each** host, run the deploy then verify before moving on:

```bash
# Deploy one host.
BINARY=./out/coincync-node SSH_KEY=~/.ssh/coincync_fleet \
  bash scripts/deploy-node-binary.sh --only relay1

# --- VERIFY before the next host ---
IP=208.85.17.18   # this host's ip
# a) service is up
ssh -i ~/.ssh/coincync_fleet root@$IP 'systemctl is-active coincync-node'
# b) it self-reports 1.0.13
ssh -i ~/.ssh/coincync_fleet root@$IP '/usr/local/bin/coincync-node --version'
# c) the new binary's hash matches what you built
ssh -i ~/.ssh/coincync_fleet root@$IP 'sha256sum /usr/local/bin/coincync-node'
# d) it's making progress — heartbeat + tip advancing (watch ~60s)
ssh -i ~/.ssh/coincync_fleet root@$IP 'journalctl -u coincync-node -n 40 --no-pager | grep -E "heartbeat|supervisor|height"'
```

Only proceed to the next host once (a)–(d) look healthy. Watch specifically for
the **`node::heartbeat`** line continuing and **no `node::supervisor` CRITICAL** —
that's the silent-hang hardening reporting the maintenance loop is alive.

## 5. Rollback (if a host misbehaves)

**The deploy script does NOT keep an on-host backup** — it `scp`s the new binary to
`/tmp/coincync-node.new` and `mv`s it over `/usr/local/bin/coincync-node`,
overwriting the old one. So to roll back you must **redeploy the previous
known-good binary**, which means keeping it around *before* you start.

```bash
# BEFORE deploying: stash the currently-running binary as your rollback artifact.
# (Pull it from any not-yet-upgraded host, or from your last release build.)
scp -i ~/.ssh/coincync_fleet root@216.128.156.239:/usr/local/bin/coincync-node ./coincync-node.rollback

# To roll a host back, redeploy that saved binary to just that host:
BINARY=./coincync-node.rollback SSH_KEY=~/.ssh/coincync_fleet \
  bash scripts/deploy-node-binary.sh --only relay1
```
This is exactly why we go **one host at a time** — a bad binary is contained to a
single node you can immediately revert, while the rest of the fleet stays on the
known-good version.

## 6. Optional — live caste telemetry (observe only)

On any one box, run the sidecar in observe mode to watch the biomimetic castes
react to the real fleet — sends nothing, changes nothing:

```bash
ssh -i ~/.ssh/coincync_fleet root@$IP \
  'RUST_LOG=info coincync-tick --once --castes-observe'   # or without --once for a loop
```

---

## Alternative build path: cut a release tag

Instead of building locally, tag `v1.0.13` to trigger `release.yml`:

```bash
git tag v1.0.13
git push origin v1.0.13
```
Then download the Linux artifact from the release and use it as `out/coincync-node`
in step 4. (Per the release checklist, `Cargo.toml` version already matches the
tag — done in #237.)
