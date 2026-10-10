# Fleet guardrails

Built after the **2026-10-10 testnet outage**, where the public fleet was taken
down by two avoidable failure modes. These tools stop both from recurring.

## What went wrong

1. **Concurrent deploys stomped each other.** Two operators/sessions managed the
   same boxes (same IP, same `coincync_fleet` key) at once. One session's deploy
   `systemctl stop`ped every node and **overwrote the installed binary** while the
   other was mid-rollout. The fleet flapped and then crash-looped.
2. **A broken/wrong-chain binary got installed.** The binary that landed was a
   different build that **segfaulted on startup** → `status=11/SEGV` restart loop
   on every node. Nothing checked the binary before installing it.
3. **Nodes silently wedged in IBD.** Some relays froze with the download
   scheduler spinning `Recovered N stuck downloads (no pending_request)` without
   advancing, while peers were far ahead. Only a manual restart cleared it.

## The guardrails

### 1. `safe-deploy.sh` — guarded deploys (prevents #1 and #2)

Use this instead of raw `scp binary + systemctl restart`:

```bash
bash deploy/fleet/safe-deploy.sh ./coincync-node 2.29.34.197 37.27.185.37 77.42.64.199 89.167.93.52 89.167.113.125
```

Per host it:
- **Takes an advisory lock** (`/run/coincync-deploy.lock`, holder + timestamp).
  If another operator holds a fresh lock it **refuses** (exit 75) — no more
  concurrent stomps. `FORCE_LOCK=1` steals a lock you're sure is dead.
- **Preflights the binary**: the staged binary must run `--version` cleanly
  (catches the segfault, exit 76) **and** print a testnet consensus fingerprint
  equal to `expected_consensus_fingerprint_testnet` in
  [`scripts/fleet-config.json`](../../scripts/fleet-config.json) (catches a
  wrong build/chain, exit 77). Only then does it install.
- Restarts, confirms the node stays `active`, and appends a line to
  `/var/log/coincync/deploy.journal` (who / sha / fingerprint / when).

Bump `expected_consensus_fingerprint_testnet` **only** on an intentional
consensus relaunch, in the same commit that changes the locked consensus files.

### 2. `coincync-sync-watchdog` — IBD self-heal (prevents #3)

A systemd timer on each node (every 2 min). If height hasn't advanced for
`STALL_SECS` (default 300s) while the node is still **behind its sync target**,
it restarts `coincync-node`. It is rate-limited (`MIN_RESTART_GAP`, default
600s), does nothing when synced/progressing, defers to systemd on a crash loop,
and skips while a deploy lock is held (`ConditionPathExists=!/run/coincync-deploy.lock`).

Install on every node:

```bash
bash deploy/fleet/install-watchdog.sh 2.29.34.197 37.27.185.37 77.42.64.199 89.167.93.52 89.167.113.125
```

Check it: `systemctl list-timers coincync-sync-watchdog.timer` and
`journalctl -t coincync-watchdog`.

## Still the operator's job

- **One driver at a time.** The lock stops *accidental* concurrency; it is not a
  substitute for not running two deploy sessions on purpose.
- Keep `scripts/fleet-config.json`, the explorer node arrays
  (`src/explorer/app/{01-core,07-map,08-globe-network,15-operator-tools}.js`),
  and `TESTNET_SEED_NODES`/`TESTNET_FALLBACK` in sync when the fleet changes.
- The watchdog is a *mitigation* for the IBD stall, not the root-cause fix — see
  the IBD download-scheduler work for the real fix.
