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
bash deploy/fleet/safe-deploy.sh ./coincync-node 2.29.34.197 37.27.185.37 77.42.64.199 89.167.93.52 2.31.63.25 5.161.214.98
```

The 6 seed/relay boxes above are the current backbone (hel1 seed + hel2/hel3/hel4
+ nbg1 + ash1), matching `nodes` in [`scripts/fleet-config.json`](../../scripts/fleet-config.json).
The miner rig `62.238.121.186` is **not** a P2P node (it mines via an RPC tunnel) —
do not deploy the node binary to it. `89.167.113.125` (old hel5) is decommissioned.

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
bash deploy/fleet/install-watchdog.sh 2.29.34.197 37.27.185.37 77.42.64.199 89.167.93.52 2.31.63.25 5.161.214.98
```

Check it: `systemctl list-timers coincync-sync-watchdog.timer` and
`journalctl -t coincync-watchdog`.

### 3. Miner boxes — reserve huge pages (~2x hashrate)

Full-mem miner boxes (`coincync-fullmem-miner.service` / `coincync-rig run-solo`,
e.g. the rig `62.238.121.186`) run the ~2.3 GB RandomX dataset. On 4 KB pages
that thrashes the TLB — the ~2x gap a tester measured vs XMRig. Reserve 2 MB huge
pages once per miner box (persists across reboot):

```bash
sudo cp deploy/60-coincync-hugepages.conf /etc/sysctl.d/ && sudo sysctl --system
grep HugePages /proc/meminfo   # expect HugePages_Total: 1280
```

Then install the rig binary (built `--features testnet`, full-mem) and restart
`coincync-fullmem-miner`. The rig **requests** huge pages and falls back to 4 KB
with a loud warning if none are reserved — it never hard-fails, just mines slower.
Light-mode validating nodes don't build the dataset, so this is a miner-only step.

### 4. `coincync-hugepage-guard` — keep the huge-page fallback from sitting silently

Reserving huge pages (step 3) is not self-healing. At a RandomX epoch key-change
the rig rebuilds the ~2 GB dataset while the previous epoch's dataset (and/or the
background prewarm) still holds the reserved pages, so the new dataset's
`FLAG_LARGE_PAGES` allocation can fail and the rig falls back to 4 KB — logging
`Falling back to 4 KB pages` — and does **not** retry until a restart. Seen live
2026-11-14 on both full-mem miners at the same epoch; one ran ~16% slow for ~3
days before anyone noticed.

A systemd timer on each miner box (every 2 min) detects the fallback — huge pages
reserved but the pool sits ~unused (`HugePages_Free ≈ Total`) while the miner is
active — and restarts the miner so it re-grabs them. It is heavily guarded against
hot-looping: the fallback must persist past `DEGRADED_SECS` (default 180s, longer
than one dataset rebuild), the pool must actually be free enough for a rebuild to
re-grab it, restarts are rate-limited (`MIN_RESTART_GAP`, default 2h), and it
no-ops when huge pages aren't reserved, large pages are already engaged, or the
miner is down. It skips while a deploy lock is held.

Install on the full-mem miner boxes only:

```bash
bash deploy/fleet/install-hugepage-guard.sh <miner-host> [miner-host...]
```

Check it: `systemctl list-timers coincync-hugepage-guard.timer` and
`journalctl -t coincync-hugepage-guard`. The miner unit defaults to
`coincync-baseline-miner` (override `COINCYNC_MINER_UNIT`).

This is the safety net, not the cure — the root fix belongs in the rig's dataset
builder (free the old epoch's huge pages before the new-epoch large-page
allocation, so the steady-state dataset is always on huge pages).

## Still the operator's job

- **One driver at a time.** The lock stops *accidental* concurrency; it is not a
  substitute for not running two deploy sessions on purpose.
- Keep `scripts/fleet-config.json`, the explorer node arrays
  (`src/explorer/app/{01-core,07-map,08-globe-network,15-operator-tools}.js`),
  and `TESTNET_SEED_NODES`/`TESTNET_FALLBACK` in sync when the fleet changes.
- The watchdog is a *mitigation* for the IBD stall, not the root-cause fix — see
  the IBD download-scheduler work for the real fix.
