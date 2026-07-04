# Runbook: fleet deploy for PRs #138 + #139 + #140

**Scope**: rolling deploy of the coincync-node binary containing three merged PRs to the 5-node public testnet fleet + 4 auxiliary hosts.

**PRs in this deploy window**:

| PR | Scope | Impact on deployed binary |
|---|---|---|
| **#138** | `fix(swap): eliminate 2-hour CI hang in coordinator SOCKS5 tests` | **NONE** — test-only change in the `coincync-swap` crate. No binary the fleet runs is affected. Do not deploy separately. |
| **#139** | `feat(watchdog): thread names, syscall args, SIGUSR1 on-demand dump, CAP_SYS_PTRACE artifacts` | **YES** — modifies `src/runtime_watchdog.rs`. Enriched thread-comm + syscall fields, SIGUSR1 handler installation, new `signal-hook = "0.3"` dep. |
| **#140** | `fix(network): eliminate DashMap-Ref-across-await deadlock class (20 sites + helper + regression tests)` | **YES** — modifies `src/network/node.rs`. Every peer-messaging hot path now clones `mpsc::Sender` out of the `DashMap` before awaiting. |

Both binary-impacting PRs land together — one build, one rolling restart. Do NOT deploy them in two separate windows; that doubles the fleet-restart risk without any benefit.

## Standing rules that apply to this window

- **`[[feedback_no_bulk_rolling_restart]]`** — never restart all 5 fleet nodes within 10 min, even serially. The `deploy-node-binary.sh` mesh gate (`peer_count >= 3 AND tip_age < 300s`, default 30 attempts × 6s = 180s) is the enforcement mechanism. Do not lower `MESH_GATE_ATTEMPTS`.
- **`[[feedback_ufw_audit_before_release]]`** — audit `ufw status verbose` across all 9 hosts before this release. Missing inbound `:28080` on any canonical host is silent-partition territory.
- **`[[project_chain_partition_2026_06_22]]`** — on miner hosts, `systemctl restart coincync-rig` after the node restarts. The script does this automatically for `role=miner` hosts.
- **Fleet-wide capability change** — `CAP_SYS_PTRACE` drop-in from PR #139 is NOT auto-deployed. Apply it to `seed3` + `randomx2` first (per the drop-in file header) once the base deploy has soaked for 24h without regressions.

## Pre-deploy checklist

### 1. Verify PR #140 is merged on origin/main

```bash
gh pr view 140 --json state,mergeCommit
# state must be MERGED and mergeCommit must be non-null
```

### 2. Verify origin/main is at the expected commit

```bash
git fetch origin main
git log --oneline origin/main -5
```

Expected: top 3 commits include the #140 merge, `dad8ab75 feat(watchdog): ... (#139)`, `406736c1 fix(swap): ... (#138)`. If missing, do NOT proceed.

### 3. UFW audit across all 9 hosts

```bash
for HOST in relay1 relay2 seed1 seed2 seed3 randomx randomx2 explorer api; do
  IP=$(jq -r ".nodes.\"$HOST\".ip" scripts/fleet-config.json)
  echo "── $HOST ($IP) ──"
  ssh -i ~/.ssh/coincync_fleet root@${IP} "ufw status verbose | grep -E '28080|28081|Status'"
done
```

Verify every non-`role=api` host shows `28080/tcp ALLOW` inbound. Any host missing this line will silent-partition post-deploy (verified 2026-06-30 incident — seed3 + randomx2 silent for weeks under this exact condition).

### 4. Chain health baseline snapshot

```bash
curl -s https://api.coincync.network/rpc/testnet \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' | jq '.result | {height, peer_count, tip_age_secs, target_height, is_synced}'
```

Record `height` — post-deploy check will confirm it advanced. Confirm `tip_age_secs < 60` and `peer_count >= 3` on the api box before starting.

### 5. Build the Linux release binary in WSL

```bash
# On Windows dev host, via WSL Ubuntu:
wsl -d Ubuntu -- bash -lc "cd /mnt/c/dev/coincync && cargo build --release --features 'randomx testnet' --bin coincync-node"

# Or via the reproducible Docker path (preferred once verify-reproducible.yml lands):
wsl -d Ubuntu -- bash -lc "cd /mnt/c/dev/coincync && ./scripts/build-in-docker.sh"
```

Verify binary type + size:

```bash
wsl -d Ubuntu -- bash -lc "file /mnt/c/dev/coincync/out/coincync-node"
# Expected: ELF 64-bit LSB pie executable, x86-64, ...
wsl -d Ubuntu -- bash -lc "sha256sum /mnt/c/dev/coincync/out/coincync-node"
# Record SHA — the deploy script re-verifies this per host.
```

**If `file` reports a PE32 or Mach-O binary, you built on the wrong host** — the fleet is Linux only. Rebuild via WSL.

### 6. TLS-ACK env drop-in for hosts with `rpc_bind=0.0.0.0`

**Required for**: `api`, `seed1`, `seed2` (per prior deploy pattern).

If the drop-in isn't already present on those hosts, install it BEFORE the rolling restart:

```bash
cat > /tmp/coincync-node-tls-ack.conf <<'EOF'
[Service]
Environment=COINCYNC_RPC_TLS_PROXY_ACK=1
EOF

for HOST in api seed1 seed2; do
  IP=$(jq -r ".nodes.\"$HOST\".ip" scripts/fleet-config.json)
  scp -i ~/.ssh/coincync_fleet /tmp/coincync-node-tls-ack.conf \
    root@${IP}:/etc/systemd/system/coincync-node.service.d/tls-ack.conf
  ssh -i ~/.ssh/coincync_fleet root@${IP} 'mkdir -p /etc/systemd/system/coincync-node.service.d/ && systemctl daemon-reload'
done
```

`daemon-reload` alone doesn't restart the service — the rolling deploy will pick up the env var on next `systemctl restart`.

## Rolling deploy

```bash
cd /c/dev/coincync
BINARY=out/coincync-node bash scripts/deploy-node-binary.sh
```

Default behavior:

- Deploys to all hosts in `scripts/fleet-config.json` where `role != api`
- SHA-verifies binary on each host BEFORE stopping the service (fail-fast)
- On miner hosts (`role=miner`), stops + restarts `coincync-rig` as well
- Between hosts: waits for `peer_count >= 3 AND tip_age < 300s` (up to 180s)
- Aborts with exit code 4 if any host fails the mesh gate

**Total wall-clock time**: ~5-8 minutes across the 8 non-api hosts (assuming healthy gates).

**Do NOT parallelize**. Do NOT lower `MESH_GATE_ATTEMPTS`. The gate is exactly what prevents the [[feedback_no_bulk_rolling_restart]] partition pattern.

### If the deploy aborts mid-run

The script exits at the failing host, leaving prior hosts on the new binary and unrestarted hosts on the old binary. This is safe — the mesh handles mixed-version peering as long as no wire-format change was in the deploy.

Recover by:

1. Investigating the failing host's `journalctl -u coincync-node -n 50 --no-pager` (the script prints the tail on failure)
2. Fixing the specific issue (usually: fleet-config.json IP wrong, ufw missing rule, disk full)
3. Re-running `deploy-node-binary.sh` from the top — the SHA re-verification will short-circuit any host that already has the new binary

## Post-deploy verification

Immediately after the script returns:

### 1. Fleet-wide sanity

```bash
bash scripts/check-fleet-partition.sh
# Exit 0 means all hosts agree on the tip hash. Any non-zero is a partition.
```

### 2. Watchdog install log

```bash
for HOST in relay1 relay2 seed1 seed2 seed3 randomx randomx2 explorer; do
  IP=$(jq -r ".nodes.\"$HOST\".ip" scripts/fleet-config.json)
  echo "── $HOST ──"
  ssh -i ~/.ssh/coincync_fleet root@${IP} \
    "journalctl -u coincync-node --since '5 min ago' | grep -E 'watchdog|SIGUSR1' | tail -5"
done
```

Every host should log:
- `runtime deadlock watchdog armed: heartbeat every 5s, ...`
- `SIGUSR1 on-demand snapshot handler installed`

If SIGUSR1 log is missing on any host, PR #139's signal-hook registration failed silently. Log a WARN — the automatic watchdog still works, but `kill -USR1` won't produce a snapshot.

### 3. Smoke-test SIGUSR1 dump on ONE host

```bash
# On relay1 (least critical fleet host):
IP=$(jq -r '.nodes.relay1.ip' scripts/fleet-config.json)
ssh -i ~/.ssh/coincync_fleet root@${IP} \
  'kill -USR1 $(pgrep -f coincync-node) && sleep 20 && ls -la /var/lib/coincync/snapshot-*.log | tail -3'
```

Should show a fresh `snapshot-<ts>.log` within 15 seconds of the signal. If it doesn't appear within 20s, the signal handler is not wired — investigate before soaking.

### 4. Chain still advancing

```bash
# 3 minutes after deploy completes:
sleep 180
curl -s https://api.coincync.network/rpc/testnet \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' | jq '.result | {height, peer_count, tip_age_secs}'
```

`height` must be higher than the pre-deploy baseline from step 4. `tip_age_secs < 300`. If height is stuck OR tip_age is growing, the fleet is in soft-partition — investigate immediately.

## Soak window (24h)

Do NOT enable `CAP_SYS_PTRACE` until the base deploy has soaked without regressions for 24h. If any of the following happens in the soak window, the deploy failed and needs to be reverted:

- Watchdog fires on ANY host (even without deadlock — a false positive is a real signal)
- Chain stalls (`tip_age > 600s` observed on api)
- `peer_count < 3` sustained for >5min on any fleet host
- systemd auto-restart loop (>3 restarts in 1h on same host)

## Revert path (if soak window fails)

The old binary is preserved at `/usr/local/bin/coincync-node` **before** each deploy step overwrites it. To revert:

```bash
# On the box being reverted:
systemctl stop coincync-node
mv /usr/local/bin/coincync-node.previous /usr/local/bin/coincync-node
systemctl start coincync-node
```

Note: the deploy script does NOT currently save `coincync-node.previous`. **Save one manually before the deploy** if you want a fast revert path:

```bash
for HOST in relay1 relay2 seed1 seed2 seed3 randomx randomx2 explorer; do
  IP=$(jq -r ".nodes.\"$HOST\".ip" scripts/fleet-config.json)
  ssh -i ~/.ssh/coincync_fleet root@${IP} \
    'cp /usr/local/bin/coincync-node /usr/local/bin/coincync-node.pre-138-139-140'
done
```

## Post-soak: CAP_SYS_PTRACE rollout (Fort-Knox Item 6 follow-up)

After 24h of clean soak, per `scripts/systemd-drop-in-cap-sys-ptrace.conf` header:

1. Apply drop-in to `seed3` first. Watch 24h.
2. Apply to `randomx2` next. Watch 24h.
3. Only after BOTH have soaked without regression do you consider fleet-wide expansion.

Read `docs/operations/runbook-watchdog-diagnostic.md` for the full deploy sequence + verification.

## Cross-references

- [`scripts/deploy-node-binary.sh`](../../scripts/deploy-node-binary.sh) — the actual deploy script
- [`scripts/fleet-config.json`](../../scripts/fleet-config.json) — single source of truth for fleet host list
- [`scripts/systemd-drop-in-cap-sys-ptrace.conf`](../../scripts/systemd-drop-in-cap-sys-ptrace.conf) — CAP_SYS_PTRACE drop-in (Fort-Knox Item 6 side-quest)
- [`docs/operations/runbook-watchdog-diagnostic.md`](runbook-watchdog-diagnostic.md) — how to read watchdog output
- [`docs/operations/runbook-chain-stall.md`](runbook-chain-stall.md) — if chain stalls post-deploy
- [`docs/operations/runbook-peer-partition.md`](runbook-peer-partition.md) — if partition detected
