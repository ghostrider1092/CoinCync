# Runbook: miner down

**`coincync-rig` on the miner box (`randomx`, 173.199.93.21) is not producing blocks. Network has no block source.**

Until a second miner (`randomx2`) is provisioned, this is a single point of failure for the testnet. Miner down = chain stalls in ~2 min. Recovery is usually 60 seconds.

The miner-stall-watchdog cron (`scripts/miner-stall-watchdog.sh`, runs every 5 min on the miner) self-heals most of these without operator action. If you got paged, the watchdog either hasn't fired yet, is on its 10-min anti-loop cooldown, or the underlying problem is outside its scope.

---

## Detect

| Source | What to look for |
|---|---|
| Grafana alert | `critical_tip_stale` (chain stalls fast when miner is down) |
| Discord webhook | `coincync-rig` `info_node_restart_burst` |
| Manual | `journalctl -u coincync-rig --since "10 min ago" \| grep "block accepted"` returns nothing |
| Watchdog log | `journalctl -t miner-stall-watchdog -n 10` shows recent restart attempts |

Quick triage:

```bash
ssh -i ~/.ssh/coincync_fleet root@173.199.93.21 '
  systemctl is-active coincync-node coincync-rig
  journalctl -u coincync-rig --since "10 min ago" | grep -E "block accepted|hashrate|error" | tail -10
  journalctl -t miner-stall-watchdog -n 5 --no-pager
'
```

---

## Decision tree

1. **Watchdog will recover in the next 5 min** (most common; check first!)
   - `journalctl -t miner-stall-watchdog -n 3` shows a recent or imminent restart attempt.
   - If yes, wait 5 min. Re-check. Only intervene if watchdog has fired twice without success.

2. **`coincync-rig` is inactive, `coincync-node` is active** (systemd dep footgun — 2026-06-24)
   - `coincync-rig.service` has `Requires=coincync-node.service`. Stopping/restarting the node does NOT auto-restart the rig. Operator restarted the node 1hr ago and forgot to restart the rig.
   - **This is the #1 manual cause.** Easy fix.

3. **Both inactive** (node crash brought rig down with it)
   - Node OOM (see [runbook-oom](runbook-oom.md)), panic, or operator stop.

4. **Both active, no block produced**
   - Rig sync-gate flipped (node briefly thought it wasn't synced and rig refuses to mine).
   - Wallet inaccessible (`/root/.coincync/wallets/miner2.wallet` permissions changed).
   - RandomX dataset allocation failed (OOM on dataset init, ~2 GB needed).

5. **Miner box unreachable** (SSH timeout)
   - Vultr instance crashed, network outage, or DDoS. Escalate to operator immediately; nothing this runbook can do without console access.

---

## Fix

### Step 1 — Restart rig only (covers ~70% of cases)

If `coincync-node` is `active` and `coincync-rig` is `inactive`:

```bash
ssh -i ~/.ssh/coincync_fleet root@173.199.93.21 'systemctl restart coincync-rig'
sleep 5
ssh -i ~/.ssh/coincync_fleet root@173.199.93.21 'systemctl is-active coincync-rig'
```

Then jump to Verify.

### Step 2 — Restart pair (covers the rest)

If both inactive, or rig restart didn't take, restart **both** with the **explicit rig second**:

```bash
ssh -i ~/.ssh/coincync_fleet root@173.199.93.21 '
  systemctl restart coincync-node
  sleep 30   # let node come up, peer mesh re-handshake, sync-gate clear
  systemctl restart coincync-rig
  sleep 5
  systemctl is-active coincync-node coincync-rig
'
```

**Never skip the explicit `systemctl restart coincync-rig`** — the `Requires=` dep is one-shot at boot, not a runtime "auto-restart-when-node-comes-back." This is the footgun documented in `[[project_chain_partition_2026_06_22]]`.

### Step 3 — If rig refuses to start (wallet or dataset issue)

```bash
ssh -i ~/.ssh/coincync_fleet root@173.199.93.21 '
  # Check rig journal for the actual error
  journalctl -u coincync-rig -n 30 --no-pager

  # Wallet permissions check
  ls -la /root/.coincync/wallets/miner2.wallet

  # Memory available for RandomX dataset (~2 GB)
  free -h
'
```

- **"wallet file not found / permission denied"** → wallet path moved or perms changed; restore from operator's backup (`C:\Users\unkno\.coincync\wallets\miner2.wallet` on dev box). Operator action.
- **"failed to allocate RandomX dataset"** → OOM. [runbook-oom](runbook-oom.md), then come back.
- **"node not synced / refusing to mine"** → rig sync-gate. Wait 60s, restart rig again. If persistent, restart node first then rig.

---

## Verify

```bash
ssh -i ~/.ssh/coincync_fleet root@173.199.93.21 '
  # 1. Both services active
  systemctl is-active coincync-node coincync-rig

  # 2. Hashrate is non-zero (should be ~520 H/s on 3 threads)
  journalctl -u coincync-rig --since "2 min ago" | grep -i hashrate | tail -3

  # 3. A block accepted within last 3 min
  journalctl -u coincync-rig --since "5 min ago" | grep "block accepted" | tail -1
'

# 4. Tip is advancing (confirm from a different host so you know gossip works)
curl -s https://api.coincync.network/rpc/testnet \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' | jq '.result.height, .result.tip_age_secs'
```

Expect: services active, hashrate ~520 H/s, recent "block accepted" line, `tip_age_secs < 180`.

---

## What went wrong if this didn't help

- **Rig produces hashrate but no "block accepted"** → mining solo against a different chain than the network. Check `get_info.height` on miner vs on api.coincync.network — if they differ, [runbook-peer-partition](runbook-peer-partition.md).
- **Rig keeps restarting in a loop** → check `journalctl -u coincync-rig -n 100 --no-pager`. Common: wallet decrypt fails (wrong password env), or RPC bearer key mismatch with local node.
- **Miner box itself unreachable** → Vultr dashboard, console reboot, then start at Step 2 immediately on boot.
- **Watchdog firing every 5 min but no recovery** → the watchdog itself is misconfigured or the chain is broken in a way restarts can't fix (mempool poisoning, fork). Go to [runbook-chain-stall](runbook-chain-stall.md).

---

## Pending: provision `randomx2` (second miner) before mainnet

The single-miner SPOF is the largest pre-mainnet risk. Tracked in `docs/BACKLOG.md`. Until `randomx2` exists, every miner-down incident risks the chain stalling visibly to the community.

Min spec for `randomx2`: 4 vCPU / 7.2 GB / 150 GB (matches `randomx`). Use a different Vultr region for failure-domain diversity. Wallet keys: rotate to fresh `miner3.wallet` on operator dev box, never share with `randomx`.

## Post-incident

Append to `docs/operations/incidents/` with:
- timestamp + duration
- which step recovered it
- whether the watchdog fired and either succeeded or hit its cooldown
- whether the cause is something the watchdog *could* be taught to handle (e.g., add "if rig is inactive but node is active, just restart rig" to the watchdog logic)
