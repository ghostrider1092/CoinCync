# Runbook: chain stall

**Tip not advancing. Every fleet host agrees on the same height; no new blocks for 5+ minutes.**

This is the most common 3am page. 80% of the time the miner stopped producing and the watchdog hasn't kicked yet. Other 20% is fleet-side. Work top-down.

---

## Detect

| Source | What to look for |
|---|---|
| Grafana alert | `critical_tip_stale` (tip_age_secs > 600) |
| Discord webhook | `tip_age_secs=NNN` on multiple hosts |
| Manual | `curl -s https://api.coincync.network/rpc/testnet -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' | jq '.result.tip_age_secs, .result.height'` |
| Bulk check | `scripts/check-fleet-partition.sh` (exit 0 = fleet agrees, just stuck; exit 1 = partition — go to [runbook-peer-partition](runbook-peer-partition.md) instead) |

If `check-fleet-partition.sh` returns **0** but tip_age is rising on every host → continue here.
If it returns **1** → this is not a stall, it's a partition → [runbook-peer-partition](runbook-peer-partition.md).

**Also check for the 2026-07-04 pattern**: `check-fleet-partition.sh` may exit 0 because the fleet agrees with itself, but a **separate mining host** has a heavier chain the fleet is refusing to accept via reorg. Grep for `hard finality` in fleet node logs:

```bash
ssh seed1 'journalctl -u coincync-node -n 500 --no-pager | grep -i "hard finality"'
```

If you see `Rejecting reorg at depth <N>: exceeds absolute maximum 100 (hard finality)` → this is not a stall in the usual sense, it's [runbook-hard-finality-stuck](runbook-hard-finality-stuck.md). Fleet is stuck on a losing minor fork; miner has the winner but can't push it in.

---

## Decision tree

1. **Miner stopped producing** (most common — 2026-06-24 incident, 2026-06-26 incident)
   - `ssh -i ~/.ssh/coincync_fleet root@173.199.93.21 'systemctl is-active coincync-node coincync-rig'`
   - If either is **inactive** → see [runbook-miner-down](runbook-miner-down.md). Stop here.
   - If both are **active** but no recent "block accepted" in rig journal → continue to step 2.

2. **Miner's local node thinks it's not synced** (rig sync-gate flips)
   - `ssh -i ~/.ssh/coincync_fleet root@173.199.93.21 'journalctl -u coincync-rig -n 30 --no-pager | grep -E "synced|sync_gate|refusing"'`
   - If you see "refusing to mine, node not synced": miner's tip vs network tip drifted. Restart restores it.

3. **Mempool poisoning** (rare since v1.0.11.7 added `shadow_evict_invalid`)
   - `ssh seed1 'journalctl -u coincync-node -n 200 --no-pager | grep -iE "reject|invalid block"'`
   - If repeated rejects on same tx_hash: mempool is feeding a bad tx into every template. Fix: restart any one fleet node — mempool is in-memory only.

4. **Chain DB corruption** (very rare; shows as panic in journal)
   - `ssh seed1 'journalctl -u coincync-node -n 100 --no-pager | grep -iE "panic|fatal|corrupt"'`
   - If panic: chaindata-tarball recovery from a healthy host (see Fix § "Chaindata-tarball recovery" below).

---

## Fix

### Step 1 — Restart the miner pair (handles 90% of cases)

The `coincync-rig` systemd unit `Requires=coincync-node.service`. Stopping or restarting the node **does not** automatically restart the rig — this footgun caused the 2026-06-24 stall. Always restart **both**, rig **second**:

```bash
ssh -i ~/.ssh/coincync_fleet root@173.199.93.21 '
  systemctl restart coincync-node
  sleep 30
  systemctl restart coincync-rig
  sleep 5
  systemctl is-active coincync-node coincync-rig
'
```

Expect: both → `active`.

### Step 2 — Verify a block produces within 3 minutes

```bash
ssh -i ~/.ssh/coincync_fleet root@173.199.93.21 \
  'journalctl -u coincync-rig -f --since "1 min ago" | grep -i "block accepted"'
```

Block time is 120s; you should see one within ~3 min. If yes → done; capture timestamps for incident log.

### Step 3 — If still stalled after 5 minutes: chaindata-tarball recovery

The miner has the freshest chain. Push it to whichever fleet host is most lagged:

```bash
ssh -i ~/.ssh/coincync_fleet root@173.199.93.21 \
  'bash /usr/local/bin/chaindata-sync-miner-to-seed1.sh'
```

This script (resident on miner) creates an atomic tar of `chaindata/`, scps to seed1, stops seed1's node, swaps in the new chaindata, restarts. ~15s of seed1 downtime. Proven recovery pattern.

---

## Verify

After the fix, confirm three things:

```bash
# 1. Tip is advancing (call twice, 60s apart — heights should differ)
for i in 1 2; do
  curl -s https://api.coincync.network/rpc/testnet \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' | jq '.result.height'
  sleep 60
done

# 2. Fleet agrees (exit 0)
bash scripts/check-fleet-partition.sh

# 3. Miner producing (last "block accepted" should be <3 min ago)
ssh -i ~/.ssh/coincync_fleet root@173.199.93.21 \
  'journalctl -u coincync-rig --since "5 min ago" | grep "block accepted" | tail -1'
```

All three green → resolved.

---

## What went wrong if this didn't help

- **Restart didn't restore mining** → `coincync-rig` journal will tell you why. Most likely: wallet keys inaccessible (`/root/.coincync/wallets/miner2.wallet` permissions), or RandomX dataset failed to allocate (OOM — see [runbook-oom](runbook-oom.md)).
- **Block produced but fleet still doesn't catch up** → peer-partition, not stall → [runbook-peer-partition](runbook-peer-partition.md).
- **Two miners producing two chains** → fork — [runbook-fork-rollback](runbook-fork-rollback.md).
- **Out of ideas** → operator escalation: post `#mining` channel, `@ghostrider1092`. Include `journalctl -u coincync-node -n 200` from seed1 + miner.

## Post-incident

Add a line to `docs/operations/incidents/` (one file per incident) with: timestamp UTC, duration, root cause, what fixed it, what didn't. Future-you will thank you.
