# Runbook: fork rollback

**Two valid chains exist at the same height with different tip hashes. Need to choose which is canonical and force everything else to follow.**

⚠️ **HYPOTHETICAL — no production test yet.** This runbook is reasoned from Bitcoin Core's `invalidateblock`/`reconsiderblock` RPC pattern and Monero's `pop_blocks` admin command. It has not been exercised on CoinCync testnet. Treat as a starting point, not a script — and **always announce in `#announcements` before any operator action**. Coordinating action is more important than the action itself.

Distinct from [runbook-peer-partition](runbook-peer-partition.md): a partition is "same chain, hosts haven't gossiped recently." A fork is "different valid chains, consensus says only one is canonical, and your fleet is split across both."

---

## Detect

| Source | What to look for |
|---|---|
| `check-fleet-partition.sh` | Different `tip_hash` reported at the **same** height across hosts |
| Explorer + api | `api.coincync.network` shows hash X at height N; `explorer.coincync.network` shows hash Y at height N |
| Community report | Miner says "my block was accepted locally but not by anyone else" |

Confirmation:

```bash
# Pull tip hash from every host
for h in seed1 seed2 seed3 explorer randomx relay1 relay2; do
  IP=$(jq -r ".nodes.\"$h\".ip" scripts/fleet-config.json)
  H=$(ssh -i ~/.ssh/coincync_fleet root@$IP \
    "curl -s -m 4 http://127.0.0.1:28081/rpc/testnet \
       -H 'Authorization: Bearer \$(grep COINCYNC_RPC_API_KEY /etc/coincync/coincync.env | cut -d= -f2)' \
       -H 'Content-Type: application/json' \
       -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_info\"}' \
     | jq -r '.result | \"\(.height) \(.top_block_hash)\"'")
  echo "$h $H"
done
```

If multiple distinct hashes at the same height → fork confirmed.

---

## Decision tree

1. **Two miners both produced valid chains** (rare; will become more common once `randomx2` exists)
   - Consensus rule: highest cumulative work wins. Your nodes should resolve this **automatically** within a few blocks. If they don't, the issue is not which-chain-wins but a peering failure preventing one side from learning about the other → [runbook-peer-partition](runbook-peer-partition.md).
   - Action: usually **wait**. 2-3 more blocks and the lighter chain reorgs away.

2. **One chain contains an invalid/poisoned block, but locally validated as OK** (consensus bug; escalate immediately)
   - Capture EVERYTHING before acting. Block hash, height, full block body, the rejection reasons on the hosts that didn't accept it.
   - Open a critical issue; tag the operator. **Do not invalidate without operator approval.** Wrong invalidate-block call can permanently fork your fleet from honest miners.

3. **Validation rule disagreement** (pre-fork node sees post-fork blocks as invalid; or vice versa)
   - The most likely real cause near 2026-07-01 testnet hard fork at h=13_000.
   - Action: this isn't a rollback, it's an **upgrade**. The minority side runs old binary. Upgrade all hosts to v1.0.12-rc1 or later. Chain self-heals.

4. **Operator-triggered: need to roll back N blocks** (e.g., chain ingested a bad-state block, need to redo)
   - Coordinated action only. Announce well in advance.

---

## Fix

### Case 1 — Wait (do nothing for 5 minutes)

If the fork is shallow (≤3 blocks deep) AND both sides have peering connectivity, **wait**. Consensus's cumulative-work rule will resolve it. The miner producing on the heavier chain will pull the other side over.

```bash
# Re-check every 60s
for i in 1 2 3 4 5; do
  sleep 60
  bash scripts/check-fleet-partition.sh
done
```

If after 5 minutes the fork persists, you have a peering problem masquerading as a fork → [runbook-peer-partition](runbook-peer-partition.md).

### Case 3 — Validation rule disagreement (near hard fork)

If you're within ±100 blocks of h=13_000 (testnet hard fork height) and you see a fork:

- The minority chain is being produced/validated by pre-v1.0.12 binaries.
- The majority chain is the post-fork chain enforcing the 5 new consensus rules.

```bash
# Identify which hosts are on the wrong chain
for h in seed1 seed2 seed3 explorer randomx relay1 relay2; do
  IP=$(jq -r ".nodes.\"$h\".ip" scripts/fleet-config.json)
  V=$(ssh -i ~/.ssh/coincync_fleet root@$IP 'coincync-node --version 2>/dev/null')
  echo "$h $V"
done

# Upgrade any host not on v1.0.12-rc1+:
ssh -i ~/.ssh/coincync_fleet root@<host> '
  systemctl stop coincync-node
  systemctl stop coincync-rig 2>/dev/null
  cp /usr/local/bin/coincync-node /usr/local/bin/coincync-node.previous
  wget -O /usr/local/bin/coincync-node \
    https://github.com/ghostrider1092/Coincync-Testnet-/releases/download/v1.0.12-rc1/coincync-node-v1.0.12-rc1
  chmod +x /usr/local/bin/coincync-node
  sha256sum /usr/local/bin/coincync-node  # expect 5d099719ace...
  systemctl start coincync-node
  systemctl start coincync-rig 2>/dev/null
'
```

Once on v1.0.12-rc1, the host will re-sync to the canonical post-fork chain on its own (it'll reject the old blocks as invalid and pull headers from peers).

### Case 4 — Coordinated rollback of N blocks (OPERATOR-AUTHORIZED ONLY)

⚠️ **Requires operator approval. Announce in `#announcements` with at least 10 min notice. Capture full chain state first.**

CoinCync does not currently expose an `invalidate_block` admin RPC (gap — see "Long-term" below). The workaround is manual: stop the node, truncate chaindata to the rollback height, restart, let it re-sync from peers.

```bash
# DO NOT RUN WITHOUT OPERATOR OK
ROLLBACK_HEIGHT=12990  # the last good height; everything above gets discarded

ssh -i ~/.ssh/coincync_fleet root@<host> '
  systemctl stop coincync-node
  systemctl stop coincync-rig 2>/dev/null

  # Backup current chaindata BEFORE truncating
  tar -czf /root/chaindata-pre-rollback-$(date +%s).tar.gz /var/lib/coincync/chaindata/
  ls -lh /root/chaindata-pre-rollback-*.tar.gz

  # NOTE: there is no built-in chaindata truncate. The safe approach is
  # to WIPE chaindata entirely and re-sync from peers. Slower, but
  # avoids any half-rolled-back DB state.
  rm -rf /var/lib/coincync/chaindata/*

  systemctl start coincync-node
  # Node will IBD from peers, stopping naturally at the canonical tip
'

# Watch progress
ssh -i ~/.ssh/coincync_fleet root@<host> 'journalctl -u coincync-node -f' | grep -E 'height|sync'
```

This is the "scorched earth" rollback. Each host takes 10-30 min to re-sync depending on chain length. Do them **one at a time** with the [sync-fleet-config.sh safety gate](../../scripts/sync-fleet-config.sh) pattern (`peer_count >= 3 AND tip_age < 300s` before next host).

---

## Verify

```bash
# 1. Single canonical tip across all hosts
bash scripts/check-fleet-partition.sh  # exit 0

# 2. Tip matches public expectation (cross-check explorer + api)
curl -s https://api.coincync.network/rpc/testnet \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' | jq '.result.top_block_hash, .result.height'
curl -s https://explorer.coincync.network/api/get_info | jq '.top_block_hash, .height'

# 3. Mining resumed
ssh -i ~/.ssh/coincync_fleet root@173.199.93.21 \
  'journalctl -u coincync-rig --since "5 min ago" | grep "block accepted" | tail -1'
```

All three agree → resolved.

---

## What went wrong if this didn't help

- **Wipe-and-resync host can't find peers** → check `--addnode` list in the systemd unit; should include all 6 other live fleet hosts (excluding `api`).
- **Wipe-and-resync host syncs to the wrong chain** → it's pulling from a peer on the wrong chain. Stop, blacklist that peer, restart. Or fix the source peer.
- **Two miners both keep producing on different chains** → kill one miner until you decide which chain is canonical. Coordination problem, not a code problem.
- **Out of ideas** → STOP. Do not improvise reorgs. Post `#announcements`, tag operator, wait for direction. Bad rollbacks are far more destructive than slow rollbacks.

---

## Long-term: ship `invalidate_block` admin RPC

CoinCync should ship an admin RPC equivalent to Bitcoin Core's `invalidateblock` + `reconsiderblock`. Currently the only rollback path is wipe-chaindata-and-resync, which is slow and total. A proper `invalidate_block` would let an operator surgically excise N blocks on one host and let it re-sync the canonical chain from peers without losing the rest of the DB.

Tracked in `docs/BACKLOG.md` — promote priority before mainnet.

## Post-incident

Document EXTENSIVELY in `docs/operations/incidents/`:
- timestamp + duration + height range affected
- the two (or more) tip hashes
- which chain won and why (cumulative work? validation rule? operator decision?)
- whether any user funds were affected
- what would have made detection faster
- whether the consensus rules behaved as intended

Forks are the rarest + most learnable incidents. Treat every one as a chance to harden detection.
