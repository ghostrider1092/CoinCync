# Runbook: hard-finality stuck

**Fleet's chain tip is stuck. A single host (usually a miner) has a heavier chain many blocks ahead, but the fleet refuses every reorg attempt with `Rejecting reorg at depth N: exceeds absolute maximum 100 (hard finality)`. Recoverable via p2p is IMPOSSIBLE at this point — needs manual chaindata swap.**

Anchored to the 2026-07-04 incident: 20-hour testnet stall (h=9369 → h=9997+). Root cause was TWO stacked bugs — peer-punishment mislabelled a "missing parent" sync-order race as `InvalidBlockProofs` and banned the miner, then by the time the ban expired the miner was 628 blocks ahead and `hard_finality=100` refused every reorg attempt. Recovery took 45 minutes of coordinated chaindata tarball swaps across 7 hosts.

This runbook covers the **operational recovery**. The permanent fix (splitting `MissingParent` out of `InvalidBlockProofs` in the peer-punishment enum) is described at the bottom — must ship before mainnet.

⚠️ **This is NOT [runbook-peer-partition](runbook-peer-partition.md).** Peer-partition = fleet hosts disagree with each other. Hard-finality-stuck = ALL fleet hosts agree on a stalled chain, but a separate host has the actual canonical chain and can't reach in via reorg. Read Detect below carefully — the two look similar in Grafana but need different recovery paths.

---

## Detect

| Source | What to look for |
|---|---|
| Grafana | `tip_age_secs` high on **every** host equally (not a subset — every fleet host is stuck at the same height) |
| Node logs | `Rejecting reorg at depth <N>: exceeds absolute maximum 100 (hard finality)` — this log line is the signature |
| Miner logs | Miner is producing blocks fine, but its `total_difficulty` is climbing while fleet's stays flat |
| `check-fleet-partition.sh` | Exits 0 (no partition among fleet) — misleading; you have to check the miner separately |

The critical diagnostic: compare `difficulty` (cumulative work) between the fleet and the isolated miner. Not `height` — height ties don't rule this out. Run [feedback_partition_diagnosis_compare_difficulty](../..)-style check across ALL hosts including the isolated one:

```bash
# From your local box
for h in seed1 seed2 seed3 explorer randomx randomx-2 relay1 relay2 api; do
  IP=$(jq -r ".nodes.\"$h\".ip" scripts/fleet-config.json)
  INFO=$(ssh -i ~/.ssh/coincync_fleet root@$IP \
    "curl -s -m 4 http://127.0.0.1:28081/rpc/testnet \
       -H 'Authorization: Bearer \$(grep COINCYNC_RPC_API_KEY /etc/coincync/coincync.env | cut -d= -f2)' \
       -H 'Content-Type: application/json' \
       -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_info\"}'")
  H=$(echo "$INFO" | jq -r .result.height)
  D=$(echo "$INFO" | jq -r .result.difficulty)
  echo "$h  height=$H  difficulty=$D"
done
```

**Signature pattern:**
- 8 of 9 hosts: identical (`height=X`, `difficulty=D`)
- 1 host (usually a miner): `height=X+628`, `difficulty=D+M` where `M` is significantly larger

If `M / D >≈ 5%` and height gap `> 100` → **hard-finality stuck.** Proceed.

If gap `≤ 100` blocks → NOT hard-finality-stuck; the reorg WILL succeed once network path clears. Try [runbook-peer-partition](runbook-peer-partition.md) Option A/B first.

---

## Decision tree

Only ONE cause reaches this state — the peer-punishment misclass bug interacting with `hard_finality`. But you need to figure out **which host has the canonical chain** before you can recover.

1. **Confirm canonical is the highest-difficulty host.** Not just highest height — difficulty. In the 2026-07-04 event, canonical was `randomx-2` at `total_difficulty` 720M vs fleet's 685M. Height alone would have said the same thing (628 blocks) but difficulty is the actual consensus rule.

2. **Confirm the canonical host is reachable to you** (SSH works, node is running, RPC responds). If canonical is unreachable → you cannot recover, escalate to operator immediately. This is the "the truth is on a dead disk" case.

3. **Confirm the canonical host's chain is valid PoW** by pulling a sample block and re-verifying it locally, if you have any doubt. In 2026-07-04 we verified via the tarball SHA matching the canonical host's own record.

Once you have the canonical host identified: proceed to Fix.

---

## Fix

**There is no p2p recovery path.** The canonical chain cannot arrive at the fleet via GetBlocks because `hard_finality=100` rejects every reorg beyond 100 blocks regardless of PoW. You have to physically transport the chaindata.

Use the [feedback_snapshot_procedure](../..) rules:
- Live-tar the canonical host (do NOT stop the node)
- Wait for `tip_age > 60s` before tarring to reduce WAL inconsistency
- Cross-verify SHA on each target
- One host at a time — never rolling-restart the fleet ([feedback_no_bulk_rolling_restart](../..))

### Step 1 — Snapshot canonical chaindata

```bash
CANONICAL=randomx-2  # whichever host from Detect
CANONICAL_IP=$(jq -r ".nodes.\"$CANONICAL\".ip" scripts/fleet-config.json)

# Live tar (node stays running); ensure tip is stable first
ssh -i ~/.ssh/coincync_fleet root@$CANONICAL_IP <<'EOF'
  # Wait for tip_age > 60s
  for i in 1 2 3 4 5; do
    AGE=$(curl -s http://127.0.0.1:28081/rpc/testnet \
      -H "Authorization: Bearer $(grep COINCYNC_RPC_API_KEY /etc/coincync/coincync.env | cut -d= -f2)" \
      -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' | jq -r .result.tip_age_secs)
    [ "$AGE" -gt 60 ] && break
    sleep 15
  done

  cd /var/lib/coincync
  tar czf /tmp/testnet-canonical.tgz testnet/
  sha256sum /tmp/testnet-canonical.tgz > /tmp/testnet-canonical.tgz.sha256
EOF

# Pull to local box
scp -i ~/.ssh/coincync_fleet root@$CANONICAL_IP:/tmp/testnet-canonical.tgz .
scp -i ~/.ssh/coincync_fleet root@$CANONICAL_IP:/tmp/testnet-canonical.tgz.sha256 .

# Verify locally
sha256sum -c testnet-canonical.tgz.sha256
```

Record the SHA — you'll re-verify it on every target host before extract.

### Step 2 — Push to each stuck host, one at a time

Recommended order (least-critical to most-critical, so you catch procedural errors on a low-blast-radius host first):

```
explorer → api → relay1 → relay2 → randomx → seed3 → seed2 → seed1
```

For each host `H`:

```bash
H=explorer  # cycle through the order above
IP=$(jq -r ".nodes.\"$H\".ip" scripts/fleet-config.json)

# Push tarball + SHA
scp -i ~/.ssh/coincync_fleet testnet-canonical.tgz root@$IP:/tmp/
scp -i ~/.ssh/coincync_fleet testnet-canonical.tgz.sha256 root@$IP:/tmp/

# Extract with node down, verifying SHA first
ssh -i ~/.ssh/coincync_fleet root@$IP <<EOF
  set -e
  cd /tmp
  sha256sum -c testnet-canonical.tgz.sha256

  systemctl stop coincync-node

  cd /var/lib/coincync
  mv testnet testnet.stalled-\$(date +%Y%m%d-%H%M) || true
  tar xzf /tmp/testnet-canonical.tgz
  chown -R coincync:coincync testnet/

  systemctl start coincync-node
EOF

# Wait for this host to catch up to the canonical tip before proceeding
CANONICAL_TIP=$(ssh -i ~/.ssh/coincync_fleet root@$CANONICAL_IP \
  "curl -s http://127.0.0.1:28081/rpc/testnet \
     -H 'Authorization: Bearer \$(grep COINCYNC_RPC_API_KEY /etc/coincync/coincync.env | cut -d= -f2)' \
     -H 'Content-Type: application/json' \
     -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_info\"}'" | jq -r .result.tip_hash)

for i in $(seq 1 20); do
  TIP=$(ssh -i ~/.ssh/coincync_fleet root@$IP \
    "curl -s http://127.0.0.1:28081/rpc/testnet \
       -H 'Authorization: Bearer \$(grep COINCYNC_RPC_API_KEY /etc/coincync/coincync.env | cut -d= -f2)' \
       -H 'Content-Type: application/json' \
       -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_info\"}'" | jq -r .result.tip_hash)
  [ "$TIP" = "$CANONICAL_TIP" ] && { echo "$H caught up"; break; }
  sleep 15
done
```

**Do not batch this loop.** One host at a time — start the next host only after the previous is at the canonical tip AND `peer_count >= 3`. Bulk restarts caused the same class of stall in 2026-06-20 and 2026-06-21 ([feedback_no_bulk_rolling_restart](../..)).

### Step 3 — DO NOT delete `testnet.stalled-<timestamp>` yet

Keep the pre-swap chaindata on every host for at least 48 hours after recovery. If the class-fix PR retrospectively reveals the canonical chain was WRONG (unlikely but possible if the miner was itself misconfigured), you need the pre-swap state to reconstruct.

---

## Verify

```bash
# 1. Every host on the same tip_hash as canonical
CANONICAL_TIP=<from Step 2>
for h in seed1 seed2 seed3 explorer randomx randomx-2 relay1 relay2 api; do
  IP=$(jq -r ".nodes.\"$h\".ip" scripts/fleet-config.json)
  TIP=$(ssh -i ~/.ssh/coincync_fleet root@$IP \
    "curl -s http://127.0.0.1:28081/rpc/testnet \
       -H 'Authorization: Bearer \$(grep COINCYNC_RPC_API_KEY /etc/coincync/coincync.env | cut -d= -f2)' \
       -H 'Content-Type: application/json' \
       -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_info\"}'" | jq -r .result.tip_hash)
  MATCH=$([ "$TIP" = "$CANONICAL_TIP" ] && echo OK || echo DRIFT)
  echo "$h  tip=$TIP  $MATCH"
done

# 2. Mining is active on both randomx AND randomx-2
for h in randomx randomx-2; do
  IP=$(jq -r ".nodes.\"$h\".ip" scripts/fleet-config.json)
  ssh -i ~/.ssh/coincync_fleet root@$IP 'systemctl is-active coincync-rig'
done

# 3. Fleet is producing blocks (tip advances within 2 min of restart completion)
bash scripts/check-fleet-partition.sh --watch 60  # Ctrl+C after 3 readings
```

All 9 hosts at the same tip_hash, both miners active, tip advancing → resolved.

---

## What went wrong if this didn't help

- **After swap, one host re-diverges to the old stalled chain within minutes** → that host's peer list still points at other stalled hosts and they're gossiping the losing chain back. Rerun the swap on that host AFTER all others are converged, and check `get_connections` on it to see which peer is feeding the wrong chain.
- **After swap, the fleet catches up but the isolated miner falls behind (roles reversed)** → the tarball was NOT from the actual canonical host. Re-run Detect with fresh RPC readings, identify the correct canonical, redo Step 1 from THAT host.
- **`hard_finality` reject log lines re-appear after recovery** → the class-fix hasn't shipped and a new divergence is forming. Watch for peer-punishment ban events; if any host bans another for `InvalidBlockProofs` on a block whose parent it doesn't have, that's the same bug re-triggering. Manually unban and re-check.
- **Out of ideas** → operator escalation: this is a novel angle on the July 4 pattern. Post `#announcements` with the divergence height, difficulty gap, and the specific reject log lines.

---

## Long-term class fix (must ship before mainnet)

The July 4 partition was caused by peer-punishment mapping a sync-state error (`Non-genesis block without parent`) to a peer-integrity category (`InvalidBlockProofs`, penalty 50 = instant ban). The fix, per [project_hard_finality_partition_2026_07_04](../..) memory:

In `src/network/sync.rs` (peer-punishment enum), split:

```rust
enum PunishmentReason {
    // WAS all lumped together as InvalidBlockProofs — WRONG for sync-state cases.
    MissingParent { requested: bool },  // request parents; DO NOT punish. Ban only if peer refuses to send parents after N retries.
    CryptographicallyInvalid,           // real PoW/signature/consensus violation. Ban as today.
    // ... other categories
}
```

The reorg-tip path in `src/chain.rs` must classify "block arrived before its parent" as `MissingParent`, not as an invalid block.

Once this ships, this runbook stops being reachable — the peer-punishment misclass will no longer be able to cause a >100-block divergence, and `hard_finality` will only trigger on genuinely-divergent chains where it's supposed to.

Track under `docs/BACKLOG.md` — MUST land before 2026-10-01 mainnet GA.

---

## Post-incident

Add an entry to `docs/operations/incidents/` with:
- timestamp + duration
- canonical host + divergence depth (blocks and difficulty delta)
- specific reject log lines observed
- whether the class-fix has shipped yet (if not, this incident is likely to recur)
- verification that `peer_count >= 3` and `is_synced=true` on all 9 hosts at the end

Reference the [feedback_partition_diagnosis_compare_difficulty](../..) rule — "first thing in a stall investigation: compare `difficulty` across two fleet hosts." If future you comes back and sees only `height` was checked but not `difficulty`, that's the diagnostic that would have flagged this class instantly.
