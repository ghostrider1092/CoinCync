# Runbook: peer partition

**Fleet hosts disagree about the chain. Some are at height X, others at X+N, or they have different tip hashes at the same height.**

Anchored to the 2026-06-22 incident: orphan-flood scoring banned the miner from seed1, then dead-IP pollution in `--addnode` lists starved real fleet peers out of the outbound slot pool, miner mined alone to h=4714 while fleet sat stuck at h=4170 for 18 hours.

This runbook covers the **operational recovery**. The permanent fix (peer-aging) shipped in PR #112 / v1.0.12+ — see "Long-term" at the bottom.

---

## Detect

| Source | What to look for |
|---|---|
| Grafana alert | `warning_peer_count_low` (peer_count < 3 on any host) |
| Discord webhook | `tip_age_secs` rising on a *subset* of hosts (not all) |
| Authoritative | `bash scripts/check-fleet-partition.sh` exit code: **1 = partition** |

`check-fleet-partition.sh` polls every host in `fleet-config.json` and reports:

- **height drift** between hosts > 10 blocks
- **tip hash mismatch** at the same height
- **tip_age_secs** > 600 across hosts

Run it first:

```bash
bash scripts/check-fleet-partition.sh
# or, for ongoing monitoring during recovery:
bash scripts/check-fleet-partition.sh --watch 60
```

If exit 0 → no partition, you're in [runbook-chain-stall](runbook-chain-stall.md) instead.
If exit 1 → continue here.

---

## Decision tree

1. **Recent bulk fleet action triggered mesh dissolution** (operator-induced; see `[[feedback_no_bulk_rolling_restart]]`)
   - Did anyone restart >1 fleet node in the last 15 min? Rolling restarts without the `sync-fleet-config.sh` peer/tip gate cause this. 2026-06-20 + 2026-06-21 + 2026-06-22 all started this way.

2. **Stale dead IPs in peer cache starving real peers** (pre-PR #112 fleet)
   - `ssh seed1 'curl -s -X POST http://127.0.0.1:28081/rpc/testnet -H "Content-Type: application/json" -H "Authorization: Bearer $(grep COINCYNC_RPC_API_KEY /etc/coincync/coincync.env | cut -d= -f2)" -d "{\"jsonrpc\":\"2.0\",\"method\":\"get_connections\"}"'`
   - If you see peers that aren't in `fleet-config.json` and aren't from DNS seeds → those slots are wasted.

3. **Eclipse-defense subnet counter blocking real peers** (intentional, working as designed)
   - `MAX_OUTBOUND_PER_SUBNET = 2`. If too many fleet hosts ended up in the same /16, this kicks in.
   - Check via `get_connections` — if outbound count to a subnet is stuck at 2 with healthy real peers waiting, that's it.

4. **Asymmetric reachability** (firewall, NAT, IPv6 leak)
   - From each pair: `ssh A 'nc -zv <B_ip> 28080'` then reverse. If A→B works but B→A doesn't, it's network-layer, not coincync-node.

5. **Wrong chain entirely** (real fork, not partition)
   - Same height but DIFFERENT tip_hash → not a partition, it's a fork → [runbook-fork-rollback](runbook-fork-rollback.md).

---

## Fix

Pick the option with the smallest blast radius that solves it. Don't escalate prematurely.

### Option A — Targeted pair restart (lowest risk, try first)

Restart **only** the 2 worst-affected hosts. 2 of 8 hosts down means 6 stay up to maintain mesh quorum. Used successfully 2026-06-26.

```bash
# Identify the 2 hosts with lowest peer_count from check-fleet-partition.sh output
WORST1=randomx  # whichever host
WORST2=seed2    # whichever host

for h in $WORST1 $WORST2; do
  IP=$(jq -r ".nodes.\"$h\".ip" scripts/fleet-config.json)
  ssh -i ~/.ssh/coincync_fleet root@$IP 'systemctl restart coincync-node'
done

# WAIT 90 seconds before checking — mesh re-handshake takes ~60-90s
sleep 90
bash scripts/check-fleet-partition.sh
```

If exit 0 → done.
If still partitioned → Option B.

### Option B — chaindata-tarball recovery (one host)

If one specific host is the one diverged (most often seed1 — public RPC) and the others agree, push the canonical chain to it:

```bash
ssh -i ~/.ssh/coincync_fleet root@173.199.93.21 \
  'bash /usr/local/bin/chaindata-sync-miner-to-seed1.sh'
```

This is the "miner has the truth, force-sync seed1 to it" pattern. ~15s of seed1 downtime, ~6 MB transfer.

For other hosts: copy the script to that host, edit the destination IP, run. Or use the staggered fleet config sync:

```bash
bash scripts/sync-fleet-config.sh --only <hostname>
```

This restarts that one host AND waits for `peer_count >= 3 AND tip_age < 300s` before exiting (built-in safety gate).

### Option C — Coordinated mass-stop / mass-start (last resort, REQUIRES OPERATOR OK)

**This bypasses the standing `[[feedback_no_bulk_rolling_restart]]` rule.** Used successfully 2026-06-26 to clear dead-IP pollution across the entire fleet at once. Risks: brief total outage (~30-45s).

**Do not run without an explicit operator instruction for THIS incident.** Not a default move.

```bash
# Stop ALL nodes simultaneously
HOSTS=$(jq -r '.nodes | to_entries[] | select(.value.role != "api") | .value.ip' scripts/fleet-config.json)
for IP in $HOSTS; do
  ssh -i ~/.ssh/coincync_fleet root@$IP 'systemctl stop coincync-node' &
done
wait

sleep 30  # let TCP TIME_WAIT clear so old peer entries age out

# Start ALL nodes simultaneously
for IP in $HOSTS; do
  ssh -i ~/.ssh/coincync_fleet root@$IP 'systemctl start coincync-node' &
done
wait

# Wait for mesh re-establishment
sleep 120
bash scripts/check-fleet-partition.sh
```

Why this works when A/B don't: every host starts fresh with an empty in-memory peer pool, gossip rebuilds from `--addnode` + DNS seeds, no dead IPs carry over.

---

## Verify

```bash
# 1. Fleet converged
bash scripts/check-fleet-partition.sh  # exit 0

# 2. Every host has peer_count >= 3
for h in seed1 seed2 seed3 explorer randomx relay1 relay2; do
  IP=$(jq -r ".nodes.\"$h\".ip" scripts/fleet-config.json)
  COUNT=$(ssh -i ~/.ssh/coincync_fleet root@$IP \
    "curl -s -m 4 http://127.0.0.1:28081/rpc/testnet \
       -H 'Authorization: Bearer \$(grep COINCYNC_RPC_API_KEY /etc/coincync/coincync.env | cut -d= -f2)' \
       -H 'Content-Type: application/json' \
       -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_info\"}' | jq -r .result.peer_count")
  echo "$h peer_count=$COUNT"
done

# 3. Tip age is climbing toward 0 (chain catching up)
bash scripts/check-fleet-partition.sh --watch 30  # Ctrl+C after 2 readings
```

All hosts at `peer_count >= 3` and converged → resolved.

---

## What went wrong if this didn't help

- **Option C ran but partition immediately reformed** → it's a real fork, not stale-state → [runbook-fork-rollback](runbook-fork-rollback.md).
- **One host stays at low peer_count forever** → firewall / iptables / Vultr cloud-firewall blocking inbound 28080. Check `ssh <host> 'iptables -L INPUT -n | head -20'` and Vultr dashboard cloud-firewall rules.
- **`get_connections` shows mystery dead IPs persisting after Option C** → your fleet is on pre-PR-#112 binary. Schedule the v1.0.12+ deploy (see Long-term below).
- **Out of ideas** → operator escalation: post `#announcements` with timestamps + `check-fleet-partition.sh --json` output.

---

## Long-term: deploy v1.0.12+ to eliminate the recurring stale-IP cause

PR #112 (peer-aging) purges addresses from `AddressManager` after 5 consecutive failed dial attempts. Once every fleet host runs v1.0.12-rc1 or later, the "dead IPs starve real peers" failure mode disappears at the source — Option C becomes unnecessary.

Staggered deploy via `scripts/sync-fleet-config.sh` (built-in `peer_count >= 3 AND tip_age < 300s` gate between hosts).

## Post-incident

Add an entry to `docs/operations/incidents/` with:
- timestamp + duration
- which option (A/B/C) resolved it
- whether stale-IP pollution was confirmed in `get_connections`
- whether any new dead IPs were found in `fleet-config.json` that should be moved to `deactivated`

The deactivated-IP audit is the single highest-leverage post-incident task: every IP you remove from `fleet-config.json` is one fewer wasted outbound slot fleet-wide.
