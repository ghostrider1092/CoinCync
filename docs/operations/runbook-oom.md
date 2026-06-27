# Runbook: out-of-memory (OOM)

**`coincync-node` is being killed by the kernel OOM-killer and auto-restarted by systemd in a tight loop.**

Anchored to the 2026-06-24 seed1 incident: 4 GB box, peak RSS hit 2.4 GB during IBD on top of system overhead, kernel killed the node, systemd restarted, IBD restarted, killed again. Stuck in a 60-second loop until swap was added.

---

## Detect

| Source | What to look for |
|---|---|
| Grafana alert | `warning_memory_tight` (<500 MB available) or `info_node_restart_burst` (≥3 restarts/10min) |
| journal | `coincync-node.service: Main process exited, code=killed, status=9/KILL` |
| dmesg | `Out of memory: Killed process NNNN (coincync-node)` |
| Manual | `free -h` shows `available` < 500 MB |

Quick remote check:

```bash
ssh -i ~/.ssh/coincync_fleet root@<host> '
  free -h
  systemctl show coincync-node -p NRestarts -p ActiveEnterTimestamp
  dmesg -T 2>/dev/null | grep -i "out of memory" | tail -5
'
```

If `NRestarts >= 3` in a short window AND `dmesg` shows OOM kills → you're here.

---

## Decision tree

1. **Box is undersized** (most common — see `[[project_node_min_ram_8gb]]`)
   - Minimum verified RAM (2026-06-20): **6 GB for node-only, 8 GB for node+miner**. Quote 8 GB for any "spec a box" answer.
   - Anything under 4 GB will OOM during IBD. Anything under 6 GB is fragile under load.

2. **Real memory leak in coincync-node** (rare, escalate if suspected)
   - RSS climbs monotonically over hours with no IBD activity. Bitcoin-Core-equivalent UTXO + chainstate cache should plateau.
   - If suspected: capture `/proc/$(pidof coincync-node)/status` snapshots over 30 min; open issue with the deltas.

3. **Another process eating memory** (rare on dedicated fleet boxes)
   - `ps -eo pid,rss,cmd --sort=-rss | head -10` — if anything other than `coincync-node` is >500 MB on a fleet host, that's the bug.

---

## Fix

### Step 1 — Add swap (immediate, 30 seconds, low risk)

This unblocks the OOM loop while you decide on a permanent fix. Swap is slow but reliable; better than crash-loop.

```bash
ssh -i ~/.ssh/coincync_fleet root@<host> '
  # Idempotent: if /swapfile exists and is on, skip
  if ! swapon --show=NAME | grep -q /swapfile; then
    fallocate -l 8G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo "/swapfile none swap sw 0 0" >> /etc/fstab
  fi
  swapon --show
  free -h
'
```

Expect: `free -h` now shows ~8 GB swap available. Node's RSS will spill into swap instead of getting killed.

### Step 2 — Add systemd memory limits (prevent runaway, 10 seconds)

Caps coincync-node's memory so it can't starve the system. Tuned for a 7-8 GB box:

```bash
ssh -i ~/.ssh/coincync_fleet root@<host> '
  mkdir -p /etc/systemd/system/coincync-node.service.d
  cat > /etc/systemd/system/coincync-node.service.d/memory.conf <<EOF
[Service]
MemoryHigh=5G
MemoryMax=6G
MemorySwapMax=4G
EOF
  systemctl daemon-reload
  systemctl restart coincync-node
  systemctl show coincync-node -p MemoryHigh -p MemoryMax
'
```

`MemoryHigh` is the throttle threshold; `MemoryMax` is the hard kill. Setting `MemoryMax` < total RAM means systemd kills the node before the kernel OOM-killer does — same outcome, but you get a clean systemd restart cycle and a clear log line instead of a kernel surprise.

### Step 3 — Schedule a box upgrade (permanent fix)

Swap is a workaround. For seed/miner boxes carrying real load, upgrade the box:

| Role | Min spec | Vultr SKU (approx) | Cost |
|---|---|---|---|
| relay | 2 vCPU / 3.3 GB | Regular Performance | $24/mo |
| seed (public RPC) | 4 vCPU / 7.2 GB | CPU-Optimized 4c | ~$48/mo |
| miner | 4 vCPU / 7.2 GB | CPU-Optimized 4c | ~$48/mo |
| explorer | 2 vCPU / 4 GB | Regular Performance | $24/mo |

To resize a Vultr instance: dashboard → instance → Settings → Change Plan. Requires a reboot. Operator action — no script.

---

## Verify

```bash
ssh -i ~/.ssh/coincync_fleet root@<host> '
  # 1. Node is up and stable
  systemctl is-active coincync-node
  systemctl show coincync-node -p NRestarts

  # 2. Memory headroom is healthy
  free -h

  # 3. No OOM kills in last 10 min
  dmesg -T 2>/dev/null | grep -i "out of memory" | tail -3

  # 4. Heartbeat is firing (v1.0.11.7+)
  journalctl -u coincync-node --since "2 min ago" | grep heartbeat | tail -3
'
```

Expect: `active`, `NRestarts` stable (not incrementing), `free` shows >500 MB available, no recent OOM lines, heartbeat every ~30s.

---

## What went wrong if this didn't help

- **Still crash-looping with swap on** → either the RSS is genuinely >MemoryMax (raise it, or upgrade box), or it's not OOM at all (read `journalctl -u coincync-node -n 100` for the actual exit reason — could be panic, could be `127` from missing shared lib after an upgrade).
- **Swap fills up immediately** → not enough RAM **plus** not enough swap; bump to 16 GB swap or just resize the box.
- **System unresponsive (SSH hangs)** → host is thrashing. Console reboot via Vultr dashboard, then start at Step 1 immediately on boot.
- **Out of disk for swap** → `df -h /` shows full; clean up `journalctl --vacuum-time=7d` and `/var/cache/apt/archives/*.deb`, then try again.

## Post-incident

If you added swap or memory limits, update `scripts/fleet-config.json` notes for that host so the next operator knows. Pattern:

```
"seed1": {
  ...
  "notes": "... +8 GB swap added 2026-06-24 after OOM-cycle. MemoryHigh=5G/MemoryMax=6G via /etc/systemd/system/coincync-node.service.d/memory.conf."
}
```
