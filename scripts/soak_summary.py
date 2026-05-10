#!/usr/bin/env python3
"""Summarize a CoinCync soak-test JSONL log.

Usage:  python scripts/soak_summary.py logs/soak/<timestamp>.jsonl
"""
import json
import statistics
import sys
from pathlib import Path


def load(p: Path):
    rows = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
    return rows


def fmt_bytes(kb):
    if kb is None:
        return "—"
    if kb >= 1024 * 1024:
        return f"{kb / 1024 / 1024:.2f} GB"
    if kb >= 1024:
        return f"{kb / 1024:.1f} MB"
    return f"{kb} KB"


def main():
    if len(sys.argv) != 2:
        print("usage: soak_summary.py <log.jsonl>", file=sys.stderr)
        sys.exit(2)

    log_path = Path(sys.argv[1])
    rows = load(log_path)
    if not rows:
        print("No samples in log.")
        sys.exit(1)

    samples = [r for r in rows if "height" in r and r.get("height") is not None]
    if not samples:
        print("No usable samples.")
        sys.exit(1)

    first = samples[0]
    last = samples[-1]
    duration_h = (last["ts"] - first["ts"]) / 3600

    heights = [s["height"] for s in samples]
    blocks = max(heights) - min(heights)
    avg_block_time = (duration_h * 3600) / blocks if blocks else 0

    tip_ages = [s.get("tip_age_secs") or 0 for s in samples]
    health = [s.get("health_score") or 0 for s in samples]
    peers = [s.get("peer_count") or 0 for s in samples]
    mempool = [s.get("mempool_size") or 0 for s in samples]

    node_mems = [s.get("node", {}).get("mem_kb") for s in samples if s.get("node")]
    node_mems = [m for m in node_mems if m]
    miner_mems = [s.get("miner", {}).get("mem_kb") for s in samples if s.get("miner")]
    miner_mems = [m for m in miner_mems if m]

    aborts = [r for r in rows if r.get("event") == "soak_aborted_stall"]

    p = print
    p("-" * 60)
    p(f"CoinCync soak summary  -- {log_path.name}")
    p("-" * 60)
    p(f"samples:        {len(samples)}")
    p(f"duration:       {duration_h:.2f} h")
    p(f"start ts:       {first.get('iso')}")
    p(f"end ts:         {last.get('iso')}")
    if aborts:
        p(f"** ABORTED:     stall after {aborts[0].get('stall_secs')}s at h={aborts[0].get('last_height')}")
    p("")
    p(f"chain height:   {min(heights)}  -> {max(heights)}   (+{blocks})")
    p(f"avg block time: {avg_block_time:.1f} s   (target = 120s for testnet)")
    p(f"tip_age (s):    min={min(tip_ages):.0f}  median={statistics.median(tip_ages):.0f}  max={max(tip_ages):.0f}")
    p(f"health_score:   min={min(health):.2f}  median={statistics.median(health):.2f}  max={max(health):.2f}")
    p(f"peer_count:     min={min(peers)}  median={statistics.median(peers):.0f}  max={max(peers)}")
    p(f"mempool_size:   min={min(mempool)}  max={max(mempool)}  median={statistics.median(mempool):.0f}")
    p("")

    if node_mems:
        node_growth = node_mems[-1] - node_mems[0]
        p(f"node memory:    {fmt_bytes(node_mems[0])} ->{fmt_bytes(node_mems[-1])}   (delta {fmt_bytes(node_growth)})")
        p(f"  peak:         {fmt_bytes(max(node_mems))}")
    if miner_mems:
        miner_growth = miner_mems[-1] - miner_mems[0]
        p(f"miner memory:   {fmt_bytes(miner_mems[0])} ->{fmt_bytes(miner_mems[-1])}   (delta {fmt_bytes(miner_growth)})")
        p(f"  peak:         {fmt_bytes(max(miner_mems))}")
    p("")

    # Verdict
    issues = []
    if aborts:
        issues.append("chain stalled (auto-aborted)")
    if max(tip_ages) > 600:
        issues.append(f"tip went stale (max={max(tip_ages)}s > 600s threshold)")
    if min(health) < 0.5:
        issues.append(f"health dropped below 0.5 (min={min(health):.2f})")
    if avg_block_time and (avg_block_time < 60 or avg_block_time > 300):
        issues.append(f"avg block time {avg_block_time:.0f}s outside 60–300s window (target 120)")
    if node_mems and (node_mems[-1] / max(node_mems[0], 1)) > 3:
        issues.append(f"node memory grew >3x ({fmt_bytes(node_mems[0])} ->{fmt_bytes(node_mems[-1])}) --possible leak")

    p("verdict:")
    if not issues:
        p("  OK - no anomalies detected over the soak window")
    else:
        for i in issues:
            p(f"  FAIL - {i}")
    p("-" * 60)


if __name__ == "__main__":
    main()
