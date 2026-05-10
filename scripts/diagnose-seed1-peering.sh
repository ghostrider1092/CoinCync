#!/bin/bash
set -uo pipefail

echo "=== TCP reachability from this box to other fleet members ==="
for ip in 140.82.57.168 207.148.111.76 207.148.6.50 95.179.165.225; do
  printf "  -> %-18s : " "$ip:28080"
  timeout 5 bash -c "</dev/tcp/$ip/28080" 2>/dev/null && echo "OPEN" || echo "BLOCKED/REFUSED"
done

echo ""
echo "=== DNS resolution of fleet hostnames as seen by this box ==="
for n in seed1 seed2 seed3 explorer api; do
  printf "  %-30s -> " "$n.coincync.network"
  getent hosts "$n.coincync.network" | head -1 || echo "(no resolution)"
done

echo ""
echo "=== --addnode connection attempts in journal (last 100 lines) ==="
journalctl -u coincync-node --no-pager 2>/dev/null \
  | grep -E '140\.82\.57\.168|207\.148\.111\.76|207\.148\.6\.50|95\.179\.165\.225|addnode|manual peer' \
  | tail -30

echo ""
echo "=== Active outbound connections (from this box to anywhere:28080) ==="
ss -Hntp state established 2>/dev/null \
  | grep ':28080' \
  | awk '{print $4 " -> " $5}' \
  | head -20
