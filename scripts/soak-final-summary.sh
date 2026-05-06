#!/usr/bin/env bash
# soak-final-summary.sh
#
# Pulls the per-box soak .jsonl from each fleet host and prints a
# markdown table suitable for pasting into
# docs/launch/v1.0.2-testnet-soak-summary.md.
#
# Run after the 72h window completes (2026-05-07 02:48 UTC for v1.0.2).
#
# Requires: ssh access to root@<each-fleet-ip> via ~/.ssh/coincync_fleet.

set -uo pipefail

KEY="${HOME}/.ssh/coincync_fleet"
SSH_OPTS="-i $KEY -o StrictHostKeyChecking=no -o ConnectTimeout=8"

# Hostname / IP / human label
FLEET=(
  "seed1 (NJ)|66.135.23.193"
  "seed2 (AMS)|140.82.57.168"
  "seed3 (Tokyo)|207.148.111.76"
  "explorer (Dallas)|207.148.6.50"
  "api (Frankfurt)|95.179.165.225"
)

echo "| Box | Samples | Max stall | Desync samples | Final tip | Notes |"
echo "|---|---|---|---|---|---|"

for entry in "${FLEET[@]}"; do
  name="${entry%%|*}"
  ip="${entry##*|}"
  result=$(ssh $SSH_OPTS "root@${ip}" "
    f=\$(ls -t /var/lib/coincync/soak/*.jsonl 2>/dev/null | head -1)
    [ -z \"\$f\" ] && { echo 'NO_FILE'; exit 0; }
    total=\$(grep -c '\"ts\"' \$f)
    max_stall=\$(grep -oE '\"stall\":[0-9]+' \$f | awk -F: '{print \$2}' | sort -n | tail -1)
    desync=\$(grep -c '\"synced\":false' \$f)
    latest_h=\$(grep -oE '\"height\":[0-9]+' \$f | tail -1 | awk -F: '{print \$2}')
    echo \"\$total|\${max_stall}s|\$desync|\$latest_h\"
  " 2>/dev/null)

  if [ "$result" = "NO_FILE" ] || [ -z "$result" ]; then
    echo "| ${name} | ? | ? | ? | ? | ssh/data unavailable |"
  else
    IFS='|' read -r total stall desync height <<< "$result"
    echo "| ${name} | ${total} | ${stall} | ${desync} | ${height} |  |"
  fi
done

echo ""
echo "_Generated $(date -u +'%Y-%m-%dT%H:%M:%SZ') by scripts/soak-final-summary.sh_"
