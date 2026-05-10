#!/bin/bash
# Print peer-state for the local coincync-node:
#   - total ESTABLISHED TCP peers on port 28080
#   - which of those are members of our own fleet (proves cross-peering)
set -uo pipefail

FLEET_IPS="66.135.23.193 140.82.57.168 207.148.111.76 207.148.6.50 95.179.165.225"

PEERS=$(ss -Hn state established 2>/dev/null \
        | grep ':28080' \
        | awk '{print $5}' \
        | sed 's/:.*//' \
        | sort -u)

TOTAL=$(echo "$PEERS" | grep -c .)
echo "total established peers: $TOTAL"

if [ "$TOTAL" -gt 0 ]; then
  echo "peer IPs:"
  echo "$PEERS" | sed 's/^/  /'

  FLEET_PEERS=$(echo "$PEERS" | grep -Fx -f <(echo "$FLEET_IPS" | tr ' ' '\n') || true)
  FLEET_COUNT=$(echo "$FLEET_PEERS" | grep -c . || true)
  echo "fleet self-peering: $FLEET_COUNT of 4 other fleet members"
  if [ -n "$FLEET_PEERS" ]; then
    echo "$FLEET_PEERS" | sed 's/^/  /'
  fi
fi

# Also report height/tip if we can reach RPC locally (no auth needed for /rest endpoints)
echo "--- chain state ---"
sudo -u coincync /usr/local/bin/coincync-node --data-dir /var/lib/coincync --network testnet status 2>&1 | grep -E 'Network|Height|Tip' || echo "(status command failed)"
