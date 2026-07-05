#!/bin/bash
# Print peer-state for the local coincync-node:
#   - total ESTABLISHED TCP peers on port 28080
#   - which of those are members of our own fleet (proves cross-peering)
#
# Fleet IPs are sourced from ../scripts/fleet-config.json (via jq) if that
# file is reachable, so this script stays correct as the fleet is rewired.
# Pre-fix versions hardcoded 66.135.23.193 (destroyed 2026-06-25) and
# 207.148.111.76 (destroyed 2026-06-18) — dead IPs made "fleet self-
# peering" report incorrectly low every time it ran, causing false-
# positive peer-partition alarms.
#
# Falls back to an env override if jq/config isn't available:
#   FLEET_IPS="ip1 ip2 ..." bash check-fleet-peers.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="$SCRIPT_DIR/fleet-config.json"

if [[ -z "${FLEET_IPS:-}" ]]; then
  if [[ -f "$CONFIG" ]] && command -v jq >/dev/null 2>&1; then
    # Active fleet IPs (skip role=api nginx-only host — it doesn't run coincync-node)
    FLEET_IPS=$(jq -r '.nodes | to_entries | map(select(.value.role != "api")) | map(.value.ip) | join(" ")' "$CONFIG")
  else
    # Fallback — safe empty default so the "fleet self-peering" count is 0 rather than
    # comparing against dead IPs (which is worse than not comparing at all).
    FLEET_IPS=""
    echo "warning: fleet-config.json not readable; fleet self-peering check disabled" >&2
  fi
fi

# Count fleet peers excluding ourselves — need to subtract 1 for the "self" count
# in the "X of Y other members" message.
FLEET_TOTAL=$(echo "$FLEET_IPS" | tr ' ' '\n' | grep -cv '^$' || echo 0)
OTHERS=$((FLEET_TOTAL > 0 ? FLEET_TOTAL - 1 : 0))

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

  if [ -n "$FLEET_IPS" ]; then
    FLEET_PEERS=$(echo "$PEERS" | grep -Fx -f <(echo "$FLEET_IPS" | tr ' ' '\n') || true)
    FLEET_COUNT=$(echo "$FLEET_PEERS" | grep -c . || true)
    echo "fleet self-peering: $FLEET_COUNT of $OTHERS other fleet members"
    if [ -n "$FLEET_PEERS" ]; then
      echo "$FLEET_PEERS" | sed 's/^/  /'
    fi
  fi
fi

# Also report height/tip if we can reach RPC locally (no auth needed for /rest endpoints)
echo "--- chain state ---"
sudo -u coincync /usr/local/bin/coincync-node --data-dir /var/lib/coincync --network testnet status 2>&1 | grep -E 'Network|Height|Tip' || echo "(status command failed)"
