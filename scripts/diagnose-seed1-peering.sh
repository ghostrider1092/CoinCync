#!/bin/bash
# diagnose-seed1-peering.sh — quick reachability + journal-grep against
# every other fleet host. Run from seed1 (or wherever peering is
# suspected broken).
#
# Fleet IPs are sourced from ../scripts/fleet-config.json (via jq) if
# available, else fall back to whatever's baked in. Pre-fix versions
# hardcoded 207.148.111.76 (destroyed 2026-06-18) as an "other fleet
# member" — reachability check would report BLOCKED forever, misleading
# the operator that seed1 had a firewall problem when the real cause
# was a stale IP.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="${FLEET_CONFIG:-$SCRIPT_DIR/fleet-config.json}"
SELF_IP="${SELF_IP:-}"

if [[ -f "$CONFIG" ]] && command -v jq >/dev/null 2>&1; then
  # Source active peer IPs from fleet-config.json. Skip role=api (nginx-
  # only host, doesn't answer P2P 28080). Skip self.
  P2P_PORT=$(jq -r '.p2p_port // 28080' "$CONFIG" | tr -d '\r')

  # Try to auto-detect self by matching one of the primary IPs on this
  # host to a node entry in the config.
  if [[ -z "$SELF_IP" ]] && command -v hostname >/dev/null 2>&1; then
    HOST_IPS=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '^$' || true)
    for cand in $HOST_IPS; do
      if jq -e --arg ip "$cand" '.nodes | to_entries[] | select(.value.ip == $ip)' "$CONFIG" >/dev/null 2>&1; then
        SELF_IP="$cand"
        break
      fi
    done
  fi

  # Peer IPs = fleet nodes minus api-role hosts minus (best-effort) self.
  if [[ -n "$SELF_IP" ]]; then
    PEER_IPS=$(jq -r --arg self "$SELF_IP" '.nodes | to_entries | map(select(.value.role != "api")) | map(select(.value.ip != $self)) | map(.value.ip) | join(" ")' "$CONFIG")
  else
    PEER_IPS=$(jq -r '.nodes | to_entries | map(select(.value.role != "api")) | map(.value.ip) | join(" ")' "$CONFIG")
  fi

  # DNS names to check are still worth listing — even if the actual
  # servers move, coincync.network subdomains are the canonical bootstrap
  # entry points and DNS drift there is worth flagging.
  DNS_NAMES=$(jq -r '.nodes | keys | map(select(. != "randomx" and . != "randomx2" and . != "relay1" and . != "relay2")) | join(" ")' "$CONFIG")
  # Fallback if the config's keys don't map cleanly to public DNS:
  [[ -z "$DNS_NAMES" ]] && DNS_NAMES="seed1 seed2 seed3 explorer api"
else
  echo "warning: fleet-config.json not readable at $CONFIG — using baked-in fallback list" >&2
  # Fallback matches current 2026-07-05 fleet minus dead IPs
  PEER_IPS="140.82.57.168 45.32.251.6 207.148.6.50 95.179.165.225 173.199.93.21 208.85.17.18 70.34.250.31 45.32.79.234"
  P2P_PORT=28080
  DNS_NAMES="seed1 seed2 seed3 explorer api"
fi

echo "=== TCP reachability from this box to other fleet members ==="
for ip in $PEER_IPS; do
  printf "  -> %-18s : " "$ip:$P2P_PORT"
  timeout 5 bash -c "</dev/tcp/$ip/$P2P_PORT" 2>/dev/null && echo "OPEN" || echo "BLOCKED/REFUSED"
done

echo ""
echo "=== DNS resolution of fleet hostnames as seen by this box ==="
for n in $DNS_NAMES; do
  printf "  %-30s -> " "$n.coincync.network"
  getent hosts "$n.coincync.network" | head -1 || echo "(no resolution)"
done

echo ""
echo "=== --addnode connection attempts in journal (last 100 lines) ==="
# Build a grep alternation from the current PEER_IPS list so the journal
# grep stays in sync with reality. Escapes dots for regex.
if [[ -n "$PEER_IPS" ]]; then
  PATTERN=$(echo "$PEER_IPS" | tr ' ' '\n' | sed 's/\./\\./g' | paste -sd '|' -)
  journalctl -u coincync-node --no-pager 2>/dev/null \
    | grep -E "${PATTERN}|addnode|manual peer" \
    | tail -30
else
  journalctl -u coincync-node --no-pager 2>/dev/null \
    | grep -E "addnode|manual peer" \
    | tail -30
fi

echo ""
echo "=== Active outbound connections (from this box to anywhere:28080) ==="
ss -Hntp state established 2>/dev/null \
  | grep ":$P2P_PORT" \
  | awk '{print $4 " -> " $5}' \
  | head -20
