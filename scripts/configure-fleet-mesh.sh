#!/usr/bin/env bash
# configure-fleet-mesh.sh — rewrite each fleet box's coincync-node systemd
# unit so it dials every OTHER fleet box via --addnode.
#
# ⚠️  DEPRECATED for the current 9-node fleet — prefer:
#
#         scripts/sync-fleet-config.sh
#
#     …which renders each unit from scripts/fleet-config.json (via
#     scripts/render-systemd-unit.sh), correctly excludes the
#     role=api nginx-only host from every addnode list, and gates
#     each host restart on `peer_count >= 3 AND tip_age < 300s`
#     before proceeding to the next one (feedback_no_bulk_rolling_restart).
#
# This script is retained as an emergency fallback for the case where the
# fleet-config.json workflow itself is broken. Two important fixes vs the
# 2026-05-10 original:
#
#   1. FLEET_IPS default is now derived from fleet-config.json at runtime,
#      not hardcoded to the destroyed 2026-05-10 5-box list
#      (66.135.23.193 destroyed 2026-06-25, 207.148.111.76 destroyed
#      2026-06-18 — see fleet-config.json `_history` block for the
#      full record of destroyed IPs).
#
#   2. role=api hosts are excluded (they run nginx-only, not
#      coincync-node — dialing them wastes outbound dial budget).
#
# Usage (from this repo's root):
#   bash scripts/configure-fleet-mesh.sh
#
# Environment overrides:
#   FLEET_IPS  — space-separated fleet IPs. If unset, sourced from
#                fleet-config.json (active nodes with role != "api").
#   SSH_KEY    — ssh private key (default: ~/.ssh/coincync_fleet)
#   SERVICE    — systemd unit name (default: coincync-node)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="$SCRIPT_DIR/fleet-config.json"

SSH_KEY="${SSH_KEY:-$HOME/.ssh/coincync_fleet}"
SERVICE="${SERVICE:-coincync-node}"
P2P_PORT="${P2P_PORT:-28080}"

if [[ -z "${FLEET_IPS:-}" ]]; then
  if [[ ! -f "$CONFIG" ]]; then
    echo "FATAL: FLEET_IPS not set and $CONFIG not found" >&2
    echo "  Either export FLEET_IPS='<ip1> <ip2> ...' or run from the repo root." >&2
    exit 1
  fi
  if ! command -v jq >/dev/null 2>&1; then
    echo "FATAL: jq is required to source FLEET_IPS from fleet-config.json (apt install jq)" >&2
    exit 1
  fi
  # Active nodes only (from .nodes, not .deactivated). Exclude role=api
  # (nginx-only host, not a coincync-node peer).
  FLEET_IPS=$(jq -r '.nodes | to_entries | map(select(.value.role != "api")) | map(.value.ip) | join(" ")' "$CONFIG")
  P2P_PORT=$(jq -r '.p2p_port // 28080' "$CONFIG" | tr -d '\r')
fi

[ -f "$SSH_KEY" ] || { echo "SSH_KEY not found: $SSH_KEY" >&2; exit 1; }

ssh_cmd() {
  ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 "root@$1" "$2"
}

echo "==> Configuring full-mesh --addnode topology"
echo "    fleet : $FLEET_IPS"
echo "    port  : $P2P_PORT"
echo "    NOTE  : role=api hosts are excluded from FLEET_IPS above."
echo

for HOST in $FLEET_IPS; do
  # Build --addnode list pointing at every OTHER fleet IP.
  PEERS_LINE=""
  for P in $FLEET_IPS; do
    [ "$P" = "$HOST" ] && continue
    PEERS_LINE="$PEERS_LINE --addnode $P:$P2P_PORT"
  done

  echo "── $HOST → $PEERS_LINE ──"

  # The unit's ExecStart spans multiple lines with `\` continuations.
  # The last argument line is the one containing `--log-level`. We rewrite
  # that whole line to: `<existing log-level>` + our full --addnode list.
  ssh_cmd "$HOST" "sed -i 's|--log-level info.*|--log-level info${PEERS_LINE}|' /etc/systemd/system/${SERVICE}.service \
    && systemctl daemon-reload \
    && systemctl restart ${SERVICE} \
    && echo '   ✓ unit rewritten + ${SERVICE} restarted'"
done

echo
echo "==> Done. Mesh is up. Wait ~60s for handshakes to complete, then verify:"
echo "    bash scripts/check-fleet-peers.sh"
