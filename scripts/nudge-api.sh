#!/bin/bash
# Add --addnode <seed1-current-ip>:28080 to api's systemd unit and restart.
#
# ⚠️  DEPRECATED — prefer the fleet-config.json workflow:
#
#         scripts/render-systemd-unit.sh api > /etc/systemd/system/coincync-node.service
#         systemctl daemon-reload && systemctl restart coincync-node
#
#     …or the batched version `scripts/sync-fleet-config.sh --only api`
#     which handles rendering + reload + safety-gates (peer_count >= 3
#     AND tip_age < 300s) in one shot.
#
# This script is retained because it was historically referenced from
# recovery docs. Prior versions hardcoded the seed1 IP (66.135.23.193
# and its successor 104.207.140.83, both destroyed), which would append
# a DEAD IP to api's addnode list and burn its outbound dial budget on
# connections that always fail. Now sourced dynamically from
# scripts/fleet-config.json — but the fleet-config workflow above is
# still the canonical way to change this.
#
# Bails if run against a fleet-config.json whose api node isn't at the
# expected IP (safety catch in case of manual host rewiring).

set -euo pipefail

UNIT=/etc/systemd/system/coincync-node.service
CONFIG="$(dirname "$0")/fleet-config.json"

if ! command -v jq >/dev/null 2>&1; then
  echo "FATAL: jq is required (apt install jq)" >&2
  exit 1
fi

if [[ ! -f "$CONFIG" ]]; then
  echo "FATAL: $CONFIG not found — run this from the coincync repo root" >&2
  exit 1
fi

# Pull the CURRENT seed1 IP from fleet-config.json rather than hardcoding.
# If a future rename moves seed1 to a different key, edit fleet-config.json
# and re-render; do not hardcode here.
SEED1_IP=$(jq -r '.nodes.seed1.ip // empty' "$CONFIG" | tr -d '\r')
P2P_PORT=$(jq -r '.p2p_port // 28080' "$CONFIG" | tr -d '\r')

if [[ -z "$SEED1_IP" || "$SEED1_IP" == "null" ]]; then
  echo "FATAL: seed1.ip missing from $CONFIG" >&2
  exit 1
fi

# Idempotent — only patch if this specific seed1 IP isn't already in there
if grep -q "addnode $SEED1_IP" "$UNIT"; then
  echo "seed1 ($SEED1_IP) already present in --addnode list; just restarting"
else
  # Inject after --log-level info (same hook the provisioner uses)
  sed -i "s|--log-level info|--log-level info --addnode $SEED1_IP:$P2P_PORT|" "$UNIT"
  echo "Patched: added --addnode $SEED1_IP:$P2P_PORT"
fi

systemctl daemon-reload
systemctl restart coincync-node

for i in 1 2 3 4 5 6 7 8 9 10; do
  sleep 1
  systemctl is-active --quiet coincync-node && break
done
systemctl is-active --quiet coincync-node || {
  echo "FAIL: service did not become active"
  journalctl -u coincync-node -n 30 --no-pager
  exit 1
}
echo "Service restarted; ExecStart now:"
systemctl cat coincync-node | grep ExecStart -A 1 | head -3
