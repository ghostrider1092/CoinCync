#!/usr/bin/env bash
# configure-fleet-mesh.sh — rewrite each fleet box's coincync-node systemd
# unit so it dials every OTHER fleet box via --addnode. This gives us a
# full N-way mesh of TCP-28080 connections among the public-testnet boxes
# rather than the partial topology where only a few seeds know about each
# other.
#
# Why this is needed: relying on DNS-seed-discovery + a couple of static
# --addnode entries leaves boxes like the explorer (no addnodes at all)
# and api (only seed1) one connection away from being isolated. When that
# single peer wedges or the connection goes half-open, the box stops
# receiving blocks and the chain looks stalled to anything reading from
# it — which is exactly what we hit on 2026-05-10 (explorer reading
# "chain data is N minutes old" while api was busy mining h=200+).
#
# After running this script, every fleet box dials the other four; the
# total mesh has 20 directed P2P slots (5×4) which gives the network
# redundancy to a single peer failure on any box.
#
# Usage (from this repo's root):
#   bash scripts/configure-fleet-mesh.sh
#
# Environment overrides:
#   FLEET_IPS  — space-separated fleet IPs (default: production Vultr 5-box)
#   SSH_KEY    — ssh private key (default: ~/.ssh/coincync_fleet)
#   SERVICE    — systemd unit name (default: coincync-node)

set -euo pipefail

SSH_KEY="${SSH_KEY:-$HOME/.ssh/coincync_fleet}"
SERVICE="${SERVICE:-coincync-node}"
FLEET_IPS="${FLEET_IPS:-66.135.23.193 140.82.57.168 207.148.111.76 207.148.6.50 95.179.165.225}"
P2P_PORT="${P2P_PORT:-28080}"

[ -f "$SSH_KEY" ] || { echo "SSH_KEY not found: $SSH_KEY" >&2; exit 1; }

ssh_cmd() {
  ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 "root@$1" "$2"
}

echo "==> Configuring full-mesh --addnode topology"
echo "    fleet : $FLEET_IPS"
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
