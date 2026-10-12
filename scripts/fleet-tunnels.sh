#!/usr/bin/env bash
# fleet-tunnels.sh — open SSH local forwards to every core fleet node's
# loopback-bound RPC, so `cytop --fleet` (or any local HTTP client) can poll the
# whole testnet from one workstation.
#
# The core nodes bind RPC to 127.0.0.1 (see fleet-config.json `rpc_bind`), so
# they are not reachable directly. This script reads the fleet topology, opens
# one `ssh -L <localport>:127.0.0.1:<rpc_port>` per node (ports 28081, 28082, …),
# prints the matching `--fleet` spec, and holds the tunnels open until Ctrl-C.
#
# Usage:
#   scripts/fleet-tunnels.sh                 # all nodes with rpc_bind=127.0.0.1
#   KEY=~/.ssh/other scripts/fleet-tunnels.sh
#   BASE_PORT=29000 scripts/fleet-tunnels.sh
#
# Env:
#   KEY        SSH key              (default ~/.ssh/coincync_fleet)
#   SSH_USER   remote user          (default root)
#   BASE_PORT  first local port     (default 28081)
#   CONFIG     fleet-config.json    (default alongside this script)
#
# Read-only: opens port-forwards only, runs nothing on the remote hosts.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${CONFIG:-$HERE/fleet-config.json}"
KEY="${KEY:-$HOME/.ssh/coincync_fleet}"
SSH_USER="${SSH_USER:-root}"
BASE_PORT="${BASE_PORT:-28081}"

command -v jq >/dev/null || { echo "error: jq not found" >&2; exit 1; }
[ -f "$CONFIG" ] || { echo "error: no config at $CONFIG" >&2; exit 1; }
[ -f "$KEY" ] || { echo "error: no SSH key at $KEY (set KEY=…)" >&2; exit 1; }

RPC_PORT="$(jq -r '.rpc_port // 28081' "$CONFIG")"

# Core nodes = those that bind RPC to loopback (the operator-controlled fleet we
# can SSH into). name<TAB>ip, in config order.
mapfile -t NODES < <(jq -r '
  .nodes | to_entries[]
  | select(.value.rpc_bind == "127.0.0.1")
  | "\(.key)\t\(.value.ip)"' "$CONFIG")

[ "${#NODES[@]}" -gt 0 ] || { echo "error: no rpc_bind=127.0.0.1 nodes in $CONFIG" >&2; exit 1; }

PIDS=()
SPEC=""
cleanup() {
  echo; echo "closing ${#PIDS[@]} tunnel(s)…"
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

port="$BASE_PORT"
echo "opening tunnels (key=$KEY user=$SSH_USER rpc_port=$RPC_PORT)…"
for row in "${NODES[@]}"; do
  name="${row%%$'\t'*}"
  ip="${row##*$'\t'}"
  ssh -i "$KEY" \
      -o BatchMode=yes \
      -o ConnectTimeout=12 \
      -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
      -o ExitOnForwardFailure=yes \
      -o StrictHostKeyChecking=accept-new \
      -N -L "127.0.0.1:${port}:127.0.0.1:${RPC_PORT}" "${SSH_USER}@${ip}" &
  PIDS+=("$!")
  printf '  %-14s %-16s → 127.0.0.1:%s\n' "$name" "$ip" "$port"
  [ -n "$SPEC" ] && SPEC+=","
  SPEC+="${name}=http://127.0.0.1:${port}"
  port=$((port + 1))
done

# Give the forwards a moment to establish (or fail fast via ExitOnForwardFailure).
sleep 2

echo
echo "fleet spec:"
echo "  $SPEC"
echo
echo "run the monitor:"
echo "  cytop --fleet '$SPEC'"
echo
echo "tunnels are open; press Ctrl-C to close them."
wait
