#!/usr/bin/env bash
#
# render-systemd-unit.sh <hostname>
#
# Read scripts/fleet-config.json and emit a complete systemd unit file
# for the named host on stdout. The unit includes --addnode flags for
# EVERY OTHER active node in the fleet, eliminating the
# fleet-topology-drift bug that caused the 2026-06-17/18 stall (miner
# box was missing from seed1/seed2/explorer/api dial lists).
#
# Usage:
#     scripts/render-systemd-unit.sh miner | \
#       ssh root@149.248.37.11 'cat > /etc/systemd/system/coincync-node.service'
#
#     # Or via sync-fleet-config.sh for a full fleet rollout.
#
# Requires: jq (for JSON parsing).
#
# Output is deterministic for a given fleet-config.json — the addnode
# list is sorted alphabetically by hostname so two renders of the same
# config produce byte-identical units. Makes diffing trivial.

set -euo pipefail

HOSTNAME="${1:-}"
if [[ -z "$HOSTNAME" ]]; then
    echo "usage: $0 <hostname>" >&2
    echo "  available hosts in fleet-config.json:" >&2
    jq -r '.nodes | keys[] | "    " + .' "$(dirname "$0")/fleet-config.json" >&2 2>/dev/null || true
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="$SCRIPT_DIR/fleet-config.json"

if [[ ! -f "$CONFIG" ]]; then
    echo "FATAL: $CONFIG not found" >&2
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "FATAL: jq is required (apt install jq / brew install jq)" >&2
    exit 1
fi

# Validate target host exists
if ! jq -e ".nodes.\"$HOSTNAME\"" "$CONFIG" >/dev/null 2>&1; then
    echo "FATAL: '$HOSTNAME' not found in fleet-config.json nodes" >&2
    echo "  available:" >&2
    jq -r '.nodes | keys[] | "    " + .' "$CONFIG" >&2
    exit 1
fi

# Extract config
P2P_PORT=$(jq -r '.p2p_port' "$CONFIG" | tr -d '\r')
RPC_PORT=$(jq -r '.rpc_port' "$CONFIG" | tr -d '\r')
NETWORK=$(jq -r '.network' "$CONFIG" | tr -d '\r')

# Per-host RPC bind address. Default to loopback if not specified.
# 127.0.0.1 = loopback-only (safer; assumes nginx/stunnel for public exposure).
# 0.0.0.0 = listen on all interfaces (public RPC).
RPC_BIND=$(jq -r ".nodes.\"$HOSTNAME\".rpc_bind // \"127.0.0.1\"" "$CONFIG" | tr -d '\r')

# Build the addnode list: every OTHER active node THAT RUNS A
# COINCYNC-NODE, sorted by hostname for deterministic output.
#
# Exclude role=api: those hosts run an nginx reverse proxy ONLY,
# not coincync-node, so adding them to addnode wastes outbound
# dial budget on connection attempts that always fail. Repeatedly
# triggers eclipse-defense throttling (it counts api as a known
# peer in api's /16 subnet) and starves legitimate fleet peers
# out of outbound slots. Discovered 2026-06-24 during chain-
# partition recovery: see [[project_chain_partition_2026_06_22]]
# in operator memory.
#
# Any new non-node infra roles (frost-coordinator host, faucet-
# only host, etc.) should be added to this exclusion list.
ADDNODES=$(jq -r \
    --arg self "$HOSTNAME" \
    --arg port "$P2P_PORT" \
    '.nodes
     | to_entries
     | map(select(.key != $self))
     | map(select(.value.role != "api"))
     | sort_by(.key)
     | map("    --addnode " + .value.ip + ":" + $port + " \\")
     | join("\n")
     | rtrimstr(" \\")' \
    "$CONFIG")

cat <<EOF
[Unit]
Description=CoinCync 1.0 Full Node
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/coincync/coincync.env
Type=simple
User=coincync
Group=coincync
# Testnet defaults: P2P 28080, RPC 28081 (see src/testnet.rs).
# Expose P2P publicly for seed/relay; keep RPC on loopback unless you
# know the exposure model (reverse proxy, firewall, auth).
#
# --addnode list rendered from scripts/fleet-config.json by
# scripts/render-systemd-unit.sh. To add/remove a node from the fleet,
# update the JSON and re-run scripts/sync-fleet-config.sh — never edit
# this unit file by hand.
ExecStart=/usr/local/bin/coincync-node \\
    --data-dir /var/lib/coincync \\
    --network ${NETWORK} \\
    --p2p-bind 0.0.0.0:${P2P_PORT} \\
    --rpc-bind ${RPC_BIND}:${RPC_PORT} \\
    --log-level info \\
${ADDNODES}
Restart=on-failure
RestartSec=10
LimitNOFILE=65536
TimeoutStartSec=300
TimeoutStopSec=60
# Don't auto-restart on every wobble — clean exits should stay exited.
# (We removed the per-5-min watchdog timer in 2026-06-17 because its
# "tip > 10min stale = restart" heuristic produced false positives on
# low-hashrate periods. Real RPC-deadlock detection is a Tier 2 item.)

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/coincync
ProtectHome=yes

StandardOutput=journal
StandardError=journal
SyslogIdentifier=coincync-node

[Install]
WantedBy=multi-user.target
EOF
