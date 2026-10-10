#!/usr/bin/env bash
#
# deploy-node.sh — stand up a PUBLIC, inbound-reachable CoinCync node on a fresh
# Linux VPS (Hetzner / any Debian/Ubuntu box). Run it ON THE VPS, as root (or
# with sudo), FROM a clone of this repo:
#
#     git clone <repo-url> coincync && cd coincync
#     sudo COINCYNC_ADDNODES="2.29.34.197:28080 <vps2-ip>:28080" bash scripts/deploy-node.sh
#
# It installs build deps, builds the release node, opens the P2P port in the
# firewall, and installs + starts a systemd service that restarts on failure.
# RPC/metrics/REST stay bound to localhost (never exposed).
#
# See docs/ops/public-node-runbook.md for the why + the mesh topology.
#
# NOTE: this does NOT provision the VPS or touch any cloud account — you create
# the server and SSH in yourself; this only configures the node on it.
set -euo pipefail

# ── settings (override via env) ──────────────────────────────────────────────
NETWORK="${COINCYNC_NETWORK:-testnet}"
P2P_PORT="${COINCYNC_P2P_PORT:-28080}"
DATA_DIR="${COINCYNC_DATA_DIR:-/var/lib/coincync}"
RUN_USER="${COINCYNC_USER:-coincync}"
# Space-separated ip:port peers to --addnode (the seed + your other VPS nodes).
# CROSS-CONNECT: give each node the addresses of the OTHERS, not just the seed.
ADDNODES="${COINCYNC_ADDNODES:-2.29.34.197:28080}"
# Light RandomX avoids the ~2 GB full-dataset build; fine for a relay/validation
# node. Set to 0 only if this box also mines heavily.
LIGHT_RANDOMX="${COINCYNC_RANDOMX_LIGHT_MODE:-1}"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_SRC="$REPO_DIR/target/release/coincync-node"
BIN_DST="/usr/local/bin/coincync-node"

echo "==> CoinCync node deploy  (network=$NETWORK port=$P2P_PORT user=$RUN_USER)"
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }

# ── 1. build deps ────────────────────────────────────────────────────────────
echo "==> installing build dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y build-essential clang libclang-dev cmake pkg-config \
  libssl-dev git curl ca-certificates ufw

# ── 2. rust toolchain ────────────────────────────────────────────────────────
if ! command -v cargo >/dev/null 2>&1; then
  echo "==> installing rustup"
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
fi
# shellcheck disable=SC1090
source "$HOME/.cargo/env" 2>/dev/null || true

# ── 3. build the node ────────────────────────────────────────────────────────
echo "==> building coincync-node --release (this takes a while)"
( cd "$REPO_DIR" && cargo build --release --bin coincync-node --features "$NETWORK" )
install -m 0755 "$BIN_SRC" "$BIN_DST"
"$BIN_DST" --version 2>/dev/null || true

# ── 4. service user + data dir ───────────────────────────────────────────────
id -u "$RUN_USER" >/dev/null 2>&1 || useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin "$RUN_USER"
install -d -o "$RUN_USER" -g "$RUN_USER" "$DATA_DIR"

# ── 5. firewall: open the P2P port, keep SSH, leave RPC/metrics/REST closed ──
echo "==> opening inbound TCP $P2P_PORT (P2P); RPC/metrics/REST stay on localhost"
ufw allow OpenSSH >/dev/null 2>&1 || ufw allow 22/tcp || true
ufw allow "${P2P_PORT}/tcp" || true
yes | ufw enable >/dev/null 2>&1 || true

# ── 6. systemd service ───────────────────────────────────────────────────────
ADDNODE_ARGS=""
for p in $ADDNODES; do ADDNODE_ARGS="$ADDNODE_ARGS --addnode $p"; done

cat > /etc/systemd/system/coincync-node.service <<UNIT
[Unit]
Description=CoinCync node ($NETWORK)
After=network-online.target
Wants=network-online.target

[Service]
User=$RUN_USER
Group=$RUN_USER
Environment=COINCYNC_RANDOMX_LIGHT_MODE=$LIGHT_RANDOMX
ExecStart=$BIN_DST --network $NETWORK --data-dir $DATA_DIR$ADDNODE_ARGS
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
# hardening (RPC/metrics/REST already bind to 127.0.0.1)
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=$DATA_DIR
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now coincync-node.service

echo
echo "==> done. node is running as a service."
echo "    logs:    journalctl -u coincync-node -f"
echo "    status:  curl -s -X POST http://127.0.0.1:28081 -H 'content-type: application/json' \\"
echo "               -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_info\",\"params\":[]}' | jq '{height,peer_count,inbound_peers,inbound_reachable}'"
echo "    After a few minutes, inbound_reachable should be true (someone dialed you)."
echo "    Verify the port from another machine:  nc -vz <this-vps-public-ip> $P2P_PORT"
