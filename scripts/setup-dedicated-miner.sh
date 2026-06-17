#!/usr/bin/env bash
#
# setup-dedicated-miner.sh
#
# One-shot provisioning for a CoinCync dedicated mining box.
# Sets up: full coincync-node (testnet), coincync-rig solo miner
# pointed at localhost RPC, both as systemd services.
#
# REQUIRES root or sudo. Tested on Ubuntu 22.04 + 24.04. Assumes
# the box has internet + can reach api.coincync.network for the
# bootstrap genesis sync.
#
# Usage (after fresh Vultr/cloud box boot):
#   1. SCP both binaries to /tmp/:
#        scp coincync-node-v1.0.11.2-linux root@<box>:/tmp/coincync-node
#        scp coincync-rig-v1.0.11.2-linux  root@<box>:/tmp/coincync-rig
#   2. SCP this script to /tmp/setup.sh
#   3. SSH in and run:
#        bash /tmp/setup.sh <miner-payout-address>
#
# Where <miner-payout-address> is a tCYNC testnet address you control
# (generate with `coincync-wallet new` if you don't have one yet).
#
# Idempotent — re-running is safe; will refresh binaries + restart
# services without wiping chaindata.

set -euo pipefail

MINER_ADDR="${1:-}"
if [[ -z "$MINER_ADDR" ]]; then
    echo "FATAL: pass a tCYNC payout address as the first arg"
    echo "  usage: $0 <miner-address>"
    exit 1
fi
if [[ "$MINER_ADDR" != tCYNC* ]] && [[ "$MINER_ADDR" != tcync* ]]; then
    echo "WARNING: address '$MINER_ADDR' doesn't look like a testnet address"
    echo "  (expected prefix 'tCYNC'). Continue? [y/N]"
    read -r ans
    [[ "$ans" == "y" ]] || exit 1
fi

# Default to 1 thread; override with MINER_THREADS=4 ./setup.sh
MINER_THREADS="${MINER_THREADS:-1}"

# RandomX mode: fast = ~2 GB shared dataset (10× hashrate), light =
# 256 MB/thread (much slower). Default to light to fit small boxes;
# set RANDOMX_FAST=1 to flip if box has >= 4 GB free RAM.
RANDOMX_FAST="${RANDOMX_FAST:-0}"

NODE_BIN_SRC="${NODE_BIN_SRC:-/tmp/coincync-node}"
RIG_BIN_SRC="${RIG_BIN_SRC:-/tmp/coincync-rig}"
DATA_DIR="/var/lib/coincync"
NODE_USER="coincync"

echo "=== CoinCync dedicated miner setup ==="
echo "Miner address:   $MINER_ADDR"
echo "Threads:         $MINER_THREADS"
echo "RandomX mode:    $([ "$RANDOMX_FAST" = 1 ] && echo "fast (~2 GB)" || echo "light (~256 MB/thread)")"
echo "Node binary:     $NODE_BIN_SRC"
echo "Rig binary:      $RIG_BIN_SRC"
echo

# ── 1. user + dirs ───────────────────────────────────────────────────
if ! id "$NODE_USER" >/dev/null 2>&1; then
    echo "[1/7] creating $NODE_USER system user..."
    useradd --system --home-dir "$DATA_DIR" --create-home --shell /usr/sbin/nologin "$NODE_USER"
fi
mkdir -p "$DATA_DIR/testnet"
chown -R "$NODE_USER:$NODE_USER" "$DATA_DIR"
chmod 750 "$DATA_DIR"

# ── 2. install binaries ──────────────────────────────────────────────
echo "[2/7] installing binaries..."
for src in "$NODE_BIN_SRC" "$RIG_BIN_SRC"; do
    if [[ ! -f "$src" ]]; then
        echo "FATAL: binary missing: $src"
        echo "  SCP it from your build host first (see usage at top of this script)"
        exit 1
    fi
done
install -m 755 "$NODE_BIN_SRC" /usr/local/bin/coincync-node
install -m 755 "$RIG_BIN_SRC"  /usr/local/bin/coincync-rig
/usr/local/bin/coincync-node --version
/usr/local/bin/coincync-rig  --version

# ── 3. coincync-node systemd unit ────────────────────────────────────
echo "[3/7] writing coincync-node.service..."
cat > /etc/systemd/system/coincync-node.service <<EOF
[Unit]
Description=CoinCync 1.0 Full Node (testnet)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$NODE_USER
Group=$NODE_USER
ExecStart=/usr/local/bin/coincync-node \\
    --data-dir $DATA_DIR \\
    --network testnet \\
    --p2p-bind 0.0.0.0:28080 \\
    --rpc-bind 127.0.0.1:28081 \\
    --log-level info \\
    --addnode 66.135.23.193:28080 \\
    --addnode 140.82.57.168:28080 \\
    --addnode 207.148.6.50:28080 \\
    --addnode 95.179.165.225:28080
Restart=on-failure
RestartSec=10
LimitNOFILE=65536
# Don't auto-restart on every wobble — we removed the watchdog timer
# for a reason. on-failure (not always) means clean exits stay exited.

[Install]
WantedBy=multi-user.target
EOF

# ── 4. coincync-rig solo-mining systemd unit ─────────────────────────
echo "[4/7] writing coincync-rig.service..."
# Build the Environment= block. Two env vars worth pinning:
#   COINCYNC_RANDOMX_LIGHT_MODE=1 — only when the operator opted into
#     light mode (saves ~2 GB RAM at ~10× hashrate cost). Skipped when
#     RANDOMX_FAST=1.
#   COINCYNC_RIG_SKIP_SYNC_CHECK=1 — bypasses the rig's "is local node
#     synced" gate. This gate is correct for testers IBD'ing into a
#     long-established chain (don't mine on a private fork), but it
#     deadlocks on a fresh-genesis chain that has no recent block
#     production: the node reports synced=false because no recent
#     blocks have arrived, but no blocks can arrive until SOMEONE
#     mines — Catch-22. A dedicated miner box is, by definition, the
#     operator-verified canonical-chain miner, so the bypass is the
#     correct posture here. See the rationale comment in
#     crates/coincync-rig/src/orchestrator.rs:200-211.
RX_LIGHT=""
if [[ "$RANDOMX_FAST" != "1" ]]; then
    RX_LIGHT="Environment=COINCYNC_RANDOMX_LIGHT_MODE=1"
fi
cat > /etc/systemd/system/coincync-rig.service <<EOF
[Unit]
Description=CoinCync solo miner (coincync-rig)
After=coincync-node.service network-online.target
Requires=coincync-node.service

[Service]
Type=simple
User=$NODE_USER
Group=$NODE_USER
Environment=COINCYNC_RIG_SKIP_SYNC_CHECK=1
$RX_LIGHT
ExecStart=/usr/local/bin/coincync-rig run-solo \\
    --node http://127.0.0.1:28081 \\
    --network testnet \\
    --address $MINER_ADDR \\
    --threads $MINER_THREADS
Restart=on-failure
RestartSec=15
# Give the node 30s after start to come up before the miner attempts
# to fetch its first block template.
ExecStartPre=/bin/sleep 30

[Install]
WantedBy=multi-user.target
EOF

# ── 5. enable + start services ───────────────────────────────────────
echo "[5/7] enabling + starting services..."
systemctl daemon-reload
systemctl enable --now coincync-node.service
echo "  node started; waiting 40s for it to begin syncing..."
sleep 40
systemctl status coincync-node --no-pager | head -10

systemctl enable --now coincync-rig.service
echo "  rig started; waiting 15s for first template fetch..."
sleep 15
systemctl status coincync-rig --no-pager | head -10

# ── 6. firewall (best-effort; only if ufw is in use) ─────────────────
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    echo "[6/7] ufw detected; allowing p2p port 28080..."
    ufw allow 28080/tcp
fi

# ── 7. summary ───────────────────────────────────────────────────────
echo
echo "=== setup complete ==="
echo
echo "Tail the logs to watch sync + mining:"
echo "  journalctl -fu coincync-node    # node sync + peer activity"
echo "  journalctl -fu coincync-rig     # mining attempts + block finds"
echo
echo "Check sync progress:"
echo "  ssh root@<this-box> 'journalctl -u coincync-node --since 30s | grep -E \"height=|BLOCK_COMMIT\"'"
echo
echo "When you find a block, you'll see in coincync-rig logs:"
echo "  INFO orchestrator: BLOCK FOUND ..."
echo "And in coincync-node logs:"
echo "  INFO BLOCK_COMMIT height=... ... target=..."
echo
echo "Stop/restart with:"
echo "  systemctl stop  coincync-rig coincync-node"
echo "  systemctl start coincync-node coincync-rig    # (node first)"
