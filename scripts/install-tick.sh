#!/usr/bin/env bash
# install-tick.sh — install/upgrade the coincync-tick read-only health
# sidecar on ONE fleet host. Run as root AFTER scp'ing the three files to
# /tmp:
#   /tmp/coincync-tick                       (the Linux x86_64 binary)
#   /tmp/coincync-tick.service               (deploy/coincync-tick.service)
#   /tmp/coincync-tick.config.example.toml   (deploy/coincync-tick.config.example.toml)
#
# The sidecar is READ-ONLY: it monitors the local node over RPC + /proc and
# reports health (and, with --colony-observe, logs colony recommendations).
# It NEVER restarts or touches coincync-node — installing it is additive.
#
# Runs as User=coincync (same as the node) so it can read the shared RPC
# token at /etc/coincync/rpc-token. Idempotent: safe to re-run to upgrade.
#
# Per-host, ONE AT A TIME (feedback_no_bulk_rolling_restart) — but note this
# starts a NEW unit; it does not restart the node, so the "rolling" concern
# is only about not hammering all hosts simultaneously.
#
# Optional env:
#   DEPLOYMENT_MODE=personal|fleet   (default: personal; set fleet on the one
#                                     aggregator box that should run the sensor)

set -euo pipefail

BIN_SRC=/tmp/coincync-tick
BIN_DST=/usr/local/bin/coincync-tick
SERVICE_SRC=/tmp/coincync-tick.service
SERVICE_DST=/etc/systemd/system/coincync-tick.service
CONFIG_SRC=/tmp/coincync-tick.config.example.toml
CONFIG_DIR=/etc/coincync-tick
CONFIG_DST=$CONFIG_DIR/config.toml
RUN_USER=coincync
DEPLOYMENT_MODE=${DEPLOYMENT_MODE:-personal}

# ── 1. Preconditions ──────────────────────────────────────────────
if ! id "$RUN_USER" >/dev/null 2>&1; then
    echo "ERROR: user '$RUN_USER' does not exist — is coincync-node installed here?" >&2
    exit 1
fi
if [ ! -f "$BIN_SRC" ]; then
    echo "ERROR: $BIN_SRC missing — scp the built Linux binary there first" >&2
    exit 1
fi
if [ ! -r /etc/coincync/rpc-token ]; then
    echo "WARN: /etc/coincync/rpc-token not readable — sidecar will run without RPC auth" >&2
fi

# ── 2. Binary ─────────────────────────────────────────────────────
install -m 0755 "$BIN_SRC" "$BIN_DST"
echo "Installed coincync-tick at $BIN_DST"

# ── 3. Config (never overwrite an existing one) ───────────────────
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DST" ]; then
    if [ ! -f "$CONFIG_SRC" ]; then
        echo "ERROR: $CONFIG_SRC missing and no existing $CONFIG_DST" >&2
        exit 1
    fi
    sed "s/^deployment_mode = .*/deployment_mode = \"$DEPLOYMENT_MODE\"/" \
        "$CONFIG_SRC" > "$CONFIG_DST"
    chown "$RUN_USER:$RUN_USER" "$CONFIG_DST"
    chmod 0640 "$CONFIG_DST"
    echo "Wrote $CONFIG_DST (deployment_mode=$DEPLOYMENT_MODE)"
else
    echo "Existing $CONFIG_DST preserved"
fi

# ── 4. Service unit ───────────────────────────────────────────────
if [ ! -f "$SERVICE_SRC" ]; then
    echo "ERROR: $SERVICE_SRC missing — scp deploy/coincync-tick.service there" >&2
    exit 1
fi
install -m 0644 "$SERVICE_SRC" "$SERVICE_DST"
systemctl daemon-reload
systemctl enable coincync-tick.service

# ── 5. Start / restart the SIDECAR ONLY (node is never touched) ───
if systemctl is-active --quiet coincync-tick.service; then
    echo "Restarting coincync-tick.service (sidecar only)"
    systemctl restart coincync-tick.service
else
    echo "Starting coincync-tick.service"
    systemctl start coincync-tick.service
fi

# ── 6. Verify it is reporting health ──────────────────────────────
sleep 3
if systemctl is-active --quiet coincync-tick.service; then
    echo ""
    echo "=== coincync-tick is RUNNING (read-only; node untouched) ==="
    echo "  systemctl status coincync-tick.service    # status"
    echo "  journalctl -u coincync-tick.service -f    # live health/colony logs"
    echo ""
    echo "Recent output:"
    journalctl -u coincync-tick.service -n 8 --no-pager || true
else
    echo "" >&2
    echo "=== coincync-tick FAILED TO START ===" >&2
    journalctl -u coincync-tick.service -n 40 --no-pager >&2 || true
    exit 1
fi
