#!/usr/bin/env bash
# install-coord.sh — runs on the deploy host after deploy-coord.ps1
# scps the binary + service + env-example to /tmp.
#
# Creates a dedicated `coincync-coord` system user, installs the
# coord binary at /usr/local/bin/coincync-coord, places the service
# unit, ensures the state directory exists, generates a fresh
# invitation-token HMAC key if the env file doesn't exist yet,
# enables + starts the service.
#
# Idempotent — safe to re-run on the same host.

set -euo pipefail

BIN_SRC=/tmp/coincync-coord
BIN_DST=/usr/local/bin/coincync-coord
SERVICE_SRC=/tmp/coincync-coord.service
SERVICE_DST=/etc/systemd/system/coincync-coord.service
ENV_EXAMPLE_SRC=/tmp/coincync-coord.env.example
ENV_DST=/etc/coincync/coord.env
STATE_DIR=/var/lib/coincync-coord
USER_NAME=coincync-coord

# ── 1. System user ────────────────────────────────────────────────
if ! id "$USER_NAME" >/dev/null 2>&1; then
    echo "Creating system user $USER_NAME"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
fi

# ── 2. Binary ─────────────────────────────────────────────────────
if [ ! -f "$BIN_SRC" ]; then
    echo "ERROR: $BIN_SRC missing; deploy-coord.ps1 should have scp'd it" >&2
    exit 1
fi
install -m 0755 "$BIN_SRC" "$BIN_DST"
echo "Installed coord binary at $BIN_DST"

# ── 3. State directory ────────────────────────────────────────────
mkdir -p "$STATE_DIR"
chown "$USER_NAME:$USER_NAME" "$STATE_DIR"
chmod 0750 "$STATE_DIR"

# Bootstrap an empty sessions store if missing — the coord refuses to
# start without one, and an empty `[]` is the canonical zero-session
# state.
if [ ! -f "$STATE_DIR/sessions.json" ]; then
    echo "[]" > "$STATE_DIR/sessions.json"
    chown "$USER_NAME:$USER_NAME" "$STATE_DIR/sessions.json"
    chmod 0640 "$STATE_DIR/sessions.json"
fi

# ── 4. Env file ───────────────────────────────────────────────────
mkdir -p /etc/coincync
if [ ! -f "$ENV_DST" ]; then
    echo "Generating fresh invitation-token HMAC key"
    SECRET=$(openssl rand -hex 32)
    sed "s|__REPLACE_WITH_HEX32__|$SECRET|" "$ENV_EXAMPLE_SRC" > "$ENV_DST"
    chown "$USER_NAME:$USER_NAME" "$ENV_DST"
    chmod 0600 "$ENV_DST"
    echo "Wrote $ENV_DST with a fresh HMAC key"
    echo "  Out-of-band hand this prefix to other operators issuing invites:"
    echo "    $(echo "$SECRET" | head -c 16)…"
else
    echo "Existing $ENV_DST preserved (delete it manually to regenerate)"
fi

# ── 5. Service unit ───────────────────────────────────────────────
install -m 0644 "$SERVICE_SRC" "$SERVICE_DST"
systemctl daemon-reload
systemctl enable coincync-coord.service

# ── 6. Start (or restart if already running) ──────────────────────
if systemctl is-active --quiet coincync-coord.service; then
    echo "Restarting coincync-coord.service"
    systemctl restart coincync-coord.service
else
    echo "Starting coincync-coord.service"
    systemctl start coincync-coord.service
fi

# ── 7. Verify ─────────────────────────────────────────────────────
sleep 2
if systemctl is-active --quiet coincync-coord.service; then
    echo ""
    echo "=== coincync-coord is RUNNING ==="
    echo "  systemctl status coincync-coord.service     # status"
    echo "  journalctl -u coincync-coord.service -f     # logs"
    echo ""
    echo "Listen address (from $ENV_DST): $(grep COINCYNC_COORD_LISTEN $ENV_DST | cut -d= -f2)"
else
    echo "" >&2
    echo "=== coincync-coord FAILED TO START ===" >&2
    echo "  journalctl -u coincync-coord.service -n 60 --no-pager" >&2
    journalctl -u coincync-coord.service -n 60 --no-pager >&2 || true
    exit 1
fi
