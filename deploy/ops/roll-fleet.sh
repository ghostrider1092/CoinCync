#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# CoinCync — Fleet roll (rebuild + restart, PRESERVES chain DB)
#
# Use this when a commit changes node code BUT NOT consensus rules — e.g.
# bug fixes, networking improvements, RPC additions. The chain DB is left
# untouched so the node resumes from its current tip after restart.
#
# DO NOT use this for consensus-changing rebuilds — those need
# `redeploy-fleet.sh` which wipes and restarts from genesis on the new
# rules. Mixing nodes with different consensus on the same DB will fork.
#
# Default behaviour (per fleet host):
#   1. Stop the node systemd unit
#   2. git fetch + pull --ff-only main
#   3. cargo build --release with randomx + testnet features
#   4. Install new binaries into /usr/local/bin (KEEPS chain DB)
#   5. Start the node, wait for RPC to come up
#   6. Confirm the running build_commit matches HEAD
#
# Run on EACH fleet node with: sudo bash deploy/ops/roll-fleet.sh
# Override: REPO_DIR, BRANCH, NODE_SERVICE, DATA_DIR, RPC_PORT, SKIP_PULL.
# ──────────────────────────────────────────────────────────────────────────

set -euo pipefail

REPO_DIR="${REPO_DIR:-/opt/coincync}"
BRANCH="${BRANCH:-main}"
NODE_SERVICE="${NODE_SERVICE:-coincync-node}"
DATA_DIR="${DATA_DIR:-/var/lib/coincync/data}"
RPC_PORT="${RPC_PORT:-28081}"
BIN_INSTALL_DIR="${BIN_INSTALL_DIR:-/usr/local/bin}"
CARGO_FEATURES="${CARGO_FEATURES:-randomx testnet}"
CARGO_BIN_NAMES=(coincync-node coincync-wallet coincync-tui-miner)
SKIP_PULL="${SKIP_PULL:-0}"

log()   { printf '\e[36m==>\e[0m %s\n' "$*"; }
warn()  { printf '\e[33m[!]\e[0m %s\n' "$*" >&2; }
fatal() { printf '\e[31m[ERR]\e[0m %s\n' "$*" >&2; exit 1; }

[ "$EUID" -eq 0 ] || fatal "must run as root (or with sudo) — needs to stop systemd + write to ${BIN_INSTALL_DIR}"
[ -d "$REPO_DIR" ] || fatal "repo not found at ${REPO_DIR} (set REPO_DIR=...)"
[ -d "$DATA_DIR" ] || fatal "data dir not found at ${DATA_DIR} (set DATA_DIR=...)"

cd "$REPO_DIR"

# ── 1. Stop the node ──────────────────────────────────────────────────
log "Stopping ${NODE_SERVICE}"
if systemctl is-active --quiet "$NODE_SERVICE"; then
  systemctl stop "$NODE_SERVICE"
  for i in $(seq 1 30); do
    systemctl is-active --quiet "$NODE_SERVICE" || break
    sleep 1
  done
  if systemctl is-active --quiet "$NODE_SERVICE"; then
    fatal "${NODE_SERVICE} did not stop within 30s"
  fi
fi
log "Stopped."

# ── 2. Pull latest source ─────────────────────────────────────────────
if [ "$SKIP_PULL" = "1" ] || [ "$SKIP_PULL" = "true" ]; then
  log "SKIP_PULL=1 — using working tree as-is"
else
  log "git fetch + pull ${BRANCH}"
  REPO_OWNER="$(stat -c '%U' "$REPO_DIR")"
  sudo -u "$REPO_OWNER" git fetch origin "$BRANCH"
  sudo -u "$REPO_OWNER" git checkout "$BRANCH"
  sudo -u "$REPO_OWNER" git pull --ff-only origin "$BRANCH"
fi
HEAD_HASH="$(git rev-parse --short=12 HEAD)"
log "HEAD now ${HEAD_HASH}"

# ── 3. Rebuild release binaries ───────────────────────────────────────
REPO_OWNER="$(stat -c '%U' "$REPO_DIR")"
OWNER_HOME="$(getent passwd "$REPO_OWNER" | cut -d: -f6)"
CARGO_BIN="${CARGO:-}"
if [ -z "$CARGO_BIN" ] && [ -x "$OWNER_HOME/.cargo/bin/cargo" ]; then
  CARGO_BIN="$OWNER_HOME/.cargo/bin/cargo"
fi
if [ -z "$CARGO_BIN" ]; then
  CARGO_BIN="$(command -v cargo || true)"
fi
[ -n "$CARGO_BIN" ] && [ -x "$CARGO_BIN" ] || \
  fatal "cargo not found. Install rustup as user '$REPO_OWNER' or set CARGO=/path/to/cargo"
log "cargo build --release --features \"${CARGO_FEATURES}\"  (using $CARGO_BIN)"
BIN_FLAGS=()
for n in "${CARGO_BIN_NAMES[@]}"; do BIN_FLAGS+=(--bin "$n"); done
sudo -u "$REPO_OWNER" "$CARGO_BIN" build --release \
  --features "$CARGO_FEATURES" "${BIN_FLAGS[@]}"

# ── 4. Install new binaries (CHAIN DB IS PRESERVED — no wipe) ────────
log "Installing new binaries into ${BIN_INSTALL_DIR}"
for n in "${CARGO_BIN_NAMES[@]}"; do
  install -m 0755 "$REPO_DIR/target/release/$n" "$BIN_INSTALL_DIR/$n"
done

# ── 5. Start service, wait for RPC ────────────────────────────────────
log "Starting ${NODE_SERVICE}"
systemctl start "$NODE_SERVICE"

RPC_KEY="$(systemctl show "$NODE_SERVICE" -p Environment --value 2>/dev/null \
           | tr ' ' '\n' | grep '^COINCYNC_RPC_API_KEY=' | head -1 | cut -d= -f2)"
AUTH_HDR=()
[ -n "$RPC_KEY" ] && AUTH_HDR=(-H "authorization: Bearer ${RPC_KEY}")

log "Waiting for RPC on 127.0.0.1:${RPC_PORT}…"
RPC_UP=0
for _ in $(seq 1 60); do
  if curl -sS -m 2 -o /dev/null -w '%{http_code}' \
        -X POST "http://127.0.0.1:${RPC_PORT}" \
        "${AUTH_HDR[@]}" \
        -H 'content-type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' | grep -q '^2'; then
    RPC_UP=1
    break
  fi
  sleep 1
done

[ "$RPC_UP" = "1" ] || fatal "RPC did not come up within 60s — check 'journalctl -u ${NODE_SERVICE}'"

# ── 6. Verify the running build_commit matches HEAD ──────────────────
RUNNING=$(curl -sS -m 5 -X POST "http://127.0.0.1:${RPC_PORT}" \
            "${AUTH_HDR[@]}" \
            -H 'content-type: application/json' \
            -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' \
          | grep -oE '"build_commit":"[a-f0-9]+"' | cut -d'"' -f4)

INFO=$(curl -sS -m 5 -X POST "http://127.0.0.1:${RPC_PORT}" \
        "${AUTH_HDR[@]}" \
        -H 'content-type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}')
HEIGHT=$(echo "$INFO" | grep -oE '"height":[0-9]+' | cut -d: -f2)
PEERS=$(echo "$INFO" | grep -oE '"peer_count":[0-9]+' | cut -d: -f2)
TIP_AGE=$(echo "$INFO" | grep -oE '"tip_age_secs":[0-9]+' | cut -d: -f2)

log "Running build:    ${RUNNING}"
log "Repo HEAD:        ${HEAD_HASH}"
log "Chain height:     ${HEIGHT}"
log "Peer count:       ${PEERS}"
log "Tip age (sec):    ${TIP_AGE}"

if [ -z "$RUNNING" ] || [[ "$HEAD_HASH" != "$RUNNING"* && "$RUNNING" != "$HEAD_HASH"* ]]; then
  warn "build_commit mismatch! running=${RUNNING}  HEAD=${HEAD_HASH}"
  warn "Did the install step work? Is /usr/local/bin/coincync-node the right binary?"
  exit 2
fi

log "Roll complete on $(hostname). Chain DB preserved; tip will catch up via P2P."
