#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# CoinCync — Fleet redeploy after consensus change
#
# Use this when a commit changes the consensus rules (e.g. genesis hash,
# difficulty params, RandomX seed) and the public testnet needs to be
# wiped and restarted on the new rules. Run on EACH fleet node
# (LON / SFO / NYC1 / FRA / NYC3 / TOR / RIC / ATL / AMS / SYD).
#
# Default behaviour:
#   1. Stop the node systemd unit
#   2. git pull --ff-only main
#   3. cargo build --release with randomx + testnet features
#   4. Wipe testnet chain DB (keeps node_key, peers.json, recovery.json)
#   5. Install new binary into /usr/local/bin
#   6. Start the node, wait for RPC to come up
#   7. Print the new genesis hash so you can confirm all nodes match
#
# Run with: sudo bash deploy/ops/redeploy-fleet.sh
# Override: REPO_DIR, BRANCH, NODE_SERVICE, DATA_DIR, RPC_PORT, SKIP_PULL (env vars).
#
# SKIP_PULL=1 — skip the `git fetch + pull` step. Use this when the working
# tree at REPO_DIR was already synced via an out-of-band mechanism (e.g. a
# direct `git push ssh://root@host/opt/coincync main` from an operator
# laptop). Useful when the canonical remote is private/unreachable but the
# operator has SSH access to every fleet host. The script still runs the
# rebuild from whatever is currently in the working tree.
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
  # Wait up to 30s for clean shutdown
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
  log "SKIP_PULL=1 — skipping git fetch/pull, using working tree as-is"
else
  log "git fetch + pull ${BRANCH}"
  sudo -u "$(stat -c '%U' "$REPO_DIR")" git fetch origin "$BRANCH"
  sudo -u "$(stat -c '%U' "$REPO_DIR")" git checkout "$BRANCH"
  sudo -u "$(stat -c '%U' "$REPO_DIR")" git pull --ff-only origin "$BRANCH"
fi
HEAD_HASH="$(git rev-parse --short HEAD)"
log "HEAD now ${HEAD_HASH}"

# ── 3. Rebuild release binaries ───────────────────────────────────────
log "cargo build --release --features \"${CARGO_FEATURES}\""
BIN_FLAGS=()
for n in "${CARGO_BIN_NAMES[@]}"; do BIN_FLAGS+=(--bin "$n"); done
sudo -u "$(stat -c '%U' "$REPO_DIR")" \
  cargo build --release --features "$CARGO_FEATURES" "${BIN_FLAGS[@]}"

# ── 4. Wipe chain DB (keep node identity + peers.json + recovery) ─────
NETWORK_DIR="${DATA_DIR%/}/testnet"
if [ -d "$NETWORK_DIR" ]; then
  WIPE_BACKUP="${DATA_DIR%/}/testnet.wiped.$(date -u +%Y%m%dT%H%M%SZ)"
  log "Wiping chain DB at ${NETWORK_DIR} (moved to ${WIPE_BACKUP} for safety)"
  mv "$NETWORK_DIR" "$WIPE_BACKUP"
fi
# node_key and peers.json live in $DATA_DIR root, not under testnet/ — preserved.

# ── 5. Install new binary ─────────────────────────────────────────────
log "Installing new binaries into ${BIN_INSTALL_DIR}"
for n in "${CARGO_BIN_NAMES[@]}"; do
  install -m 0755 "$REPO_DIR/target/release/$n" "$BIN_INSTALL_DIR/$n"
done

# ── 6. Start service, wait for RPC ────────────────────────────────────
log "Starting ${NODE_SERVICE}"
systemctl start "$NODE_SERVICE"

log "Waiting for RPC on 127.0.0.1:${RPC_PORT}…"
for i in $(seq 1 60); do
  if curl -sS -m 2 -o /dev/null \
        -X POST "http://127.0.0.1:${RPC_PORT}" \
        -H 'content-type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}'; then
    break
  fi
  sleep 1
done

# ── 7. Print the new genesis (so you can compare across nodes) ────────
log "RPC up. New tip / genesis:"
RESP="$(curl -sS -X POST "http://127.0.0.1:${RPC_PORT}" \
       -H 'content-type: application/json' \
       -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}')"
echo "$RESP" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
r = d.get("result", {})
print(f"  network:   {r.get(\"network\")}")
print(f"  height:    {r.get(\"height\")}")
print(f"  tip_hash:  {r.get(\"tip_hash\", \"\")}")
print(f"  version:   {r.get(\"version\")}")
'

log "Redeploy complete on $(hostname). HEAD=${HEAD_HASH}"
log "Verify all fleet nodes report the SAME tip_hash before mining starts."
log "Then on ONE node only, start the miner to seed block 1:"
log "  coincync-tui-miner --address <tCYNC...> --testnet --rpc http://127.0.0.1:${RPC_PORT}"
