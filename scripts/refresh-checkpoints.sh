#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# CoinCync — checkpoint refresh helper
#
# Pulls block hashes from a running local node and prints the diff to
# add to src/testnet.rs's TESTNET_CHECKPOINT_LIST. It deliberately does
# NOT edit the source file or commit anything — checkpoints are
# consensus-adjacent and the human review step matters.
#
# Defaults are conservative: only suggests checkpoints up to (tip - 500)
# so you always have reorg headroom. Adjust BUFFER if you have stronger
# guarantees about chain stability.
#
# Usage:
#   bash scripts/refresh-checkpoints.sh                       # default
#   STEP=200 BUFFER=1000 bash scripts/refresh-checkpoints.sh  # tighter
#
# Env:
#   RPC=http://127.0.0.1:28081       node to pull from
#   KEY_FILE=$APPDATA/coincync/rpc.key  (Windows) or ~/.config/coincync/rpc.key
#   STEP=500                         block interval between checkpoints
#   BUFFER=500                       blocks to leave below tip (NEVER lower for mainnet)
#   START_AT=                        only suggest checkpoints above this height (auto-detected from existing list if empty)
# ──────────────────────────────────────────────────────────────────────

set -euo pipefail

RPC="${RPC:-http://127.0.0.1:28081}"
STEP="${STEP:-500}"
BUFFER="${BUFFER:-500}"

# Resolve key file location (Windows APPDATA or Linux/macOS XDG)
if [ -z "${KEY_FILE:-}" ]; then
  if [ -n "${APPDATA:-}" ] && [ -f "$APPDATA/coincync/rpc.key" ]; then
    KEY_FILE="$APPDATA/coincync/rpc.key"
  elif [ -f "$HOME/.config/coincync/rpc.key" ]; then
    KEY_FILE="$HOME/.config/coincync/rpc.key"
  fi
fi
KEY=""
if [ -n "${KEY_FILE:-}" ] && [ -f "$KEY_FILE" ]; then
  KEY="$(cat "$KEY_FILE")"
fi
AUTH=()
[ -n "$KEY" ] && AUTH=(-H "authorization: Bearer $KEY")

rpc_call() {
  local body="$1"
  curl -sS -m 5 -X POST "$RPC" "${AUTH[@]}" -H 'content-type: application/json' -d "$body"
}

require_jq_or_python() {
  if command -v jq >/dev/null 2>&1; then
    EXTRACT() { jq -r "$1"; }
  else
    EXTRACT() {
      python -c "
import sys,json
d = json.loads(sys.stdin.read())
keys = '''$1'''.replace('.', ' ').strip().split()
v = d
for k in keys:
    if isinstance(v, dict):
        v = v.get(k, '')
    else:
        v = ''
print(v)"
    }
  fi
}
require_jq_or_python

# ── Get current tip ──────────────────────────────────────────────────
TIP_INFO="$(rpc_call '{"jsonrpc":"2.0","id":1,"method":"get_info"}')"
TIP_HEIGHT="$(echo "$TIP_INFO" | EXTRACT '.result.height')"
if ! [ "$TIP_HEIGHT" -ge 0 ] 2>/dev/null; then
  echo "FATAL: could not read tip height from $RPC" >&2
  echo "  raw response: $TIP_INFO" >&2
  exit 2
fi
LATEST_SAFE=$(( TIP_HEIGHT - BUFFER ))

if [ "$LATEST_SAFE" -lt 1 ]; then
  echo "Chain is too short for new checkpoints."
  echo "  tip:    $TIP_HEIGHT"
  echo "  buffer: $BUFFER (configured)"
  echo "  needed: $((BUFFER + STEP))"
  exit 0
fi

# ── Detect highest existing checkpoint ───────────────────────────────
EXISTING_HIGH=0
TESTNET_RS="$(dirname "$0")/../src/testnet.rs"
if [ -f "$TESTNET_RS" ]; then
  EXISTING_HIGH="$(grep -oE '\(\s*[0-9]+,\s*"[0-9a-f]{64}"\s*\)' "$TESTNET_RS" \
    | grep -oE '^\(\s*[0-9]+' \
    | grep -oE '[0-9]+' \
    | sort -n | tail -1)"
  EXISTING_HIGH="${EXISTING_HIGH:-0}"
fi

START_AT="${START_AT:-$EXISTING_HIGH}"
NEXT_HEIGHT=$(( ((START_AT / STEP) + 1) * STEP ))

echo "──────────────────────────────────────────────────────────────"
echo "  current tip:           h=$TIP_HEIGHT"
echo "  highest existing chk:  h=$EXISTING_HIGH"
echo "  buffer below tip:      $BUFFER blocks"
echo "  step between chk:      $STEP blocks"
echo "  safe ceiling:          h=$LATEST_SAFE"
echo "──────────────────────────────────────────────────────────────"

if [ "$NEXT_HEIGHT" -gt "$LATEST_SAFE" ]; then
  REMAINING=$(( NEXT_HEIGHT + BUFFER - TIP_HEIGHT ))
  echo
  echo "Nothing to add yet. The chain hasn't aged enough above the"
  echo "highest existing checkpoint. Re-run when h >= $((NEXT_HEIGHT + BUFFER))."
  echo "(Currently $REMAINING blocks short.)"
  exit 0
fi

# ── Pull hashes for each new checkpoint ──────────────────────────────
echo
echo "New checkpoints to paste into TESTNET_CHECKPOINT_LIST in src/testnet.rs:"
echo
H="$NEXT_HEIGHT"
while [ "$H" -le "$LATEST_SAFE" ]; do
  RESP="$(rpc_call "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_block_by_height\",\"params\":[$H]}")"
  HASH="$(echo "$RESP" | EXTRACT '.result.hash')"
  if [ -z "$HASH" ] || [ "${#HASH}" -ne 64 ]; then
    echo "    // h=$H: failed to fetch hash (response: $RESP)" >&2
  else
    printf "    (%5d, \"%s\"),\n" "$H" "$HASH"
  fi
  H=$(( H + STEP ))
done

echo
echo "──────────────────────────────────────────────────────────────"
echo "Next steps (manual review required — checkpoints are forever):"
echo
echo "  1. Open src/testnet.rs"
echo "  2. Append the lines above to TESTNET_CHECKPOINT_LIST"
echo "  3. Update test_checkpoints_populated assertion to use new highest height"
echo "  4. cargo run --release --bin update-critical-hashes"
echo "  5. cargo test --lib --features 'randomx testnet' testnet::"
echo "  6. git add -p && git commit"
echo
echo "  Do NOT auto-edit. The whole point of asking the human to paste"
echo "  is to make sure someone with chain-context approves each entry."
echo "──────────────────────────────────────────────────────────────"
