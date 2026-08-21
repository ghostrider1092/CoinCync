#!/usr/bin/env bash
# Verify the RandomX Windows-JIT crash fix (FLAG_SECURE).
#
# Every pre-fix run died from an uncatchable native crash while mining in
# light+JIT mode, at varying heights (66, 91, 99) -- all well under 150.
# This soak mines a fresh regtest chain and watches whether the rig PROCESS
# stays alive past that range. It does NOT use the watchdog: the whole point
# is to see the *unsupervised* rig survive. A single silent exit = the crash
# is not fixed.
#
#   PASS: rig alive continuously, chain reaches TARGET_HEIGHT.
#   FAIL: rig process vanished before TARGET_HEIGHT (crash persists).
set -uo pipefail
ROOT="/c/dev/cc-integrate"
NODE_BIN="$ROOT/target/debug/coincync-node.exe"
WALLET_BIN="$ROOT/target/debug/coincync-wallet.exe"
RIG_BIN="$ROOT/target/debug/coincync-rig.exe"
RPC="http://127.0.0.1:18081"
TARGET_HEIGHT="${1:-260}"          # ~2.5x the worst pre-fix crash height
export COINCYNC_RANDOMX_LIGHT_MODE=1
export COINCYNC_WALLET_PASSWORD='soak-do-not-reuse'
TMP="/c/Users/unkno/AppData/Local/Temp/cync-soak-$(date +%s)"
mkdir -p "$TMP/chain"
NODE_LOG="$TMP/node.log"; RIG_LOG="$TMP/rig.log"; NODE_PID=""

cleanup() { taskkill //IM coincync-rig.exe //F >/dev/null 2>&1; [ -n "$NODE_PID" ] && kill "$NODE_PID" >/dev/null 2>&1; }
trap cleanup EXIT

node_height() { curl -s -m 3 -X POST "$RPC" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_info","params":[]}' 2>/dev/null | grep -oE '"height":[0-9]+' | grep -oE '[0-9]+'; }

echo "=== RandomX FLAG_SECURE soak (target height $TARGET_HEIGHT, NO watchdog) ==="
echo "  workspace: $TMP"

"$NODE_BIN" --network regtest --data-dir "$TMP/chain" --log-level info > "$NODE_LOG" 2>&1 &
NODE_PID=$!
up=0
for i in $(seq 1 30); do
  curl -s -m 3 -X POST "$RPC" -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"get_info","params":[]}' 2>/dev/null | grep -q '"regtest"' && { up=1; break; }
  sleep 2
done
[ "$up" = 1 ] && echo "  OK node up" || { echo "FAIL: node RPC never came up"; exit 1; }

"$WALLET_BIN" --network regtest --wallet "$TMP/M.bin" --node "$RPC" create --force >/dev/null 2>&1
ADDR=$("$WALLET_BIN" --network regtest --wallet "$TMP/M.bin" --node "$RPC" address 2>&1 \
  | sed -E 's/\x1b\[[0-9;]*m//g' | grep -E "^[[:space:]]*Address:" | head -1 \
  | sed -E "s/^[[:space:]]*Address:[[:space:]]*//" | tr -d '\r ')
[ -n "$ADDR" ] || { echo "FAIL: no mining address"; exit 1; }
echo "  mining to ${ADDR:0:18}.."

# Unsupervised rig -- if it crashes, it stays dead and we detect it.
"$RIG_BIN" run-solo --node "$RPC" --address "$ADDR" --network regtest \
  --threads 4 --poll-interval-secs 3 > "$RIG_LOG" 2>&1 &
RIG_START_PID=$!
echo "  rig launched (pid $RIG_START_PID, light+JIT, 4 threads)"

# Grace period: the rig takes ~2-3s to build its RandomX cache and appear
# in the process table. Wait for it to register BEFORE the liveness loop,
# or the first check races startup and reports a false "died at height 0".
appeared=0
for i in $(seq 1 15); do
  if tasklist 2>/dev/null | grep -qi "coincync-rig"; then appeared=1; break; fi
  sleep 1
done
[ "$appeared" = 1 ] || { echo "FAIL: rig never appeared in the process table (startup failure)"; tail -6 "$RIG_LOG" | sed -E 's/\x1b\[[0-9;]*m//g'; exit 1; }

start=$(date +%s)
while true; do
  if ! tasklist 2>/dev/null | grep -qi "coincync-rig"; then
    h=$(node_height); h=${h:-?}
    echo ""
    echo "FAIL: rig PROCESS DIED at height $h after $(( $(date +%s) - start ))s -- crash NOT fixed."
    echo "  last rig.log lines:"; tail -4 "$RIG_LOG" | sed -E 's/\x1b\[[0-9;]*m//g'
    exit 1
  fi
  h=$(node_height); h=${h:-0}
  echo "  height=$h / $TARGET_HEIGHT  rig=alive  elapsed=$(( $(date +%s) - start ))s"
  if [ "$h" -ge "$TARGET_HEIGHT" ]; then
    echo ""
    echo "PASS: rig survived to height $h with NO crash and NO restart (FLAG_SECURE fix verified)."
    exit 0
  fi
  sleep 15
done
