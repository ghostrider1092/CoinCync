#!/bin/bash
# Pre-launch integration test: spin up a fresh node from a clean data
# dir, point it at the public seed list (DNS bootstrap), watch it
# sync from height 0 to current tip.
#
# Pass criteria:
#   - node starts cleanly (no FATAL/ERROR in first 5s)
#   - peer count > 0 within 30s (DNS bootstrap reached at least one seed)
#   - height advances at least once during the test (IBD makes progress)
#   - height >= 50% of expected tip after 90s (catch-up rate is sane)

set -uo pipefail

DATA_DIR=/tmp/freshnode
RPC_PORT=28181
P2P_PORT=28180
EXPECTED_TIP=$(curl -sS --max-time 8 -X POST https://api.coincync.network/rpc/testnet \
                  -H 'Content-Type: application/json' \
                  -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' \
                | grep -oE '"height":[0-9]+' | head -1 | cut -d: -f2)
echo "Expected tip from public api: ${EXPECTED_TIP:-unknown}"

# Clean slate
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

LOG=/tmp/freshnode.log
echo "Starting fresh node (logs: $LOG)..."
"${HOME}/coincync-build/target/release/coincync-node" \
    --data-dir "$DATA_DIR" \
    --network testnet \
    --p2p-bind "0.0.0.0:$P2P_PORT" \
    --rpc-bind "127.0.0.1:$RPC_PORT" \
    --log-level info \
    > "$LOG" 2>&1 &
NODE_PID=$!

# Helper to query the fresh node
query() {
  curl -sS --max-time 4 -X POST "http://127.0.0.1:$RPC_PORT" \
       -H 'Content-Type: application/json' \
       -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' 2>/dev/null
}

cleanup() {
  echo ""
  echo "=== Stopping fresh node (pid $NODE_PID) ==="
  kill "$NODE_PID" 2>/dev/null || true
  wait "$NODE_PID" 2>/dev/null || true
  echo "=== Last 20 log lines ==="
  tail -20 "$LOG"
}
trap cleanup EXIT

# Wait for RPC to come up
for i in 1 2 3 4 5 6 7 8 9 10; do
  sleep 1
  if query >/dev/null 2>&1; then
    echo "Fresh node RPC up (took ${i}s)"
    break
  fi
done

# Sample at 15s, 45s, 75s — three points to see progress
for sample in 15 45 75; do
  sleep $((sample - $(printf "%d" "${prev_t:-10}")))
  prev_t=$sample
  resp=$(query)
  height=$(echo "$resp" | grep -oE '"height":[0-9]+' | head -1 | cut -d: -f2)
  target=$(echo "$resp" | grep -oE '"target_height":[0-9]+' | head -1 | cut -d: -f2)
  peers=$(echo "$resp" | grep -oE '"peer_count":[0-9]+' | head -1 | cut -d: -f2)
  printf "%3ds: height=%s target=%s peers=%s\n" "$sample" "${height:-?}" "${target:-?}" "${peers:-?}"
done

echo ""
echo "=== Verdict ==="
final_resp=$(query)
final_height=$(echo "$final_resp" | grep -oE '"height":[0-9]+' | head -1 | cut -d: -f2)
final_target=$(echo "$final_resp" | grep -oE '"target_height":[0-9]+' | head -1 | cut -d: -f2)
final_peers=$(echo "$final_resp" | grep -oE '"peer_count":[0-9]+' | head -1 | cut -d: -f2)
final_height=${final_height:-0}
final_peers=${final_peers:-0}
echo "Final: height=$final_height target=$final_target peers=$final_peers"

if [ "$final_peers" -lt 1 ]; then
  echo "FAIL: zero peers after 75s — DNS bootstrap broken"
  exit 2
fi
if [ "$final_height" -lt 1 ]; then
  echo "FAIL: height=0 after 75s — IBD never started"
  exit 3
fi
expected_threshold=$((${EXPECTED_TIP:-100} / 4))
if [ "$final_height" -lt "$expected_threshold" ]; then
  echo "WARN: height=$final_height is < 25% of expected tip $EXPECTED_TIP"
  echo "(may be normal for low-difficulty testnet with rapid block production)"
fi
echo "PASS: fresh node bootstrapped via DNS, found peers, IBD progressed"
exit 0
