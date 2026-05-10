#!/bin/bash
# Tighter debug: full info log capture, peek at messages, see what's
# actually happening at the framing layer.
set -uo pipefail

DATA_DIR=/tmp/freshnode2
RPC_PORT=28181
P2P_PORT=28180
LOG=/tmp/freshnode2.log

rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

echo "Starting fresh node with full info logging..."
RUST_LOG=info,coincync::network=debug \
  /home/abe/coincync-build/target/release/coincync-node \
    --data-dir "$DATA_DIR" \
    --network testnet \
    --p2p-bind "0.0.0.0:$P2P_PORT" \
    --rpc-bind "127.0.0.1:$RPC_PORT" \
    --log-level info \
    > "$LOG" 2>&1 &
NODE_PID=$!

# Wait for RPC to come up
for i in 1 2 3 4 5 6 7 8 9 10; do
  sleep 1
  curl -sS --max-time 4 -X POST "http://127.0.0.1:$RPC_PORT" \
       -H 'Content-Type: application/json' \
       -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' >/dev/null 2>&1 && break
done

echo "Letting it run for 45 seconds to gather a real sample..."
sleep 45

echo ""
echo "=== State at 45s ==="
curl -sS --max-time 4 -X POST "http://127.0.0.1:$RPC_PORT" \
     -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}'
echo ""

kill "$NODE_PID" 2>/dev/null || true
wait "$NODE_PID" 2>/dev/null || true

echo ""
echo "=== Connected peer info ==="
grep -iE 'Noise handshake succeeded|Connected to|outbound peer|Handshake complete' "$LOG" | head -10

echo ""
echo "=== GetHeaders requests sent (count + first 5) ==="
grep -c 'GetHeaders.*sent' "$LOG" || true
grep 'GetHeaders.*sent' "$LOG" | head -5

echo ""
echo "=== Headers RECEIVED (any incoming Headers messages) ==="
grep -iE 'Received Headers|Headers from|incoming headers|process_headers' "$LOG" | head -10
echo "(empty above = problem isolated: seed1 not responding OR fresh node not parsing)"

echo ""
echo "=== Any block-related INFO/WARN ==="
grep -iE 'block|Block' "$LOG" | head -10

echo ""
echo "=== Any errors/warnings in last 10s ==="
tail -50 "$LOG" | grep -iE 'WARN|ERROR|FATAL'

echo ""
echo "=== Last 15 lines of full log ==="
tail -15 "$LOG"
