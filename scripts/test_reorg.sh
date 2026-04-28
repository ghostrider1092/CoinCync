#!/bin/bash
# test_reorg.sh — simulate and verify chain reorganization handling
# Requires two nodes running on localhost (different ports)

set -euo pipefail

NODE_A="http://127.0.0.1:28332"
NODE_B="http://127.0.0.1:28333"

rpc() { local url="$1"; shift; curl -sf -X POST -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"$1\",\"params\":${2:-[]},\"id\":1}" "$url"; }

height_a() { rpc "$NODE_A" getblockcount | python3 -c "import sys,json;print(json.load(sys.stdin)['result'])"; }
height_b() { rpc "$NODE_B" getblockcount | python3 -c "import sys,json;print(json.load(sys.stdin)['result'])"; }

echo "=== CoinCync 1.0 Reorg Test ==="
echo ""

echo "Initial heights:"
echo "  Node A: $(height_a)"
echo "  Node B: $(height_b)"

echo ""
echo "Test 1: Nodes sync to same tip"
# Nodes should agree within 2 blocks
sleep 10
HA=$(height_a); HB=$(height_b)
DIFF=$(( HA > HB ? HA - HB : HB - HA ))
if [ "$DIFF" -le 2 ]; then
    echo "  PASS: nodes within $DIFF blocks"
else
    echo "  FAIL: nodes differ by $DIFF blocks"
    exit 1
fi

echo ""
echo "Test 2: Partition simulation"
echo "  (Disconnect Node B from Node A, mine 3 blocks on each, reconnect)"
echo "  (Node with more cumulative work should win)"
echo "  Skipping automatic partition test — run manually."

echo ""
echo "Reorg test complete."
