#!/bin/bash
# flood_mempool.sh — Send many privacy transactions to stress-test the mempool
#
# Sends from LON mining wallet to ATL mining wallet in a burst.
# Each tx is a full CLSAG + BP+ privacy transaction, indistinguishable
# from real transfers.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/lib/coincync_rpc_auth.sh" ]]; then
  # shellcheck source=lib/coincync_rpc_auth.sh
  . "${SCRIPT_DIR}/lib/coincync_rpc_auth.sh"
  coincync_rpc_load_env
else
  coincync_curl_rpc() { curl "$@"; }
fi

WALLET="/root/.coincync/wallets/miner.wallet"
PASSWORD="miner123"
NODE="http://127.0.0.1:28081"
WALLET_BIN="/root/coincync-new/target/release/coincync-wallet"

# ATL recipient keys
TO_SPEND="50034366ea79e06ab179b51510d6ee09cbbcadbc5e9ebaf2464820e5a5a2f22d"
TO_VIEW="bce2e5319e130967e4fa716ab1993465f69c422caa6739bd0776c2d033d6b721"

# Number of transactions to send
NUM_TXS=${1:-20}
# Amount per tx (in atomic CYNC — 1 CYNC = 1,000,000,000,000)
AMOUNT=${2:-1000000000000}  # 1 CYNC default

echo "═══════════════════════════════════════════════════"
echo "  CoinCync Mempool Flood Test"
echo "═══════════════════════════════════════════════════"
echo ""
echo "  Wallet:    $WALLET"
echo "  Node:      $NODE"
echo "  Recipient: ATL miner (${TO_SPEND:0:16}...)"
echo "  Txs:       $NUM_TXS"
echo "  Amount:    $AMOUNT atomic each"
echo ""

# Re-scan to get latest UTXOs
echo "Scanning for latest UTXOs..."
source /root/.cargo/env
$WALLET_BIN --wallet "$WALLET" --node "$NODE" scan -p "$PASSWORD" --from 0 --max-blocks 1000 2>&1 | tail -3
echo ""

SENT=0
FAILED=0

for i in $(seq 1 $NUM_TXS); do
    printf "  tx %3d/%d ... " "$i" "$NUM_TXS"

    # Send a privacy transaction
    OUTPUT=$($WALLET_BIN \
        --wallet "$WALLET" \
        --node "$NODE" \
        send \
        -p "$PASSWORD" \
        --to-spend "$TO_SPEND" \
        --to-view "$TO_VIEW" \
        --amount "$AMOUNT" \
        2>&1) || true

    if echo "$OUTPUT" | grep -q "accepted"; then
        HASH=$(echo "$OUTPUT" | grep "Hash:" | awk '{print $2}')
        printf "OK (${HASH:0:16}...)\n"
        SENT=$((SENT + 1))
    else
        ERROR=$(echo "$OUTPUT" | tail -1)
        printf "FAILED: %s\n" "$ERROR"
        FAILED=$((FAILED + 1))

        # If we run out of UTXOs, re-scan and try to continue
        if echo "$OUTPUT" | grep -qi "insufficient\|no.*utxo\|no spendable"; then
            echo "    Re-scanning for new UTXOs..."
            $WALLET_BIN --wallet "$WALLET" --node "$NODE" scan -p "$PASSWORD" --from 0 --max-blocks 1000 2>&1 | tail -1
        fi
    fi
done

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Results: $SENT sent, $FAILED failed"
echo "═══════════════════════════════════════════════════"

# Check mempool
echo ""
echo "Mempool status:"
coincync_curl_rpc -s -X POST "$NODE" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"get_mempool_info","params":[],"id":1}' | \
    python3 -c "import sys,json; d=json.load(sys.stdin).get('result',{}); print(f'  Size: {d.get(\"size\",0)} txs, Bytes: {d.get(\"bytes\",0)}')" 2>/dev/null || echo "  (unavailable)"
