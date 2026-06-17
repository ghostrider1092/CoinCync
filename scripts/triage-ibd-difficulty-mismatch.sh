#!/usr/bin/env bash
#
# triage-ibd-difficulty-mismatch.sh
#
# Collect everything we need to diagnose an IBD difficulty-target
# mismatch (the "expected X, got Y" log line). Output goes to a single
# file the user can paste back.
#
# Usage:
#     ./triage-ibd-difficulty-mismatch.sh \
#         <node-log-path> \
#         <rejected-block-hash> \
#         <rejected-block-parent-hash> \
#         [rpc-url]
#
# Example:
#     ./triage-ibd-difficulty-mismatch.sh \
#         ~/.coincync/coincync-node.log \
#         c50b452f085faf98 \
#         55616ad588738525
#
# Default RPC URL: http://127.0.0.1:28081 (testnet). Override if your
# node listens elsewhere.
#
# Requires: curl, jq, grep, sed, awk. All present on any standard
# Linux distro + macOS + WSL.

set -u

LOG_PATH="${1:-}"
REJECTED_HASH="${2:-}"
PARENT_HASH="${3:-}"
RPC_URL="${4:-http://127.0.0.1:28081}"

if [[ -z "$LOG_PATH" || -z "$REJECTED_HASH" || -z "$PARENT_HASH" ]]; then
    echo "usage: $0 <node-log-path> <rejected-block-hash> <rejected-block-parent-hash> [rpc-url]"
    echo "example: $0 ~/.coincync/coincync-node.log c50b452f085faf98 55616ad588738525"
    exit 1
fi

OUT="ibd-triage-$(date +%Y%m%d-%H%M%S).txt"
{
    echo "=== CoinCync IBD Difficulty-Mismatch Triage Report ==="
    echo "Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "Host: $(hostname)"
    echo "RPC: $RPC_URL"
    echo "Log: $LOG_PATH"
    echo "Rejected block: $REJECTED_HASH"
    echo "Parent block:   $PARENT_HASH"
    echo

    echo "=== 1. Binary version ==="
    if command -v coincync-node >/dev/null 2>&1; then
        coincync-node --version 2>&1 || true
    else
        echo "coincync-node not on PATH — run this with the binary's directory in PATH,"
        echo "or paste the output of '/path/to/coincync-node --version' manually."
    fi
    echo

    echo "=== 2. Local tip ==="
    curl -sS -m 5 -X POST "$RPC_URL/rpc/testnet" \
        -H 'content-type: application/json' \
        --data '{"jsonrpc":"2.0","id":1,"method":"get_blockchain_info","params":[]}' \
        2>&1 | head -c 4096
    echo
    echo

    echo "=== 3. Parent block (the input to the ASERT calc that diverged) ==="
    echo "--- get_block($PARENT_HASH) ---"
    curl -sS -m 10 -X POST "$RPC_URL/rpc/testnet" \
        -H 'content-type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_block\",\"params\":[\"$PARENT_HASH\"]}" \
        2>&1 | head -c 8192
    echo
    echo

    echo "=== 4. Rejected block (may not be in our DB if we rejected it before persisting) ==="
    echo "--- get_block($REJECTED_HASH) ---"
    curl -sS -m 10 -X POST "$RPC_URL/rpc/testnet" \
        -H 'content-type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_block\",\"params\":[\"$REJECTED_HASH\"]}" \
        2>&1 | head -c 8192
    echo
    echo

    echo "=== 5. Difficulty-blocks window we computed against ==="
    echo "(if the node exposes this — older builds may not)"
    curl -sS -m 10 -X POST "$RPC_URL/rpc/testnet" \
        -H 'content-type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_difficulty_blocks\",\"params\":[]}" \
        2>&1 | head -c 4096
    echo
    echo

    echo "=== 6. Log context around the rejection ==="
    if [[ -f "$LOG_PATH" ]]; then
        echo "--- grep -C3 $REJECTED_HASH ---"
        grep -C3 "$REJECTED_HASH" "$LOG_PATH" 2>&1 | tail -c 16384
        echo
        echo "--- grep -C3 $PARENT_HASH ---"
        grep -C3 "$PARENT_HASH" "$LOG_PATH" 2>&1 | tail -c 16384
        echo
        echo "--- Last 80 lines of log ---"
        tail -80 "$LOG_PATH" 2>&1
    else
        echo "LOG NOT FOUND at $LOG_PATH — paste the relevant log lines manually."
    fi
    echo

    echo "=== 7. Fleet peer the rejected block came from ==="
    echo "(check that our peer table actually points at the live fleet,"
    echo " not a stale IP from a pre-2026-06-06 build.)"
    curl -sS -m 5 -X POST "$RPC_URL/rpc/testnet" \
        -H 'content-type: application/json' \
        --data '{"jsonrpc":"2.0","id":1,"method":"get_connections","params":[]}' \
        2>&1 | head -c 4096
    echo
    echo
    echo "=== END ==="
} > "$OUT" 2>&1

echo "Triage report written to: $OUT"
echo "Paste its contents back to whoever asked for it."
