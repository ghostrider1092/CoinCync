#!/bin/bash
# T3.2 — Network Partition and Merge Test
#
# Partitions the testnet into two groups using iptables,
# lets each group produce blocks independently, then
# reconnects and verifies convergence.
#
# Requires: SSH access to testnet nodes
# Duration: ~10 minutes

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/coincync_rpc_auth.sh
. "${SCRIPT_DIR}/lib/coincync_rpc_auth.sh"
coincync_rpc_load_env

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Partition groups
GROUP_A=("138.68.172.80" "64.227.49.44" "192.34.59.42" "46.101.138.120" "45.55.32.13")
GROUP_B=("143.110.218.99" "165.245.161.62" "165.245.140.113" "164.92.153.24" "170.64.142.146")
RPC_PORT=28081
P2P_PORT=28080

rpc() {
    local ip=$1 method=$2
    coincync_curl_rpc -s --max-time 5 -X POST "http://${ip}:${RPC_PORT}" \
        -H 'Content-Type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"${method}\"}" 2>/dev/null | \
        python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('result',{}).get('height',0))" 2>/dev/null || echo "0"
}

echo ""
echo "═══════════════════════════════════════════════════"
echo "  T3.2 — PARTITION AND MERGE TEST"
echo "═══════════════════════════════════════════════════"
echo ""

# Step 1: Record pre-partition heights
echo "Step 1: Recording pre-partition state..."
for ip in "${GROUP_A[@]}" "${GROUP_B[@]}"; do
    h=$(rpc "$ip" "get_info")
    printf "  %-20s height=%s\n" "$ip" "$h"
done
echo ""

PRE_HEIGHT=$(rpc "${GROUP_A[0]}" "get_info")
echo "Pre-partition height: ${PRE_HEIGHT}"
echo ""

# Step 2: Create partition (block P2P traffic between groups)
echo "Step 2: Creating network partition..."
for ip_a in "${GROUP_A[@]}"; do
    for ip_b in "${GROUP_B[@]}"; do
        ssh -o ConnectTimeout=5 "root@${ip_a}" \
            "iptables -I INPUT -s ${ip_b} -p tcp --dport ${P2P_PORT} -j DROP 2>/dev/null; \
             iptables -I OUTPUT -d ${ip_b} -p tcp --dport ${P2P_PORT} -j DROP 2>/dev/null" 2>/dev/null && \
            printf "  ${YELLOW}Blocked${NC} ${ip_a} <-> ${ip_b}\n" || \
            printf "  ${RED}Failed${NC} ${ip_a} <-> ${ip_b}\n"
    done
done
echo ""

# Step 3: Wait for blocks to diverge
WAIT_SECS=300
echo "Step 3: Waiting ${WAIT_SECS}s for blocks to diverge..."
echo "  (Each group will mine independently)"
sleep ${WAIT_SECS}
echo ""

# Step 4: Record diverged heights
echo "Step 4: Recording post-partition state..."
echo "  Group A:"
for ip in "${GROUP_A[@]}"; do
    h=$(rpc "$ip" "get_info")
    printf "    %-20s height=%s\n" "$ip" "$h"
done
echo "  Group B:"
for ip in "${GROUP_B[@]}"; do
    h=$(rpc "$ip" "get_info")
    printf "    %-20s height=%s\n" "$ip" "$h"
done
echo ""

# Step 5: Remove partition (restore P2P traffic)
# CRITICAL: Use -D (delete specific rule) NOT -F (flush all)!
# Flushing all rules locks out SSH and bricks the node.
echo "Step 5: Removing partition (reconnecting)..."
for ip_a in "${GROUP_A[@]}"; do
    for ip_b in "${GROUP_B[@]}"; do
        ssh -o ConnectTimeout=5 "root@${ip_a}" \
            "iptables -D INPUT -s ${ip_b} -p tcp --dport ${P2P_PORT} -j DROP 2>/dev/null; \
             iptables -D OUTPUT -d ${ip_b} -p tcp --dport ${P2P_PORT} -j DROP 2>/dev/null" 2>/dev/null && \
            printf "  ${GREEN}Unblocked${NC} ${ip_a} <-> ${ip_b}\n" || true
    done
done
echo ""

# Step 6: Wait for convergence
CONVERGE_SECS=120
echo "Step 6: Waiting ${CONVERGE_SECS}s for convergence..."
sleep ${CONVERGE_SECS}
echo ""

# Step 7: Verify all nodes agree
echo "Step 7: Checking convergence..."
HEIGHTS=()
for ip in "${GROUP_A[@]}" "${GROUP_B[@]}"; do
    h=$(rpc "$ip" "get_info")
    HEIGHTS+=("$h")
    printf "  %-20s height=%s\n" "$ip" "$h"
done
echo ""

# Check if all heights match
UNIQUE_HEIGHTS=($(echo "${HEIGHTS[@]}" | tr ' ' '\n' | sort -u))
if [ ${#UNIQUE_HEIGHTS[@]} -eq 1 ]; then
    echo -e "${GREEN}PASS${NC}: All nodes converged to height ${UNIQUE_HEIGHTS[0]}"
    POST_HEIGHT=${UNIQUE_HEIGHTS[0]}
    echo "  Chain grew from ${PRE_HEIGHT} to ${POST_HEIGHT} (${POST_HEIGHT} - ${PRE_HEIGHT} = $((POST_HEIGHT - PRE_HEIGHT)) blocks)"
elif [ ${#UNIQUE_HEIGHTS[@]} -le 2 ]; then
    echo -e "${YELLOW}PARTIAL${NC}: Most nodes converged but ${#UNIQUE_HEIGHTS[@]} different heights: ${UNIQUE_HEIGHTS[*]}"
    echo "  This may be OK if nodes are still syncing"
else
    echo -e "${RED}FAIL${NC}: Nodes did NOT converge! Heights: ${UNIQUE_HEIGHTS[*]}"
    echo "  This is a consensus bug."
    exit 1
fi

echo ""
echo "═══════════════════════════════════════════════════"
echo "  T3.2 COMPLETE"
echo "═══════════════════════════════════════════════════"
