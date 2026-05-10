#!/usr/bin/env bash
# health-check.sh — quick local-node smoke test for testnet operators.
#
# Verifies:
#   1. Node RPC is reachable
#   2. Node has peers (P2P working)
#   3. Chain is advancing (compares two get_info calls 10s apart)
#   4. Tip is reasonably fresh
#   5. Anonymity-set + ring-size sanity
#   6. Mempool reachable
#
# Run from anywhere:
#     bash scripts/health-check.sh
#     RPC=http://my.node:28081 bash scripts/health-check.sh
#     RPC=https://api.coincync.network/rpc/testnet bash scripts/health-check.sh
#
# Exits 0 on healthy, non-zero with a labeled reason on failure.

set -uo pipefail

RPC="${RPC:-http://127.0.0.1:28081}"
KEY="${COINCYNC_RPC_API_KEY:-}"
# Auto-source local env file if no key passed.
if [ -z "$KEY" ] && [ -f /etc/coincync/coincync.env ]; then
  KEY=$(grep '^COINCYNC_RPC_API_KEY=' /etc/coincync/coincync.env 2>/dev/null | cut -d= -f2 || true)
fi

AUTH=()
[ -n "$KEY" ] && AUTH=(-H "authorization: Bearer $KEY")

green() { printf '\e[32m✓\e[0m %s\n' "$*"; }
yellow() { printf '\e[33m!\e[0m %s\n' "$*"; }
red()   { printf '\e[31m✗\e[0m %s\n' "$*" >&2; }

# ── 1. RPC reachable ─────────────────────────────────────────────────
INFO=$(curl -sS -m 5 -X POST "$RPC" "${AUTH[@]}" \
       -H 'content-type: application/json' \
       -d '{"jsonrpc":"2.0","id":1,"method":"get_info","params":[]}' 2>/dev/null) || INFO=""
if [ -z "$INFO" ] || ! echo "$INFO" | grep -q '"result"'; then
  red "RPC not reachable at $RPC"
  if echo "$INFO" | grep -q '"Unauthorized"'; then
    red "  (got 401 Unauthorized — set COINCYNC_RPC_API_KEY env var)"
  fi
  exit 2
fi
green "RPC reachable at $RPC"

# Helper: extract fields via python (universally available).
parse() {
  echo "$INFO" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)['result']
    print(d.get('$1', ''))
except Exception:
    print('')
" 2>/dev/null
}

H1=$(parse height)
TIP_AGE=$(parse tip_age_secs)
PEERS=$(parse peer_count)
SYNCED=$(parse is_synced)
STATUS=$(parse status)
ANON=$(parse anonymity_set)
RING=$(parse effective_ring_size)
MPOOL=$(parse mempool_size)
BUILD=$(parse build_commit)

# ── 2. Peers ─────────────────────────────────────────────────────────
if [ "${PEERS:-0}" = "0" ]; then
  red "0 peers — P2P isolated. Check firewall (TCP 28080 inbound + outbound)."
  exit 3
elif [ "${PEERS:-0}" -lt 3 ]; then
  yellow "Only $PEERS peer(s). 3+ is healthy. Bootstrap may still be in progress."
else
  green "$PEERS peer(s) connected"
fi

# ── 3. Chain advancing ───────────────────────────────────────────────
if [ "$SYNCED" = "True" ] || [ "$SYNCED" = "true" ]; then
  green "Chain synced (height=$H1, status=$STATUS)"
else
  echo "  ⏳ Not yet synced (h=$H1, target=$(parse target_height)) — sleeping 10s to confirm advancing…"
  sleep 10
  INFO2=$(curl -sS -m 5 -X POST "$RPC" "${AUTH[@]}" \
         -H 'content-type: application/json' \
         -d '{"jsonrpc":"2.0","id":1,"method":"get_info","params":[]}' 2>/dev/null) || INFO2=""
  H2=$(echo "$INFO2" | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['height'])" 2>/dev/null || echo "$H1")
  if [ "$H2" -gt "$H1" ]; then
    green "Chain advancing (h=$H1 → h=$H2 in 10s)"
  else
    red "Height stuck at $H1 for 10s. Possible IBD wedge or no peers serving blocks."
    yellow "Check journalctl -u coincync-node -f for orphan-loop or 'invalid magic' warnings."
    exit 4
  fi
fi

# ── 4. Tip freshness ─────────────────────────────────────────────────
if [ -z "$TIP_AGE" ] || [ "$TIP_AGE" = "null" ]; then
  yellow "tip_age_secs is null (clock may be skewed)"
elif [ "$TIP_AGE" -gt 600 ] && [ "$STATUS" = "stalled" ]; then
  red "Chain stalled — tip is ${TIP_AGE}s old (no miner producing blocks?)"
elif [ "$TIP_AGE" -gt 600 ]; then
  yellow "Tip is ${TIP_AGE}s old — chain may be quiet"
else
  green "Tip is ${TIP_AGE}s old"
fi

# ── 5. Privacy stats ─────────────────────────────────────────────────
if [ -n "$ANON" ] && [ -n "$RING" ]; then
  green "Anonymity set: $ANON outputs · effective ring size: $RING"
  if [ "${RING:-0}" -lt 11 ]; then
    yellow "  Ring size $RING < 11 — chain is in bootstrap phase (ramps to 16 after h=10000)."
  fi
else
  yellow "anonymity_set / effective_ring_size not exposed — node may be on an older build"
fi

# ── 6. Mempool ───────────────────────────────────────────────────────
if [ -n "$MPOOL" ]; then
  green "Mempool: $MPOOL pending tx(s)"
fi

# ── Summary ──────────────────────────────────────────────────────────
echo
echo "Node:       $RPC"
echo "Build:      ${BUILD:-unknown}"
echo "Status:     $STATUS"
echo "Height:     $H1"
echo "Peers:      $PEERS"
echo "Tip age:    ${TIP_AGE}s"
echo
green "Health check passed."
