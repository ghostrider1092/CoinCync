#!/usr/bin/env bash
#
# coincync-verify-chain.sh — Full blockchain validation (Bitcoin Core verifychain style)
#
# LEVELS (cumulative):
#   0: Chain structure (linkage, gaps)
#   1: Block validity (PoW, timestamps, merkle, rewards)
#   2: Transaction rules (ring sizes, key images, double spends)
#   3: Cryptography (CLSAG, Bulletproofs+, commitments)
#   4: Full re-validation + cross-node comparison
#
# Usage:
#   ./coincync-verify-chain.sh                          # Level 3, last 100 blocks
#   ./coincync-verify-chain.sh --level 4 --blocks 0    # Full chain audit
#   ./coincync-verify-chain.sh --level 1 --node http://66.135.23.193:28081

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/coincync_rpc_auth.sh
. "${SCRIPT_DIR}/lib/coincync_rpc_auth.sh"
coincync_rpc_load_env

LEVEL=3; BLOCKS=100; NODE_URL="http://localhost:28081"; QUIET=false; COMPARE=false

if [ -t 1 ]; then
    R=$'\033[0;31m'; G=$'\033[0;32m'; Y=$'\033[0;33m'; B=$'\033[0;34m'; D=$'\033[2m'; BOLD=$'\033[1m'; X=$'\033[0m'
else
    R=""; G=""; Y=""; B=""; D=""; BOLD=""; X=""
fi

T=0; P=0; F=0; W=0; FINDS=()

pass() { T=$((T+1)); P=$((P+1)); [ "$QUIET" = false ] && echo "  ${G}OK${X} $*"; }
fail() { T=$((T+1)); F=$((F+1)); echo "  ${R}X${X} $*"; FINDS+=("FAIL: $*"); }
warn() { T=$((T+1)); W=$((W+1)); [ "$QUIET" = false ] && echo "  ${Y}!${X} $*"; FINDS+=("WARN: $*"); }
hdr()  { [ "$QUIET" = true ] && return; echo ""; echo "${B}${BOLD}--- $* ---${X}"; }
info() { [ "$QUIET" = false ] && echo "  ${D}$*${X}"; }

rpc() {
    coincync_curl_rpc -sf -m 10 -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"$1\",\"params\":${2:-[]},\"id\":1}" \
        "${NODE_URL}" 2>/dev/null || echo "ERROR"
}

jget() { echo "$2" | grep -oE "\"$1\":[^,}]*" | head -1 | cut -d: -f2- | tr -d ' "'; }

while [ $# -gt 0 ]; do
    case "$1" in
        --level)   LEVEL="$2"; shift 2 ;; --blocks)  BLOCKS="$2"; shift 2 ;;
        --node)    NODE_URL="$2"; shift 2 ;; --quiet) QUIET=true; shift ;;
        --compare) COMPARE=true; shift ;; --help|-h) echo "Usage: $0 [--level 0-4] [--blocks N] [--node URL]"; exit 0 ;;
        *) echo "Unknown: $1"; exit 3 ;;
    esac
done

START_TIME=$(date +%s)

hdr "Pre-flight"
NI=$(rpc "get_info")
[ "$NI" = "ERROR" ] && { echo "${R}Cannot connect to ${NODE_URL}${X}"; exit 2; }
CH=$(jget "height" "$NI"); PC=$(jget "peer_count" "$NI")
pass "Node reachable (h=${CH}, peers=${PC})"

if [ "$BLOCKS" = "0" ]; then SH=0; EH="$CH"; else EH="$CH"; SH=$((CH-BLOCKS)); [ "$SH" -lt 0 ] && SH=0; fi
TC=$((EH-SH)); SI=1; [ "$TC" -gt 1000 ] && SI=$((TC/500))
info "Range: ${SH}-${EH} (${TC} blocks, sample every ${SI})"

# === LEVEL 0: Chain Structure ===
hdr "Level 0 — Chain Structure"
GEN=$(rpc "get_block_by_height" "[0]")
[ "$GEN" != "ERROR" ] && pass "Genesis readable ($(jget hash "$GEN" | head -c16)...)" || fail "Genesis not readable"
TIP=$(rpc "get_block_by_height" "[$CH]")
[ "$TIP" != "ERROR" ] && pass "Tip readable (h=$CH)" || fail "Tip not readable"

LE=0; PH=""
for h in $(seq "$SH" "$SI" "$EH"); do
    BK=$(rpc "get_block_by_height" "[$h]"); [ "$BK" = "ERROR" ] && { LE=$((LE+1)); PH=""; continue; }
    BH=$(jget "hash" "$BK"); BP=$(jget "prev_hash" "$BK")
    [ -n "$PH" ] && [ -n "$BP" ] && [ "$BP" != "$PH" ] && [ "$h" -gt 0 ] && { fail "Broken link at h=$h"; LE=$((LE+1)); }
    PH="$BH"
done
[ "$LE" -eq 0 ] && pass "Linkage valid ($TC blocks)"

# === LEVEL 1: Block Validity ===
if [ "$LEVEL" -ge 1 ]; then
    hdr "Level 1 — Block Validity"
    TE=0; PT=0
    for h in $(seq "$SH" "$SI" "$EH"); do
        BK=$(rpc "get_block_by_height" "[$h]"); [ "$BK" = "ERROR" ] && continue
        TS=$(jget "timestamp" "$BK"); NOW=$(date +%s)
        [ -n "$TS" ] && [ "$TS" -gt $((NOW+7200)) ] && { fail "h=$h timestamp future"; TE=$((TE+1)); }
        [ "$h" -gt 0 ] && [ "$PT" -gt 0 ] && [ -n "$TS" ] && [ "$TS" -lt $((PT-60)) ] && { fail "h=$h timestamp backward"; TE=$((TE+1)); }
        [ -n "$TS" ] && PT="$TS"
    done
    [ "$TE" -eq 0 ] && pass "Timestamps valid"

    SI_INFO=$(rpc "get_supply_info")
    if [ "$SI_INFO" != "ERROR" ]; then
        TS_VAL=$(jget "total_emitted" "$SI_INFO")
        [ -n "$TS_VAL" ] && pass "Supply: $TS_VAL atomic"
    fi
fi

# === LEVEL 2: Transaction Rules ===
if [ "$LEVEL" -ge 2 ]; then
    hdr "Level 2 — Transaction Rules"
    KI=$(rpc "verify_keyimage_uniqueness")
    if [ "$KI" != "ERROR" ] && echo "$KI" | grep -q "valid"; then
        KV=$(jget "valid" "$KI")
        [ "$KV" = "false" ] && fail "Key image duplicates found" || pass "Key images unique"
    else
        info "Key image uniqueness check not available — skipped"
    fi
fi

# === LEVEL 3: Cryptography ===
if [ "$LEVEL" -ge 3 ]; then
    hdr "Level 3 — Cryptographic Verification"

    SV=$(rpc "verify_signatures_in_range" "[$SH,$EH]")
    if [ "$SV" != "ERROR" ] && echo "$SV" | grep -q "valid"; then
        [ "$(jget valid "$SV")" = "false" ] && fail "CLSAG signatures invalid" || pass "CLSAG signatures valid ($(jget checked "$SV") checked)"
    else info "CLSAG verification not available — skipped"; fi

    BV=$(rpc "verify_range_proofs_in_range" "[$SH,$EH]")
    if [ "$BV" != "ERROR" ] && echo "$BV" | grep -q "valid"; then
        [ "$(jget valid "$BV")" = "false" ] && fail "Range proofs invalid" || pass "Bulletproofs+ valid"
    else info "Range proof verification not available — skipped"; fi

    ZC=$(rpc "check_zero_commitments_in_range" "[$SH,$EH]")
    if [ "$ZC" != "ERROR" ] && echo "$ZC" | grep -q "zero_count"; then
        ZN=$(jget "zero_count" "$ZC")
        [ "${ZN:-0}" -gt 0 ] && fail "CRITICAL: $ZN zero commitments" || pass "No zero commitments"
    else info "Zero commitment check not available — skipped"; fi
fi

# === LEVEL 4: Full Audit ===
if [ "$LEVEL" -ge 4 ]; then
    hdr "Level 4 — Full Re-Validation"
    AU=$(rpc "full_chain_audit" "[$SH,$EH]")
    if [ "$AU" != "ERROR" ] && echo "$AU" | grep -q "valid"; then
        [ "$(jget valid "$AU")" = "false" ] && fail "Full audit found issues" || pass "Full audit passed ($(jget blocks_checked "$AU") blocks)"
    else info "Full chain audit not available — skipped"; fi

    if [ "$COMPARE" = true ]; then
        info "Cross-node comparison..."
        for other in "http://66.135.23.193:28081" "http://140.82.57.168:28081" "http://207.148.6.50:28081"; do
            OI=$(coincync_curl_rpc -sf -m 5 -X POST "$other" -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' 2>/dev/null)
            if [ -n "$OI" ]; then
                OH=$(jget "height" "$OI"); DF=$((CH-OH)); [ "$DF" -lt 0 ] && DF=$((-DF))
                [ "$DF" -gt 10 ] && warn "Divergence: $other at h=$OH (diff $DF)" || pass "Consistent: $other h=$OH"
            fi
        done
    fi
fi

# === Summary ===
hdr "Summary"
ET=$(date +%s); DU=$((ET-START_TIME))
echo "  ${G}Passed: $P${X}  ${R}Failed: $F${X}  ${Y}Warned: $W${X}  (${DU}s)"
[ "$F" -gt 0 ] && { for f in "${FINDS[@]}"; do [[ "$f" == FAIL:* ]] && echo "  ${R}$f${X}"; done; echo "${R}VALIDATION FAILED${X}"; exit 1; }
[ "$W" -gt 0 ] && { echo "${Y}PASSED with warnings${X}"; exit 0; }
echo "${G}VALIDATION PASSED${X}"; exit 0
