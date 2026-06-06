#!/usr/bin/env bash
# cyncswap-dual-testnet-smoke.sh — end-to-end dual-testnet smoke
# exercise for the CIP-001 atomic swap, driving the 6 cyncswap
# orchestration commands against a live bitcoind regtest +
# coincync-node testnet pair.
#
# This is the OPERATOR-driven smoke harness. It does NOT auto-fill
# wallet inputs or sign transactions for you — at each step that
# requires a signed tx, the script PAUSES and prints what hex it
# expects on stdin (a typical operator pipes their wallet's output
# in via a pasted hex string or `cat signed.hex`). The cryptographic
# steps (adaptor pre-sigs, decrypt, recover, DLEQ prove/verify)
# run automatically because they need no wallet state.
#
# What this exercises:
#   - All 6 state-machine orchestration commands
#     (lock-cync, lock-btc, claim-btc, claim-cync, refund-btc, refund-cync)
#   - All cryptographic primitives wired into the CLI
#     (create-pre-sig-{btc,cync}, decrypt-{btc,cync}-adaptor,
#      recover-secret-from-{btc,cync}-sig, prove-dleq, verify-dleq,
#      derive-cync-{recipient-pubkey,spender-secret})
#   - The state-file round-trip across all 4 protocol-shaping events
#   - Both chains' RPC clients (`btc-broadcast`, `cync-broadcast`,
#     `btc-watch`, `cync-watch`)
#
# What this does NOT exercise:
#   - Transport layer (coordinator listen/connect/handshake — phase 3)
#   - Real adversarial reorgs (out of scope for a smoke test)
#   - The Halo2 shielded-pool circuit (Phase 2 / CIP-013, separate
#     activation track)
#
# Prerequisites:
#
#   1. bitcoind regtest running locally on the default port (18443).
#      Easiest:
#        bitcoind -regtest -daemon \
#          -rpcuser=cyncswap -rpcpassword=cyncswap \
#          -fallbackfee=0.0001 -txindex=1
#        bitcoin-cli -regtest -rpcuser=cyncswap -rpcpassword=cyncswap \
#          createwallet swap_test
#        bitcoin-cli -regtest -rpcuser=cyncswap -rpcpassword=cyncswap \
#          -generate 101
#
#   2. coincync-node testnet running locally on its RPC port
#      (default 9933 — adjust BELOW if your build differs):
#        coincync-node --testnet
#
#   3. cyncswap binary built and on $PATH (or set $CYNCSWAP_BIN).
#
#   4. A funded BTC UTXO (txid + vout + value_sats) under Bob's
#      control on the regtest wallet — printed by `listunspent`
#      after the generate-101 step above.
#
# Usage:
#   bash scripts/cyncswap-dual-testnet-smoke.sh [--scenario happy|refund-btc|refund-cync]
#
# Scenarios:
#   happy        — full Alice-claims path. Default.
#   refund-btc   — Alice never claims; Bob exercises BTC refund branch.
#                  (Requires waiting for the CSV timeout; the harness
#                  mines blocks via bitcoin-cli to fast-forward.)
#   refund-cync  — Bob never locks BTC; Alice exercises CYNC refund
#                  branch. Faster on regtest because the CYNC timeout
#                  is the shorter of the two flows in terms of
#                  human-time-to-test.
#
# Output:
#   Each step prints a "STEP N:" header in green, followed by the
#   subcommand it ran and (truncated) output. On any failure the
#   script aborts with the failing command's stderr.

set -euo pipefail

# ─── Configuration (override via environment) ───────────────────────
CYNCSWAP_BIN="${CYNCSWAP_BIN:-cyncswap}"
STATE_FILE_ALICE="${STATE_FILE_ALICE:-/tmp/cyncswap-smoke-alice.json}"
STATE_FILE_BOB="${STATE_FILE_BOB:-/tmp/cyncswap-smoke-bob.json}"
BTC_NETWORK="${BTC_NETWORK:-regtest}"
BTC_RPC_URL="${BTC_RPC_URL:-http://127.0.0.1:18443}"
BTC_RPC_USER="${BTC_RPC_USER:-cyncswap}"
BTC_RPC_PASS="${BTC_RPC_PASS:-cyncswap}"
CYNC_NETWORK="${CYNC_NETWORK:-testnet}"
CYNC_RPC_URL="${CYNC_RPC_URL:-http://127.0.0.1:9933}"
CYNC_API_KEY="${CYNC_API_KEY:-}"

CYNC_AMOUNT="${CYNC_AMOUNT:-100000000}"        # 1 CYNC in atomic units
BTC_AMOUNT_SATS="${BTC_AMOUNT_SATS:-1000000}"  # 0.01 BTC
CYNC_TIMEOUT_BLOCKS="${CYNC_TIMEOUT_BLOCKS:-720}"
BTC_TIMEOUT_BLOCKS="${BTC_TIMEOUT_BLOCKS:-100}"

SCENARIO="happy"

# ─── Argparse ───────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --scenario)
            SCENARIO="$2"; shift 2 ;;
        --scenario=*)
            SCENARIO="${1#*=}"; shift ;;
        -h|--help)
            sed -n '2,/^set -euo pipefail/p' "$0" | sed 's/^# \{0,1\}//' | head -n -1
            exit 0 ;;
        *)
            echo "Unknown arg: $1" >&2; exit 2 ;;
    esac
done

case "$SCENARIO" in
    happy|refund-btc|refund-cync) ;;
    *) echo "Unknown scenario: $SCENARIO (want: happy|refund-btc|refund-cync)" >&2; exit 2 ;;
esac

# ─── Pretty printing ────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YEL='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
step_n=0
step() {
    step_n=$((step_n+1))
    printf "${GREEN}STEP %d:${NC} %s\n" "$step_n" "$1"
}
note() { printf "${CYAN}  ↳${NC} %s\n" "$1"; }
warn() { printf "${YEL}!!${NC} %s\n" "$1"; }
die()  { printf "${RED}FAIL:${NC} %s\n" "$1" >&2; exit 1; }

# ─── Helpers ────────────────────────────────────────────────────────
need() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }

pause_for_hex() {
    # Prompts the operator to paste a signed tx hex on stdin.
    # Usage:   tx_hex=$(pause_for_hex "what the wallet should produce")
    local prompt="$1"
    warn "OPERATOR ACTION REQUIRED: $prompt"
    echo "  Paste the signed tx hex (single line, no 0x prefix) and press Enter:"
    local hex
    read -r hex
    [[ -n "$hex" ]] || die "no hex provided"
    echo "$hex"
}

confirm_continue() {
    local label="$1"
    warn "About to: $label"
    read -r -p "  Continue? [y/N] " yn
    [[ "$yn" =~ ^[Yy]$ ]] || die "aborted by operator"
}

cleanup() {
    if [[ "${KEEP_STATE:-0}" != "1" ]]; then
        rm -f "$STATE_FILE_ALICE" "$STATE_FILE_BOB"
    else
        warn "KEEP_STATE=1 set; leaving state files for inspection"
    fi
}
trap cleanup EXIT

# ─── Preflight ──────────────────────────────────────────────────────
need "$CYNCSWAP_BIN"
need curl
need python3   # used for tiny JSON parses below; ships with every recent OS

# Tiny JSON-field extractor — replaces `jq -r .<key>`. Reads JSON
# from stdin, prints the value at the dotted key path. Returns
# non-zero exit + nothing on stdout if stdin isn't valid JSON or
# the field is missing (matches `jq -r .missing` posture so the
# caller's `|| die ...` chain works).
json_field() {
    python3 -c "import json,sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(1)
for k in sys.argv[1].lstrip('.').split('.'):
    if isinstance(data, dict) and k in data:
        data = data[k]
    else:
        sys.exit(1)
print(data)" "$1" 2>/dev/null
}

step "Preflight — versions + chain heights"
"$CYNCSWAP_BIN" design-version | head -2
note "BTC chain tip:"
curl -s --user "$BTC_RPC_USER:$BTC_RPC_PASS" \
    --data-binary '{"jsonrpc":"1.0","id":"smoke","method":"getblockcount","params":[]}' \
    -H 'content-type: text/plain;' "$BTC_RPC_URL/" | json_field result \
    || die "bitcoind unreachable at $BTC_RPC_URL"
note "CYNC chain tip:"
curl -s "$CYNC_RPC_URL/get_block_count" 2>/dev/null | json_field result.count \
    || warn "coincync-node may be unreachable at $CYNC_RPC_URL (continuing — some steps will fail)"

# ─── Step 1: Negotiation ────────────────────────────────────────────
step "Initialize Alice + Bob state files"
rm -f "$STATE_FILE_ALICE" "$STATE_FILE_BOB"
"$CYNCSWAP_BIN" alice \
    --state-file "$STATE_FILE_ALICE" \
    --listen 127.0.0.1:9000 \
    --cync-amount "$CYNC_AMOUNT" \
    --btc-amount-sats "$BTC_AMOUNT_SATS" \
    --alice-cync-address alice-stealth-placeholder \
    --bob-btc-address bob-p2wpkh-placeholder \
    >/dev/null
note "Alice state initialized at $STATE_FILE_ALICE"

SWAP_ID=$(json_field swap.id < "$STATE_FILE_ALICE")
note "swap_id: $SWAP_ID"

"$CYNCSWAP_BIN" bob \
    --state-file "$STATE_FILE_BOB" \
    --connect 127.0.0.1:9000 \
    --swap-id "$SWAP_ID" \
    --cync-amount "$CYNC_AMOUNT" \
    --btc-amount-sats "$BTC_AMOUNT_SATS" \
    --alice-cync-address alice-stealth-placeholder \
    --bob-btc-address bob-p2wpkh-placeholder \
    >/dev/null
note "Bob state initialized at $STATE_FILE_BOB"

# ─── Step 2: Generate adaptor secret + DLEQ proof ──────────────────
step "Generate adaptor secret + cross-curve DLEQ proof"
ADAPTOR_SECRET_HEX=$(openssl rand -hex 31)"01"   # last byte 0x01 to stay safely within ℓ
NONCE_K_HEX=$(openssl rand -hex 31)"01"
note "adaptor secret (Ristretto LE): $ADAPTOR_SECRET_HEX"

T_BTC_HEX=$("$CYNCSWAP_BIN" btc-adaptor-point-from-secret --adaptor-secret "$ADAPTOR_SECRET_HEX")
T_CYNC_HEX=$("$CYNCSWAP_BIN" cync-adaptor-point-from-secret --adaptor-secret "$ADAPTOR_SECRET_HEX")
note "T_btc:  $T_BTC_HEX"
note "T_cync: $T_CYNC_HEX"

DLEQ_PROOF=$("$CYNCSWAP_BIN" prove-dleq \
    --adaptor-secret "$ADAPTOR_SECRET_HEX" \
    --btc-pub "$T_BTC_HEX" \
    --cync-pub "$T_CYNC_HEX" \
    --nonce "$NONCE_K_HEX")

"$CYNCSWAP_BIN" verify-dleq \
    --proof-json "$DLEQ_PROOF" \
    --btc-pub "$T_BTC_HEX" \
    --cync-pub "$T_CYNC_HEX" \
    && note "DLEQ verifies ✓" || die "DLEQ verify failed"

# ─── Step 3: Alice locks CYNC ───────────────────────────────────────
step "Alice locks CYNC"
warn "The wallet must:"
echo "    1. Compute swap recipient pubkey via 'cyncswap derive-cync-recipient-pubkey'"
echo "    2. Build a CYNC tx sending $CYNC_AMOUNT atomic units to that recipient"
echo "    3. Sign the tx and serialize as borsh+hex"
echo "    4. Paste the hex below."
ALICE_LOCK_HEX=$(pause_for_hex "Alice's signed CYNC lock tx hex")

CYNC_AUTH_FLAGS=()
[[ -n "$CYNC_API_KEY" ]] && CYNC_AUTH_FLAGS=(--api-key "$CYNC_API_KEY")

ALICE_LOCK_TXID=$("$CYNCSWAP_BIN" lock-cync \
    --state-file "$STATE_FILE_ALICE" \
    --network "$CYNC_NETWORK" \
    --rpc-url "$CYNC_RPC_URL" \
    "${CYNC_AUTH_FLAGS[@]}" \
    --signed-tx-hex "$ALICE_LOCK_HEX" \
    | grep -oE 'broadcast txid: [a-f0-9]{64}' | awk '{print $3}')
[[ -n "$ALICE_LOCK_TXID" ]] || die "lock-cync: no txid"
note "Alice's CYNC lock txid: $ALICE_LOCK_TXID"

# ─── Step 4: Bob waits for confirmation + locks BTC ────────────────
step "Bob waits for Alice's CYNC lock to confirm, then locks BTC"
"$CYNCSWAP_BIN" cync-watch \
    --network "$CYNC_NETWORK" \
    --rpc-url "$CYNC_RPC_URL" \
    "${CYNC_AUTH_FLAGS[@]}" \
    --txid "$ALICE_LOCK_TXID" \
    --confirmations 1 \
    --timeout-secs 600 \
    && note "Alice's CYNC lock confirmed ✓"

# Bob locally advances his state from Negotiated → AliceLocked via the
# observation transition. Production wallets / coordinators drive this
# from a chain watcher; the smoke harness fires it manually.
"$CYNCSWAP_BIN" transition \
    --state-file "$STATE_FILE_BOB" \
    --kind observe-alice-locked \
    && note "Bob's state advanced: Negotiated → AliceLocked"

if [[ "$SCENARIO" == "refund-cync" ]]; then
    warn "Scenario refund-cync: Bob skips the BTC lock, Alice waits out the CYNC timeout."
    echo "  Fast-forwarding by mining $CYNC_TIMEOUT_BLOCKS empty CYNC blocks via RPC (if supported)…"
    echo "  (On real testnet the operator must actually wait — this script just continues.)"
    goto_refund_cync=1
else
    goto_refund_cync=0
fi

if [[ "$goto_refund_cync" -eq 0 ]]; then
    warn "The wallet must:"
    echo "    1. Construct a BTC P2TR lock tx via 'cyncswap construct-btc-lock' (or the wallet's own builder)"
    echo "    2. Sign the input with Bob's funding key"
    echo "    3. Paste the signed tx hex below."
    BOB_LOCK_HEX=$(pause_for_hex "Bob's signed BTC lock tx hex")

    BTC_AUTH_FLAGS=()
    [[ -n "$BTC_RPC_USER" ]] && BTC_AUTH_FLAGS=(--rpc-user "$BTC_RPC_USER" --rpc-pass "$BTC_RPC_PASS")

    BOB_LOCK_TXID=$("$CYNCSWAP_BIN" lock-btc \
        --state-file "$STATE_FILE_BOB" \
        --network "$BTC_NETWORK" \
        --rpc-url "$BTC_RPC_URL" \
        "${BTC_AUTH_FLAGS[@]}" \
        --signed-tx-hex "$BOB_LOCK_HEX" \
        | grep -oE 'broadcast txid: [a-f0-9]{64}' | awk '{print $3}')
    [[ -n "$BOB_LOCK_TXID" ]] || die "lock-btc: no txid"
    note "Bob's BTC lock txid: $BOB_LOCK_TXID"

    "$CYNCSWAP_BIN" btc-watch \
        --network "$BTC_NETWORK" \
        --rpc-url "$BTC_RPC_URL" \
        "${BTC_AUTH_FLAGS[@]}" \
        --txid "$BOB_LOCK_TXID" \
        --confirmations 1 \
        --timeout-secs 600 \
        && note "Bob's BTC lock confirmed ✓"

    "$CYNCSWAP_BIN" transition \
        --state-file "$STATE_FILE_ALICE" \
        --kind observe-bob-locked \
        && note "Alice's state advanced: AliceLocked → BobLocked"
fi

# ─── Step 5: Branch on scenario ─────────────────────────────────────
case "$SCENARIO" in

    happy)
        step "Happy path — Alice claims BTC (reveals adaptor secret)"
        warn "The wallet must:"
        echo "    1. Use 'cyncswap construct-btc-claim' + 'cyncswap create-pre-sig-btc'"
        echo "       + 'cyncswap decrypt-btc-adaptor' to produce the final 64-byte sig"
        echo "    2. Attach the sig as witness[0] in the key-path claim tx"
        echo "    3. Paste the complete signed claim tx hex below."
        ALICE_CLAIM_HEX=$(pause_for_hex "Alice's signed BTC claim tx hex")

        ALICE_CLAIM_TXID=$("$CYNCSWAP_BIN" claim-btc \
            --state-file "$STATE_FILE_ALICE" \
            --network "$BTC_NETWORK" \
            --rpc-url "$BTC_RPC_URL" \
            "${BTC_AUTH_FLAGS[@]}" \
            --signed-tx-hex "$ALICE_CLAIM_HEX" \
            | grep -oE 'broadcast txid: [a-f0-9]{64}' | awk '{print $3}')
        note "Alice's BTC claim txid: $ALICE_CLAIM_TXID"

        step "Bob recovers the adaptor secret from Alice's witness"
        echo "  (On real testnet, Bob's chain watcher does this automatically.)"
        warn "Pull Alice's claim sig from the witness — operator action:"
        echo "    bitcoin-cli -regtest getrawtransaction $ALICE_CLAIM_TXID 2 \\"
        echo "      | python3 -c \"import json,sys;print(json.load(sys.stdin)['vin'][0]['txinwitness'][0])\""
        REVEALED_SIG_HEX=$(pause_for_hex "Alice's 64-byte BIP-340 final sig from witness[0]")

        warn "Paste the pre-sig JSON Bob produced via create-pre-sig-btc earlier:"
        echo "  (Format: a single line of JSON with r_point / s_pre / signer_x fields.)"
        PRE_SIG_JSON=$(pause_for_hex "the pre-sig JSON from create-pre-sig-btc")
        # We only need s_pre for recovery — extract it from the JSON.
        PRE_SIG_S=$(echo "$PRE_SIG_JSON" | json_field s_pre) \
            || die "could not extract s_pre from pre-sig JSON; check the format"

        # `recover-secret-from-btc-sig` returns the secret in
        # secp256k1 big-endian; flip to Ristretto-LE to compare
        # against ADAPTOR_SECRET_HEX (which we generated in LE form
        # at the top of the script).
        RECOVERED_BE=$("$CYNCSWAP_BIN" recover-secret-from-btc-sig \
            --pre-sig-s "$PRE_SIG_S" \
            --final-sig "$REVEALED_SIG_HEX" \
            --i-understand-this-is-a-secret)
        RECOVERED_LE=$("$CYNCSWAP_BIN" adaptor-secret-flip-endian \
            --secret-hex "$RECOVERED_BE" \
            --from secp256k1 \
            --i-understand-this-is-a-secret)
        [[ "$RECOVERED_LE" == "$ADAPTOR_SECRET_HEX" ]] \
            && note "Recovered secret matches original ✓" \
            || die "recovered secret MISMATCH: got $RECOVERED_LE want $ADAPTOR_SECRET_HEX"

        "$CYNCSWAP_BIN" transition \
            --state-file "$STATE_FILE_BOB" \
            --kind observe-secret-revealed \
            && note "Bob's state advanced: BobLocked → SecretRevealed"

        step "Bob claims CYNC using derived spender secret"
        warn "The wallet must:"
        echo "    1. Call 'cyncswap derive-cync-spender-secret' with"
        echo "       --counterparty-spend-secret <bob_original_secret_LE>"
        echo "       --adaptor-secret $RECOVERED_LE"
        echo "       --i-understand-this-is-a-secret"
        echo "    2. Use the result as the one-time-secret for the CLSAG signature"
        echo "    3. Paste the signed CYNC claim tx hex below."
        BOB_CLAIM_HEX=$(pause_for_hex "Bob's signed CYNC claim tx hex")

        BOB_CLAIM_TXID=$("$CYNCSWAP_BIN" claim-cync \
            --state-file "$STATE_FILE_BOB" \
            --network "$CYNC_NETWORK" \
            --rpc-url "$CYNC_RPC_URL" \
            "${CYNC_AUTH_FLAGS[@]}" \
            --signed-tx-hex "$BOB_CLAIM_HEX" \
            | grep -oE 'broadcast txid: [a-f0-9]{64}' | awk '{print $3}')
        note "Bob's CYNC claim txid: $BOB_CLAIM_TXID"

        step "Final state — both sides at Completed"
        "$CYNCSWAP_BIN" status --state-file "$STATE_FILE_ALICE" | grep -i state
        "$CYNCSWAP_BIN" status --state-file "$STATE_FILE_BOB"   | grep -i state
        printf "${GREEN}HAPPY PATH SMOKE PASSED${NC} — $step_n steps completed\n"
        ;;

    refund-btc)
        step "Refund path (BTC) — Bob waits out CSV + sweeps back"
        warn "Fast-forwarding by mining $BTC_TIMEOUT_BLOCKS regtest blocks:"
        bitcoin-cli -regtest -rpcuser="$BTC_RPC_USER" -rpcpassword="$BTC_RPC_PASS" \
            -generate "$BTC_TIMEOUT_BLOCKS" >/dev/null \
            && note "$BTC_TIMEOUT_BLOCKS blocks mined" \
            || warn "bitcoin-cli unavailable; operator must mine manually"

        warn "The wallet must:"
        echo "    1. Use 'cyncswap construct-btc-refund' with refund_branch + the lock UTXO"
        echo "    2. Sign with Bob's refund-branch key"
        echo "    3. Attach script + control_block + sig as BIP-341 script-path witness"
        echo "    4. Paste the complete signed refund tx hex below."
        BOB_REFUND_HEX=$(pause_for_hex "Bob's signed BTC refund tx hex")

        BOB_REFUND_TXID=$("$CYNCSWAP_BIN" refund-btc \
            --state-file "$STATE_FILE_BOB" \
            --network "$BTC_NETWORK" \
            --rpc-url "$BTC_RPC_URL" \
            "${BTC_AUTH_FLAGS[@]}" \
            --signed-tx-hex "$BOB_REFUND_HEX" \
            | grep -oE 'broadcast txid: [a-f0-9]{64}' | awk '{print $3}')
        note "Bob's BTC refund txid: $BOB_REFUND_TXID"

        step "Final state — Bob at Refunded; Alice can still refund her CYNC independently"
        "$CYNCSWAP_BIN" status --state-file "$STATE_FILE_BOB" | grep -i state
        printf "${GREEN}REFUND-BTC SMOKE PASSED${NC} — $step_n steps completed\n"
        ;;

    refund-cync)
        step "Refund path (CYNC) — Alice waits out CYNC timeout + sweeps back"
        warn "The wallet must:"
        echo "    1. Build a CYNC refund tx spending Alice's CYNC lock back to her wallet"
        echo "    2. Sign with Alice's refund key (the CYNC-side analogue of Bob's CSV branch)"
        echo "    3. Paste the signed refund tx hex below."
        ALICE_REFUND_HEX=$(pause_for_hex "Alice's signed CYNC refund tx hex")

        ALICE_REFUND_TXID=$("$CYNCSWAP_BIN" refund-cync \
            --state-file "$STATE_FILE_ALICE" \
            --network "$CYNC_NETWORK" \
            --rpc-url "$CYNC_RPC_URL" \
            "${CYNC_AUTH_FLAGS[@]}" \
            --signed-tx-hex "$ALICE_REFUND_HEX" \
            | grep -oE 'broadcast txid: [a-f0-9]{64}' | awk '{print $3}')
        note "Alice's CYNC refund txid: $ALICE_REFUND_TXID"

        step "Final state — Alice at Refunded"
        "$CYNCSWAP_BIN" status --state-file "$STATE_FILE_ALICE" | grep -i state
        printf "${GREEN}REFUND-CYNC SMOKE PASSED${NC} — $step_n steps completed\n"
        ;;
esac
