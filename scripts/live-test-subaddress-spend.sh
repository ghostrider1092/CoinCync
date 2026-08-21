#!/usr/bin/env bash
# Live regtest E2E proving W-A: a subaddress-received output is SPENDABLE.
#
# Isolates the subaddress spend so no other output can mask it:
#   1. regtest node + rig mining to wallet A (funder).
#   2. wallet C generates a subaddress S.
#   3. A sends to C's subaddress S TWICE (a consensus spend needs 2 inputs, so C
#      must hold two outputs -- both on subaddress S).
#   4. C now holds funds ONLY on subaddress S, and spends (2-in) to wallet B.
#      Every input is a subaddress output, so the spend succeeds ONLY if the
#      per-subaddress offset is threaded correctly (the W-A fix). Pre-fix the key
#      images are wrong -> the node rejects C's tx -> B never receives.
#   5. B receives  =>  subaddress output was spendable  =>  PASS.
#
# Run:  bash scripts/live-test-subaddress-spend.sh
set -uo pipefail
ROOT="/c/dev/cc-integrate"
NODE_BIN="$ROOT/target/debug/coincync-node.exe"
WALLET_BIN="$ROOT/target/debug/coincync-wallet.exe"
RIG_BIN="$ROOT/target/debug/coincync-rig.exe"
RPC="http://127.0.0.1:18081"
export COINCYNC_RANDOMX_LIGHT_MODE=1
export COINCYNC_WALLET_PASSWORD='live-test-do-not-reuse'
TMP="/c/Users/unkno/AppData/Local/Temp/cync-wa-bash-$(date +%s)"
mkdir -p "$TMP/chain"
A="$TMP/A.bin"; B="$TMP/B.bin"; C="$TMP/C.bin"
NODE_LOG="$TMP/node.log"; RIG_LOG="$TMP/rig.log"
NODE_PID=""

cleanup() { taskkill //IM coincync-rig.exe //F >/dev/null 2>&1; [ -n "$NODE_PID" ] && kill "$NODE_PID" >/dev/null 2>&1; }
trap cleanup EXIT

# The Windows light-mode rig crashes silently and intermittently (process
# vanishes mid-loop, no panic) at varying heights. It is a mining-tool
# stability issue, NOT a consensus/wallet bug -- the node persists the chain,
# so a fresh rig just resumes from the current tip. A watchdog keeps mining
# alive across those crashes for the duration of the test.
start_rig() { # requires global AADDR
  "$RIG_BIN" run-solo --node "$RPC" --address "$AADDR" --network regtest \
    --threads 4 --poll-interval-secs 3 >> "$RIG_LOG" 2>&1 &
}
ensure_rig() {
  if ! tasklist 2>/dev/null | grep -qi "coincync-rig"; then
    echo "      [watchdog] rig not running -> relaunching"; start_rig; sleep 3
  fi
}

wallet() { "$WALLET_BIN" --network regtest --wallet "$1" --node "$RPC" "${@:2}" 2>&1; }
getf() { sed -E 's/\x1b\[[0-9;]*m//g' | grep -E "^[[:space:]]*$1:" | head -1 | sed -E "s/^[[:space:]]*$1:[[:space:]]*//" | tr -d '\r' | tr -d ' '; }
# `scan` prints the REAL balance ("Balance total: <X> CYNC ..."); the `balance`
# subcommand only reads stale wallet-file state (P1). Note: total INCLUDES
# coinbase outputs still pending maturity, so it is only a "has funds" signal.
bal_cync() { wallet "$1" scan 2>&1 | sed -E 's/\x1b\[[0-9;]*m//g' | grep -E "Balance total:" | grep -oE "[0-9]+\.?[0-9]*" | head -1; }
wait_bal() { # wallet min_cync timeout_sec who
  local end=$(( $(date +%s) + $3 )) bal
  while [ "$(date +%s)" -lt "$end" ]; do
    ensure_rig
    bal=$(bal_cync "$1"); bal=${bal:-0}
    if awk -v b="$bal" -v m="$2" 'BEGIN{exit !(b+0>=m+0)}'; then echo "      OK $4 balance=$bal CYNC (>= $2)"; return 0; fi
    echo "      $4 balance=$bal CYNC / $2 ... $(( end - $(date +%s) ))s left"; sleep 12
  done
  return 1
}
# Send, RETRYING only while inputs are pending coinbase maturity (the rig keeps
# mining, so they mature). Prints the wallet output; returns 0 once it stops
# being an immaturity error (success prints "Hash:"; a node rejection prints
# reject/ERROR -- the caller inspects the output).
do_send() { # walletfile  send-args...
  # Window must cover the output-maturity wait (~10 confirmations). By this
  # point regtest ASERT difficulty has ramped up (early fast blocks pull the
  # rate toward the 120s target), so 10 blocks can take ~15 min -- size the
  # window generously so the spend isn't abandoned mid-maturity.
  local wf="$1"; shift; local end=$(( $(date +%s) + 1500 )) out
  while [ "$(date +%s)" -lt "$end" ]; do
    ensure_rig
    wallet "$wf" scan >/dev/null 2>&1
    out=$(wallet "$wf" send "$@")
    if echo "$out" | grep -qiE "pending maturity|not yet spendable"; then sleep 12; continue; fi
    printf '%s\n' "$out"; return 0
  done
  printf '%s\n' "$out"; return 1
}
node_height() { curl -s -m 3 -X POST "$RPC" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_info","params":[]}' 2>/dev/null | grep -oE '"height":[0-9]+' | grep -oE '[0-9]+'; }
wait_height() { # min_height timeout_sec
  local end=$(( $(date +%s) + $2 )) h
  while [ "$(date +%s)" -lt "$end" ]; do
    ensure_rig
    h=$(node_height); h=${h:-0}
    if [ "$h" -ge "$1" ]; then echo "      OK chain height=$h (>= $1)"; return 0; fi
    echo "      chain height=$h / $1 (need outputs for ring decoys) ... $(( end - $(date +%s) ))s left"; sleep 8
  done
  return 1
}

echo "=== W-A LIVE TEST (bash): subaddress receive -> spend (regtest) ==="
echo "  workspace: $TMP"

echo "[1] starting regtest node..."
"$NODE_BIN" --network regtest --data-dir "$TMP/chain" --log-level info > "$NODE_LOG" 2>&1 &
NODE_PID=$!
up=0
for i in $(seq 1 30); do
  if curl -s -m 3 -X POST "$RPC" -H "Content-Type: application/json" \
       -d '{"jsonrpc":"2.0","id":1,"method":"get_info","params":[]}' 2>/dev/null | grep -q '"regtest"'; then up=1; break; fi
  sleep 2
done
[ "$up" = 1 ] && echo "      OK node up (regtest)" || { echo "FAIL: node RPC did not come up"; exit 1; }

echo "[2] creating wallets A (funder), C (subaddr holder), B (final)..."
wallet "$A" create --force >/dev/null 2>&1
wallet "$B" create --force >/dev/null 2>&1
wallet "$C" create --force >/dev/null 2>&1
AADDR=$(wallet "$A" address | getf "Address")
BOUT=$(wallet "$B" address)
BSPEND=$(echo "$BOUT" | getf "Spend public")
BVIEW=$(echo "$BOUT" | getf "View public")
CSUB=$(wallet "$C" subaddress create --account 0 --label live)
SSPEND=$(echo "$CSUB" | getf "Spend public")
SVIEW=$(echo "$CSUB" | getf "View public")
echo "      A=${AADDR:0:18}.. Bspend=${BSPEND:0:14}.. Ssub=${SSPEND:0:14}.."
[ -n "$AADDR" ] && [ -n "$BSPEND" ] && [ -n "$BVIEW" ] && [ -n "$SSPEND" ] && [ -n "$SVIEW" ] \
  || { echo "FAIL: could not parse addresses/pubkeys"; exit 1; }

echo "[3] mining to A (rig, light-mode; watchdog restarts it if it crashes)..."
start_rig
# Grace: let the rig build its RandomX cache (~2-3s) and register in the
# process table before any ensure_rig check, so the watchdog doesn't race
# startup and spawn a spurious second rig.
for i in $(seq 1 15); do tasklist 2>/dev/null | grep -qi "coincync-rig" && break; sleep 1; done
wait_bal "$A" 100 600 "A" || { echo "FAIL: A never accrued a balance"; exit 1; }
# A ring spend selects real chain outputs as decoys (~126 needed), so mine until
# the chain has enough mature outputs before attempting any send.
wait_height 150 800 || { echo "FAIL: chain did not reach enough outputs for ring decoys"; exit 1; }

echo "[4] A -> C.subaddress (x2, 5 CYNC each; retries past coinbase maturity)..."
for i in 1 2; do
  out=$(do_send "$A" --to-spend "$SSPEND" --to-view "$SVIEW" --amount 5000000000000 --subaddress)
  echo "$out" >> "$TMP/A.send$i.log"
  if ! echo "$out" | grep -qE "Hash:"; then echo "FAIL: A send #$i did not build/submit:"; echo "$out" | tail -4; exit 1; fi
  echo "      OK A send #$i to C.subaddress (built + submitted)"; sleep 10
done

echo "[5] waiting for C to receive both subaddress outputs..."
wait_bal "$C" 9.5 480 "C" || { echo "FAIL: C did not receive both subaddress outputs"; exit 1; }

echo "[6] C spends its SUBADDRESS outputs -> B (1 CYNC; the W-A spend)..."
out=$(do_send "$C" --to-spend "$BSPEND" --to-view "$BVIEW" --amount 1000000000000)
echo "$out" >> "$TMP/C.send.log"
if echo "$out" | grep -qiE "reject"; then echo "FAIL: C subaddress-spend REJECTED (W-A broken?):"; echo "$out" | tail -6; exit 1; fi
if ! echo "$out" | grep -qE "Hash:"; then echo "FAIL: C subaddress-spend did not build/submit:"; echo "$out" | tail -6; exit 1; fi
echo "      OK C subaddress-spend built + submitted"

echo "[7] waiting for B to receive (proves the subaddress output was spendable)..."
wait_bal "$B" 0.9 900 "B" || { echo "FAIL: B never received C's spend of the subaddress output"; exit 1; }

echo ""
echo "PASS - a subaddress-received output was received AND spent on-chain (W-A verified live)."
echo "  artifacts: $TMP"
exit 0
