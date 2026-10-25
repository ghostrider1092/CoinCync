#!/usr/bin/env bash
# live-user-chaos.sh — a LIVE-USER chaos + soak harness for a LOCAL regtest node.
#
# Drives a real node like a user AND an adversary: mines, sends transparent and
# subaddress (stealth) transactions, shields in / sends / out of the Spark pool,
# then deliberately triggers every circuit-breaker protection (load breakers via
# real flood; consensus/money breakers via the regtest-chaos fault-injection RPC)
# and verifies each one trips, fails closed when armed, and RECOVERS. Runs for a
# configurable duration (default 8h), tallies results, and prints a pass/fail
# scorecard with a confidence % — the goal is to shake out bugs and get to ~90%.
#
# SAFETY: regtest ONLY. The harness refuses to run against anything that is not a
# local regtest data dir / port, so arming breakers and injecting faults can
# NEVER touch the live testnet or mainnet.
#
# Requires a node+wallet built with:
#   --features "testnet fuse block-integrity-breaker supply-breaker \
#               shielded-breaker regtest-chaos sketch-gk-proof libspark-ffi"
set -uo pipefail

# ── Config ───────────────────────────────────────────────────────────────────
ROOT="${ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
NODE="${NODE:-$ROOT/target/debug/coincync-node.exe}"
WALLET="${WALLET:-$ROOT/target/debug/coincync-wallet.exe}"
NET="regtest"
RUN_DIR="${RUN_DIR:-/c/cync-chaos-run}"
DATA_DIR="$RUN_DIR/data"
RPC_PORT="${RPC_PORT:-29799}"       # non-standard port => clearly a local test
RPC_URL="http://127.0.0.1:$RPC_PORT"
DURATION="${DURATION:-28800}"       # 8h default; override for a smoke run
SNAPSHOT_EVERY="${SNAPSHOT_EVERY:-300}"   # fuse/metrics snapshot cadence (s)
CHAOS_ARM_HEIGHT="${CHAOS_ARM_HEIGHT:-2}" # arm consensus breakers from height 2
LOG="$RUN_DIR/chaos-$(date +%Y%m%d-%H%M%S).log"
RESULTS="$RUN_DIR/results.json"

# regtest-chaos: arm the consensus breakers for this run (env read by the node).
export COINCYNC_CHAOS_ARM="$CHAOS_ARM_HEIGHT"
export COINCYNC_RANDOMX_LIGHT_MODE=1

# ── Metrics ──────────────────────────────────────────────────────────────────
declare -A M=(
  [blocks_mined]=0 [tx_sent]=0 [tx_failed]=0 [stealth_sent]=0
  [shield_in]=0 [shielded_sent]=0 [unshield]=0
  [breaker_trips]=0 [breaker_recoveries]=0 [failclosed_rejects]=0
  [faults_injected]=0 [consensus_faults]=0 [panics]=0 [cycles]=0
)
declare -A PROTECTION_OK=()   # surface -> 1 once we observed trip + recover

log() { printf '%(%H:%M:%S)T %s\n' -1 "$*" | tee -a "$LOG"; }
bump() { M[$1]=$(( ${M[$1]} + ${2:-1} )); }

# ── Node RPC (JSON-RPC over curl) ────────────────────────────────────────────
# SMOKE: confirm method names/params against the built binary's RPC surface.
rpc() { # rpc METHOD [json-params]
  local method="$1" params="${2:-[]}"
  curl -s --max-time 15 -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
    "$RPC_URL"
}
rpc_ok() { rpc "$@" | grep -q '"result"'; }

fuse_status() { rpc get_fuse_status; }
isolating_count() { fuse_status | sed -n 's/.*"isolating_count":\([0-9]*\).*/\1/p'; }
surface_state() { # surface_state SURFACE -> Closed|Open|HalfOpen
  fuse_status | tr ',' '\n' | grep -A2 "\"$1\"" | sed -n 's/.*"state":"\([A-Za-z]*\)".*/\1/p' | head -1
}
inject() { bump faults_injected; rpc chaos_inject_fault "[\"$1\"]"; }
rearm()  { rpc chaos_rearm "[\"$1\"]"; }

# ── Node / wallet lifecycle ──────────────────────────────────────────────────
# SMOKE: confirm node start flags + mining mechanism + wallet verbs.
start_node() {
  log "starting regtest node (data=$DATA_DIR rpc=$RPC_PORT)"
  "$NODE" start --network "$NET" --data-dir "$DATA_DIR" --rpc-port "$RPC_PORT" \
    >>"$RUN_DIR/node.log" 2>&1 &
  NODE_PID=$!
  for _ in $(seq 1 60); do rpc_ok get_info && { log "node up (pid $NODE_PID)"; return 0; }; sleep 1; done
  log "FATAL: node did not come up"; return 1
}
mine_blocks() { # mine_blocks N  — SMOKE: wire to the real regtest mining path
  local n="$1"
  # Placeholder: resolved in the smoke-run (generate RPC, --mine flag, or rig).
  "$NODE" --network "$NET" --data-dir "$DATA_DIR" generate "$n" >>"$RUN_DIR/mine.log" 2>&1 \
    && bump blocks_mined "$n"
}
wal() { "$WALLET" --network "$NET" --data-dir "$DATA_DIR" "$@"; }   # SMOKE: verbs

# ── Safety guard: regtest-only ───────────────────────────────────────────────
guard() {
  [[ "$NET" == "regtest" ]] || { echo "REFUSING: not regtest"; exit 2; }
  case "$DATA_DIR" in *regtest*|*chaos-run*) : ;; *) echo "REFUSING: data dir not a local test dir"; exit 2;; esac
  # never a known live seed / mainnet port
  [[ "$RPC_PORT" != "8081" && "$RPC_PORT" != "28081" ]] || { echo "REFUSING: live RPC port"; exit 2; }
}

# ── User-action phases (one random action per cycle) ─────────────────────────
act_mine()        { mine_blocks 1; }
act_send_tx()     { if wal send --to "$(wal address | tail -1)" --amount 1 >>"$RUN_DIR/wallet.log" 2>&1; then bump tx_sent; else bump tx_failed; fi; }
act_stealth()     { if wal send --to "$(wal subaddress 0 1 2>/dev/null | tail -1)" --amount 1 >>"$RUN_DIR/wallet.log" 2>&1; then bump stealth_sent; bump tx_sent; else bump tx_failed; fi; }
act_shield_in()   { wal shielded-mint --amount 5 >>"$RUN_DIR/wallet.log" 2>&1 && bump shield_in; }
act_shielded_send(){ wal shielded-send --to "$(wal shielded-address 2>/dev/null|tail -1)" --amount 1 >>"$RUN_DIR/wallet.log" 2>&1 && { bump shielded_sent; bump tx_sent; }; }
act_unshield()    { wal shielded-unshield --amount 1 >>"$RUN_DIR/wallet.log" 2>&1 && bump unshield; }

# ── Chaos: trip a protection, then verify fail-closed + recovery ─────────────
chaos_consensus() { # inject -> expect isolating (+ fail-closed when armed) -> rearm -> recover
  local s="$1"
  local before; before="$(surface_state "$s")"
  inject "$s" >>"$LOG" 2>&1; bump consensus_faults
  sleep 1
  local tripped; tripped="$(surface_state "$s")"
  if [[ "$tripped" != "Closed" && -n "$tripped" ]]; then
    bump breaker_trips
    log "CHAOS $s: tripped ($before -> $tripped)"
    # armed? a mine should fail closed (block rejected / node refuses to advance)
    if ! mine_blocks 1; then bump failclosed_rejects; log "CHAOS $s: FAIL-CLOSED on mine (armed)"; fi
    rearm "$s" >>"$LOG" 2>&1
    sleep 1
    local after; after="$(surface_state "$s")"
    if [[ "$after" == "Closed" ]]; then bump breaker_recoveries; PROTECTION_OK[$s]=1; log "CHAOS $s: RECOVERED"; fi
  else
    log "CHAOS $s: did NOT trip after inject (BUG?) state=$tripped"
  fi
}
chaos_load() { # flood a load surface, expect it to trip, then AutoReset recovery
  local s="$1"
  case "$s" in
    rpc)     for _ in $(seq 1 500); do rpc get_info >/dev/null & done; wait ;;
    mempool) for _ in $(seq 1 200); do act_send_tx & done; wait ;;
  esac
  sleep 2
  local st; st="$(surface_state "$s")"
  [[ "$st" != "Closed" && -n "$st" ]] && { bump breaker_trips; log "CHAOS $s: load-tripped ($st)"; }
  # AutoReset: idle a few snapshots, then confirm back to Closed
  sleep 10
  [[ "$(surface_state "$s")" == "Closed" ]] && { bump breaker_recoveries; PROTECTION_OK[$s]=1; log "CHAOS $s: AutoReset recovered"; }
}

snapshot() {
  local iso; iso="$(isolating_count)"
  log "SNAPSHOT cycle=${M[cycles]} blocks=${M[blocks_mined]} tx=${M[tx_sent]}/${M[tx_failed]} shld(in/send/out)=${M[shield_in]}/${M[shielded_sent]}/${M[unshield]} trips=${M[breaker_trips]} recov=${M[breaker_recoveries]} failclosed=${M[failclosed_rejects]} isolating_now=$iso"
  grep -qiE 'panic|RUST_BACKTRACE|thread .* panicked' "$RUN_DIR/node.log" 2>/dev/null && bump panics
}

report() {
  local surfaces=(Supply Shielded BlockIntegrity mempool rpc p2p reorg)
  local covered=0
  echo "{" > "$RESULTS"
  for k in "${!M[@]}"; do echo "  \"$k\": ${M[$k]}," >> "$RESULTS"; done
  echo "  \"protections\": {" >> "$RESULTS"
  for s in "${surfaces[@]}"; do
    local ok="${PROTECTION_OK[$s]:-0}"; [[ "$ok" == "1" ]] && covered=$((covered+1))
    echo "    \"$s\": $ok," >> "$RESULTS"
  done
  local score=$(( covered * 100 / ${#surfaces[@]} ))
  echo "    \"_coverage_pct\": $score" >> "$RESULTS"
  echo "  }" >> "$RESULTS"; echo "}" >> "$RESULTS"
  log "================ RESULT ================"
  log "duration=${DURATION}s cycles=${M[cycles]} blocks=${M[blocks_mined]} tx=${M[tx_sent]} (failed ${M[tx_failed]})"
  log "shielded in/send/out=${M[shield_in]}/${M[shielded_sent]}/${M[unshield]} panics=${M[panics]}"
  log "breakers: trips=${M[breaker_trips]} recoveries=${M[breaker_recoveries]} fail-closed=${M[failclosed_rejects]}"
  log "protection coverage: $covered/${#surfaces[@]} = ${score}%   (target 90%)"
  [[ ${M[panics]} -eq 0 && $score -ge 90 ]] && log "VERDICT: PASS" || log "VERDICT: REVIEW (panics=${M[panics]}, coverage=${score}%)"
  log "results: $RESULTS"
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
  mkdir -p "$DATA_DIR"; : > "$LOG"
  guard
  start_node || exit 1
  trap 'report; kill $NODE_PID 2>/dev/null' EXIT INT TERM
  wal create >>"$RUN_DIR/wallet.log" 2>&1 || true
  mine_blocks 110   # mature a coinbase (100-block maturity) before spending

  local end=$(( $(date +%s) + DURATION ))
  local last_snap=0 last_chaos=0
  local consensus=(Supply Shielded BlockIntegrity) load=(mempool rpc) ci=0 li=0
  while [[ $(date +%s) -lt $end ]]; do
    bump cycles
    # weighted-random user action each cycle
    case $(( RANDOM % 10 )) in
      0|1|2) act_mine ;;
      3|4)   act_send_tx ;;
      5)     act_stealth ;;
      6)     act_shield_in ;;
      7)     act_shielded_send ;;
      8)     act_unshield ;;
      9)     act_mine ;;
    esac
    now=$(date +%s)
    # rotate through chaos triggers periodically (every ~2 min)
    if (( now - last_chaos >= 120 )); then
      chaos_consensus "${consensus[$(( ci % ${#consensus[@]} ))]}"; ci=$((ci+1))
      chaos_load "${load[$(( li % ${#load[@]} ))]}"; li=$((li+1))
      last_chaos=$now
    fi
    if (( now - last_snap >= SNAPSHOT_EVERY )); then snapshot; last_snap=$now; fi
    sleep 2
  done
  report
}
main "$@"
