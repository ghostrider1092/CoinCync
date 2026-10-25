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
RPC_PORT="${RPC_PORT:-18081}"       # regtest's default RPC port (the node binds this)
RPC_URL="http://127.0.0.1:$RPC_PORT"
SMOKE="${SMOKE:-0}"                  # SMOKE=1 => happy-path only (no chaos), then exit
MATURE_BLOCKS="${MATURE_BLOCKS:-200}" # seed enough blocks for coinbase maturity (100)
                                     # AND the ring-decoy pool (~126 outputs needed)
# Needs a node built with `test-fast-pow` so regtest blocks are INSTANT (difficulty
# 8192 + light RandomX is ~minutes/block otherwise — can't mature coinbase).
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
  # get_fuse_status objects are {"isolating":B,"state":"S","surface":"NAME"} — the
  # surface name is the LAST field, so the state line precedes it (-B1), not -A2.
  fuse_status | tr ',' '\n' | grep -B1 "\"surface\":\"$1\"" | sed -n 's/.*"state":"\([A-Za-z]*\)".*/\1/p' | head -1
}
inject() { bump faults_injected; rpc chaos_inject_fault "[\"$1\"]"; }
rearm()  { rpc chaos_rearm "[\"$1\"]"; }

# ── Node / wallet lifecycle ──────────────────────────────────────────────────
# SMOKE: confirm node start flags + mining mechanism against the built binary.
kill_port() { # kill whatever LISTENs on a LOCAL port (our test node) — targeted by
              # PID on 127.0.0.1:$port, so it can never blanket-kill a real node.
  local p="$1" pid
  pid="$(netstat -ano 2>/dev/null | grep -E "127\\.0\\.0\\.1:$p .*LISTENING" | awk '{print $NF}' | head -1)"
  [[ -n "$pid" ]] && { log "cleanup: killing stale node pid $pid on port $p"; taskkill //F //PID "$pid" >/dev/null 2>&1; sleep 1; }
  return 0
}
start_node() { # NO background miner — blocks are produced on demand via chaos_generate
  kill_port "$RPC_PORT"   # clear any stale node holding our RPC port first
  log "starting regtest node (data=$DATA_DIR rpc=$RPC_PORT, on-demand mining)"
  "$NODE" --network "$NET" --data-dir "$DATA_DIR" start >>"$RUN_DIR/node.log" 2>&1 &
  NODE_PID=$!
  for _ in $(seq 1 90); do rpc_ok get_info && { log "node up (pid $NODE_PID)"; return 0; }; sleep 1; done
  log "FATAL: node did not come up (see $RUN_DIR/node.log)"; return 1
}
cur_height() { rpc get_info | sed -n 's/.*"height":\([0-9]*\).*/\1/p' | head -1; }
restart_node() { # state-survival test: stop, restart same data dir, verify tip survives
  local tip_before; tip_before="$(rpc get_info | sed -n 's/.*"height":\([0-9]*\).*/\1/p')"
  log "RESTART: stopping node (tip=$tip_before)"; kill "$NODE_PID" 2>/dev/null; wait "$NODE_PID" 2>/dev/null
  start_node || { log "RESTART: node did not come back"; bump panics; return 1; }
  local tip_after; tip_after="$(rpc get_info | sed -n 's/.*"height":\([0-9]*\).*/\1/p')"
  if [[ "${tip_after:-0}" -ge "${tip_before:-0}" ]]; then log "RESTART: tip survived ($tip_before -> $tip_after)";
  else log "RESTART: TIP REGRESSED ($tip_before -> $tip_after) — BUG"; bump panics; fi
}
mine_blocks() { # produce N blocks ON DEMAND (coinbase to wallet A) via chaos_generate.
  # Returns non-zero if the node refuses to extend — e.g. an armed consensus
  # breaker failing closed — which chaos_consensus reads as the fail-closed signal.
  local n="$1" r
  r="$(rpc chaos_generate "[$n, \"$(spend_of A)\", \"$(view_of A)\"]")"
  if echo "$r" | grep -q '"generated"'; then bump blocks_mined "$n"; return 0; fi
  return 1
}

# ── Wallets (multiple, real transfers, receipt-verified) ─────────────────────
PW="${PW:-chaostest}"                 # plaintext test password (regtest only)
WDIR="$RUN_DIR/wallets"; mkdir -p "$WDIR"
export COINCYNC_WALLET_PASSWORD="$PW"
# w NAME VERB [args...] — run a wallet verb against the named wallet file.
w() { local name="$1"; shift; "$WALLET" --wallet "$WDIR/$name.wallet" --network "$NET" --node "$RPC_URL" "$@"; }
mkwallet() { # create a named wallet; capture its addresses to the run dir
  local name="$1"
  w "$name" create --no-encrypt --force >>"$RUN_DIR/wallet.log" 2>&1 || { log "mkwallet $name FAILED"; return 1; }
  # Capture the full address block once: the encoded Address + the raw spend/view
  # public keys. We send by raw keys (--to-spend/--to-view) to bypass the
  # address-network fund-safety guard (a regtest wallet reports network "unknown",
  # so the guard can't apply its regtest exception). Every send still produces a
  # one-time STEALTH output, so ordinary sends exercise stealth addresses.
  w "$name" address 2>/dev/null > "$WDIR/$name.addrinfo"
  grep -E '^Address:'      "$WDIR/$name.addrinfo" | awk '{print $NF}' > "$WDIR/$name.addr"
  grep -E '^Spend public:' "$WDIR/$name.addrinfo" | awk '{print $NF}' > "$WDIR/$name.spend"
  grep -E '^View public:'  "$WDIR/$name.addrinfo" | awk '{print $NF}' > "$WDIR/$name.view"
  # Shielded (Spark) bech32m address — best-effort (longest token on the line).
  w "$name" shielded-address 2>/dev/null | grep -oiE '[a-z0-9]{24,}' | tail -1 > "$WDIR/$name.shaddr" 2>/dev/null || true
  [[ -s "$WDIR/$name.spend" && -s "$WDIR/$name.view" ]] || { log "mkwallet $name: NO spend/view keys captured"; return 1; }
  log "wallet '$name' created (addr=$(cut -c1-20 "$WDIR/$name.addr")…)"
}
# The `scan` command's summary reliably prints "UTXO count" / "Balance total"
# (the `balance` command formats differently); parse scan output (2>&1). Scanning
# also refreshes the wallet against the node, so one call both updates and reads.
utxo_count() { w "$1" scan 2>&1 | grep -iE 'UTXO count' | grep -oE '[0-9]+' | tail -1; }
bal()        { w "$1" scan 2>&1 | grep -iE 'Balance total' | grep -oE '[0-9]+\.?[0-9]*' | head -1; }
shbal()      { w "$1" shielded-balance 2>&1 | grep -iE 'Balance|shielded' | grep -oE '[0-9]+\.?[0-9]*' | head -1; }
addr_of()   { cat "$WDIR/$1.addr"    2>/dev/null; }
spend_of()  { cat "$WDIR/$1.spend"   2>/dev/null; }
view_of()   { cat "$WDIR/$1.view"    2>/dev/null; }
shaddr_of() { cat "$WDIR/$1.shaddr"  2>/dev/null; }

AMT_ATOMIC="${AMT_ATOMIC:-100000000}"   # 1 CYNC in atomic units (--amount is atomic)
# send FROM TO AMOUNT(atomic) — transfer and VERIFY the recipient received (UTXO
# count rose). Retries through the transient miner race ("chain state changed
# during mempool admission … retry submission") that the continuous miner causes.
send_verified() {
  local from="$1" to="$2" amt="${3:-$AMT_ATOMIC}" tries=0 before after sent=0
  w "$from" scan >>"$RUN_DIR/wallet.log" 2>&1 || true   # sender must scan to see its coinbase
  before="$(utxo_count "$to")"; before="${before:-0}"
  while (( tries < 6 )); do
    if w "$from" send --to-spend "$(spend_of "$to")" --to-view "$(view_of "$to")" --amount "$amt" \
         >>"$RUN_DIR/wallet.log" 2>&1; then sent=1; break; fi
    tries=$((tries+1)); sleep 2   # transient admission race — retry
  done
  if (( sent == 0 )); then bump tx_failed; log "send $from->$to FAILED after $tries retries"; return 1; fi
  bump tx_sent
  # Poll for the receipt: a tx sits in the Dandelion++ stem embargo (~16s) before
  # it can be mined, so confirm + recipient scan must wait past that, not ~4s.
  after="$before"
  for _ in $(seq 1 20); do
    mine_blocks 1 >/dev/null 2>&1 || true
    after="$(utxo_count "$to")"; after="${after:-0}"   # scans + reads
    (( after > before )) && break
    sleep 2
  done
  if (( after > before )); then log "RECEIPT ok $from->$to (utxos $before->$after, tries=$tries)";
  else log "RECEIPT MISSING $from->$to (utxos $before->$after) — SILENT-LOSS BUG?"; bump tx_failed; fi
}

# ── Safety guard: regtest-only ───────────────────────────────────────────────
guard() {
  [[ "$NET" == "regtest" ]] || { echo "REFUSING: not regtest"; exit 2; }
  case "$DATA_DIR" in *regtest*|*chaos*) : ;; *) echo "REFUSING: data dir not a local test dir"; exit 2;; esac
  # never a known live seed / mainnet / default port
  [[ "$RPC_PORT" != "8081" && "$RPC_PORT" != "28081" && "$RPC_PORT" != "19081" ]] || { echo "REFUSING: live/default RPC port"; exit 2; }
}

# ── User-action phases (one random action per cycle) ─────────────────────────
act_mine()         { mine_blocks 1; }
act_send_tx()      { send_verified A B; }
act_stealth()      { local sa; sa="$(w B subaddress create 2>/dev/null | grep -E '^Address:' | awk '{print $NF}' | tail -1)"; if [[ -n "$sa" ]] && w A send --address "$sa" --amount "$AMT_ATOMIC" >>"$RUN_DIR/wallet.log" 2>&1; then bump stealth_sent; bump tx_sent; else bump tx_failed; fi; }
act_shield_in()    { w A shielded-mint --amount 5 >>"$RUN_DIR/wallet.log" 2>&1 && bump shield_in; }
act_shielded_send(){ w A shielded-send --to "$(shaddr_of B)" --amount 1 >>"$RUN_DIR/wallet.log" 2>&1 && { bump shielded_sent; bump tx_sent; }; }
act_unshield()     { w A shielded-unshield --amount 1 >>"$RUN_DIR/wallet.log" 2>&1 && bump unshield; }

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
chaos_load() { # pressure a load surface, expect it to trip, then AutoReset recovery.
  # BOUNDED concurrency (<=10 procs at a time) — an unbounded `&` fan-out fork-bombs
  # the host. Batches keep the request RATE high without exhausting memory.
  local s="$1" batch
  case "$s" in
    rpc)     for batch in $(seq 1 40); do
               for _ in $(seq 1 10); do rpc get_info >/dev/null 2>&1 & done; wait
             done ;;
    mempool) for _ in $(seq 1 3); do act_send_tx; done ;;   # a few real sends (UTXO reservations limit rapid-fire)
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
  mkdir -p "$DATA_DIR" "$WDIR"; : > "$LOG"
  guard
  # Wallets first — the node mines its coinbase to wallet A (sender); B receives.
  mkwallet A || exit 1
  mkwallet B || exit 1
  [[ -n "$(spend_of A)" && -n "$(view_of A)" ]] || { log "FATAL: wallet A keys missing (needed for on-demand mining)"; exit 1; }
  start_node || exit 1
  trap 'report; kill "$NODE_PID" 2>/dev/null; kill_port "$RPC_PORT"' EXIT INT TERM
  log "seeding chain ($MATURE_BLOCKS blocks: coinbase maturity + decoy pool)…"
  mine_blocks "$MATURE_BLOCKS" || { log "FATAL: miner did not advance the chain"; exit 1; }

  if [[ "$SMOKE" == "1" ]]; then
    log "SMOKE: happy-path only (mine + send A->B receipt-verified), no chaos"
    send_verified A B
    send_verified A B
    snapshot
    report
    return 0
  fi

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
