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
CHAOS_EVERY="${CHAOS_EVERY:-120}"         # how often (s) to rotate a breaker trigger
SHIELDED_EVERY="${SHIELDED_EVERY:-90}"    # how often (s) to run a full shielded round-trip
UNSHIELD_EVERY="${UNSHIELD_EVERY:-150}"   # how often (s) to run a pool EXIT (shield-in -> unshield)
CHAOS_ARM_HEIGHT="${CHAOS_ARM_HEIGHT:-2}" # arm consensus breakers from height 2
LOG="$RUN_DIR/chaos-$(date +%Y%m%d-%H%M%S).log"
RESULTS="$RUN_DIR/results.json"

# regtest-chaos: arm the consensus breakers for this run (env read by the node).
export COINCYNC_CHAOS_ARM="$CHAOS_ARM_HEIGHT"
export COINCYNC_RANDOMX_LIGHT_MODE=1

# ── Metrics ──────────────────────────────────────────────────────────────────
declare -A M=(
  [blocks_mined]=0 [tx_sent]=0 [tx_failed]=0 [stealth_sent]=0
  [shield_in]=0 [shielded_sent]=0 [shielded_recv_ok]=0 [unshield]=0
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
  local killed=0
  # Kill EVERY listener on the port, not just the first — a lingering node from a
  # prior run on the same port makes our node bind-fail and we then talk to the
  # stale one (wrong data dir → "miner did not advance"). sort -u dedups.
  for pid in $(netstat -ano 2>/dev/null | grep -E "127\\.0\\.0\\.1:$p .*LISTENING" | awk '{print $NF}' | sort -u); do
    log "cleanup: killing stale node pid $pid on port $p"; taskkill //F //PID "$pid" >/dev/null 2>&1; killed=1
  done
  [[ $killed = 1 ]] && sleep 1
  return 0
}
start_node() { # NO background miner — blocks are produced on demand via chaos_generate
  kill_port "$RPC_PORT"   # clear any stale node holding our RPC port first
  log "starting regtest node (data=$DATA_DIR rpc=$RPC_PORT, on-demand mining)"
  "$NODE" --network "$NET" --data-dir "$DATA_DIR" start >>"$RUN_DIR/node.log" 2>&1 &
  NODE_PID=$!
  # RandomX dataset init on a fresh data dir is slow — much slower on a release
  # build than debug — so the readiness window is configurable (NODE_WAIT polls).
  for _ in $(seq 1 "${NODE_WAIT:-90}"); do rpc_ok get_info && { log "node up (pid $NODE_PID)"; return 0; }; sleep 1; done
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
# Parse the owned shielded balance (atomic). Match the "Balance:" line ONLY (with
# the colon) — the header "Shielded balance (anchor height N)" has no colon, so
# this won't grab the anchor height by mistake.
shbal()      { w "$1" shielded-balance 2>&1 | grep -E 'Balance:' | grep -oE '[0-9]+' | head -1; }
addr_of()   { cat "$WDIR/$1.addr"    2>/dev/null; }
spend_of()  { cat "$WDIR/$1.spend"   2>/dev/null; }
view_of()   { cat "$WDIR/$1.view"    2>/dev/null; }
shaddr_of() { cat "$WDIR/$1.shaddr"  2>/dev/null; }

AMT_ATOMIC="${AMT_ATOMIC:-100000000}"   # 1 CYNC in atomic units (--amount is atomic)
SHIELD_NOTE_ATOMIC="${SHIELD_NOTE_ATOMIC:-210000000}" # 2.1 CYNC per shield-in note
SHIELDED_SEND_ATOMIC="${SHIELDED_SEND_ATOMIC:-200000000}" # 2.0 CYNC sent (0.1 fee, no large remainder)
EMBARGO_WAIT="${EMBARGO_WAIT:-15}"   # wait out the Dandelion stem embargo before mining a shielded tx
                                     # (single-node regtest fluffs via the no-relay-peer fail-safe ~6s)
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
# STEALTH / SUBADDRESS RECEIVE: generate a fresh unlinkable subaddress on B and
# pay it from A, then VERIFY B recovered it. Two things the old one-liner got
# wrong (both made stealth_sent stick at 0 for the whole soak):
#   1. it sent via `--address <encoded subaddr>`, which the wallet's recipient
#      network guard REFUSES on a regtest wallet ("--address is a testnet
#      address but this wallet is unknown; refusing to send") — every other send
#      in this harness deliberately uses raw --to-spend/--to-view for this reason.
#   2. a subaddress payment needs the `--subaddress` flag so the sender derives
#      the one-time output against the subaddress view key; without it the
#      recipient cannot detect/spend the output.
# `subaddress create` prints the raw Spend/View public keys alongside the encoded
# address — parse those and send by raw keys + --subaddress, mirroring the verified
# transparent-send path so a silent non-receipt is caught, not counted as success.
act_stealth() {
  local out sp vp before after tries=0 sent=0
  out="$(w B subaddress create 2>/dev/null)"
  sp="$(echo "$out" | grep -E '^ *Spend public:' | awk '{print $NF}' | tail -1)"
  vp="$(echo "$out" | grep -E '^ *View public:'  | awk '{print $NF}' | tail -1)"
  if [[ -z "$sp" || -z "$vp" ]]; then bump tx_failed; log "stealth: subaddress create gave no keys"; return 1; fi
  w A scan >>"$RUN_DIR/wallet.log" 2>&1 || true
  before="$(utxo_count B)"; before="${before:-0}"
  while (( tries < 6 )); do
    if w A send --to-spend "$sp" --to-view "$vp" --subaddress --amount "$AMT_ATOMIC" \
         >>"$RUN_DIR/wallet.log" 2>&1; then sent=1; break; fi
    tries=$((tries+1)); sleep 2
  done
  if (( sent == 0 )); then bump tx_failed; log "stealth A->B(sub) FAILED after $tries retries"; return 1; fi
  bump tx_sent
  after="$before"
  for _ in $(seq 1 20); do
    mine_blocks 1 >/dev/null 2>&1 || true
    after="$(utxo_count B)"; after="${after:-0}"
    (( after > before )) && break
    sleep 2
  done
  if (( after > before )); then bump stealth_sent; log "RECEIPT ok stealth A->B(sub) (utxos $before->$after, tries=$tries)";
  else bump tx_failed; log "RECEIPT MISSING stealth A->B(sub) (utxos $before->$after) — subaddress not recovered?"; fi
}
# SHIELD-IN (transparent → Spark pool): VALIDATED end-to-end on the regtest test
# bridge — the mint is admitted, mined, applied to the pool, and A recovers the
# owned note. Each call shields a fresh note (needs mature transparent coinbase,
# which the mine actions provide). Confirmation happens on the next act_mine.
act_shield_in()    { if w A shielded-mint --amount "$SHIELD_NOTE_ATOMIC" >>"$RUN_DIR/wallet.log" 2>&1; then bump shield_in; fi; }
# SHIELDED ROUND-TRIP (shield-in -> shielded-send -> receipt), VALIDATED end-to-end
# with the Option-B miner-paid fee model (value_balance == tx.fee == bundle fee):
# shield a fresh note, mine it in (after the Dandelion embargo), shielded-send it to
# B, mine, and VERIFY B's owned shielded balance rose by the sent amount. Spent-note
# exclusion (coin_ltag + is_spark_pool_tag_spent) keeps the sender from re-picking a
# spent note, so this is safe to repeat. Self-contained so it reliably exercises the
# whole shielded user-path each time it fires (rather than racing the random loop).
act_shielded_roundtrip(){
  local b0 b1
  b0="$(shbal B)"; b0="${b0:-0}"
  # Scan A first: shielded-mint spends A's transparent UTXOs but does NOT auto-scan,
  # so without a prior scan the wallet sees "have 0" and the shield-in fails. (This
  # silently breaks the shielded path early in a run, before any transparent send
  # has scanned A.)
  w A scan >>"$RUN_DIR/wallet.log" 2>&1 || true
  if w A shielded-mint --amount "$SHIELD_NOTE_ATOMIC" >>"$RUN_DIR/wallet.log" 2>&1; then bump shield_in; else bump tx_failed; return; fi
  sleep "$EMBARGO_WAIT"; mine_blocks 2 >/dev/null
  if w A shielded-send --to "$(shaddr_of B)" --amount "$SHIELDED_SEND_ATOMIC" >>"$RUN_DIR/wallet.log" 2>&1; then
    sleep "$EMBARGO_WAIT"; mine_blocks 2 >/dev/null
    bump shielded_sent; bump tx_sent
    b1="$(shbal B)"; b1="${b1:-0}"
    if (( ${b1:-0} > ${b0:-0} )); then bump shielded_recv_ok; log "RECEIPT ok shielded A->B (B shbal $b0 -> $b1)"; else log "WARN shielded A->B not received (B shbal $b0 -> $b1)"; fi
  else
    bump tx_failed
  fi
}

# UNSHIELD (shielded pool -> transparent EXIT): mint a fresh pool note for A,
# then unshield part of it back to A's OWN transparent balance via the
# `shielded-unshield` command and VERIFY the pool shrank. The command returns OK
# only if the node ACCEPTED the unshield tx — the key proof that consensus
# validates the outward veil crossing (value-revealing transparent output, no
# transparent inputs, value_balance = amount + miner_fee). Receipt is checked by
# A's shielded balance DROPPING (not transparent UTXO count, which A — the miner —
# inflates every block via coinbase, so it would false-positive).
act_unshield(){
  local s0 s1 tries=0 sent=0
  w A scan >>"$RUN_DIR/wallet.log" 2>&1 || true
  # ensure A owns a fresh pool note strictly larger than amount + fee
  if ! w A shielded-mint --amount "$SHIELD_NOTE_ATOMIC" >>"$RUN_DIR/wallet.log" 2>&1; then bump tx_failed; return 1; fi
  bump shield_in
  sleep "$EMBARGO_WAIT"; mine_blocks 2 >/dev/null
  s0="$(shbal A)"; s0="${s0:-0}"
  while (( tries < 4 )); do
    if w A shielded-unshield --amount "$AMT_ATOMIC" >>"$RUN_DIR/wallet.log" 2>&1; then sent=1; break; fi
    tries=$((tries+1)); sleep 2
  done
  if (( sent == 0 )); then bump tx_failed; log "unshield A FAILED after $tries retries"; return 1; fi
  bump tx_sent
  sleep "$EMBARGO_WAIT"; mine_blocks 2 >/dev/null
  w A scan >>"$RUN_DIR/wallet.log" 2>&1 || true
  s1="$(shbal A)"; s1="${s1:-0}"
  if (( ${s1:-0} < ${s0:-0} )); then bump unshield; log "RECEIPT ok unshield A->A(transparent) (pool shbal $s0 -> $s1)"; else bump tx_failed; log "WARN unshield A pool did not shrink ($s0 -> $s1)"; fi
}

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
chaos_load() { # trip a load surface via realistic pressure, falling back to a
  # deterministic inject if the flood is below the breaker's threshold, then
  # verify recovery. `$s` is the CANONICAL surface name (capitalized, as
  # get_fuse_status reports it) — surface_state greps the JSON for it, so a
  # lowercase name silently never matches and the trip goes undetected.
  local s="$1" batch
  case "$s" in
    Rpc)     # BOUNDED concurrency (<=10 procs/batch) — an unbounded `&` fan-out
             # fork-bombs the host; batches keep the RATE high without it.
             for batch in $(seq 1 40); do
               # Wait only on THIS batch's curl PIDs — a bare `wait` would also wait
               # on the backgrounded node (NODE_PID) and block forever.
               local pids=()
               for _ in $(seq 1 10); do rpc get_info >/dev/null 2>&1 & pids+=($!); done
               wait "${pids[@]}"
             done ;;
    Mempool) for _ in $(seq 1 3); do act_send_tx; done ;;   # a few real sends (UTXO reservations limit rapid-fire)
  esac
  sleep 2
  local st; st="$(surface_state "$s")"
  if [[ "$st" == "Closed" || -z "$st" ]]; then
    # Flood stayed under the threshold — prove the breaker machinery
    # deterministically (regtest-chaos inject), same as the consensus surfaces.
    inject "$s" >>"$LOG" 2>&1; sleep 1; st="$(surface_state "$s")"
  fi
  if [[ "$st" != "Closed" && -n "$st" ]]; then
    bump breaker_trips; log "CHAOS $s: tripped ($st)"
    rearm "$s" >>"$LOG" 2>&1; sleep 1
    # AutoReset load breakers also reconnect on an idle window; give one more.
    [[ "$(surface_state "$s")" != "Closed" ]] && sleep 10
    [[ "$(surface_state "$s")" == "Closed" ]] && { bump breaker_recoveries; PROTECTION_OK[$s]=1; log "CHAOS $s: RECOVERED"; }
  else
    log "CHAOS $s: did NOT trip after flood+inject (BUG?) state=$st"
  fi
}

snapshot() {
  local iso; iso="$(isolating_count)"
  log "SNAPSHOT cycle=${M[cycles]} blocks=${M[blocks_mined]} tx=${M[tx_sent]}/${M[tx_failed]} shld(in/send/recv)=${M[shield_in]}/${M[shielded_sent]}/${M[shielded_recv_ok]} trips=${M[breaker_trips]} recov=${M[breaker_recoveries]} failclosed=${M[failclosed_rejects]} isolating_now=$iso"
  grep -qiE 'panic|RUST_BACKTRACE|thread .* panicked' "$RUN_DIR/node.log" 2>/dev/null && bump panics
}

report() {
  # Names MUST match the keys chaos_consensus/chaos_load set in PROTECTION_OK
  # exactly (case-sensitive): the consensus triggers use P2p/Reorg (capitalized),
  # so the scorecard must too, or those surfaces never count as covered.
  local surfaces=(Supply Shielded BlockIntegrity P2p Reorg Mempool Rpc)
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
  log "shielded in/send/recv-ok=${M[shield_in]}/${M[shielded_sent]}/${M[shielded_recv_ok]} panics=${M[panics]}"
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
    log "SMOKE: happy-path only (mine + transparent send + full shielded round-trip), no chaos"
    send_verified A B
    send_verified A B
    # Subaddress (stealth) receive: pay a fresh unlinkable subaddress of B and
    # verify B recovers it (receipt-checked inside act_stealth).
    act_stealth
    # Exercise the full validated shielded user-path: shield-in -> shielded-send ->
    # verify B received (receipt-checked inside act_shielded_roundtrip).
    act_shielded_roundtrip
    # Pool EXIT: shield-in -> unshield back to transparent -> verify the pool
    # shrank (receipt-checked inside act_unshield). Completes the shielded triad.
    act_unshield
    log "SMOKE: B shielded-balance after round-trip:"; w B shielded-balance 2>&1 | grep -iE 'Balance:|Owned|Note values' | tee -a "$LOG"
    snapshot
    return 0   # the EXIT trap runs report() once — don't double-report here
  fi

  local end=$(( $(date +%s) + DURATION ))
  local last_snap=0 last_chaos=0 last_shielded=0 last_unshield=0
  # inject-tested surfaces (trip -> [fail-closed if consensus-armed] -> rearm ->
  # recover): all 5 Latch/consensus + P2p/Reorg. load=flood-tested. Covers all 7.
  local consensus=(Supply Shielded BlockIntegrity P2p Reorg) load=(Mempool Rpc) ci=0 li=0
  while [[ $(date +%s) -lt $end ]]; do
    bump cycles
    # weighted-random user action each cycle. The per-cycle SHIELD-IN exercises
    # shielded-tx mempool admission + v2 block-connect verify/apply frequently; the
    # FULL shielded round-trip (shield-in -> shielded-send -> receipt) runs on its
    # own cadence below (it waits out the embargo, so it must not stall every cycle).
    # The whole shielded user-path is wired here via the Option-B miner-paid fee
    # model. The shielded BREAKER is also exercised via chaos inject below.
    case $(( RANDOM % 10 )) in
      0|1|9)   act_mine ;;
      3|4)     act_send_tx ;;
      5|7)     act_stealth ;;
      2|6|8)   act_shield_in ;;
    esac
    now=$(date +%s)
    # full shielded round-trip (shield-in -> send -> verify B) on its cadence
    if (( now - last_shielded >= SHIELDED_EVERY )); then act_shielded_roundtrip; last_shielded=$now; fi
    # pool EXIT (shield-in -> unshield back to transparent -> verify pool shrank)
    if (( now - last_unshield >= UNSHIELD_EVERY )); then act_unshield; last_unshield=$now; fi
    # rotate through chaos triggers on its cadence
    if (( now - last_chaos >= CHAOS_EVERY )); then
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
