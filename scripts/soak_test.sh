#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# CoinCync — 72-hour soak harness
#
# Captures node + miner health every SAMPLE_INTERVAL seconds to a JSONL
# log so you can audit what happened over the soak window. Stops
# automatically after SOAK_HOURS hours OR if the chain stalls > STALL_KILL_SECS.
#
# Run:   bash scripts/soak_test.sh &
# Watch: tail -f logs/soak/<timestamp>.jsonl
# Final: python scripts/soak_summary.py logs/soak/<timestamp>.jsonl
#
# Env overrides:
#   SOAK_HOURS=72         total runtime cap
#   SAMPLE_INTERVAL=300   seconds between samples (default 5 min)
#   STALL_KILL_SECS=1800  abort if tip_age exceeds this (chain stuck)
#   RPC=http://127.0.0.1:28081
# ──────────────────────────────────────────────────────────────────────

set -uo pipefail

SOAK_HOURS="${SOAK_HOURS:-72}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-300}"
STALL_KILL_SECS="${STALL_KILL_SECS:-1800}"
RPC="${RPC:-http://127.0.0.1:28081}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$REPO_ROOT/logs/soak"
mkdir -p "$LOG_DIR"

START_TS="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$LOG_DIR/$START_TS.jsonl"
META="$LOG_DIR/$START_TS.meta.json"

START_EPOCH="$(date -u +%s)"
END_EPOCH=$((START_EPOCH + SOAK_HOURS * 3600))

# ── Pre-flight ────────────────────────────────────────────────────────
INITIAL=$(curl -sS -m 5 -X POST "$RPC" -H 'Content-Type: application/json' \
          -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' 2>/dev/null \
          | python -c 'import sys,json;d=json.loads(sys.stdin.read())["result"];print(d.get("height"),d.get("tip_hash",""))' 2>/dev/null)
if [ -z "$INITIAL" ]; then
  echo "ERROR: cannot reach node at $RPC — is it running?"
  exit 1
fi
INITIAL_HEIGHT="${INITIAL%% *}"
INITIAL_TIP="${INITIAL##* }"

cat > "$META" <<EOF
{
  "start_utc": "$START_TS",
  "soak_hours": $SOAK_HOURS,
  "sample_interval_secs": $SAMPLE_INTERVAL,
  "stall_kill_secs": $STALL_KILL_SECS,
  "rpc": "$RPC",
  "initial_height": $INITIAL_HEIGHT,
  "initial_tip_hash": "$INITIAL_TIP",
  "host": "$(hostname 2>/dev/null || echo unknown)"
}
EOF

echo "── CoinCync 72h soak harness ──────────────────────────"
echo "  log:        $LOG"
echo "  meta:       $META"
echo "  start:      $START_TS"
echo "  end (cap):  $(date -u -d @$END_EPOCH +%Y%m%dT%H%M%SZ 2>/dev/null || python -c "import datetime;print(datetime.datetime.utcfromtimestamp($END_EPOCH).strftime('%Y%m%dT%H%M%SZ'))")"
echo "  height@0:   $INITIAL_HEIGHT"
echo "  interval:   ${SAMPLE_INTERVAL}s"
echo "  stall kill: ${STALL_KILL_SECS}s"
echo "──────────────────────────────────────────────────────"

# ── Sample loop ───────────────────────────────────────────────────────
sample_count=0
last_height=$INITIAL_HEIGHT
last_progress_epoch=$START_EPOCH

while true; do
  now_epoch="$(date -u +%s)"
  if [ "$now_epoch" -ge "$END_EPOCH" ]; then
    echo "[$(date -u +%FT%TZ)] soak window elapsed — stopping cleanly"
    break
  fi

  # Pull get_info
  resp=$(curl -sS -m 5 -X POST "$RPC" -H 'Content-Type: application/json' \
         -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' 2>/dev/null || echo '{}')

  # Pull node + miner process stats (Windows)
  node_stats=$(tasklist //FI "IMAGENAME eq coincync-node.exe" //FO CSV //NH 2>/dev/null | head -1 || echo "")
  miner_stats=$(tasklist //FI "IMAGENAME eq coincync-tui-miner.exe" //FO CSV //NH 2>/dev/null | head -1 || echo "")

  # Single-line JSON record per sample
  python -c "
import json, sys, time
resp = '''$resp'''
node_csv = '''$node_stats'''.strip().strip('\"')
miner_csv = '''$miner_stats'''.strip().strip('\"')
try:
    r = json.loads(resp).get('result', {}) if resp else {}
except Exception:
    r = {}

def parse_csv(s):
    if not s or 'INFO' in s.upper(): return None
    parts = [p.strip('\"') for p in s.split('\",\"')]
    if len(parts) < 5: return None
    try:
        # Image, PID, Session, SessionId, Mem (e.g. '12,345 K')
        mem_kb = int(parts[4].replace(',','').replace(' K','').strip())
    except Exception:
        mem_kb = 0
    return {'pid': parts[1], 'mem_kb': mem_kb}

rec = {
    'ts': int(time.time()),
    'iso': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'height': r.get('height'),
    'tip_age_secs': r.get('tip_age_secs'),
    'difficulty': r.get('difficulty'),
    'total_difficulty': r.get('total_difficulty'),
    'peer_count': r.get('peer_count'),
    'mempool_size': r.get('mempool_size'),
    'status': r.get('status'),
    'health_score': r.get('health_score'),
    'supply_atomic': r.get('supply_atomic'),
    'node': parse_csv(node_csv),
    'miner': parse_csv(miner_csv),
}
print(json.dumps(rec))
" >> "$LOG"

  # Track stall
  cur_height=$(python -c "
import json
try:
    d = json.loads('''$resp''').get('result', {})
    print(d.get('height') or 0)
except Exception:
    print(0)
" 2>/dev/null)

  if [ -n "$cur_height" ] && [ "$cur_height" -gt "$last_height" ] 2>/dev/null; then
    last_height=$cur_height
    last_progress_epoch=$now_epoch
  fi

  stall_secs=$((now_epoch - last_progress_epoch))
  if [ "$stall_secs" -gt "$STALL_KILL_SECS" ]; then
    echo "[$(date -u +%FT%TZ)] STALL: chain has not advanced in ${stall_secs}s (> ${STALL_KILL_SECS}s threshold). Stopping soak."
    echo "{\"ts\":$now_epoch,\"event\":\"soak_aborted_stall\",\"stall_secs\":$stall_secs,\"last_height\":$last_height}" >> "$LOG"
    break
  fi

  sample_count=$((sample_count + 1))
  # Concise progress line every 12 samples (~1h on 5-min interval)
  if [ $((sample_count % 12)) -eq 0 ]; then
    elapsed_h=$(python -c "print(f'{($now_epoch - $START_EPOCH) / 3600:.1f}')")
    echo "[$(date -u +%FT%TZ)] sample $sample_count  elapsed=${elapsed_h}h  h=$cur_height  delta=+$((cur_height - INITIAL_HEIGHT))  stall=${stall_secs}s"
  fi

  sleep "$SAMPLE_INTERVAL"
done

echo "── Soak finished ─────────────────────────────────────"
echo "  log:    $LOG"
echo "  total samples: $sample_count"
echo "  height:  $INITIAL_HEIGHT → $last_height (+$((last_height - INITIAL_HEIGHT)))"
echo "  summary: python scripts/soak_summary.py \"$LOG\""
