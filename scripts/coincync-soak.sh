#!/bin/bash
# coincync-soak — long-duration sampler for retrospective fleet analysis.
#
# Runs locally on each fleet box, samples its own RPC every 5 min for the
# configured window (default 12h), dumps JSONL to /var/lib/coincync/soak/.
# Posts "soak started" to Discord at the beginning and a summary at the
# end. Ignores transitions during — that's the self-check's job.
#
# Triggered by a one-shot systemd unit so it survives reboots cleanly
# and shows up in `systemctl list-units --state=running`.
#
# Env (in /etc/coincync/coincync.env):
#   COINCYNC_RPC_API_KEY   - bearer for RPC
#   DISCORD_WEBHOOK        - stats channel webhook
#
# Optional override env:
#   SOAK_HOURS=12          - soak window
#   SAMPLE_INTERVAL=300    - seconds between samples

set -uo pipefail

[ -f /etc/coincync/coincync.env ] && . /etc/coincync/coincync.env
# Webhook in separately-permissioned file (0600 root-only); see selfcheck.sh.
[ -f /etc/coincync/discord.env ] && . /etc/coincync/discord.env
API_KEY="${COINCYNC_RPC_API_KEY:-}"
WEBHOOK="${DISCORD_WEBHOOK:-}"
SOAK_HOURS="${SOAK_HOURS:-12}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-300}"
HOST="$(hostname)"

if [ -z "$API_KEY" ] || [ -z "$WEBHOOK" ]; then
  logger -t coincync-soak "ERROR: missing COINCYNC_RPC_API_KEY or DISCORD_WEBHOOK"
  exit 1
fi

LOG_DIR=/var/lib/coincync/soak
mkdir -p "$LOG_DIR"
chown coincync:coincync "$LOG_DIR"

START_TS=$(date -u +%Y%m%dT%H%M%SZ)
LOG="$LOG_DIR/$START_TS.jsonl"
START_EPOCH=$(date -u +%s)
END_EPOCH=$((START_EPOCH + SOAK_HOURS * 3600))

# ─── Discord helper ──────────────────────────────────────────────────────
post_discord() {
  local content="$1"
  local payload
  payload=$(printf '%s' "$content" | python3 -c '
import json, sys
print(json.dumps({"username": "coincync-soak", "content": sys.stdin.read()}))
')
  curl -sS --max-time 10 -X POST -H 'Content-Type: application/json' \
       -d "$payload" "$WEBHOOK" >/dev/null 2>&1 \
    || logger -t coincync-soak "discord post failed"
}

# ─── start announcement ──────────────────────────────────────────────────
INITIAL=$(curl -sS --max-time 8 -X POST http://127.0.0.1:28081 \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $API_KEY" \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' 2>&1)
INIT_HEIGHT=$(echo "$INITIAL" | grep -oE '"height":[0-9]+' | head -1 | cut -d: -f2)
INIT_PEERS=$(echo "$INITIAL" | grep -oE '"peer_count":[0-9]+' | head -1 | cut -d: -f2)

post_discord "🟦 **${HOST}** soak started — ${SOAK_HOURS}h window, sample every $((SAMPLE_INTERVAL/60))min, height@start=${INIT_HEIGHT:-?} peers@start=${INIT_PEERS:-?}"

# ─── sample loop ─────────────────────────────────────────────────────────
sample_count=0
errors=0
last_height="${INIT_HEIGHT:-0}"
max_stall_secs=0
last_progress_epoch=$START_EPOCH

while true; do
  now_epoch=$(date -u +%s)
  if [ "$now_epoch" -ge "$END_EPOCH" ]; then break; fi

  body=$(curl -sS --max-time 8 -X POST http://127.0.0.1:28081 \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $API_KEY" \
    -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' 2>&1)

  if echo "$body" | grep -q '"result"'; then
    height=$(echo "$body"   | grep -oE '"height":[0-9]+'        | head -1 | cut -d: -f2)
    target=$(echo "$body"   | grep -oE '"target_height":[0-9]+' | head -1 | cut -d: -f2)
    peers=$(echo "$body"    | grep -oE '"peer_count":[0-9]+'    | head -1 | cut -d: -f2)
    synced=$(echo "$body"   | grep -oE '"synced":(true|false)'  | head -1 | cut -d: -f2)
    tip_age=$(echo "$body"  | grep -oE '"tip_age_secs":[0-9]+'  | head -1 | cut -d: -f2)
    diff=$(echo "$body"     | grep -oE '"difficulty":"?[0-9]+"?'| head -1 | sed 's/.*://;s/"//g')

    # Track stalls (height not advancing)
    if [ -n "$height" ] && [ "$height" -gt "$last_height" ] 2>/dev/null; then
      last_height=$height
      last_progress_epoch=$now_epoch
    fi
    stall=$((now_epoch - last_progress_epoch))
    if [ "$stall" -gt "$max_stall_secs" ]; then max_stall_secs=$stall; fi

    # Memory + load (cheap, no extra packages needed)
    mem_pct=$(free | awk '/^Mem:/ {printf "%d", ($3/$2)*100}')
    load1=$(cut -d' ' -f1 /proc/loadavg)

    # Count broadcast_raw partial delivery in the last interval (the
    # propagation-fix telemetry — should remain zero if the fix works)
    bcast_partial=$(journalctl -u coincync-node --since "$((SAMPLE_INTERVAL+30)) seconds ago" --no-pager 2>/dev/null \
                    | grep -c 'broadcast_raw partial delivery' || echo 0)

    printf '{"ts":%d,"iso":"%s","height":%s,"target":%s,"peers":%s,"synced":%s,"tip_age":%s,"diff":"%s","mem_pct":%d,"load1":%s,"stall":%d,"bcast_partial":%s}\n' \
      "$now_epoch" "$(date -u +%FT%TZ)" \
      "${height:-null}" "${target:-null}" "${peers:-null}" "${synced:-null}" \
      "${tip_age:-null}" "${diff:-?}" "${mem_pct:-0}" "${load1:-0}" \
      "$stall" "${bcast_partial:-0}" \
      >> "$LOG"
  else
    errors=$((errors + 1))
    printf '{"ts":%d,"iso":"%s","error":true}\n' "$now_epoch" "$(date -u +%FT%TZ)" >> "$LOG"
  fi

  sample_count=$((sample_count + 1))
  sleep "$SAMPLE_INTERVAL"
done

# ─── summary ─────────────────────────────────────────────────────────────
FINAL=$(curl -sS --max-time 8 -X POST http://127.0.0.1:28081 \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $API_KEY" \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' 2>&1)
FINAL_HEIGHT=$(echo "$FINAL" | grep -oE '"height":[0-9]+' | head -1 | cut -d: -f2)

# Aggregate counts from the JSONL
TOTAL_BCAST_PARTIAL=$(grep -oE '"bcast_partial":[0-9]+' "$LOG" | awk -F: '{s+=$2} END {print s+0}')
MIN_PEERS=$(grep -oE '"peers":[0-9]+' "$LOG" | awk -F: '{print $2}' | sort -n | head -1)
MAX_PEERS=$(grep -oE '"peers":[0-9]+' "$LOG" | awk -F: '{print $2}' | sort -n | tail -1)

if [ "$errors" -eq 0 ] && [ "$max_stall_secs" -lt 1800 ] && [ "$TOTAL_BCAST_PARTIAL" -eq 0 ]; then
  emoji="🟢"
  verdict="all green"
elif [ "$max_stall_secs" -ge 1800 ] || [ "$errors" -gt $((sample_count / 10)) ]; then
  emoji="🔴"
  verdict="critical"
else
  emoji="🟡"
  verdict="warnings"
fi

post_discord "${emoji} **${HOST}** soak complete (${verdict}) — ${sample_count} samples, ${SOAK_HOURS}h
\`\`\`
height       ${INIT_HEIGHT:-?} -> ${FINAL_HEIGHT:-?}  (delta ${FINAL_HEIGHT:-0} - ${INIT_HEIGHT:-0})
peers        min=${MIN_PEERS:-?} max=${MAX_PEERS:-?}
max stall    ${max_stall_secs}s
errors       ${errors}/${sample_count}
bcast_partial ${TOTAL_BCAST_PARTIAL}    (the lossy-propagation counter — should be 0)
log          ${LOG}
\`\`\`"

logger -t coincync-soak "complete: $verdict, $sample_count samples, max_stall=${max_stall_secs}s, errors=$errors, bcast_partial=$TOTAL_BCAST_PARTIAL"
exit 0
