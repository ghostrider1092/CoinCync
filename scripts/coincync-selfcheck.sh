#!/bin/bash
# coincync-selfcheck — runs every 10 min via systemd.timer.
#
# Posts to Discord on drift TRANSITIONS only (drift starts → 1 alert,
# drift ends → 1 recovery alert). State lives at /var/lib/coincync/.selfcheck-state
# so we don't spam the channel.
#
# Drift conditions:
#   - service not active
#   - RPC unreachable / non-200
#   - peer_count == 0
#   - height stalled (same as last_advance height) for > 20 min
#
# Loads from /etc/coincync/coincync.env:
#   COINCYNC_RPC_API_KEY=...
#   DISCORD_WEBHOOK=https://discord.com/api/webhooks/...

set -uo pipefail

# Load env (silent on missing - we'll error out below if vars unset)
[ -f /etc/coincync/coincync.env ] && . /etc/coincync/coincync.env
# Webhook URLs are credentials - keep them out of coincync.env (0640 -
# group-readable) and in /etc/coincync/discord.env (0600 root-only) so a
# backup or accidental share doesn't leak the channel post permission.
# Sourced after coincync.env so values here override.
[ -f /etc/coincync/discord.env ] && . /etc/coincync/discord.env

API_KEY="${COINCYNC_RPC_API_KEY:-}"
WEBHOOK="${DISCORD_WEBHOOK:-}"
HOST="$(hostname)"
STATE=/var/lib/coincync/.selfcheck-state
NOW=$(date +%s)
STALL_THRESHOLD_SEC=1200   # 20 min
RPC_TIMEOUT=8

if [ -z "$API_KEY" ] || [ -z "$WEBHOOK" ]; then
  logger -t coincync-selfcheck "ERROR: missing COINCYNC_RPC_API_KEY or DISCORD_WEBHOOK in /etc/coincync/coincync.env"
  exit 1
fi

# ─── 1. gather signals ───────────────────────────────────────────────────
SVC_STATE=$(systemctl is-active coincync-node 2>/dev/null || echo unknown)

RPC_BODY=$(curl -sS --max-time "$RPC_TIMEOUT" -X POST http://127.0.0.1:28081 \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $API_KEY" \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' 2>&1)
RPC_RC=$?

HEIGHT="?"; TARGET="?"; PEERS="?"; SYNCED="?"; RPC_OK=0
if [ $RPC_RC -eq 0 ] && echo "$RPC_BODY" | grep -q '"result"'; then
  RPC_OK=1
  # Tiny inline parser — we don't have jq guaranteed, and the result shape is fixed
  HEIGHT=$(echo "$RPC_BODY"   | grep -oE '"height":[0-9]+'        | head -1 | cut -d: -f2)
  TARGET=$(echo "$RPC_BODY"   | grep -oE '"target_height":[0-9]+' | head -1 | cut -d: -f2)
  PEERS=$(echo "$RPC_BODY"    | grep -oE '"peer_count":[0-9]+'    | head -1 | cut -d: -f2)
  SYNCED=$(echo "$RPC_BODY"   | grep -oE '"synced":(true|false)'  | head -1 | cut -d: -f2)
fi

# ─── 2. read prior state ─────────────────────────────────────────────────
PREV_DRIFT="ok"; PREV_HEIGHT="0"; PREV_ADVANCE_TS="$NOW"
if [ -f "$STATE" ]; then . "$STATE" || true; fi

# ─── 3. compute current drift ────────────────────────────────────────────
CUR_DRIFT="ok"; REASON=""

if [ "$SVC_STATE" != "active" ]; then
  CUR_DRIFT="service-down"; REASON="systemd state: $SVC_STATE"
elif [ "$RPC_OK" -ne 1 ]; then
  CUR_DRIFT="rpc-down"; REASON="RPC unreachable / no result"
elif [ "$PEERS" = "0" ]; then
  CUR_DRIFT="zero-peers"; REASON="peer_count=0"
elif [ -n "$HEIGHT" ] && [ "$HEIGHT" = "$PREV_HEIGHT" ] && \
     [ $((NOW - PREV_ADVANCE_TS)) -gt "$STALL_THRESHOLD_SEC" ]; then
  STALL_MIN=$(( (NOW - PREV_ADVANCE_TS) / 60 ))
  CUR_DRIFT="height-stalled"; REASON="height $HEIGHT stalled for ${STALL_MIN} min"
fi

# Update last-advance timestamp on real progress
if [ -n "$HEIGHT" ] && [ "$HEIGHT" != "$PREV_HEIGHT" ] && [ "$HEIGHT" != "?" ]; then
  PREV_ADVANCE_TS="$NOW"
fi

# ─── 4. post on transition ───────────────────────────────────────────────
post_discord() {
  local content="$1"
  curl -sS --max-time 8 -X POST -H 'Content-Type: application/json' \
    -d "{\"username\":\"coincync-selfcheck\",\"content\":$(printf '%s' "$content" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')}" \
    "$WEBHOOK" >/dev/null 2>&1 || logger -t coincync-selfcheck "discord post failed"
}

if [ "$CUR_DRIFT" != "$PREV_DRIFT" ]; then
  if [ "$CUR_DRIFT" = "ok" ]; then
    MSG="✅ **${HOST}** recovered — height=${HEIGHT} target=${TARGET} peers=${PEERS} synced=${SYNCED}"
  else
    MSG="⚠️ **${HOST}** drift: \`${CUR_DRIFT}\` — ${REASON} (height=${HEIGHT} target=${TARGET} peers=${PEERS} synced=${SYNCED})"
  fi
  post_discord "$MSG"
  logger -t coincync-selfcheck "$MSG"
fi

# ─── 5. persist state ────────────────────────────────────────────────────
{
  echo "PREV_DRIFT=\"$CUR_DRIFT\""
  echo "PREV_HEIGHT=\"${HEIGHT:-0}\""
  echo "PREV_ADVANCE_TS=\"$PREV_ADVANCE_TS\""
} > "$STATE"
chown coincync:coincync "$STATE" 2>/dev/null || true

exit 0
