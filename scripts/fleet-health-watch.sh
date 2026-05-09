#!/usr/bin/env bash
# fleet-health-watch.sh — alert when any fleet node degrades.
#
# Polls the explorer's /health/* nginx routes (which proxy to each fleet
# member's RPC with the Bearer key added server-side). Compares each
# node's height against the consensus median. Alerts via Discord webhook
# if any node is:
#   - unreachable
#   - >= STALE_BLOCK_DELTA blocks behind median (default 3)
#   - tip_age_secs > MAX_TIP_AGE_SECS (default 1200 = 20 min)
#   - peer_count < MIN_PEER_COUNT (default 3)
#
# Designed for cron on the explorer box (which already has
# /health/* configured for the Node Health dashboard):
#   */5 * * * * /usr/local/bin/fleet-health-watch.sh \
#     >> /var/log/fleet-health-watch.log 2>&1
#
# Required env (in /etc/coincync/fleet-watch.env):
#   FLEET_DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
#
# Optional knobs (with defaults):
#   STALE_BLOCK_DELTA=3
#   MAX_TIP_AGE_SECS=1200
#   MIN_PEER_COUNT=3
#   ALERT_REPEAT_SECS=3600
#
# State file: /var/lib/coincync/fleet-watch/last-alert.txt
# Idempotent: a single ongoing degradation re-alerts at most every
# ALERT_REPEAT_SECS (default 1h).

set -euo pipefail

ENV_FILE=${ENV_FILE:-/etc/coincync/fleet-watch.env}
ALERT_STATE_FILE=${ALERT_STATE_FILE:-/var/lib/coincync/fleet-watch/last-alert.txt}

# shellcheck source=/dev/null
[ -f "$ENV_FILE" ] && . "$ENV_FILE"

WEBHOOK=${FLEET_DISCORD_WEBHOOK:-}
STALE_BLOCK_DELTA=${STALE_BLOCK_DELTA:-3}
MAX_TIP_AGE_SECS=${MAX_TIP_AGE_SECS:-1200}
MIN_PEER_COUNT=${MIN_PEER_COUNT:-3}
ALERT_REPEAT_SECS=${ALERT_REPEAT_SECS:-3600}

ts_now=$(date -u +%s)
hr_now=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# /health/* hits the local nginx which adds the Bearer + proxies to each
# fleet node's RPC. Same endpoints the dashboard uses.
NODES=(seed1 seed2 seed3 explorer api)

declare -A HEIGHT
declare -A TIP_AGE
declare -A PEERS
declare -A SYNCED
declare -A REACHED
declare -a HEIGHTS_NUMERIC

for n in "${NODES[@]}"; do
  RESP=$(curl -sS --max-time 8 -X POST -H 'Content-Type: application/json' \
          -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' \
          "https://explorer.coincync.network/health/$n" 2>/dev/null || echo "")
  if [ -z "$RESP" ]; then
    REACHED[$n]=0
    HEIGHT[$n]=0
    TIP_AGE[$n]=0
    PEERS[$n]=0
    SYNCED[$n]=false
    continue
  fi
  REACHED[$n]=1
  H=$(echo "$RESP"   | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("result",{}).get("height",0))' 2>/dev/null || echo 0)
  T=$(echo "$RESP"   | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("result",{}).get("tip_age_secs",0))' 2>/dev/null || echo 0)
  P=$(echo "$RESP"   | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("result",{}).get("peer_count",0))' 2>/dev/null || echo 0)
  S=$(echo "$RESP"   | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("result",{}).get("is_synced",False))' 2>/dev/null || echo false)
  HEIGHT[$n]=$H
  TIP_AGE[$n]=$T
  PEERS[$n]=$P
  SYNCED[$n]=$S
  HEIGHTS_NUMERIC+=("$H")
done

# Median height across reachable nodes.
if [ ${#HEIGHTS_NUMERIC[@]} -eq 0 ]; then
  MEDIAN_H=0
else
  IFS=$'\n' SORTED=($(sort -n <<<"${HEIGHTS_NUMERIC[*]}"))
  unset IFS
  MID=$(( ${#SORTED[@]} / 2 ))
  MEDIAN_H=${SORTED[$MID]}
fi

# Build per-node status lines + the alert summary.
PROBLEMS=()
SUMMARY_LINES=()
for n in "${NODES[@]}"; do
  H=${HEIGHT[$n]}
  T=${TIP_AGE[$n]}
  P=${PEERS[$n]}
  if [ "${REACHED[$n]}" -eq 0 ]; then
    SUMMARY_LINES+=("  $n: 🔴 UNREACHABLE")
    PROBLEMS+=("$n unreachable via /health/$n")
    continue
  fi
  STATUS="🟢"
  ISSUES=()
  if [ -n "$MEDIAN_H" ] && [ "$MEDIAN_H" -gt "$H" ]; then
    LAG=$(( MEDIAN_H - H ))
    if [ "$LAG" -ge "$STALE_BLOCK_DELTA" ]; then
      STATUS="🟡"
      ISSUES+=("lag=${LAG}")
    fi
  fi
  if [ "$T" -gt "$MAX_TIP_AGE_SECS" ]; then
    STATUS="🟡"
    ISSUES+=("tip_age=${T}s")
  fi
  if [ "$P" -lt "$MIN_PEER_COUNT" ]; then
    STATUS="🟡"
    ISSUES+=("peers=${P}")
  fi
  if [ ${#ISSUES[@]} -gt 0 ]; then
    PROBLEMS+=("$n: ${ISSUES[*]}")
    SUMMARY_LINES+=("  $n: $STATUS h=$H age=${T}s peers=$P  (${ISSUES[*]})")
  else
    SUMMARY_LINES+=("  $n: $STATUS h=$H age=${T}s peers=$P")
  fi
done

# Print to stdout (cron captures into log).
printf '[%s] median=%s problems=%d\n' "$hr_now" "$MEDIAN_H" "${#PROBLEMS[@]}"
for line in "${SUMMARY_LINES[@]}"; do printf '%s\n' "$line"; done

if [ ${#PROBLEMS[@]} -eq 0 ]; then
  rm -f "$ALERT_STATE_FILE"
  exit 0
fi

# Throttle: if alerted within the last ALERT_REPEAT_SECS, skip.
last_alert=0
if [ -f "$ALERT_STATE_FILE" ]; then
  last_alert=$(cat "$ALERT_STATE_FILE" 2>/dev/null || echo 0)
fi
since_last=$((ts_now - last_alert))
if [ "$since_last" -lt "$ALERT_REPEAT_SECS" ]; then
  echo "  (problems present but already alerted ${since_last}s ago, throttled)"
  exit 0
fi

if [ -z "$WEBHOOK" ]; then
  echo "  WARN: FLEET_DISCORD_WEBHOOK not set — cannot post alert"
  exit 0
fi

# Build Discord message
TITLE=":rotating_light: **Fleet health degraded**"
PROBLEM_LIST=$(printf '\\n• %s' "${PROBLEMS[@]}")
DETAIL=$(printf '\\n%s' "${SUMMARY_LINES[@]}")
PAYLOAD=$(printf '{"username":"fleet-health-watch","content":"%s%s\\n\\n**Per-node:**%s\\n\\nThresholds: stale_lag>=%s, tip_age>%ss, peers<%s. Throttled: re-alerts at most every %ss."}' \
  "$TITLE" "$PROBLEM_LIST" "$DETAIL" \
  "$STALE_BLOCK_DELTA" "$MAX_TIP_AGE_SECS" "$MIN_PEER_COUNT" "$ALERT_REPEAT_SECS")

curl -sS --max-time 10 -X POST -H 'Content-Type: application/json' \
  --data "$PAYLOAD" "$WEBHOOK" >/dev/null && \
  echo "  alert posted to Discord" || \
  echo "  WARN: webhook POST failed"

mkdir -p "$(dirname "$ALERT_STATE_FILE")"
echo "$ts_now" > "$ALERT_STATE_FILE"
