#!/bin/bash
# coincync-weekly-review — Sunday 9am PT (16:00 UTC). One post per box to Discord.
#
# Catches slow-burn problems the every-10-min self-check won't see:
#   - disk filling toward full
#   - mem creeping toward OOM
#   - cert expiry approaching
#   - peer-set diversity degrading
#   - log files runaway
#   - pending kernel reboot
#
# Loads from /etc/coincync/coincync.env:
#   COINCYNC_RPC_API_KEY=...
#   DISCORD_WEBHOOK=...
#
# Severity tiers:
#   🟢 ok          all metrics within thresholds
#   🟡 warn        any metric > 70% threshold OR cert < 30 days
#   🔴 critical    any metric > 90% threshold OR cert < 14 days OR service down
#
# Fleet IPs are baked in so we can report cross-peering visibility.

set -uo pipefail

[ -f /etc/coincync/coincync.env ] && . /etc/coincync/coincync.env
# Webhook in separately-permissioned file (0600 root-only); see selfcheck.sh.
[ -f /etc/coincync/discord.env ] && . /etc/coincync/discord.env
API_KEY="${COINCYNC_RPC_API_KEY:-}"
WEBHOOK="${DISCORD_WEBHOOK:-}"
HOST="$(hostname)"

if [ -z "$WEBHOOK" ]; then
  logger -t coincync-weekly-review "ERROR: missing DISCORD_WEBHOOK in /etc/coincync/coincync.env"
  exit 1
fi

# Fleet IPs: sourced from fleet-config.json if reachable (deployed at
# /etc/coincync/fleet-config.json by sync-fleet-config.sh), else falls
# back to the historical hardcoded list with a warning. Pre-fix
# versions hardcoded 66.135.23.193 (destroyed 2026-06-25) and
# 207.148.111.76 (destroyed 2026-06-18); the "in_fleet" peer counter
# would then undercount by matching only live IPs among a stale list.
FLEET_CONFIG="${FLEET_CONFIG:-/etc/coincync/fleet-config.json}"
if [ -f "$FLEET_CONFIG" ] && command -v jq >/dev/null 2>&1; then
  # Active nodes only; exclude role=api nginx-only host
  # (weekly-review is expected to run on coincync-node hosts;
  # the api host runs nginx, and it's the only role legitimately
  # excluded from fleet-peer counting).
  mapfile -t FLEET_IPS < <(jq -r '.nodes | to_entries | map(select(.value.role != "api")) | map(.value.ip) | .[]' "$FLEET_CONFIG")
else
  logger -t coincync-weekly-review "warning: fleet-config.json not found at $FLEET_CONFIG; using empty FLEET_IPS (in_fleet=0)"
  FLEET_IPS=()
fi

# ─── disk ────────────────────────────────────────────────────────────────
disk_root_pct=$(df / | awk 'NR==2 {print $5}' | tr -d %)
disk_data_pct=$(df /var/lib/coincync 2>/dev/null | awk 'NR==2 {print $5}' | tr -d %)
[ -z "$disk_data_pct" ] && disk_data_pct=0

# ─── memory ──────────────────────────────────────────────────────────────
mem_pct=$(free | awk '/^Mem:/ {printf "%d", ($3/$2)*100}')
mem_human=$(free -h | awk '/^Mem:/ {printf "%s/%s", $3, $2}')

# ─── chain state via RPC ─────────────────────────────────────────────────
height="?"; target="?"; peers="?"; synced="?"; rpc_ok=0
if [ -n "$API_KEY" ]; then
  body=$(curl -sS --max-time 8 -X POST http://127.0.0.1:28081 \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $API_KEY" \
    -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' 2>&1)
  if echo "$body" | grep -q '"result"'; then
    rpc_ok=1
    height=$(echo "$body" | grep -oE '"height":[0-9]+'        | head -1 | cut -d: -f2)
    target=$(echo "$body" | grep -oE '"target_height":[0-9]+' | head -1 | cut -d: -f2)
    peers=$(echo "$body"  | grep -oE '"peer_count":[0-9]+'    | head -1 | cut -d: -f2)
    synced=$(echo "$body" | grep -oE '"synced":(true|false)'  | head -1 | cut -d: -f2)
  fi
fi

# ─── peer diversity via established TCP connections ─────────────────────
peer_ips=$(ss -Hn state established 2>/dev/null \
            | grep ':28080' \
            | awk '{print $5}' \
            | sed 's/:.*//' \
            | sort -u)
peer_total=$(echo "$peer_ips" | grep -c . || echo 0)
peer_slash16=$(echo "$peer_ips" \
                | awk -F. '{print $1"."$2}' \
                | sort -u \
                | grep -c .)

# How many of those are members of our own fleet. Guard against empty
# FLEET_IPS (fleet-config.json was unreadable): grep with an empty
# alternation pattern would match every line, producing a false-high
# in_fleet count.
if [ ${#FLEET_IPS[@]} -eq 0 ]; then
  in_fleet=0
else
  fleet_pattern=$(IFS='|'; echo "${FLEET_IPS[*]}")
  in_fleet=$(echo "$peer_ips" | grep -cE "^(${fleet_pattern//./\\.})$" || echo 0)
fi

# ─── TLS cert expiry (explorer + api only — they have nginx + LE) ────────
cert_status="n/a (no cert on this box)"
cert_days="999"
if [ -d /etc/letsencrypt/live ]; then
  for cert in /etc/letsencrypt/live/*/fullchain.pem; do
    [ -f "$cert" ] || continue
    expiry=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)
    expiry_ts=$(date -d "$expiry" +%s 2>/dev/null)
    now_ts=$(date +%s)
    days=$(( (expiry_ts - now_ts) / 86400 ))
    name=$(basename "$(dirname "$cert")")
    cert_status="${name}: ${days} days"
    cert_days=$days
    break  # report the first cert; multiple certs would be unusual
  done
fi

# ─── log sizes ───────────────────────────────────────────────────────────
journald_size=$(journalctl --disk-usage 2>/dev/null | grep -oE '[0-9.]+[MG]' | head -1)
[ -z "$journald_size" ] && journald_size="?"

# ─── kernel reboot pending ───────────────────────────────────────────────
reboot_needed="no"
[ -f /var/run/reboot-required ] && reboot_needed="YES"

# ─── service state ───────────────────────────────────────────────────────
svc_state=$(systemctl is-active coincync-node 2>/dev/null || echo unknown)

# ─── compute severity ────────────────────────────────────────────────────
severity="ok"; emoji="🟢"
warns=()

if [ "$svc_state" != "active" ]; then severity="critical"; warns+=("service: $svc_state"); fi
if [ "$rpc_ok" -ne 1 ]; then severity="critical"; warns+=("RPC unreachable"); fi

if [ "$disk_root_pct" -gt 90 ] || [ "$disk_data_pct" -gt 90 ]; then severity="critical"; warns+=("disk >90%"); fi
if [ "$disk_root_pct" -gt 70 ] || [ "$disk_data_pct" -gt 70 ]; then [ "$severity" = "ok" ] && severity="warn"; warns+=("disk >70%"); fi

if [ "$mem_pct" -gt 90 ]; then severity="critical"; warns+=("mem >90%"); fi
if [ "$mem_pct" -gt 70 ]; then [ "$severity" = "ok" ] && severity="warn"; warns+=("mem >70%"); fi

if [ "$cert_days" -lt 14 ] && [ "$cert_days" -gt -1 ]; then severity="critical"; warns+=("cert <14d"); fi
if [ "$cert_days" -lt 30 ] && [ "$cert_days" -ge 14 ]; then [ "$severity" = "ok" ] && severity="warn"; warns+=("cert <30d"); fi

if [ "$reboot_needed" = "YES" ]; then [ "$severity" = "ok" ] && severity="warn"; warns+=("reboot needed"); fi

case "$severity" in
  warn)     emoji="🟡" ;;
  critical) emoji="🔴" ;;
esac

# ─── format Discord message ──────────────────────────────────────────────
warn_summary=""
[ "${#warns[@]}" -gt 0 ] && warn_summary=" — $(IFS=', '; echo "${warns[*]}")"

content="${emoji} **${HOST}** weekly review (${severity}${warn_summary})
\`\`\`
chain     height ${height}/${target}, peers ${peers}, synced ${synced}
service   ${svc_state}
disk      / = ${disk_root_pct}%, /var/lib/coincync = ${disk_data_pct}%
memory    ${mem_pct}% (${mem_human})
peers     ${peer_total} total / ${peer_slash16} unique /16 / ${in_fleet} in-fleet
cert      ${cert_status}
journald  ${journald_size}
reboot    ${reboot_needed}
\`\`\`"

# ─── post ────────────────────────────────────────────────────────────────
payload=$(printf '%s' "$content" | python3 -c '
import json, sys
print(json.dumps({"username": "coincync-weekly-review", "content": sys.stdin.read()}))
')

curl -sS --max-time 10 -X POST -H 'Content-Type: application/json' \
     -d "$payload" "$WEBHOOK" >/dev/null \
  || logger -t coincync-weekly-review "discord post failed"

logger -t coincync-weekly-review "review posted: $severity"
