#!/usr/bin/env bash
# faucet-balance-watch.sh — alert when faucet wallet drops below a floor.
#
# Designed to run as a cron job on the api box. Checks the faucet wallet's
# balance via `coincync-wallet balance`, and if it's below FLOOR_CYNC,
# posts a Discord webhook alert. Idempotent across runs (won't spam: only
# alerts on transitions or if more than 24h since last alert).
#
# Cron suggestion (api box, every 15 min):
#   */15 * * * * /usr/local/bin/faucet-balance-watch.sh >> /var/log/faucet-watch.log 2>&1
#
# Required env (in /etc/coincync/faucet-watch.env):
#   FAUCET_BALANCE_FLOOR_CYNC=100        # alert if < 100 tCYNC available
#   FAUCET_DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
#
# Optional:
#   FAUCET_NETWORK=testnet               # default testnet
#   FAUCET_WALLET_PATH=/var/lib/coincync/faucet/hot.wallet
#   FAUCET_WALLET_BIN=/usr/local/bin/coincync-wallet
#   FAUCET_NODE_RPC=http://127.0.0.1/rpc/testnet
#   FAUCET_WALLET_PASSWORD=<from /etc/coincync/faucet.env>
#
# State file: /var/lib/coincync/faucet/last-balance-alert.txt
#   contains the unix timestamp of the most recent alert, so a sustained
#   low-balance condition only re-alerts every 24h.

set -euo pipefail

# Config
ENV_FILE=${ENV_FILE:-/etc/coincync/faucet-watch.env}
FAUCET_ENV=${FAUCET_ENV:-/etc/coincync/faucet.env}
NODE_ENV=${NODE_ENV:-/etc/coincync/coincync.env}
ALERT_STATE_FILE=${ALERT_STATE_FILE:-/var/lib/coincync/faucet/last-balance-alert.txt}
ALERT_REPEAT_SECS=${ALERT_REPEAT_SECS:-86400}  # 24h
FLOOR_CYNC_DEFAULT=100

# Source env files (FAUCET_DISCORD_WEBHOOK, FAUCET_BALANCE_FLOOR_CYNC, etc.)
# shellcheck source=/dev/null
[ -f "$ENV_FILE" ]  && . "$ENV_FILE"
# shellcheck source=/dev/null
[ -f "$FAUCET_ENV" ] && . "$FAUCET_ENV"
# shellcheck source=/dev/null
[ -f "$NODE_ENV" ]   && . "$NODE_ENV"

FLOOR_CYNC=${FAUCET_BALANCE_FLOOR_CYNC:-$FLOOR_CYNC_DEFAULT}
WEBHOOK=${FAUCET_DISCORD_WEBHOOK:-}
NETWORK=${FAUCET_NETWORK:-testnet}
WALLET_PATH=${FAUCET_WALLET_PATH:-/var/lib/coincync/faucet/hot.wallet}
WALLET_BIN=${FAUCET_WALLET_BIN:-/usr/local/bin/coincync-wallet}
NODE_RPC=${FAUCET_NODE_RPC:-http://127.0.0.1/rpc/testnet}

if [ -z "${FAUCET_WALLET_PASSWORD:-}" ]; then
  echo "ERROR: FAUCET_WALLET_PASSWORD not set; can't query balance" >&2
  exit 1
fi

if [ -z "$WEBHOOK" ]; then
  echo "WARN: FAUCET_DISCORD_WEBHOOK not set; will check balance but cannot alert" >&2
fi

ts_now=$(date -u +%s)
hr_now=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Always disable trace before exporting the password so a `bash -x` run
# can't leak it. Re-enabling trace AFTER unset is fine.
{ set +x; } 2>/dev/null
export COINCYNC_WALLET_PASSWORD="$FAUCET_WALLET_PASSWORD"

# Use `scan --max-blocks 0` (or a small value) to refresh + print balance.
# The wallet's `info` command doesn't print balance directly; `scan` does.
# At max-blocks 100 the call is fast (no work to do once we're at tip).
SCAN=$("$WALLET_BIN" --network "$NETWORK" --wallet "$WALLET_PATH" --node "$NODE_RPC" \
        scan --max-blocks 100 2>/dev/null || true)

unset COINCYNC_WALLET_PASSWORD

BAL_CYNC=$(echo "$SCAN" | grep -i "^Balance total" | head -1 | awk '{print $3}')

if [ -z "$BAL_CYNC" ]; then
  echo "[$hr_now] WARN: could not parse balance from wallet output"
  exit 0
fi

# Truncate decimals — bash can't do floats, but for >100 CYNC threshold
# we don't need decimals. Compare integer parts.
BAL_INT=${BAL_CYNC%%.*}
BAL_INT=${BAL_INT:-0}

echo "[$hr_now] faucet balance: ${BAL_CYNC} CYNC (floor: ${FLOOR_CYNC})"

if [ "$BAL_INT" -ge "$FLOOR_CYNC" ]; then
  # Healthy. Clear any stale alert state so the next dip alerts immediately.
  rm -f "$ALERT_STATE_FILE"
  exit 0
fi

# Below floor.
last_alert=0
if [ -f "$ALERT_STATE_FILE" ]; then
  last_alert=$(cat "$ALERT_STATE_FILE" 2>/dev/null || echo 0)
fi
since_last=$((ts_now - last_alert))
if [ "$since_last" -lt "$ALERT_REPEAT_SECS" ]; then
  echo "[$hr_now] below floor but already alerted ${since_last}s ago, skipping"
  exit 0
fi

echo "[$hr_now] BELOW FLOOR — posting Discord alert"

if [ -n "$WEBHOOK" ]; then
  # shellcheck disable=SC2016  # backticks here are intentional Discord markdown
  PAYLOAD=$(printf '{"username":"faucet-balance-watch","content":":warning: **Faucet wallet low balance**\\n\\nBalance: **%s CYNC** (floor: %s)\\n\\nTop up with `scripts/fund-faucet.ps1` before drip capacity runs out.\\n\\nDrip = 10 CYNC, so current capacity ≈ %d drips."}' \
    "$BAL_CYNC" "$FLOOR_CYNC" "$((BAL_INT / 10))")
  curl -sS --max-time 10 -X POST -H 'Content-Type: application/json' \
    --data "$PAYLOAD" "$WEBHOOK" >/dev/null && \
    echo "[$hr_now] alert posted" || \
    echo "[$hr_now] WARN: webhook POST failed"
fi

mkdir -p "$(dirname "$ALERT_STATE_FILE")"
echo "$ts_now" > "$ALERT_STATE_FILE"
