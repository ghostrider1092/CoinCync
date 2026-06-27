#!/bin/bash
# miner-stall-watchdog.sh — runs on the miner host via cron.
#
# Detects the recurring chain-stall pattern from 2026-06-24..26 where:
#   - miner's local coincync-node flips to is_synced=False
#   - rig sync-gate refuses to mine (correctly: prevents private-fork blocks)
#   - chain stalls until manual operator intervention
#
# Self-heal: if rig hasn't produced a block in 15+ minutes, restart
# coincync-node (clears the bad sync state) + coincync-rig (which would
# otherwise be killed by the systemd dep when node stops — DON'T forget
# this; that footgun cost us 15 min of debugging on 2026-06-24).
#
# Anti-restart-loop: don't restart again within 10 min of a previous
# restart. If the node OOM-cycles immediately on restart, watchdog
# won't make it worse.
#
# Cron: */5 * * * * root /usr/local/bin/miner-stall-watchdog.sh >> /var/log/miner-watchdog.log 2>&1

set -euo pipefail

LOG_TAG="miner-watchdog"
STALL_THRESHOLD_SECS=900       # 15 min — at 120s target block time, 7.5 blocks
RESTART_COOLDOWN_SECS=600      # 10 min between restarts
STATE_DIR="/var/lib/miner-watchdog"
LAST_RESTART_FILE="$STATE_DIR/last-restart.txt"

mkdir -p "$STATE_DIR"

log() {
    logger -t "$LOG_TAG" "$1"
    echo "[$(date -u +%H:%M:%S)] $1"
}

# Find most recent "block accepted" line in rig's journal (last 60 min window)
LAST_BLOCK_LINE=$(journalctl -u coincync-rig --since "60 minutes ago" --no-pager 2>&1 \
    | grep "block accepted" | tail -1)

if [ -z "$LAST_BLOCK_LINE" ]; then
    STALLED=1
    REASON="no block_accepted in last 60 minutes"
    AGE_DESC="unknown"
else
    # journalctl line format: "Jun 26 21:02:50 hostname coincync-rig[...]: timestamp ..."
    # Parse the first 3 tokens (month day time) — use date -d to convert.
    LAST_TS_STR=$(echo "$LAST_BLOCK_LINE" | awk '{print $1, $2, $3}')
    LAST_TS=$(date -d "$LAST_TS_STR" +%s 2>/dev/null || echo 0)
    NOW=$(date +%s)
    AGE=$((NOW - LAST_TS))
    AGE_DESC="${AGE}s"

    if [ "$LAST_TS" -eq 0 ]; then
        # date parsing failed; be conservative — don't restart if we can't measure
        log "WARN: could not parse last-block timestamp: $LAST_TS_STR"
        exit 0
    fi

    if [ "$AGE" -gt "$STALL_THRESHOLD_SECS" ]; then
        STALLED=1
        REASON="last block accepted ${AGE}s ago (> ${STALL_THRESHOLD_SECS}s threshold)"
    else
        STALLED=0
        REASON="last block accepted ${AGE}s ago — healthy"
    fi
fi

log "check: $REASON"

if [ "$STALLED" = "0" ]; then
    exit 0
fi

# Anti-restart-loop guard
if [ -f "$LAST_RESTART_FILE" ]; then
    LAST_RESTART=$(cat "$LAST_RESTART_FILE" 2>/dev/null || echo 0)
    SINCE_RESTART=$(($(date +%s) - LAST_RESTART))
    if [ "$SINCE_RESTART" -lt "$RESTART_COOLDOWN_SECS" ]; then
        log "ABORT: previous restart was ${SINCE_RESTART}s ago (cooldown ${RESTART_COOLDOWN_SECS}s)"
        exit 0
    fi
fi

# Restart sequence
log "RESTART STARTING: $REASON"
log "  stopping coincync-node"
systemctl restart coincync-node || { log "FAIL: systemctl restart coincync-node returned $?"; exit 1; }
sleep 3
log "  restarting coincync-rig (systemd dep would have killed it on node restart)"
systemctl restart coincync-rig || { log "FAIL: systemctl restart coincync-rig returned $?"; exit 1; }

date +%s > "$LAST_RESTART_FILE"

# Verify rig is back up
sleep 5
RIG_STATE=$(systemctl is-active coincync-rig)
NODE_STATE=$(systemctl is-active coincync-node)
log "RESTART DONE: node=$NODE_STATE rig=$RIG_STATE"

if [ "$RIG_STATE" != "active" ] || [ "$NODE_STATE" != "active" ]; then
    log "ALERT: post-restart services not active (node=$NODE_STATE rig=$RIG_STATE) — operator intervention needed"
    exit 1
fi

exit 0
