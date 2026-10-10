#!/usr/bin/env bash
# coincync-sync-watchdog.sh — self-heal a node wedged in IBD.
#
# Runs ON a node via a systemd timer (every ~2 min). The failure it recovers:
# on 2026-10-10 fresh relays stalled with the download scheduler spinning
#   "[IBD] Recovered N stuck downloads (no pending_request)"
# every 0.5s WITHOUT advancing — height frozen while peers were far ahead.
# A plain restart re-seeds the scheduler and the node resumes. This automates
# that: if height has NOT advanced for STALL_SECS while the node is behind its
# sync target, restart coincync-node. Edge-triggered via a state file and
# rate-limited by MIN_RESTART_GAP so it can never hot-loop restarts.
#
# It does NOTHING when the node is synced, caught up, or merely slow-but-
# progressing, and defers to systemd when the RPC is down (that is a crash
# loop, which Restart=on-failure already handles).
set -uo pipefail

RPC="http://127.0.0.1:${COINCYNC_RPC_PORT:-28081}"
STATE="${COINCYNC_WATCHDOG_STATE:-/run/coincync-watchdog.state}"
STALL_SECS="${STALL_SECS:-300}"        # no height progress this long => stalled
MIN_RESTART_GAP="${MIN_RESTART_GAP:-600}"   # never restart more often than this
UNIT="${COINCYNC_NODE_UNIT:-coincync-node}"

now=$(date +%s)
j="$(curl -s -m 5 -X POST "$RPC" -H 'content-type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"get_info","params":[]}' 2>/dev/null || true)"
h="$(printf '%s' "$j"      | grep -o '"height":[0-9]*'        | head -1 | cut -d: -f2)"
tgt="$(printf '%s' "$j"    | grep -o '"target_height":[0-9]*' | head -1 | cut -d: -f2)"
synced="$(printf '%s' "$j" | grep -o '"is_synced":[a-z]*'     | head -1 | cut -d: -f2)"
peers="$(printf '%s' "$j"  | grep -o '"peer_count":[0-9]*'    | head -1 | cut -d: -f2)"

# RPC down / no height => crash loop territory, not ours. Let systemd handle it.
[ -n "${h:-}" ] || { exit 0; }

# ISOLATED node (2026-10-10): a backbone node with ZERO peers reports
# is_synced=true BY DEFAULT — no peer tells it a higher tip exists, so it
# "converges" on its own stale height (seen live: a node restarted into 0
# outbound sat at height 248 reporting synced while the fleet was at 2855).
# An isolated backbone node is ALWAYS unhealthy: it cannot know the real tip
# and cannot advance. So it is NOT treated as healthy below — the stall clock
# runs and, since an isolated node's height is frozen, the watchdog restarts it
# (which re-dials its --addnode peers). `peers` empty (older node) => skip gate.

read_state(){ prev_h=0; prev_t=$now; last_restart=0; [ -f "$STATE" ] && IFS='|' read -r prev_h prev_t last_restart < "$STATE" || true; }
write_state(){ printf '%s|%s|%s\n' "$1" "$2" "$3" > "$STATE"; }

# Healthy requires peers AND (synced or at/above target). The peer gate rejects
# the isolated false-synced case above. (If peer_count is absent — older node —
# the gate passes so behaviour is unchanged.)
has_peers=1; [ -n "${peers:-}" ] && [ "${peers:-0}" -eq 0 ] && has_peers=0
if [ "$has_peers" = "1" ] && { [ "${synced:-false}" = "true" ] || { [ -n "${tgt:-}" ] && [ "${tgt:-0}" -gt 0 ] && [ "$h" -ge "$tgt" ]; }; }; then
  read_state; write_state "$h" "$now" "${last_restart:-0}"; exit 0
fi

read_state
# Making progress since last sample => update sample, keep waiting.
if [ "${h:-0}" -gt "${prev_h:-0}" ]; then
  write_state "$h" "$now" "${last_restart:-0}"; exit 0
fi

# No progress since prev_t. How long, and when did we last restart?
stalled=$(( now - ${prev_t:-$now} ))
gap=$(( now - ${last_restart:-0} ))
if [ "$stalled" -ge "$STALL_SECS" ] && [ "$gap" -ge "$MIN_RESTART_GAP" ]; then
  logger -t coincync-watchdog "IBD stall: height $h frozen ${stalled}s below target ${tgt:-?} — restarting $UNIT"
  systemctl restart "$UNIT" || true
  write_state "$h" "$now" "$now"   # reset stall clock + record the restart
else
  write_state "${prev_h}" "${prev_t}" "${last_restart:-0}"   # keep accumulating stall time
fi
exit 0
