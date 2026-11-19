#!/usr/bin/env bash
# coincync-hugepage-guard.sh — self-heal a full-mem miner that silently dropped
# RandomX huge pages.
#
# Runs ON a full-mem miner box via a systemd timer (every ~2 min). The failure
# it recovers (seen live 2026-11-14 22:40 on BOTH full-mem miners at a RandomX
# epoch key-change): the rig rebuilds the ~2 GB dataset for the new epoch while
# the previous epoch's dataset (and/or the background prewarm) still holds the
# reserved huge pages, so the new dataset's FLAG_LARGE_PAGES allocation fails
# and it falls back to 4 KB pages — logging
#   "RandomX huge-page dataset build failed ... Falling back to 4 KB pages".
# The rig does NOT retry large pages mid-run, so it stays ~16% slower until the
# next restart (one box ran degraded ~3 DAYS unnoticed). A restart — with no
# competing second dataset — re-grabs the huge pages. This automates that.
#
# Degraded signature: huge pages are reserved (HugePages_Total high) but ~none
# are in use (HugePages_Free ~= Total) while the miner is active — i.e. the
# 2 GB dataset sits on 4 KB pages, not the ~1170-page hugetlb pool. When healthy
# the dataset is resident in huge pages and HugePages_Free drops to ~110.
#
# Does NOTHING when: huge pages aren't reserved (box intentionally on 4 KB),
# large pages ARE engaged, the miner is down (systemd handles crash loops), or
# the pool is not actually free enough for a rebuild to re-grab it (so it can
# never hot-loop chasing pages something else holds). The degraded state must
# PERSIST past DEGRADED_SECS — longer than one ~60-90 s dataset rebuild — so a
# legitimate mid-rebuild window is never mistaken for the stuck state, and
# restarts are rate-limited by MIN_RESTART_GAP.
#
# NOTE: this is the safety net, not the cure. The root fix lives in the rig's
# dataset builder (free the old epoch's huge pages before the new-epoch
# FLAG_LARGE_PAGES alloc, so the steady-state dataset is always on huge pages);
# this guard exists so a fallback can never again sit unnoticed for days.
#
# Install on FULL-MEM MINER boxes ONLY (those with vm.nr_hugepages reserved and
# coincync-baseline-miner running) via install-hugepage-guard.sh.
set -uo pipefail

UNIT="${COINCYNC_MINER_UNIT:-coincync-baseline-miner}"
STATE="${COINCYNC_HPGUARD_STATE:-/run/coincync-hugepage-guard.state}"
DEGRADED_SECS="${DEGRADED_SECS:-180}"        # sustained degradation before acting (> one rebuild)
MIN_RESTART_GAP="${MIN_RESTART_GAP:-7200}"   # never restart more often than this (2 h)
MIN_RESERVED="${MIN_RESERVED:-1024}"         # only boxes that actually reserve huge pages
ENGAGED_MIN="${ENGAGED_MIN:-512}"            # >= this many pages in use => large pages engaged
NEED_FREE="${NEED_FREE:-1024}"               # require this many free pages before a restart can help

now=$(date +%s)

# Only our business if the miner is actually running — crash loops are systemd's.
systemctl is-active --quiet "$UNIT" || exit 0

total=$(grep -m1 HugePages_Total /proc/meminfo | awk '{print $2}')
free=$(grep -m1 HugePages_Free  /proc/meminfo | awk '{print $2}')
[ -n "${total:-}" ] && [ -n "${free:-}" ] || exit 0

# No huge pages reserved on this box => it is meant to run on 4 KB pages. Not ours.
[ "$total" -ge "$MIN_RESERVED" ] || exit 0

in_use=$(( total - free ))

read_state(){ degraded_since=0; last_restart=0; [ -f "$STATE" ] && IFS='|' read -r degraded_since last_restart < "$STATE" || true; }
write_state(){ printf '%s|%s\n' "$1" "$2" > "$STATE"; }
read_state

# Large pages engaged (dataset resident in the hugetlb pool) => healthy. Clear the clock.
if [ "$in_use" -ge "$ENGAGED_MIN" ]; then
  write_state 0 "${last_restart:-0}"; exit 0
fi

# Degraded: the reserved pool is present but the dataset is NOT in it (4 KB fallback).
if [ "${degraded_since:-0}" -eq 0 ]; then
  write_state "$now" "${last_restart:-0}"; exit 0          # first observation — start the clock
fi
degraded_for=$(( now - degraded_since ))
gap=$(( now - ${last_restart:-0} ))

# Act only once the fallback has persisted past a live-rebuild window, the pool
# is actually free enough for a restart to re-grab it (else a restart can't help
# and we must not hot-loop), and we have not restarted too recently.
if [ "$degraded_for" -ge "$DEGRADED_SECS" ] && [ "$free" -ge "$NEED_FREE" ] && [ "$gap" -ge "$MIN_RESTART_GAP" ]; then
  logger -t coincync-hugepage-guard "RandomX large pages NOT engaged (${in_use}/${total} huge pages in use) for ${degraded_for}s while ${UNIT} active; ${free} free — restarting to re-grab huge pages"
  systemctl restart "$UNIT" || true
  write_state 0 "$now"                                     # clear the clock, record the restart
else
  write_state "${degraded_since}" "${last_restart:-0}"     # keep accumulating degraded time
fi
exit 0
