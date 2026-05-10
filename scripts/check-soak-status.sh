#!/bin/bash
# Pull a live snapshot of this box's soak progress from its JSONL log.
set -uo pipefail

LOG_DIR=/var/lib/coincync/soak
LATEST=$(ls -t "$LOG_DIR"/*.jsonl 2>/dev/null | head -1)

if [ -z "$LATEST" ]; then
  echo "no soak log found"
  exit 1
fi

# Counts
TOTAL=$(wc -l < "$LATEST")
ERRORS=$(grep -c '"error":true' "$LATEST" || true)
BCAST_PARTIAL=$(grep -oE '"bcast_partial":[0-9]+' "$LATEST" | awk -F: '{s+=$2} END {print s+0}')

# Min/max peers
MIN_PEERS=$(grep -oE '"peers":[0-9]+' "$LATEST" | awk -F: '{print $2}' | sort -n | head -1)
MAX_PEERS=$(grep -oE '"peers":[0-9]+' "$LATEST" | awk -F: '{print $2}' | sort -n | tail -1)

# First and last height
FIRST_H=$(grep -m1 -oE '"height":[0-9]+' "$LATEST" | head -1 | cut -d: -f2)
LAST_H=$(grep -oE '"height":[0-9]+' "$LATEST" | tail -1 | cut -d: -f2)
DELTA=$((LAST_H - FIRST_H))

# Max stall
MAX_STALL=$(grep -oE '"stall":[0-9]+' "$LATEST" | awk -F: '{print $2}' | sort -n | tail -1)

# Last sample's tip_age
LAST_TIP_AGE=$(grep -oE '"tip_age":[0-9]+' "$LATEST" | tail -1 | cut -d: -f2)

# Last sample's mem_pct + load1
LAST_MEM=$(grep -oE '"mem_pct":[0-9]+' "$LATEST" | tail -1 | cut -d: -f2)
LAST_LOAD=$(grep -oE '"load1":[0-9.]+' "$LATEST" | tail -1 | cut -d: -f2)

# Determine verdict-so-far
VERDICT="ok"
[ "$ERRORS" -gt $((TOTAL / 10)) ] && VERDICT="errors"
[ "$BCAST_PARTIAL" -gt 0 ] && VERDICT="bcast-partial-detected"
[ "${MAX_STALL:-0}" -gt 1800 ] && VERDICT="stall>30min"

printf "samples=%d  errors=%d  bcast_partial=%d  height=%s->%s(+%d)  peers=%s..%s  stall_max=%ss  tip_age=%ss  mem=%s%%  load=%s  verdict=%s\n" \
  "$TOTAL" "$ERRORS" "$BCAST_PARTIAL" "${FIRST_H:-?}" "${LAST_H:-?}" "$DELTA" \
  "${MIN_PEERS:-?}" "${MAX_PEERS:-?}" "${MAX_STALL:-?}" "${LAST_TIP_AGE:-?}" \
  "${LAST_MEM:-?}" "${LAST_LOAD:-?}" "$VERDICT"
