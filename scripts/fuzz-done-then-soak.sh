#!/usr/bin/env bash
# scripts/fuzz-done-then-soak.sh
#
# Watcher that fires when the overnight fuzz pass completes:
#   1. Wait for the fuzz PID to exit (poll every 5 min)
#   2. Capture the fuzz report (any crashes? clean targets?)
#   3. Start the soak-monitor in a 6h polling loop
#
# Two soak targets supported:
#   --target=live      Poll api.coincync.network testnet (default).
#                      Validates live chain health for the duration of
#                      the v1.0.10 prep window. Does NOT exercise the
#                      armed MIN_OUTPUT_AGE activation guard (the live
#                      binary doesn't have it). Useful as a regression
#                      check that the chain itself stays healthy.
#
#   --target=sandbox   Poll a sandbox node running the v1.0.10 ARMED
#                      binary. This is the audit-grade soak per
#                      docs/launch/v1.0.10-SOAK-PROCEDURE.md. Requires
#                      operator provisioning — see the procedure doc.
#                      Pass --rpc=http://SANDBOX_IP:28081 alongside.
#
# Run from WSL Ubuntu (where the fuzz lives):
#   nohup bash scripts/fuzz-done-then-soak.sh > ~/soak-watcher.log 2>&1 &
#
# Reattach:
#   tail -f ~/soak-watcher.log

set -u

# --- Args ----------------------------------------------------------------
TARGET="live"
RPC="https://api.coincync.network/rpc/testnet"
SOAK_INTERVAL_SECS=21600  # 6h
SOAK_DURATION_HOURS=120   # 5 days = 120h
FUZZ_PID="${FUZZ_PID:-36688}"

while [ $# -gt 0 ]; do
  case "$1" in
    --target=*)        TARGET="${1#*=}"; shift;;
    --rpc=*)           RPC="${1#*=}"; shift;;
    --soak-hours=*)    SOAK_DURATION_HOURS="${1#*=}"; shift;;
    --interval=*)      SOAK_INTERVAL_SECS="${1#*=}"; shift;;
    --fuzz-pid=*)      FUZZ_PID="${1#*=}"; shift;;
    *)                 echo "unknown arg: $1" >&2; exit 1;;
  esac
done

if [ "$TARGET" = "sandbox" ] && [ "$RPC" = "https://api.coincync.network/rpc/testnet" ]; then
  echo "fatal: --target=sandbox requires --rpc=<sandbox-rpc-url>" >&2
  echo "       (default RPC points at production api; that's not a sandbox)" >&2
  exit 2
fi

echo "===================================================================="
echo "  fuzz-done-then-soak watcher"
echo "===================================================================="
echo "  fuzz PID watched:  $FUZZ_PID"
echo "  soak target:       $TARGET"
echo "  RPC:               $RPC"
echo "  poll interval:     ${SOAK_INTERVAL_SECS}s (every $((SOAK_INTERVAL_SECS/3600))h)"
echo "  duration:          ${SOAK_DURATION_HOURS}h"
echo "  started:           $(date -u +%FT%TZ)"
echo "===================================================================="

# --- Phase 1: wait for fuzz to exit -------------------------------------
echo ""
echo "[phase 1/3] waiting for fuzz PID $FUZZ_PID to exit..."
WAIT_START=$(date +%s)
while kill -0 "$FUZZ_PID" 2>/dev/null; do
  ELAPSED=$(( ($(date +%s) - WAIT_START) / 60 ))
  echo "  [+${ELAPSED}m] fuzz still running, polling again in 5min"
  sleep 300
done
echo "  fuzz PID $FUZZ_PID exited at $(date -u +%FT%TZ)"

# --- Phase 2: capture the fuzz report -----------------------------------
echo ""
echo "[phase 2/3] capturing fuzz report..."
RPT="$HOME/fuzz-overnight-report.txt"
if [ -f "$RPT" ]; then
  CLEAN=$(grep -c '\[CLEAN\]' "$RPT" || echo 0)
  CRASHES=$(grep -c '\[CRASHES_FOUND\]' "$RPT" || echo 0)
  echo "  report: $RPT"
  echo "  clean targets:    $CLEAN"
  echo "  targets with crashes: $CRASHES"
  if [ "$CRASHES" -gt 0 ]; then
    echo ""
    echo "  [!] CRASHES FOUND. The soak will still start, but you should"
    echo "      triage these before tagging v1.0.10:"
    echo ""
    grep '\[CRASHES_FOUND\]' "$RPT" | sed 's/^/    /'
    echo ""
    echo "  Crash artifacts dir: ~/coincync-fuzz/fuzz/artifacts/"
  fi
else
  echo "  WARN: $RPT not found — fuzz may have crashed before producing"
  echo "        a report. Check ~/fuzz-overnight.log for the failure cause."
fi

# --- Phase 3: start the soak loop ---------------------------------------
echo ""
echo "[phase 3/3] starting ${SOAK_DURATION_HOURS}h soak loop against $TARGET..."
echo "  poll cadence:  every $((SOAK_INTERVAL_SECS/3600))h"
echo "  CSV log:       $HOME/soak-monitor.csv"
echo "  Detach with Ctrl+C; nohup keeps me alive"
echo ""

# soak-monitor.ps1 lives on the Windows side. From WSL we call it via
# powershell.exe — the script handles its own native paths.
SOAK_CSV="$HOME/soak-monitor.csv"
SOAK_END=$(( $(date +%s) + (SOAK_DURATION_HOURS * 3600) ))
ITER=0
while [ "$(date +%s)" -lt "$SOAK_END" ]; do
  ITER=$((ITER + 1))
  NOW=$(date -u +%FT%TZ)
  echo "[soak iter $ITER @ $NOW] running monitor sample..."

  # The Windows PowerShell soak-monitor accepts -NodeRpc and -CsvAppend.
  # CRITICAL: powershell.exe is the Windows binary even when invoked from
  # WSL — it does NOT understand /mnt/c paths. Translate via wslpath -w.
  # Earlier version of this script forgot the script-path translation and
  # silently failed for hours; the pipe-to-tail also swallowed the real
  # exit code, making the failure invisible in the log. Both fixed below:
  # 1) wslpath -w on the script path,
  # 2) capture EXIT via PIPESTATUS so the powershell.exe exit code is what
  #    we read, not tail's.
  SOAK_SCRIPT_WIN=$(wslpath -w /mnt/c/dev/coincync/scripts/soak-monitor.ps1)
  CSV_WIN=$(wslpath -w "$SOAK_CSV")
  powershell.exe -ExecutionPolicy Bypass -File "$SOAK_SCRIPT_WIN" \
    -NodeRpc "$RPC" \
    -CsvAppend "$CSV_WIN" \
    2>&1 | tail -3
  EXIT=${PIPESTATUS[0]}
  echo "  monitor exit: $EXIT (0=PASS, 1=WARN, 2=FAIL, other=script error)"

  if [ "$EXIT" -eq 2 ]; then
    echo "  [!] soak FAIL signal — investigate via $SOAK_CSV"
    echo "      Soak continues so we capture the full timeline, but"
    echo "      v1.0.10 tag is now NOT-SAFE-TO-SHIP until this clears."
  fi

  REMAINING=$(( (SOAK_END - $(date +%s)) / 3600 ))
  echo "  next sample in $((SOAK_INTERVAL_SECS/3600))h; ${REMAINING}h soak time remaining"
  echo ""
  sleep "$SOAK_INTERVAL_SECS"
done

echo "===================================================================="
echo "  SOAK COMPLETE — $(date -u +%FT%TZ)"
echo "===================================================================="
echo ""
echo "Summary:"
echo "  iterations:    $ITER"
echo "  CSV:           $SOAK_CSV"
echo ""
echo "Review the CSV for trend (memory growth, peer-count drops, mempool"
echo "stuck-tx age) and the pass/warn/fail verdict counts. Per soak"
echo "procedure §1 'What passing looks like' — zero deep reorgs, mempool"
echo "oldest entry never exceeded 4h, memory plateau stable, etc."
echo ""
echo "If everything is green: v1.0.10 soak item is closed. Proceed to"
echo "scripts/pretag-check.ps1 for the mechanical pre-tag verification."
