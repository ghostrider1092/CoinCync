#!/usr/bin/env bash
# scripts/fuzz-overnight-from-windows.sh
#
# Sync the current Windows-side coincync working tree into the WSL
# fuzz workspace, then kick off the full overnight fuzz pass against
# the fresh source. Single command instead of the manual:
#
#   rsync ... ; cd ~/coincync-fuzz ; nohup bash scripts/fuzz-overnight.sh ...
#
# Why this wrapper exists:
#   - /mnt/c is ~10× slower than the native WSL filesystem for I/O-heavy
#     work like a cargo-fuzz compile. The overnight builds 27 separate
#     [[bin]] entries — running from /mnt/c could easily add 30+ min of
#     pure compile time vs running from ~/.
#   - The existing fuzz-overnight.sh hardcodes `cd ~/coincync-fuzz/fuzz`,
#     so the WSL workspace must reflect current main.
#   - Rsync skips `target/` and the existing fuzz `corpus/` + `artifacts/`
#     directories — preserving the prior fuzz state (the corpus is real
#     test value, not throwaway).
#
# Usage (from inside WSL Ubuntu):
#   bash /mnt/c/dev/coincync/scripts/fuzz-overnight-from-windows.sh
#
# Or from Windows PowerShell:
#   wsl -- bash /mnt/c/dev/coincync/scripts/fuzz-overnight-from-windows.sh
#
# Optional env vars (forwarded to fuzz-overnight.sh):
#   PER_TARGET_SECS=300  # 5 min per target = ~135 min total (fast overnight)
#   PER_TARGET_SECS=1200 # 20 min per target = ~9h (default, real overnight)

set -euo pipefail

WIN_SRC="/mnt/c/dev/coincync"
WSL_DST="$HOME/coincync-fuzz"

if [ ! -d "$WIN_SRC" ]; then
  echo "fatal: Windows source not found at $WIN_SRC" >&2
  echo "       Either you're not running this from WSL, or the project moved." >&2
  exit 2
fi

if [ ! -d "$WSL_DST" ]; then
  echo "fatal: WSL fuzz workspace not found at $WSL_DST" >&2
  echo "       Run scripts/fuzz-wsl-setup.sh first to bootstrap it." >&2
  exit 2
fi

# Source the cargo environment so the `cargo +nightly fuzz ...` invocation
# down the call chain finds the toolchain.
# shellcheck source=/dev/null
source "$HOME/.cargo/env"

echo "===================================================================="
echo "  fuzz-overnight-from-windows — preparing fresh WSL workspace"
echo "===================================================================="
echo ""
echo "  Windows source:  $WIN_SRC"
echo "  WSL workspace:   $WSL_DST"
echo "  per-target time: ${PER_TARGET_SECS:-1200} sec"
echo ""

# --- Rsync the source tree ------------------------------------------------
# Excludes:
#   target/       — rebuild fresh, don't drag Windows-side artifacts
#   fuzz/target/  — same
#   fuzz/corpus/  — PRESERVE existing fuzz corpus (the value of fuzzing)
#   fuzz/artifacts/ — PRESERVE existing crash artifacts
#   .git/         — fuzz workspace doesn't need git history
#   *.swp         — editor scratch
echo "Syncing source (skipping target/, preserving fuzz corpus + artifacts)..."
# Windows file-handle locks on Tauri's node_modules + nested build
# artifacts have killed this rsync three times in a row (2026-05-29):
#   "cannot delete non-empty directory: coincync-wallet/src-tauri"
#   rsync error: received SIGINT, SIGTERM, or SIGHUP (code 20)
# Excluding the Tauri / node_modules paths up front lets rsync skip
# the problematic directories instead of trying (and failing) to
# delete files Windows has open. The fuzz pass doesn't touch the
# wallet GUI anyway -- it operates on the chain crates.
rsync -a --delete \
  --exclude='target/' \
  --exclude='fuzz/target/' \
  --exclude='fuzz/corpus/' \
  --exclude='fuzz/artifacts/' \
  --exclude='.git/' \
  --exclude='*.swp' \
  --exclude='.idea/' \
  --exclude='.vscode/' \
  --exclude='out/' \
  --exclude='release-artifacts/' \
  --exclude='**/node_modules/' \
  --exclude='coincync-wallet/src-tauri/target/' \
  --exclude='coincync-wallet-v2/src-tauri/target/' \
  --exclude='coincync-wallet/dist/' \
  --exclude='coincync-wallet-v2/dist/' \
  "$WIN_SRC/" "$WSL_DST/"

echo "  Sync complete."
echo ""

# --- Verify the workspace is now in a known-good state -------------------
if [ ! -f "$WSL_DST/scripts/fuzz-overnight.sh" ]; then
  echo "fatal: fuzz-overnight.sh missing from synced workspace" >&2
  exit 2
fi
if [ ! -d "$WSL_DST/fuzz/fuzz_targets" ]; then
  echo "fatal: fuzz_targets directory missing from synced workspace" >&2
  exit 2
fi

# --- Kick off the overnight ----------------------------------------------
LOG="$HOME/fuzz-overnight.log"
RPT="$HOME/fuzz-overnight-report.txt"

echo "Kicking off overnight fuzz pass..."
echo "  Log:    $LOG"
echo "  Report: $RPT  (written when the run completes)"
echo ""
echo "  Detach with: Ctrl+C (the fuzz process continues via nohup)."
echo "  Re-attach:   tail -f $LOG"
echo ""
echo "  Estimated wallclock: $(( ${PER_TARGET_SECS:-1200} * 27 / 60 )) minutes (${PER_TARGET_SECS:-1200} sec/target x 27 targets)."
echo ""

# Background the actual fuzz run via nohup so disconnecting WSL doesn't
# kill it. Foreground a 5-second tail so the operator sees something
# happen before the prompt returns.
cd "$WSL_DST"
nohup bash scripts/fuzz-overnight.sh > "$LOG" 2>&1 &
FUZZ_PID=$!
echo "  Started PID $FUZZ_PID"
echo ""

sleep 5
echo "First 5 seconds of output:"
echo "  ----"
head -30 "$LOG" 2>/dev/null | sed 's/^/  /'
echo "  ----"
echo ""
echo "Overnight is running in the background. Check progress with:"
echo "  tail -f $LOG"
echo ""
echo "When the run completes, review:"
echo "  cat $RPT"
echo "  ls $WSL_DST/fuzz/artifacts/   # any crashes found"
