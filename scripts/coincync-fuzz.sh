#!/usr/bin/env bash
#
# coincync-fuzz.sh — continuous fuzzing loop runner.
#
# Rotates through every fuzz target in `fuzz/fuzz_targets/`,
# running each for FUZZ_DURATION_SEC. On crash, the libFuzzer
# corpus + repro file lands in `/var/lib/coincync/fuzz/<target>/crashes/`.
# A Discord webhook fires once per crash so the operator notices
# without polling the box.
#
# Designed to be run as the ExecStart of a systemd unit.
# See `coincync-fuzz.service` and `docs/operations/CONTINUOUS_FUZZING.md`.
#
# Env (loaded from /etc/coincync/fuzz.env):
#   FUZZ_REPO_DIR          — where the source tree lives
#   FUZZ_STATE_DIR         — corpus + crash storage (persistent)
#   FUZZ_DURATION_SEC      — seconds per target per rotation (default 1800 = 30 min)
#   FUZZ_JOBS              — parallel jobs per target (default 1)
#   DISCORD_WEBHOOK        — webhook to ping on crash (optional;
#                            falls back to journald log only)
#   COINCYNC_RPC_API_KEY   — not needed; here for env consistency

set -uo pipefail

# Load env (silent on missing — we'll error out below if vars unset)
[ -f /etc/coincync/coincync.env ] && . /etc/coincync/coincync.env
[ -f /etc/coincync/fuzz.env ] && . /etc/coincync/fuzz.env
# Webhook in separately-permissioned file (0600 root-only); see
# coincync-selfcheck.sh for the same pattern.
[ -f /etc/coincync/discord.env ] && . /etc/coincync/discord.env

REPO="${FUZZ_REPO_DIR:-/opt/coincync-source}"
STATE="${FUZZ_STATE_DIR:-/var/lib/coincync/fuzz}"
DURATION="${FUZZ_DURATION_SEC:-1800}"
JOBS="${FUZZ_JOBS:-1}"
WEBHOOK="${DISCORD_WEBHOOK:-}"
HOST="$(hostname)"

if [ ! -d "$REPO" ]; then
  logger -t coincync-fuzz "ERROR: source repo missing at $REPO"
  exit 1
fi

if [ ! -d "$REPO/fuzz/fuzz_targets" ]; then
  logger -t coincync-fuzz "ERROR: fuzz_targets/ not present at $REPO/fuzz/"
  exit 1
fi

mkdir -p "$STATE"

# Discover targets from the directory; resilient to additions.
mapfile -t TARGETS < <(
  find "$REPO/fuzz/fuzz_targets" -maxdepth 1 -name '*.rs' \
    -exec basename {} .rs \; | sort
)

if [ "${#TARGETS[@]}" -eq 0 ]; then
  logger -t coincync-fuzz "ERROR: no fuzz targets found"
  exit 1
fi

logger -t coincync-fuzz "starting continuous fuzz loop: ${#TARGETS[@]} targets, ${DURATION}s each, jobs=$JOBS"

# Discord helper. Silent if no webhook configured.
notify_discord() {
  local title="$1"
  local body="$2"
  if [ -z "$WEBHOOK" ]; then
    return 0
  fi
  # Truncate body to keep request small.
  local trimmed_body
  trimmed_body=$(echo -n "$body" | head -c 1500)
  local payload
  payload=$(printf '{"content":"**[%s] %s**\\n```\\n%s\\n```"}' \
    "$HOST" "$title" "$(echo "$trimmed_body" | sed 's/"/\\"/g')")
  curl -sS -m 10 -X POST -H 'Content-Type: application/json' \
    -d "$payload" "$WEBHOOK" >/dev/null 2>&1 || true
}

# One pass through each target.
run_target() {
  local target="$1"
  local target_state="$STATE/$target"
  local corpus="$target_state/corpus"
  local crashes="$target_state/crashes"
  mkdir -p "$corpus" "$crashes"

  logger -t coincync-fuzz "running target=$target for ${DURATION}s"

  # cargo fuzz expects to be invoked from the project root.
  # `--release` is correct for fuzzing — debug builds are too slow.
  # `-- -max_total_time=N` passes through to libFuzzer.
  # `-jobs=` = parallel processes.
  # `-artifact_prefix=` = where crash files land.
  # `-print_final_stats=1` = useful summary line in the journal.
  local stdout_log
  stdout_log=$(mktemp)
  local exit_code=0
  (
    cd "$REPO" && \
    cargo +stable fuzz run --release "$target" "$corpus" -- \
      "-max_total_time=$DURATION" \
      "-jobs=$JOBS" \
      "-artifact_prefix=$crashes/" \
      "-print_final_stats=1"
  ) >"$stdout_log" 2>&1
  exit_code=$?

  # libFuzzer exits non-zero on crash discovery (the artifact has
  # been written by the time we get here). Detect by counting new
  # files in crashes/.
  local crash_count
  crash_count=$(find "$crashes" -type f -newer "$stdout_log" 2>/dev/null | wc -l)
  if [ "$crash_count" -gt 0 ]; then
    local crash_summary
    crash_summary=$(tail -n 60 "$stdout_log")
    logger -t coincync-fuzz "CRASH found in $target ($crash_count new artifact(s))"
    notify_discord "fuzz CRASH: $target" \
      "host=$HOST target=$target new_artifacts=$crash_count
last 60 lines of stdout:
$crash_summary"
  elif [ $exit_code -ne 0 ]; then
    # Non-zero exit but no new crash artifact. Could be a build
    # failure or an interrupt. Log loudly so the operator
    # investigates; don't ping Discord unless real crash.
    logger -t coincync-fuzz "WARN: $target exited $exit_code with no new crashes (build failure?)"
  else
    logger -t coincync-fuzz "ok: $target finished with no new crashes"
  fi

  rm -f "$stdout_log"
}

# Main loop: rotate through targets indefinitely. systemd restarts
# us if we exit; rotation gives every target equal time.
while true; do
  for t in "${TARGETS[@]}"; do
    run_target "$t"
    # Brief pause between targets so syslog/journald can flush.
    sleep 5
  done
done
