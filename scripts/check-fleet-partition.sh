#!/usr/bin/env bash
#
# check-fleet-partition.sh
#
# Polls every active node in scripts/fleet-config.json and reports any
# tip-hash divergence or height-drift suggesting the fleet has partitioned.
# Designed to catch incidents the way 2026-06-20→21's partition wedge
# WAS NOT caught (it ran for 8+ hours before the operator noticed —
# randomx mining alone on a 520-block-divergent chain).
#
# Usage:
#     scripts/check-fleet-partition.sh                  # human-readable output, exit 0/1
#     scripts/check-fleet-partition.sh --json           # machine-readable JSON
#     scripts/check-fleet-partition.sh --watch [SECS]   # poll every N sec (default 60), keep going
#     scripts/check-fleet-partition.sh --quiet          # only print on divergence (cron-friendly)
#
# Exit codes:
#     0 = converged (or close enough — see thresholds)
#     1 = divergent (different tip hashes or height drift > MAX_HEIGHT_DRIFT)
#     2 = unable to reach >=1 nodes (operational failure, not partition)
#
# Thresholds (override via env):
#     MAX_HEIGHT_DRIFT=10           # blocks
#     MAX_TIP_AGE_SECS=600          # 10 min; sustained higher = miner stalled
#     MAX_RPC_FAIL_BEFORE_ALERT=1   # tolerate 1 transient SSH/RPC fail
#
# Run via cron every minute on a host with the fleet SSH key:
#     * * * * * /usr/local/bin/coincync-fleet-partition-check >> /var/log/coincync-fleet-partition.log 2>&1
# Or wire to alertmanager / Discord webhook via the JSON output.
#
# Requires: ssh key at ~/.ssh/coincync_fleet (override with SSH_KEY env),
#           jq, python3 (one of them; jq preferred).

set -uo pipefail   # NOT -e: we need to tolerate per-host failures and report them

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="${CONFIG:-$SCRIPT_DIR/fleet-config.json}"
# Resolve HOME explicitly: cron strips environment to a minimal set
# and $HOME may be unset, making `${SSH_KEY:-$HOME/.ssh/coincync_fleet}`
# expand to `/.ssh/coincync_fleet` — a filesystem-root path that doesn't
# exist, causing 100% SSH failure precisely when the script runs in the
# context it was designed for (unattended cron monitoring). The
# `${HOME:=/root}` form sets HOME if unset AND then expands it, so this
# works both for interactive use ($HOME populated → unchanged) and cron
# (HOME unset → defaults to /root, the standard cron-user for `root@`).
# Override with `SSH_KEY=/path/to/key` env var if running as non-root.
SSH_KEY="${SSH_KEY:-${HOME:=/root}/.ssh/coincync_fleet}"
SSH_USER="${SSH_USER:-root}"
MAX_HEIGHT_DRIFT="${MAX_HEIGHT_DRIFT:-10}"
MAX_TIP_AGE_SECS="${MAX_TIP_AGE_SECS:-600}"

OUTPUT_FORMAT="text"
WATCH_INTERVAL=""
QUIET=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --json) OUTPUT_FORMAT="json"; shift ;;
        --watch) WATCH_INTERVAL="${2:-60}"; shift 2 ;;
        --quiet) QUIET=1; shift ;;
        -h|--help)
            sed -n '1,/^$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo "unknown arg: $1" >&2
            exit 1
            ;;
    esac
done

SSH_OPTS="-i $SSH_KEY -o ConnectTimeout=6 -o StrictHostKeyChecking=accept-new -o BatchMode=yes"

[[ -f "$CONFIG" ]] || { echo "FATAL: $CONFIG not found" >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "FATAL: jq required (apt install jq)" >&2; exit 2; }

probe_one() {
    local host="$1" ip="$2"
    # Pull get_info via loopback RPC on the host.
    local info
    info=$(ssh $SSH_OPTS "${SSH_USER}@${ip}" '
        K=$(grep COINCYNC_RPC_API_KEY /etc/coincync/coincync.env 2>/dev/null | cut -d= -f2)
        curl -s -m 4 http://127.0.0.1:28081/rpc/testnet \
            -H "Authorization: Bearer $K" \
            -H "Content-Type: application/json" \
            -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_info\"}" 2>/dev/null
    ' 2>/dev/null)
    if [[ -z "$info" ]]; then
        echo "$host|$ip|UNREACHABLE|0|0|0|0|"
        return
    fi
    # Parse with jq, defaulting on missing keys so output is always exactly 7 pipe-separated fields.
    local height tip_hash tip_age peers diff
    height=$(echo "$info" | jq -r '.result.height // 0' 2>/dev/null || echo 0)
    tip_hash=$(echo "$info" | jq -r '.result.tip_hash // ""' 2>/dev/null || echo "")
    tip_age=$(echo "$info" | jq -r '.result.tip_age_secs // 0' 2>/dev/null || echo 0)
    peers=$(echo "$info" | jq -r '.result.peer_count // 0' 2>/dev/null || echo 0)
    diff=$(echo "$info" | jq -r '.result.difficulty // 0' 2>/dev/null || echo 0)
    echo "$host|$ip|OK|$height|${tip_hash:0:16}|$tip_age|$peers|$diff"
}

run_check() {
    # Iterate active nodes (skip 'deactivated' section).
    local hosts ip
    hosts=$(jq -r '.nodes | keys[]' "$CONFIG" | tr -d '\r' | sort)
    local results=()
    for host in $hosts; do
        ip=$(jq -r ".nodes.\"$host\".ip" "$CONFIG")
        results+=("$(probe_one "$host" "$ip")")
    done

    # Analyze. Collect heights + tip_hashes per host.
    # NOTE: declare -A inside a function under `set -u` doesn't initialize
    # array entries; we have to explicitly init the count vars and probe
    # array length only AFTER population.
    local max_height=0
    local min_height=999999999
    local unique_tips_count=0
    local hosts_seen=0
    declare -A tips_by_hash=()
    declare -A unreachable_hosts=()
    for r in "${results[@]}"; do
        IFS='|' read -r h _ status height tip _ _ _ <<< "$r"
        hosts_seen=$((hosts_seen + 1))
        if [[ "$status" == "UNREACHABLE" ]]; then
            unreachable_hosts["$h"]=1
            continue
        fi
        (( height > max_height )) && max_height=$height
        (( height < min_height )) && min_height=$height
        # Use parameter-default substitution to avoid `unbound variable`
        # the first time a tip is seen under `set -u`.
        tips_by_hash["$tip"]="${tips_by_hash["$tip"]:-} $h"
    done
    # `${#arr[@]}` is safe on an empty array (returns 0).
    unique_tips_count=${#tips_by_hash[@]}
    # When NO hosts reachable, min_height never got set; clamp to 0.
    (( min_height == 999999999 )) && min_height=0
    local height_drift=$((max_height - min_height))

    # Verdict: divergent if (multiple distinct tips at the same height window)
    # OR (height_drift > threshold sustained). Single-tip + small drift = fine.
    local verdict="CONVERGED"
    local reason=""
    if [[ ${#unreachable_hosts[@]} -ge 2 ]]; then
        verdict="UNREACHABLE_MULTIPLE"
        reason="${#unreachable_hosts[@]} of $hosts_seen nodes unreachable: ${!unreachable_hosts[*]}"
    elif (( unique_tips_count > 1 )); then
        verdict="PARTITIONED"
        reason="$unique_tips_count distinct tip hashes seen across fleet — chain has forked"
    elif (( height_drift > MAX_HEIGHT_DRIFT )); then
        verdict="DRIFT"
        reason="height drift $height_drift blocks (max $max_height, min $min_height) > threshold $MAX_HEIGHT_DRIFT"
    fi

    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        local entries=""
        for r in "${results[@]}"; do
            IFS='|' read -r h ip status height tip tipage peers diff <<< "$r"
            [[ -n "$entries" ]] && entries+=","
            entries+="{\"host\":\"$h\",\"ip\":\"$ip\",\"status\":\"$status\",\"height\":$height,\"tip\":\"$tip\",\"tip_age_secs\":$tipage,\"peers\":$peers,\"difficulty\":\"$diff\"}"
        done
        echo "{\"verdict\":\"$verdict\",\"reason\":\"$reason\",\"max_height\":$max_height,\"min_height\":$min_height,\"unique_tips\":$unique_tips_count,\"nodes\":[$entries]}"
    else
        if [[ $QUIET -eq 1 && "$verdict" == "CONVERGED" ]]; then
            :   # quiet mode + healthy = no output
        else
            echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] fleet check: $verdict"
            [[ -n "$reason" ]] && echo "  reason: $reason"
            printf "  %-12s %-18s %-12s %-7s %-18s %-7s %s\n" "HOST" "IP" "STATUS" "HEIGHT" "TIP" "PEERS" "TIP_AGE"
            for r in "${results[@]}"; do
                IFS='|' read -r h ip status height tip tipage peers _ <<< "$r"
                printf "  %-12s %-18s %-12s %-7s %-18s %-7s %ss\n" "$h" "$ip" "$status" "$height" "$tip" "$peers" "$tipage"
            done
        fi
    fi

    # Exit code: 0 converged, 1 divergent (incl. PARTITIONED/DRIFT), 2 multiple unreachable
    case "$verdict" in
        CONVERGED) return 0 ;;
        UNREACHABLE_MULTIPLE) return 2 ;;
        *) return 1 ;;
    esac
}

if [[ -n "$WATCH_INTERVAL" ]]; then
    # SIGINT (Ctrl+C) handler — default bash behavior already exits the
    # loop, but without acknowledgement the operator wonders if `sleep`
    # got the signal or if the next `run_check` will fire first. Explicit
    # trap prints a single line on shutdown so the operator sees that
    # quitting was clean, not "I'm stuck in sleep, did it accept my
    # Ctrl+C?". `exit 130` is the POSIX convention for SIGINT (128 + 2).
    trap 'echo; echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] partition check stopped (SIGINT)"; exit 130' INT
    while true; do
        run_check
        sleep "$WATCH_INTERVAL"
    done
else
    run_check
    exit $?
fi
