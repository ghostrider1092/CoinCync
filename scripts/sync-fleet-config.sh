#!/usr/bin/env bash
#
# sync-fleet-config.sh
#
# Push the systemd unit rendered from scripts/fleet-config.json to
# every active node in the fleet. Diffs against current state first
# and prompts before applying. On confirmation: scp the new unit,
# systemctl daemon-reload + restart coincync-node, verify alive.
#
# Usage:
#     scripts/sync-fleet-config.sh               # interactive; prompts before each host
#     scripts/sync-fleet-config.sh --dry-run     # diff every host, change nothing
#     scripts/sync-fleet-config.sh --yes         # skip per-host prompt (still bails on first failure)
#     scripts/sync-fleet-config.sh --only miner  # only sync the named host
#
# Requires: ssh key at ~/.ssh/coincync_fleet (override with SSH_KEY env), jq.
#
# IMPORTANT: this restarts coincync-node on every host it touches.
# Each restart is ~5-10s downtime per node. Run during a quiet period.
# Rolling sequence (one host at a time) preserves chain availability —
# the fleet keeps producing blocks even while a single node is down.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="$SCRIPT_DIR/fleet-config.json"
RENDER="$SCRIPT_DIR/render-systemd-unit.sh"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/coincync_fleet}"
SSH_USER="${SSH_USER:-root}"
REMOTE_UNIT_PATH="/etc/systemd/system/coincync-node.service"

DRY_RUN=0
ASSUME_YES=0
ONLY_HOST=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --yes|-y) ASSUME_YES=1; shift ;;
        --only) ONLY_HOST="$2"; shift 2 ;;
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

SSH_OPTS="-i $SSH_KEY -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -o BatchMode=yes"

# Iterate the nodes in deterministic order.
# `tr -d '\r'` strips Windows-CRLF carriage returns if this script is run from
# a checkout with CRLF line endings — without it, jq returns "api\r" instead
# of "api" and downstream lookups silently return null.
HOSTS=$(jq -r '.nodes | keys[]' "$CONFIG" | tr -d '\r' | sort)

for HOST in $HOSTS; do
    if [[ -n "$ONLY_HOST" && "$HOST" != "$ONLY_HOST" ]]; then
        continue
    fi
    IP=$(jq -r ".nodes.\"$HOST\".ip" "$CONFIG")
    echo
    echo "============================================================"
    echo "[$HOST $IP]"
    echo "============================================================"

    # Render the desired unit
    DESIRED=$(bash "$RENDER" "$HOST")

    # Pull the current unit (best effort — host may be down)
    CURRENT=""
    if CURRENT=$(ssh $SSH_OPTS "${SSH_USER}@${IP}" "cat $REMOTE_UNIT_PATH 2>/dev/null"); then
        :
    else
        echo "  (couldn't read current unit; treating as new install)"
    fi

    # Diff
    if [[ -n "$CURRENT" ]] && diff -q <(echo "$DESIRED") <(echo "$CURRENT") >/dev/null 2>&1; then
        echo "  unit already in sync — skipping"
        continue
    fi
    echo "  --- DIFF (current → desired) ---"
    diff <(echo "${CURRENT:-(empty)}") <(echo "$DESIRED") | sed 's/^/    /' || true
    echo

    if [[ $DRY_RUN -eq 1 ]]; then
        echo "  [dry-run] skipping apply"
        continue
    fi

    if [[ $ASSUME_YES -eq 0 ]]; then
        read -r -p "  Apply this change + restart coincync-node on $HOST? [y/N] " ans
        if [[ "$ans" != "y" && "$ans" != "Y" ]]; then
            echo "  skipped"
            continue
        fi
    fi

    # Apply
    echo "  pushing unit..."
    echo "$DESIRED" | ssh $SSH_OPTS "${SSH_USER}@${IP}" "cat > $REMOTE_UNIT_PATH"
    echo "  daemon-reload..."
    ssh $SSH_OPTS "${SSH_USER}@${IP}" "systemctl daemon-reload"
    echo "  restarting coincync-node..."
    ssh $SSH_OPTS "${SSH_USER}@${IP}" "systemctl restart coincync-node"
    sleep 6
    STATUS=$(ssh $SSH_OPTS "${SSH_USER}@${IP}" "systemctl is-active coincync-node" || echo "failed")
    echo "  status: $STATUS"
    if [[ "$STATUS" != "active" ]]; then
        echo "  FAIL: $HOST did not come back up. Investigate before continuing."
        ssh $SSH_OPTS "${SSH_USER}@${IP}" "journalctl -u coincync-node -n 20 --no-pager" || true
        exit 1
    fi

    # GATE BEFORE NEXT HOST — prevent fleet partition.
    #
    # `systemctl is-active` alone is insufficient: the node is "active" the
    # instant its main process is forked, but the P2P mesh takes 30-90s to
    # re-establish (per-peer Noise handshake + pending GETHEADERS recovery).
    # If we move to the next host before this host's mesh is healed, BOTH
    # hosts can simultaneously have peer_count < 3 while the miner keeps
    # producing blocks — the partition trigger that wedged the chain on
    # 2026-06-20 (addnode swap) and again on 2026-06-21 (recovery from
    # that wedge). See [[feedback_no_bulk_rolling_restart]] in operator
    # memory for the full incident history.
    #
    # Healthy "ready for next host" criteria:
    #   - peer_count >= 3 (enough mesh to gossip blocks)
    #   - tip_age_secs < 300 (chain producing/syncing; not stuck)
    # Wait up to 90s for both to be true; bail with diagnostic if not.
    echo "  waiting for mesh + chain to re-establish (peer_count >= 3, tip_age < 300s)..."
    READY=0
    for ATTEMPT in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        sleep 6
        # Pull get_info via loopback RPC. Need the env file for the bearer key.
        INFO=$(ssh $SSH_OPTS "${SSH_USER}@${IP}" '
            K=$(grep COINCYNC_RPC_API_KEY /etc/coincync/coincync.env 2>/dev/null | cut -d= -f2)
            curl -s -m 4 http://127.0.0.1:28081/rpc/testnet \
                -H "Authorization: Bearer $K" \
                -H "Content-Type: application/json" \
                -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_info\"}" 2>/dev/null
        ' 2>/dev/null)
        # Parse peer_count + tip_age_secs with jq if available, else python.
        if command -v jq >/dev/null 2>&1; then
            PEERS=$(echo "$INFO" | jq -r '.result.peer_count // 0' 2>/dev/null)
            TIP_AGE=$(echo "$INFO" | jq -r '.result.tip_age_secs // 999999' 2>/dev/null)
        else
            PEERS=$(echo "$INFO" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("result",{}).get("peer_count",0))' 2>/dev/null || echo 0)
            TIP_AGE=$(echo "$INFO" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("result",{}).get("tip_age_secs",999999))' 2>/dev/null || echo 999999)
        fi
        echo "    attempt $ATTEMPT/15: peer_count=$PEERS tip_age=${TIP_AGE}s"
        if [[ "$PEERS" -ge 3 && "$TIP_AGE" -lt 300 ]]; then
            READY=1
            break
        fi
    done
    if [[ $READY -ne 1 ]]; then
        echo "  FAIL: $HOST did not reach (peer_count>=3, tip_age<300s) within 90s."
        echo "  This indicates a mesh problem that could cause a fleet partition if"
        echo "  we move to the next host. Investigate before continuing (peer logs,"
        echo "  firewall, addnode reachability) — see memory feedback_no_bulk_rolling_restart."
        ssh $SSH_OPTS "${SSH_USER}@${IP}" "journalctl -u coincync-node -n 30 --no-pager | grep -E 'handshake|disconnected|orphan|peer|addnode' | tail -15" || true
        exit 1
    fi
    echo "  ✓ $HOST mesh re-established, safe to proceed to next host"
done

echo
echo "=== sync-fleet-config: complete ==="
