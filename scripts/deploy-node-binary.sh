#!/usr/bin/env bash
# deploy-node-binary.sh — push a freshly-built coincync-node binary to
# the public-testnet fleet without wiping chain state.
#
# Use this when a commit changes node behaviour but does NOT change
# consensus (no genesis-hash impact). The chain DB on each box is left
# alone — only the binary is replaced and systemd is bounced.
#
# Use deploy/ops/redeploy-fleet.sh instead when the change DOES impact
# consensus and the testnet needs a clean wipe.
#
# Usage:
#   bash scripts/deploy-node-binary.sh                    # all hosts
#   bash scripts/deploy-node-binary.sh --only randomx     # one host
#   bash scripts/deploy-node-binary.sh --dry-run          # diff fleet only
#
# Environment overrides:
#   BINARY     — path to the built binary (default: ./out/coincync-node)
#   SSH_KEY    — ssh private key (default: ~/.ssh/coincync_fleet)
#   SERVICE    — systemd unit name (default: coincync-node)
#   INSTALL    — install path (default: /usr/local/bin/coincync-node)
#
# IMPORTANT: this script reads the fleet from scripts/fleet-config.json
# (single source of truth — see fleet-config.json _description). Hosts
# with role=api are skipped because they run nginx-only and have no
# coincync-node service to restart. Pushing the binary there would
# install it on disk but the restart step would fail.
#
# IMPORTANT: between hosts this script waits for the just-restarted
# host to reach (peer_count >= 3 AND tip_age_secs < 300) before moving
# on. This prevents the fleet partition pattern from
# [[feedback_no_bulk_rolling_restart]] (2026-06-20 + 2026-06-21 + 2026-06-22
# incidents). The old SLEEP_S=8 pause was insufficient — mesh re-handshake
# takes 30-90s per peer.
#
# IMPORTANT: on the miner host (role=miner) the script ALSO restarts
# coincync-rig after the node, because `coincync-rig.service` has
# `Requires=coincync-node.service` which is a one-shot dep at boot,
# NOT a runtime auto-restart. Without explicit `systemctl restart
# coincync-rig` the rig stays down after a node restart. Documented in
# [[project_chain_partition_2026_06_22]].

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="$SCRIPT_DIR/fleet-config.json"

BINARY="${BINARY:-./out/coincync-node}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/coincync_fleet}"
SERVICE="${SERVICE:-coincync-node}"
INSTALL="${INSTALL:-/usr/local/bin/coincync-node}"

DRY_RUN=0
ONLY_HOST=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --only)    ONLY_HOST="$2"; shift 2 ;;
        -h|--help) sed -n '1,/^$/p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *)         echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

[ -f "$BINARY" ]   || { echo "BINARY not found: $BINARY" >&2; exit 1; }
[ -f "$SSH_KEY" ]  || { echo "SSH_KEY not found: $SSH_KEY" >&2; exit 1; }
[ -f "$CONFIG" ]   || { echo "fleet-config.json not found: $CONFIG" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

SHA="$(sha256sum "$BINARY" | awk '{print $1}')"
SIZE="$(stat -c%s "$BINARY" 2>/dev/null || stat -f%z "$BINARY")"

# Build deterministic, ordered host list from fleet-config.json.
# Excludes role=api (nginx-only, no coincync-node service to restart).
# tr -d '\r' strips Windows-CRLF if the script runs on a CRLF checkout.
HOSTS=$(jq -r '.nodes | to_entries[] | select(.value.role != "api") | .key' "$CONFIG" | tr -d '\r' | sort)

echo "==> Deploying $BINARY"
echo "    size : $SIZE bytes"
echo "    sha  : $SHA"
echo "    hosts:"
for HOST in $HOSTS; do
    [[ -n "$ONLY_HOST" && "$HOST" != "$ONLY_HOST" ]] && continue
    IP=$(jq -r ".nodes.\"$HOST\".ip" "$CONFIG")
    ROLE=$(jq -r ".nodes.\"$HOST\".role" "$CONFIG")
    printf "      %-10s %-18s role=%s\n" "$HOST" "$IP" "$ROLE"
done
echo ""

if [[ $DRY_RUN -eq 1 ]]; then
    echo "[dry-run] no changes pushed."
    exit 0
fi

SSH_OPTS="-i $SSH_KEY -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -o BatchMode=yes"

for HOST in $HOSTS; do
    if [[ -n "$ONLY_HOST" && "$HOST" != "$ONLY_HOST" ]]; then
        continue
    fi
    IP=$(jq -r ".nodes.\"$HOST\".ip" "$CONFIG")
    ROLE=$(jq -r ".nodes.\"$HOST\".role" "$CONFIG")

    echo "── $HOST $IP role=$ROLE ─────────────────────────"

    # 1. Copy binary to /tmp on the box and verify SHA matches.
    echo "  scp binary..."
    scp $SSH_OPTS "$BINARY" "root@${IP}:/tmp/coincync-node.new"

    # 2. Verify SHA on remote BEFORE stopping the service (fail-fast).
    REMOTE_SHA=$(ssh $SSH_OPTS "root@${IP}" "sha256sum /tmp/coincync-node.new | awk '{print \$1}'")
    if [[ "$REMOTE_SHA" != "$SHA" ]]; then
        echo "  ✗ SHA mismatch on $HOST: $REMOTE_SHA != $SHA" >&2
        echo "    (binary was corrupted in transit; aborting fleet deploy)" >&2
        exit 2
    fi
    echo "  ✓ remote SHA verified"

    # 3. Stop, swap, restart. Rig also stopped/started if this is the miner.
    EXTRA_RIG=""
    if [[ "$ROLE" == "miner" ]]; then
        EXTRA_RIG="systemctl stop coincync-rig 2>/dev/null || true"
    fi
    EXTRA_RIG_START=""
    if [[ "$ROLE" == "miner" ]]; then
        # NEVER skip this — coincync-rig.service has Requires=coincync-node.service
        # which is a one-shot dep at boot, not a runtime auto-restart. Without
        # this explicit restart, rig stays down after node restart and the chain
        # stalls. See [[project_chain_partition_2026_06_22]].
        EXTRA_RIG_START="sleep 5; systemctl restart coincync-rig"
    fi
    ssh $SSH_OPTS "root@${IP}" bash -s <<EOSSH
set -euo pipefail
$EXTRA_RIG
chmod +x /tmp/coincync-node.new
systemctl stop ${SERVICE}
mv /tmp/coincync-node.new ${INSTALL}
systemctl start ${SERVICE}
for i in 1 2 3 4 5 6 7 8 9 10; do
  if systemctl is-active --quiet ${SERVICE}; then
    echo "  ✓ ${SERVICE} active"
    break
  fi
  sleep 1
done
systemctl is-active --quiet ${SERVICE} || { echo "  ✗ ${SERVICE} did not come up" >&2; exit 3; }
$EXTRA_RIG_START
EOSSH

    # 4. GATE BEFORE NEXT HOST — prevent fleet partition.
    #
    # `systemctl is-active` alone is insufficient: the node is "active" the
    # instant its main process is forked, but the P2P mesh takes 30-90s to
    # re-establish (per-peer Noise handshake + pending GETHEADERS recovery).
    # If we move to the next host before this host's mesh is healed, BOTH
    # hosts can simultaneously have peer_count < 3 while the miner keeps
    # producing blocks — the partition trigger documented in
    # [[feedback_no_bulk_rolling_restart]].
    #
    # Healthy "ready for next host" criteria:
    #   - peer_count >= 3 (enough mesh to gossip blocks)
    #   - tip_age_secs < 300 (chain producing/syncing; not stuck)
    # Wait up to 90s for both to be true; bail with diagnostic if not.
    echo "  waiting for mesh + chain (peer_count >= 3 AND tip_age < 300s)..."
    READY=0
    for ATTEMPT in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        sleep 6
        INFO=$(ssh $SSH_OPTS "root@${IP}" '
            K=$(grep COINCYNC_RPC_API_KEY /etc/coincync/coincync.env 2>/dev/null | cut -d= -f2)
            curl -s -m 4 http://127.0.0.1:28081/rpc/testnet \
                -H "Authorization: Bearer $K" \
                -H "Content-Type: application/json" \
                -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_info\"}" 2>/dev/null
        ' 2>/dev/null)
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
        echo "  ✗ $HOST did not reach (peer_count>=3, tip_age<300s) within 90s." >&2
        echo "    Aborting fleet deploy to prevent partition cascade." >&2
        ssh $SSH_OPTS "root@${IP}" "journalctl -u coincync-node -n 20 --no-pager | tail -15" || true
        exit 4
    fi
    echo "  ✓ $HOST mesh re-established, safe to proceed to next host"
    echo ""
done

echo "==> All fleet hosts now running new binary."
echo "    Verify network-wide:"
echo "      curl -s https://api.coincync.network/rpc/testnet \\"
echo "        -H 'content-type: application/json' \\"
echo "        -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_info\"}' | jq ."
echo "      bash scripts/check-fleet-partition.sh   # should exit 0"
