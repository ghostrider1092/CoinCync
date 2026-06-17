#!/usr/bin/env bash
#
# deploy-s1-fix-2026-06-15.sh
#
# DESTRUCTIVE: stops the fleet, wipes chain data on every node, pushes
# the v1.0.11.2-testnet binary, and restarts mining from new genesis.
#
# Triggered by the 2026-06-15 discovery that v1.0.11-fleet-2026-06-06
# was missing the v1.0.12 S1 ASERT denominator fix. Every block on the
# current chain was mined under the buggy formula; the fixed binary
# (this commit 13a8b12d, tagged v1.0.11.2-testnet) computes targets
# that don't match the existing history. A wipe is the only correct
# resolution. See git log for the full root-cause writeup.
#
# REVIEW BEFORE RUNNING. Operator must:
#   1. Confirm the LINUX binary path (BINARY_PATH below) is the
#      coincync-node binary built from v1.0.11.2-testnet under Linux
#      (NOT a Windows .exe, NOT a stale 1.0.11 build).
#   2. Confirm FLEET_HOSTS — memory says seed3 + api may be DEAD; if
#      so, set FLEET_HOSTS to just the live nodes before running.
#   3. Read each step block — the script PAUSES between phases for a
#      single 'y' confirmation. Anything else aborts.
#
# Usage:
#     ./scripts/deploy-s1-fix-2026-06-15.sh [BINARY_PATH]
#
# Default BINARY_PATH: ~/cync-s1-fix-target/release/coincync-node
# (the WSL build path used in the 2026-06-15 hot-fix session).

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────
BINARY_PATH="${1:-$HOME/cync-s1-fix-target/release/coincync-node}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/coincync_fleet}"
SSH_USER="${SSH_USER:-root}"

# Latest peer-table fleet from scripts/configure-fleet-mesh.sh.
# CAVEAT (per memory): seed3 (207.148.111.76) and api (95.179.165.225)
# were flagged as dead in the 2026-06-14 v1.0.11 deploy followups list.
# Verify reachability before running. If dead, COMMENT OUT the dead
# entries (do not delete — operator may have brought them back).
declare -A FLEET_HOSTS=(
    [seed1]="66.135.23.193"
    [seed2]="140.82.57.168"
    [seed3]="207.148.111.76"      # MEMORY: flagged dead 2026-06-14 — verify
    [explorer]="207.148.6.50"
    [api]="95.179.165.225"        # MEMORY: London box deleted 2026-06-04 — verify
)

REMOTE_BINARY_DEST="/usr/local/bin/coincync-node"
REMOTE_SERVICE="coincync-node"
REMOTE_DATA_DIR="/var/lib/coincync"   # operator: confirm against systemd unit

# ── Helpers ──────────────────────────────────────────────────────────
SSH_OPTS="-i $SSH_KEY -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new"

confirm() {
    echo
    echo "================================================================"
    echo "  $1"
    echo "================================================================"
    read -r -p "Proceed? [y/N] " ans
    [[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "aborted"; exit 1; }
}

run_each() {
    local label="$1"; shift
    local cmd="$*"
    for host_name in "${!FLEET_HOSTS[@]}"; do
        local ip="${FLEET_HOSTS[$host_name]}"
        echo "→ [$host_name $ip] $label"
        if ! ssh $SSH_OPTS "${SSH_USER}@${ip}" "$cmd"; then
            echo "FAIL on $host_name ($ip). Aborting."
            exit 1
        fi
    done
}

# ── Pre-flight ───────────────────────────────────────────────────────
echo "=== Pre-flight ==="
if [[ ! -x "$BINARY_PATH" ]]; then
    echo "FATAL: binary not found or not executable: $BINARY_PATH"
    exit 1
fi
file_type=$(file "$BINARY_PATH")
echo "Binary: $BINARY_PATH"
echo "  $file_type"
if ! echo "$file_type" | grep -q "ELF.*x86-64"; then
    echo "FATAL: binary is not Linux ELF x86-64. Re-build under WSL/Linux."
    exit 1
fi
binary_version=$("$BINARY_PATH" --version 2>&1 || echo "version check failed")
echo "  reports: $binary_version"

echo
echo "Fleet hosts to deploy to:"
for h in "${!FLEET_HOSTS[@]}"; do echo "  $h → ${FLEET_HOSTS[$h]}"; done
echo
echo "SSH key: $SSH_KEY"
echo "Tag:     v1.0.11.2-testnet (commit 13a8b12d)"
echo

confirm "Phase 1 of 5: verify SSH reachability + current binary version on each host (READ-ONLY)"

# ── Phase 1: probe ───────────────────────────────────────────────────
for host_name in "${!FLEET_HOSTS[@]}"; do
    ip="${FLEET_HOSTS[$host_name]}"
    echo "→ [$host_name $ip] probe"
    ssh $SSH_OPTS -o BatchMode=yes "${SSH_USER}@${ip}" \
        "echo '  uname:' \$(uname -a); \
         echo '  version:' \$($REMOTE_BINARY_DEST --version 2>/dev/null || echo none); \
         echo '  service:' \$(systemctl is-active $REMOTE_SERVICE 2>/dev/null || echo inactive)" \
        || { echo "FAIL probe $host_name ($ip)"; exit 1; }
done

confirm "Phase 2 of 5: STOP coincync-node service on every host (DESTRUCTIVE — mining halts)"

# ── Phase 2: stop service ────────────────────────────────────────────
run_each "stop service" "systemctl stop $REMOTE_SERVICE"

confirm "Phase 3 of 5: WIPE $REMOTE_DATA_DIR/chaindata on every host (DESTRUCTIVE — chain history LOST)"

# ── Phase 3: wipe chain data ─────────────────────────────────────────
# Preserve node_key + node_signing_key (network identity); only wipe
# the chain database itself.
run_each "wipe chaindata" "rm -rf $REMOTE_DATA_DIR/chaindata $REMOTE_DATA_DIR/mempool.dat 2>/dev/null; \
                          ls -la $REMOTE_DATA_DIR/ 2>/dev/null | head -10"

confirm "Phase 4 of 5: SCP new binary + verify checksum on every host (REPLACES /usr/local/bin/coincync-node)"

# ── Phase 4: push new binary ─────────────────────────────────────────
binary_sha=$(sha256sum "$BINARY_PATH" | awk '{print $1}')
echo "local binary sha256: $binary_sha"
for host_name in "${!FLEET_HOSTS[@]}"; do
    ip="${FLEET_HOSTS[$host_name]}"
    echo "→ [$host_name $ip] push binary"
    scp $SSH_OPTS "$BINARY_PATH" "${SSH_USER}@${ip}:${REMOTE_BINARY_DEST}.new"
    remote_sha=$(ssh $SSH_OPTS "${SSH_USER}@${ip}" "sha256sum ${REMOTE_BINARY_DEST}.new | awk '{print \$1}'")
    if [[ "$remote_sha" != "$binary_sha" ]]; then
        echo "FAIL checksum mismatch on $host_name: $remote_sha != $binary_sha"
        exit 1
    fi
    ssh $SSH_OPTS "${SSH_USER}@${ip}" "chmod +x ${REMOTE_BINARY_DEST}.new && \
                                       mv ${REMOTE_BINARY_DEST}.new ${REMOTE_BINARY_DEST}"
    new_version=$(ssh $SSH_OPTS "${SSH_USER}@${ip}" "${REMOTE_BINARY_DEST} --version")
    echo "  installed: $new_version"
done

confirm "Phase 5 of 5: START seed1 FIRST, let it mine genesis + first blocks, then start seed2..."

# ── Phase 5: start in sequence (seed1 first, others sync) ────────────
# seed1 mines genesis. Wait for it to confirm a few blocks before
# starting peers — prevents seed2/3 from coming up with empty chain,
# bouncing on the genesis-validation handshake, and reconnecting in a
# tight loop.
echo "→ [seed1 ${FLEET_HOSTS[seed1]}] start service"
ssh $SSH_OPTS "${SSH_USER}@${FLEET_HOSTS[seed1]}" "systemctl start $REMOTE_SERVICE"
sleep 5
ssh $SSH_OPTS "${SSH_USER}@${FLEET_HOSTS[seed1]}" \
    "systemctl is-active $REMOTE_SERVICE && \
     journalctl -u $REMOTE_SERVICE -n 15 --no-pager"

confirm "seed1 is up. Start the remaining nodes (seed2, seed3, explorer, api) in parallel?"

for host_name in seed2 seed3 explorer api; do
    if [[ -n "${FLEET_HOSTS[$host_name]:-}" ]]; then
        ip="${FLEET_HOSTS[$host_name]}"
        echo "→ [$host_name $ip] start service"
        ssh $SSH_OPTS "${SSH_USER}@${ip}" "systemctl start $REMOTE_SERVICE" &
    fi
done
wait

echo
echo "=== Deploy complete ==="
echo "Verify with:"
echo "  curl -sS http://${FLEET_HOSTS[seed1]}:28081/rpc/testnet \\"
echo "      -X POST -H 'content-type: application/json' \\"
echo "      --data '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_blockchain_info\",\"params\":[]}'"
echo
echo "Next: post the tester message in #testnet — see message draft in"
echo "session output."
