#!/bin/bash
# chaindata-sync-miner-to-seed1.sh — periodic chaindata snapshot from
# miner to seed1 to keep public RPC fresh during the seed1 peering
# repair window.
#
# Runs ON THE MINER (173.199.93.21). Pushes to seed1 via SCP.
#
# What this works around (2026-06-23 → ~2026-07-15):
#   seed1 cannot establish outbound peering to the miner (suspected
#   eclipse-defense + self-IP-in-addnode + nginx-only api confusion).
#   Without gossip, seed1's chain tip falls behind the miner's. This
#   script periodically transfers chaindata so the public RPC stays
#   within ~10 min of the miner's tip.
#
# Cost per run:
#   ~1s miner downtime (tar window)
#   ~6 MB transfer (current chain size; will grow)
#   ~10s seed1 service downtime (stop/replace/start)
#   Total: ~15s of "fleet appears partially stalled" per run
#
# Recommended cadence: every 10 min via cron.
#   Block time = 120s → 5 blocks per 10 min → max staleness ~5 blocks.
#
# Remove this once the underlying peering issue is fixed (track via
# memory: project_chain_partition_2026_06_22).

set -euo pipefail

LOG_TAG="chaindata-sync"
SEED1_IP="66.135.23.193"
SEED1_KEY="/root/.ssh/coincync_fleet"   # deploy this key to miner first
TARBALL_LOCAL="/tmp/chaindata-sync-miner.tar.gz"
TARBALL_REMOTE="/tmp/chaindata-incoming.tar.gz"

log() { logger -t "$LOG_TAG" "$1"; echo "[$(date -u +%H:%M:%S)] $1"; }

# Verify prerequisites BEFORE stopping the node
if [ ! -f "$SEED1_KEY" ]; then
    log "ERROR: ssh key missing at $SEED1_KEY — cannot push to seed1; aborting"
    exit 1
fi

# Tar window — stop miner node briefly for consistent RocksDB snapshot
log "stopping coincync-node for snapshot"
systemctl stop coincync-node

log "tarring chaindata"
cd /var/lib/coincync
tar czf "$TARBALL_LOCAL" testnet
TARBALL_SIZE=$(stat -c%s "$TARBALL_LOCAL")

log "starting coincync-node back up (downtime ~1s)"
systemctl start coincync-node

# IMPORTANT: also restart coincync-rig — systemd dep kills it on node-stop
# (Discovered 2026-06-24: coincync-rig is killed by SIGTERM when
#  coincync-node stops; no auto-restart because exit-on-TERM isn't a
#  failure. Without this, mining stays dead.)
log "restarting coincync-rig (avoid the systemd-dep-killed-rig footgun)"
systemctl restart coincync-rig

# Transfer
log "scp tarball to seed1 (${TARBALL_SIZE} bytes)"
scp -i "$SEED1_KEY" \
    -o StrictHostKeyChecking=no \
    -o ConnectTimeout=15 \
    -o ServerAliveInterval=5 \
    "$TARBALL_LOCAL" "root@${SEED1_IP}:${TARBALL_REMOTE}"

# Trigger install on seed1
log "triggering install on seed1"
ssh -i "$SEED1_KEY" \
    -o StrictHostKeyChecking=no \
    -o ConnectTimeout=15 \
    "root@${SEED1_IP}" 'bash /usr/local/bin/install-incoming-chaindata.sh'

log "sync complete"
exit 0
