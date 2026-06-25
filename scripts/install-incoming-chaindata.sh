#!/bin/bash
# install-incoming-chaindata.sh — runs ON SEED1, called by the miner's
# chaindata-sync push. Atomically swaps in the new chaindata while
# the node is briefly stopped.
#
# Companion to: chaindata-sync-miner-to-seed1.sh

set -euo pipefail

LOG_TAG="chaindata-install"
DATA_DIR="/var/lib/coincync"
INCOMING="/tmp/chaindata-incoming.tar.gz"
CURRENT="${DATA_DIR}/testnet"
BACKUP="${DATA_DIR}/testnet.previous-sync"

log() { logger -t "$LOG_TAG" "$1"; echo "[$(date -u +%H:%M:%S)] $1"; }

if [ ! -f "$INCOMING" ]; then
    log "ERROR: no incoming tarball at $INCOMING — sync push must have failed"
    exit 1
fi

# Sanity: tarball should contain a `testnet/` directory at root
if ! tar tzf "$INCOMING" 2>/dev/null | head -1 | grep -q "^testnet/"; then
    log "ERROR: tarball does not contain testnet/ at root — refusing to install"
    log "        first entry: $(tar tzf "$INCOMING" 2>/dev/null | head -1)"
    rm -f "$INCOMING"
    exit 1
fi

log "stopping coincync-node"
systemctl stop coincync-node

# Rotate: current → previous-sync (single-deep backup, prior gets overwritten)
log "rotating current chaindata to backup"
rm -rf "$BACKUP"
mv "$CURRENT" "$BACKUP"

log "untarring incoming chaindata"
cd "$DATA_DIR"
tar xzf "$INCOMING"
chown -R coincync:coincync testnet

log "starting coincync-node"
systemctl start coincync-node

# Quick health check
sleep 5
if ! systemctl is-active --quiet coincync-node; then
    log "ERROR: node failed to start with new chaindata — rolling back"
    systemctl stop coincync-node
    rm -rf "$CURRENT"
    mv "$BACKUP" "$CURRENT"
    systemctl start coincync-node
    rm -f "$INCOMING"
    exit 1
fi

log "install complete — node active"
rm -f "$INCOMING"
exit 0
