#!/bin/bash
# setup_node.sh — bootstrap a fresh Ubuntu droplet for CoinCync 1.0
# Run as root on the new droplet:
#   curl -fsSL https://raw.githubusercontent.com/you/coincync/main/scripts/setup_node.sh | bash

set -euo pipefail

REPO="https://git.coincync.network/coincync/cync-protocol.git"
INSTALL_DIR="/opt/coincync"

echo "Setting up CoinCync 1.0 node..."

# System updates
apt-get update -q
apt-get upgrade -yq

# Dependencies
apt-get install -yq \
    docker.io \
    docker-compose-plugin \
    cmake \
    clang \
    libclang-dev \
    build-essential \
    pkg-config \
    libssl-dev \
    git \
    curl \
    ufw \
    fail2ban

# Firewall
ufw allow 22/tcp     # SSH
ufw allow 28333/tcp  # P2P testnet
ufw allow 28332/tcp  # RPC (restrict in production)
ufw allow 9091/tcp   # Prometheus metrics
ufw --force enable

# Clone repo
if [ ! -d "$INSTALL_DIR" ]; then
    git clone "$REPO" "$INSTALL_DIR"
else
    cd "$INSTALL_DIR" && git pull
fi

# Create data directory
mkdir -p /var/lib/coincync
chown root:root /var/lib/coincync

# Set up systemd service (alternative to Docker)
cp "$INSTALL_DIR/deploy/coincync-node.service" /etc/systemd/system/
systemctl daemon-reload

# Build with Docker
cd "$INSTALL_DIR"
docker compose build

echo ""
echo "Setup complete!"
echo ""
echo "To start the node:"
echo "  cd $INSTALL_DIR && docker compose up -d"
echo ""
echo "To enable mining (ATL node only):"
echo "  MINING_ADDRESS=ty1... docker compose --profile mining up -d"
echo ""
echo "To check status:"
echo "  ./scripts/check_nodes.sh"
