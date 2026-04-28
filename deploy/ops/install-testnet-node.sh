#!/usr/bin/env bash
# Install coincync-node as a systemd service for public testnet (P2P 28080, RPC 28081).
# Run as root on Debian/Ubuntu. Intended for seed/relay operators.
#
# Usage:
#   sudo ./install-testnet-node.sh [--binary /path/to/coincync-node] [--open-ufw] [--no-enable]
#
# Before running:
#   - Place coincync-node in /usr/local/bin (default), or pass --binary.
#   - Open TCP 28080 in your cloud firewall (DigitalOcean: Networking → Firewalls).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
UNIT_SRC="$ROOT/deploy/coincync-node.service"
BINARY="/usr/local/bin/coincync-node"
OPEN_UFW=0
ENABLE=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary) BINARY="$2"; shift 2 ;;
    --open-ufw) OPEN_UFW=1; shift ;;
    --no-enable) ENABLE=0; shift ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -n 20
      exit 0
      ;;
    *) echo "unknown arg: $1"; exit 2 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root (sudo)."
  exit 1
fi

if [[ ! -f "$UNIT_SRC" ]]; then
  echo "Missing unit file: $UNIT_SRC"
  exit 2
fi

if [[ ! -x "$BINARY" ]]; then
  echo "coincync-node not executable: $BINARY"
  echo "Copy your release binary there or pass: --binary /path/to/coincync-node"
  exit 2
fi

if ! id coincync &>/dev/null; then
  useradd --system -d /var/lib/coincync -m -s /usr/sbin/nologin coincync
fi

mkdir -p /var/lib/coincync
chown -R coincync:coincync /var/lib/coincync

install -m 0644 "$UNIT_SRC" /etc/systemd/system/coincync-node.service
systemctl daemon-reload

if [[ "$OPEN_UFW" -eq 1 ]]; then
  if command -v ufw >/dev/null 2>&1; then
    ufw allow 28080/tcp comment 'CoinCync testnet P2P' || true
    echo "ufw: allowed 28080/tcp (run 'ufw enable' if firewall is inactive)"
  else
    echo "ufw not installed; open TCP 28080 in your host and cloud firewall manually."
  fi
fi

if [[ "$ENABLE" -eq 1 ]]; then
  systemctl enable coincync-node.service
  systemctl restart coincync-node.service || systemctl start coincync-node.service
  systemctl --no-pager -l status coincync-node.service || true
  echo "ok=installed coincync-node.service (journalctl -u coincync-node -f)"
else
  echo "ok=installed unit (not enabled). Enable with: systemctl enable --now coincync-node"
fi
