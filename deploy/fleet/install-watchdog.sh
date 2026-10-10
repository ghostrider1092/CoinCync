#!/usr/bin/env bash
# install-watchdog.sh — install + enable the IBD-stall watchdog ON a node.
# Run locally; it pushes the script + units to each host over SSH and enables
# the timer.
#   bash deploy/fleet/install-watchdog.sh <host> [host...]
set -uo pipefail
KEY="${KEY:-$HOME/.ssh/coincync_fleet}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOSTS="$*"; [ -n "$HOSTS" ] || { echo "usage: $0 <host> [host...]" >&2; exit 64; }

for H in $HOSTS; do
  echo "######## install watchdog on $H ########"
  ssh -i "$KEY" -o ConnectTimeout=12 root@"$H" 'cat > /usr/local/bin/coincync-sync-watchdog.sh && chmod +x /usr/local/bin/coincync-sync-watchdog.sh' < "$HERE/coincync-sync-watchdog.sh"
  ssh -i "$KEY" -o ConnectTimeout=12 root@"$H" 'cat > /etc/systemd/system/coincync-sync-watchdog.service' < "$HERE/coincync-sync-watchdog.service"
  ssh -i "$KEY" -o ConnectTimeout=12 root@"$H" 'cat > /etc/systemd/system/coincync-sync-watchdog.timer'   < "$HERE/coincync-sync-watchdog.timer"
  ssh -i "$KEY" -o ConnectTimeout=12 root@"$H" 'systemctl daemon-reload; systemctl enable --now coincync-sync-watchdog.timer; echo -n "timer: "; systemctl is-active coincync-sync-watchdog.timer; systemctl list-timers coincync-sync-watchdog.timer --no-pager | sed -n 2p'
done
echo "WATCHDOG_INSTALLED"
