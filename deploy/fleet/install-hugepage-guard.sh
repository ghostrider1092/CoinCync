#!/usr/bin/env bash
# install-hugepage-guard.sh — install + enable the RandomX huge-page guard ON a
# FULL-MEM MINER box. Run locally; it pushes the script + units to each host
# over SSH and enables the timer.
#   bash deploy/fleet/install-hugepage-guard.sh <host> [host...]
#
# Install ONLY on boxes that reserve huge pages (vm.nr_hugepages set, see
# 60-coincync-hugepages.conf) and run coincync-baseline-miner. On any other box
# the guard is a harmless no-op (it exits when no huge pages are reserved), but
# there is no reason to run it there.
set -uo pipefail
KEY="${KEY:-$HOME/.ssh/coincync_fleet}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOSTS="$*"; [ -n "$HOSTS" ] || { echo "usage: $0 <host> [host...]" >&2; exit 64; }

for H in $HOSTS; do
  echo "######## install huge-page guard on $H ########"
  ssh -i "$KEY" -o ConnectTimeout=12 root@"$H" 'cat > /usr/local/bin/coincync-hugepage-guard.sh && chmod +x /usr/local/bin/coincync-hugepage-guard.sh' < "$HERE/coincync-hugepage-guard.sh"
  ssh -i "$KEY" -o ConnectTimeout=12 root@"$H" 'cat > /etc/systemd/system/coincync-hugepage-guard.service' < "$HERE/coincync-hugepage-guard.service"
  ssh -i "$KEY" -o ConnectTimeout=12 root@"$H" 'cat > /etc/systemd/system/coincync-hugepage-guard.timer'   < "$HERE/coincync-hugepage-guard.timer"
  ssh -i "$KEY" -o ConnectTimeout=12 root@"$H" 'systemctl daemon-reload; systemctl enable --now coincync-hugepage-guard.timer; echo -n "timer: "; systemctl is-active coincync-hugepage-guard.timer; systemctl list-timers coincync-hugepage-guard.timer --no-pager | sed -n 2p'
done
echo "HUGEPAGE_GUARD_INSTALLED"
