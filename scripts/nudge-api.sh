#!/bin/bash
# Add --addnode 66.135.23.193:28080 (seed1) to api's systemd unit and restart.
set -euo pipefail

UNIT=/etc/systemd/system/coincync-node.service

# Idempotent — only patch if seed1 isn't already in there
if grep -q 'addnode 66.135.23.193' "$UNIT"; then
  echo "seed1 already present in --addnode list; just restarting"
else
  # Inject after --log-level info (same hook the provisioner uses)
  sed -i 's|--log-level info|--log-level info --addnode 66.135.23.193:28080|' "$UNIT"
  echo "Patched: added --addnode 66.135.23.193:28080"
fi

systemctl daemon-reload
systemctl restart coincync-node

for i in 1 2 3 4 5 6 7 8 9 10; do
  sleep 1
  systemctl is-active --quiet coincync-node && break
done
systemctl is-active --quiet coincync-node || {
  echo "FAIL: service did not become active"
  journalctl -u coincync-node -n 30 --no-pager
  exit 1
}
echo "Service restarted; ExecStart now:"
systemctl cat coincync-node | grep ExecStart -A 1 | head -3
