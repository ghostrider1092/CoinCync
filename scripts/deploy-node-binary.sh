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
# Usage (from this repo's root, after a Docker build into ./out/):
#   bash scripts/deploy-node-binary.sh
#
# Environment overrides:
#   BINARY     — path to the built binary (default: ./out/coincync-node)
#   FLEET      — space-separated list of root@host targets
#   SSH_KEY    — ssh private key (default: ~/.ssh/coincync_fleet)
#   SERVICE    — systemd unit name (default: coincync-node)
#   INSTALL    — install path (default: /usr/local/bin/coincync-node)
#   SLEEP_S    — pause between boxes for rolling restart (default: 8)

set -euo pipefail

BINARY="${BINARY:-./out/coincync-node}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/coincync_fleet}"
SERVICE="${SERVICE:-coincync-node}"
INSTALL="${INSTALL:-/usr/local/bin/coincync-node}"
SLEEP_S="${SLEEP_S:-8}"
FLEET="${FLEET:-root@66.135.23.193 root@140.82.57.168 root@207.148.111.76 root@207.148.6.50 root@95.179.165.225}"

[ -f "$BINARY" ] || { echo "BINARY not found: $BINARY" >&2; exit 1; }
[ -f "$SSH_KEY" ] || { echo "SSH_KEY not found: $SSH_KEY" >&2; exit 1; }

SHA="$(sha256sum "$BINARY" | awk '{print $1}')"
SIZE="$(stat -c%s "$BINARY" 2>/dev/null || stat -f%z "$BINARY")"
echo "==> Deploying $BINARY"
echo "    size : $SIZE bytes"
echo "    sha  : $SHA"
echo "    fleet: $FLEET"
echo ""

for target in $FLEET; do
  echo "── $target ─────────────────────────────────────────"
  scp -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new \
    "$BINARY" "$target:/tmp/coincync-node.new"
  ssh -i "$SSH_KEY" "$target" bash -s <<EOSSH
set -euo pipefail
remote_sha=\$(sha256sum /tmp/coincync-node.new | awk '{print \$1}')
if [ "\$remote_sha" != "$SHA" ]; then
  echo "REMOTE SHA MISMATCH: \$remote_sha != $SHA" >&2
  exit 2
fi
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
EOSSH
  echo "  pause ${SLEEP_S}s before next box (rolling restart, keeps quorum)"
  sleep "$SLEEP_S"
  echo ""
done

echo "==> All fleet boxes restarted on new binary."
echo "    Verify chain advances:"
echo "      curl -s -X POST https://api.coincync.network/rpc/testnet \\"
echo "        -H 'content-type: application/json' \\"
echo "        -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_info\"}' | jq ."
