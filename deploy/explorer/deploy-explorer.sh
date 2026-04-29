#!/usr/bin/env bash
set -euo pipefail

# One-command explorer deploy for the RIC host.
# - updates git checkout
# - syncs explorer HTML to nginx docroot
# - reloads services
# - verifies new operator markers are served publicly

REPO_DIR="${REPO_DIR:-/opt/coincync}"
BRANCH="${BRANCH:-main}"
SRC_HTML="${SRC_HTML:-$REPO_DIR/src/explorer/index.html}"
DEST_HTML="${DEST_HTML:-/var/www/explorer/index.html}"
NODE_SERVICE="${NODE_SERVICE:-coincync-node}"
VERIFY_REGEX="${VERIFY_REGEX:-ops-fresh-dot|blocks-direct-lookup|ops-alert-feed}"

echo "==> Deploying CoinCync explorer"
echo "    repo:   $REPO_DIR"
echo "    branch: $BRANCH"
echo "    src:    $SRC_HTML"
echo "    dest:   $DEST_HTML"

cd "$REPO_DIR"
git fetch origin
git checkout "$BRANCH"
git pull --ff-only origin "$BRANCH"

sudo cp -f "$SRC_HTML" "$DEST_HTML"
sudo chown root:root "$DEST_HTML"
sudo chmod 644 "$DEST_HTML"

sudo systemctl restart "$NODE_SERVICE"
sudo nginx -t
sudo systemctl reload nginx

echo "==> Verifying local file markers"
grep -En "$VERIFY_REGEX" "$DEST_HTML" >/dev/null
echo "    ok: markers present in $DEST_HTML"

echo "==> Verifying public response markers"
if curl -fsSL --compressed "https://explorer.coincync.network/?v=$(date +%s)" | grep -E "$VERIFY_REGEX" >/dev/null; then
  echo "    ok: public explorer is serving updated build"
else
  echo "    warn: public response missing markers (likely CDN/browser cache)"
  echo "    hint: open https://explorer.coincync.network/?v=$(date +%s) in private window"
fi

echo "==> Done"
