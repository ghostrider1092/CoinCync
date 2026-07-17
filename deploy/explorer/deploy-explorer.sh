#!/usr/bin/env bash
set -euo pipefail

# One-command explorer deploy for the RIC host.
# - updates git checkout
# - syncs explorer first-party assets to nginx docroot
# - reloads services
# - verifies new operator markers are served publicly

REPO_DIR="${REPO_DIR:-/opt/coincync}"
BRANCH="${BRANCH:-main}"
CUSTOM_SRC_HTML=0
if [ -n "${SRC_HTML:-}" ] && [ -z "${SRC_DIR:-}" ]; then
  SRC_DIR="$(dirname "$SRC_HTML")"
  CUSTOM_SRC_HTML=1
elif [ -n "${SRC_HTML:-}" ]; then
  CUSTOM_SRC_HTML=1
fi
if [ -n "${DEST_HTML:-}" ] && [ -z "${DEST_DIR:-}" ]; then
  DEST_DIR="$(dirname "$DEST_HTML")"
fi
SRC_DIR="${SRC_DIR:-$REPO_DIR/src/explorer}"
DEST_DIR="${DEST_DIR:-/var/www/explorer}"
DEST_HTML="${DEST_HTML:-$DEST_DIR/index.html}"
NODE_SERVICE="${NODE_SERVICE:-coincync-node}"
VERIFY_REGEX="${VERIFY_REGEX:-ops-fresh-dot|blocks-direct-lookup|ops-alert-feed}"
ASSETS=(explorer.css theme-init.js)
APP_MANIFEST=app.scripts.html

echo "==> Deploying CoinCync explorer"
echo "    repo:   $REPO_DIR"
echo "    branch: $BRANCH"
echo "    src:    $SRC_DIR"
echo "    dest:   $DEST_DIR"

cd "$REPO_DIR"
git fetch origin
git checkout "$BRANCH"
git pull --ff-only origin "$BRANCH"

for asset in "${ASSETS[@]}" "$APP_MANIFEST"; do
  if [ ! -f "$SRC_DIR/$asset" ]; then
    echo "ERROR: required explorer asset missing: $SRC_DIR/$asset" >&2
    exit 1
  fi
done
if [ ! -d "$SRC_DIR/app" ]; then
  echo "ERROR: required explorer application directory missing: $SRC_DIR/app" >&2
  exit 1
fi
app_assets=()
script_prefix='<script src="'
script_suffix='"></script>'
while IFS= read -r raw || [ -n "$raw" ]; do
  line="${raw%$'\r'}"
  if [ -z "$line" ]; then
    continue
  fi
  if [[ "$line" != "$script_prefix"*"$script_suffix" ]]; then
    echo "ERROR: invalid explorer application manifest entry: $line" >&2
    exit 1
  fi
  relative="${line#"$script_prefix"}"
  relative="${relative%"$script_suffix"}"
  case "$relative" in
    app/*/*.js) echo "ERROR: nested explorer application asset path is not supported: $relative" >&2; exit 1 ;;
    app/*.js) app_assets+=("$relative") ;;
    *) echo "ERROR: invalid explorer application asset path: $relative" >&2; exit 1 ;;
  esac
done < "$SRC_DIR/$APP_MANIFEST"
if [ "${#app_assets[@]}" -eq 0 ]; then
  echo "ERROR: explorer application manifest has no scripts: $SRC_DIR/$APP_MANIFEST" >&2
  exit 1
fi

assembled_html=""
bundle_dir=""
cleanup() {
  if [ -n "$assembled_html" ]; then
    rm -f "$assembled_html"
  fi
  if [ -n "$bundle_dir" ]; then
    rm -rf "$bundle_dir"
  fi
}
trap cleanup EXIT

if [ "$CUSTOM_SRC_HTML" -eq 0 ]; then
  assembled_html="$(mktemp)"
  bash "$REPO_DIR/scripts/assemble-explorer.sh" "$SRC_DIR" "$assembled_html"
  SRC_HTML="$assembled_html"
fi
if [ ! -f "$SRC_HTML" ]; then
  echo "ERROR: required explorer HTML missing: $SRC_HTML" >&2
  exit 1
fi

DEST_DIR="$(realpath -m "$DEST_DIR")"
DEST_HTML="$(realpath -m "$DEST_HTML")"
if [ "$(dirname "$DEST_HTML")" != "$DEST_DIR" ]; then
  echo "ERROR: DEST_HTML must be a direct child of DEST_DIR for transactional deployment" >&2
  exit 1
fi
dest_html_name="$(basename "$DEST_HTML")"

bundle_dir="$(mktemp -d)"
install -d "$bundle_dir/app"
install -m 0644 "$SRC_HTML" "$bundle_dir/$dest_html_name"
for asset in "${ASSETS[@]}"; do
  install -m 0644 "$SRC_DIR/$asset" "$bundle_dir/$asset"
done
install -m 0644 "$SRC_DIR/$APP_MANIFEST" "$bundle_dir/$APP_MANIFEST"
for relative in "${app_assets[@]}"; do
  if [ ! -f "$SRC_DIR/$relative" ]; then
    echo "ERROR: explorer application asset missing: $SRC_DIR/$relative" >&2
    exit 1
  fi
  install -m 0644 "$SRC_DIR/$relative" "$bundle_dir/$relative"
done
sudo bash "$REPO_DIR/scripts/install-explorer-bundle.sh" \
  "$bundle_dir" "$DEST_DIR" "$dest_html_name"

sudo systemctl restart "$NODE_SERVICE"
sudo nginx -t
sudo systemctl reload nginx

echo "==> Verifying local file markers"
grep -En "$VERIFY_REGEX" "$DEST_HTML" "$DEST_DIR/app/"*.js >/dev/null
echo "    ok: markers present in deployed explorer sources"

echo "==> Verifying public response markers"
cache_bust="$(date +%s)"
if public_html="$(curl -fsSL --compressed "https://explorer.coincync.network/?v=$cache_bust")" &&
   public_core="$(curl -fsSL --compressed "https://explorer.coincync.network/app/01-core.js?v=$cache_bust")" &&
   printf '%s\n' "$public_html" | grep -E "$VERIFY_REGEX" >/dev/null &&
   printf '%s\n' "$public_core" | grep -F "_computeApiBase" >/dev/null; then
  echo "    ok: public explorer is serving updated build"
else
  echo "    warn: public response missing markers (likely CDN/browser cache)"
  echo "    hint: open https://explorer.coincync.network/?v=$cache_bust in private window"
fi

echo "==> Done"
