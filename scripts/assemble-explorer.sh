#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <src/explorer> <destination-index.html>" >&2
  exit 2
fi

SOURCE_ROOT="$(cd "$1" && pwd)"
MANIFEST="$SOURCE_ROOT/index.parts"
DESTINATION="$2"
if [ ! -f "$MANIFEST" ]; then
  echo "explorer source manifest missing: $MANIFEST" >&2
  exit 1
fi

mkdir -p "$(dirname "$DESTINATION")"
DESTINATION="$(cd "$(dirname "$DESTINATION")" && pwd)/$(basename "$DESTINATION")"
if [ "$DESTINATION" = "$SOURCE_ROOT" ] || [[ "$DESTINATION" == "$SOURCE_ROOT/"* ]]; then
  echo "refusing to write assembled output inside explorer sources" >&2
  exit 1
fi

temporary="$DESTINATION.tmp.$$"
trap 'rm -f "$temporary"' EXIT
: > "$temporary"

declare -A seen=()
part_count=0
while IFS= read -r part || [ -n "$part" ]; do
  case "$part" in
    ""|\#*) continue ;;
    /*|*\\*) echo "unsafe explorer source path: $part" >&2; exit 1 ;;
  esac
  case "/$part/" in
    *"/../"*) echo "unsafe explorer source path: $part" >&2; exit 1 ;;
  esac
  if [ -n "${seen[$part]+present}" ]; then
    echo "duplicate explorer source path: $part" >&2
    exit 1
  fi
  source_path="$SOURCE_ROOT/$part"
  if [ ! -s "$source_path" ]; then
    echo "missing or empty explorer source part: $part" >&2
    exit 1
  fi
  seen["$part"]=1
  cat "$source_path" >> "$temporary"
  part_count=$((part_count + 1))
done < "$MANIFEST"

if [ "$part_count" -eq 0 ]; then
  echo "explorer source manifest contains no parts: $MANIFEST" >&2
  exit 1
fi

# ── CACHE-BUSTING ────────────────────────────────────────────────────────────
# Stamp every first-party asset URL in the assembled HTML with a per-build
# ?v=<token>. The token is a content hash of the bundle (assembled HTML + all
# app/*.js + explorer.css + theme-init.js), so it changes ONLY when something
# actually changed. Because the HTML itself is served uncached (Cloudflare
# cf-cache-status: DYNAMIC for text/html), a new deploy ships new asset URLs,
# which Cloudflare/browsers treat as fresh (cache MISS) — so deploys go live
# without any manual "Purge Everything". nginx ignores the query string when
# serving the static file, so the files themselves are installed unchanged.
set +e
VBUST=$( { cat "$temporary"; cat "$SOURCE_ROOT"/app/*.js "$SOURCE_ROOT/explorer.css" "$SOURCE_ROOT/theme-init.js" 2>/dev/null; } | sha256sum 2>/dev/null | cut -c1-12 )
set -e
[ -n "$VBUST" ] || VBUST="$(date +%s)"
sed -i \
  -e 's|src="app/\([^"?]*\.js\)"|src="app/\1?v='"$VBUST"'"|g' \
  -e 's|href="explorer\.css"|href="explorer.css?v='"$VBUST"'"|g' \
  -e 's|src="theme-init\.js"|src="theme-init.js?v='"$VBUST"'"|g' \
  -e 's|src="/static/vendor/\([^"?]*\)"|src="/static/vendor/\1?v='"$VBUST"'"|g' \
  -e 's|href="/assets/\([^"?]*\.css\)"|href="/assets/\1?v='"$VBUST"'"|g' \
  "$temporary"
echo "assemble-explorer: cache-bust token v=$VBUST" >&2

mv "$temporary" "$DESTINATION"
trap - EXIT
