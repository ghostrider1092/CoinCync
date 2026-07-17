#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# CoinCync explorer — flip CDN URLs to vendored paths in frontend sources
# ──────────────────────────────────────────────────────────────────────
#
# This script does the destructive source edit that turns the embedded
# block explorer from "fetches from cdn.jsdelivr.net" into "fetches
# from /static/vendor/...". Run it AFTER `./fetch-vendor.sh` succeeds,
# so the vendored files actually exist on disk.
#
# Why it's a separate script:
#
#   - fetch-vendor.sh is idempotent (TOFU-pinned, safe to re-run)
#   - patch-vendor.sh is a one-way source edit that, if run twice,
#     would either no-op or produce broken output
#   - Splitting them means CI / ops can verify vendored files exist
#     BEFORE rewriting the sources, instead of leaving the explorer
#     broken between the download step and the patch step
#
# Workflow:
#
#   ./fetch-vendor.sh        # populate static/vendor/
#   ./patch-vendor.sh        # rewrite the explorer shell + app/*.js
#   git diff src/explorer/fragments/00-shell.html src/explorer/app
#   cargo test --lib -p coincync explorer
#                            # the existing CDN-enumeration test in
#                            # rpc/explorer.rs::tests will fail until
#                            # you update its expected list to match
#                            # the post-patch state
#
# After patch-vendor.sh runs successfully, you should ALSO update
# `rpc::explorer::tests::explorer_html_lists_external_cdns` to drop
# the patched-out origins. The test is intentionally a positive
# enumeration — it moves with the asset trimming.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR_DIR="$SCRIPT_DIR/static/vendor"
SOURCE_PATHS=(
  "$SCRIPT_DIR/../../src/explorer/fragments/00-shell.html"
  "$SCRIPT_DIR/../../src/explorer/app/"*.js
)

if [ -t 1 ]; then
  RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
  RED=''; GRN=''; YLW=''; DIM=''; RST=''
fi

for source_path in "${SOURCE_PATHS[@]}"; do
  if [ ! -f "$source_path" ]; then
    echo "${RED}ERROR${RST}: $source_path not found"
    exit 1
  fi
done

# ── Pre-flight: every vendored file must exist ────────────────────────
#
# Patching the HTML before the files are on disk would brick the
# explorer until fetch-vendor.sh runs. Refuse loudly instead.
required=(
  "chart.js/4.4.0/chart.umd.min.js"
  "d3/7/d3.min.js"
  "topojson-client/3/topojson-client.min.js"
  "globe.gl/2.27.3/globe.gl.min.js"
  "world-atlas/2/countries-110m.json"
  "three-globe/textures/earth-day.jpg"
  "three-globe/textures/earth-night.jpg"
  "three-globe/textures/earth-topology.png"
  "fonts/fonts.css"
)

missing=0
for r in "${required[@]}"; do
  if [ ! -f "$VENDOR_DIR/$r" ]; then
    echo "${RED}MISSING${RST}  $r"
    missing=$((missing + 1))
  fi
done

if [ "$missing" -gt 0 ]; then
  echo
  echo "${RED}refusing to patch HTML${RST}: $missing vendored file(s) missing."
  echo "${YLW}fix${RST}: run \`./fetch-vendor.sh\` first."
  exit 1
fi

# ── Backups ───────────────────────────────────────────────────────────
for source_path in "${SOURCE_PATHS[@]}"; do
  backup="$source_path.pre-vendor-patch.bak"
  cp "$source_path" "$backup"
  echo "${DIM}backup${RST}   $backup"
done

# ── Patch table ───────────────────────────────────────────────────────
#
# Each entry: "<find>|<replace>"
#
# The find side is the exact URL that appears in the explorer sources today.
# The replace side is the vendored same-origin path (relative to
# /static/vendor/), served by the production web server from
# `deploy/explorer/static/vendor`.
#
# IMPORTANT: each find/replace is run as a literal string substitution
# (with `sed -i 's|...|...|g'`), so neither side may contain a `|`.
# All current URLs are pipe-free, so this is safe.
#
# IMPORTANT: each patch is run with the strings passed to perl via
# the FIND/REPL environment variables (NOT bash interpolation into
# the perl source), because perl's `\Q...\E` does NOT prevent
# variable interpolation, and `@4.4.0` in a chart.js URL would be
# interpolated as the empty array `@4` and silently produce a
# pattern that doesn't match anything in the file. Discovered the
# hard way during the first vendoring run on Git Bash.
PATCHES=(
  # ── Script-tag CDN includes in the HTML shell ──────────────────
  "https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js|/static/vendor/chart.js/4.4.0/chart.umd.min.js"
  "https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js|/static/vendor/d3/7/d3.min.js"
  "https://cdn.jsdelivr.net/npm/topojson-client@3/dist/topojson-client.min.js|/static/vendor/topojson-client/3/topojson-client.min.js"
  "https://cdn.jsdelivr.net/npm/globe.gl@2.27.3/dist/globe.gl.min.js|/static/vendor/globe.gl/2.27.3/globe.gl.min.js"

  # ── Inline d3.json() world-atlas fetches ───────────────────────
  # The explorer application calls d3.json('https://...countries-110m.json')
  # at multiple points (line ~3076 and ~3687). Both fetch the same
  # file we already vendored above as the script-tag asset.
  "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json|/static/vendor/world-atlas/2/countries-110m.json"

  # ── three-globe earth textures ─────────────────────────────────
  # The 3D globe widget loads three textures via TWO different URL
  # forms (npm/... and gh/vasturiano/...) which both resolve to the
  # same upstream files. We patch both forms to the same vendored
  # path so the globe works regardless of which URL the application
  # tries.
  "https://cdn.jsdelivr.net/npm/three-globe/example/img/earth-day.jpg|/static/vendor/three-globe/textures/earth-day.jpg"
  "https://cdn.jsdelivr.net/gh/vasturiano/three-globe/example/img/earth-day.jpg|/static/vendor/three-globe/textures/earth-day.jpg"
  "https://cdn.jsdelivr.net/npm/three-globe/example/img/earth-night.jpg|/static/vendor/three-globe/textures/earth-night.jpg"
  "https://cdn.jsdelivr.net/gh/vasturiano/three-globe/example/img/earth-night.jpg|/static/vendor/three-globe/textures/earth-night.jpg"
  "https://cdn.jsdelivr.net/npm/three-globe/example/img/earth-topology.png|/static/vendor/three-globe/textures/earth-topology.png"
  "https://cdn.jsdelivr.net/gh/vasturiano/three-globe/example/img/earth-topology.png|/static/vendor/three-globe/textures/earth-topology.png"

  # ── Google Fonts CSS bundle ────────────────────────────────────
  # The HTML has ONE <link href="https://fonts.googleapis.com/..."> that
  # pulls in IBM Plex Mono, Instrument Serif, and Geist. fetch-vendor.sh
  # downloads that CSS, parses out every fonts.gstatic.com .woff2 URL,
  # fetches each woff2 to static/vendor/fonts/, and rewrites the CSS to
  # use same-directory relative paths. This patch swaps the single
  # Google Fonts URL for the locally-served CSS, which then references
  # the vendored woff2s without ever hitting Google again.
  "https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Instrument+Serif:ital@0;1&family=Geist:wght@300;400;500;600&display=swap|/static/vendor/fonts/fonts.css"
)

# ── Apply patches ─────────────────────────────────────────────────────
#
# We use perl in slurp mode (-0777) because the source assets can have
# lines longer than 60,000 characters and line-based perl chokes on the
# in-place rename for files like that on some platforms.
#
# CRITICAL: strings are passed to perl via the FIND/REPL environment
# variables, NOT interpolated into the perl source by bash. Reason:
# perl's `\Q...\E` quotes regex metacharacters but does NOT prevent
# variable interpolation, which happens earlier. A URL like
# `chart.js@4.4.0` would have its `@4` interpolated as the empty
# perl array (everything after `@4` becomes part of the var name
# until a non-identifier character), silently producing a regex
# pattern that matches nothing. Reading the strings from %ENV
# bypasses interpolation entirely.
#
# We also avoid `perl -i` and instead do read → substitute → write
# to a temp file → atomic mv, because `perl -i` on Git Bash / msys
# is unreliable on large files.
applied=0
for p in "${PATCHES[@]}"; do
  find_str="${p%|*}"
  repl_str="${p#*|}"

  found=0
  for source_path in "${SOURCE_PATHS[@]}"; do
    if ! grep -qF "$find_str" "$source_path"; then
      continue
    fi
    found=1

    tmp="$(mktemp)"
    if FIND="$find_str" REPL="$repl_str" perl -0777 -pe '
          BEGIN { $f = $ENV{FIND}; $r = $ENV{REPL}; }
          s/\Q$f\E/$r/g;
        ' "$source_path" > "$tmp"; then
      mv "$tmp" "$source_path"
      echo "${GRN}PATCHED${RST}  $find_str"
      echo "         ${DIM}→ $repl_str ($source_path)${RST}"
      applied=$((applied + 1))
    else
      rm -f "$tmp"
      echo "${RED}FAILED${RST}   $find_str  ${DIM}(perl error in $source_path)${RST}"
    fi
  done

  if [ "$found" -eq 0 ]; then
    echo "${YLW}SKIP${RST}     $find_str  ${DIM}(not found — already patched?)${RST}"
  fi
done

# ── Sanity-check the result ───────────────────────────────────────────
remaining=$({ grep -h "cdn.jsdelivr.net" "${SOURCE_PATHS[@]}" || true; } | wc -l | tr -d ' ')
if [ "$remaining" -gt 0 ]; then
  echo
  echo "${YLW}WARN${RST}: $remaining cdn.jsdelivr.net references remain in explorer sources."
  echo "       Either the PATCHES table is incomplete or a source uses"
  echo "       multiple URL formats for the same asset. Review with:"
  echo "         grep -n cdn.jsdelivr.net ${SOURCE_PATHS[*]}"
fi

google_fonts=$({ grep -h "fonts.googleapis.com" "${SOURCE_PATHS[@]}" || true; } | wc -l | tr -d ' ')
if [ "$google_fonts" -gt 0 ]; then
  echo
  echo "${YLW}NOTE${RST}: $google_fonts fonts.googleapis.com reference(s) still present."
  echo "       Google Fonts vendoring is a separate task — it requires"
  echo "       parsing the CSS and rewriting all .woff2 references."
  echo "       See the Google Fonts TODO comment in fetch-vendor.sh."
fi

echo
echo "${DIM}─────────────────────────────────────────────${RST}"
echo "${GRN}OK${RST}: applied $applied patch(es)"
echo "${DIM}     review the diff:  git diff -- src/explorer/fragments/00-shell.html src/explorer/app${RST}"
echo "${DIM}     restore backups:  move each *.pre-vendor-patch.bak over its source${RST}"
echo
echo "${YLW}NEXT${RST}: update the explorer CDN test to match the new state:"
echo "       \`cargo test --lib -p coincync explorer_html_lists_external_cdns\`"
echo "       Edit src/rpc/explorer.rs to remove the patched-out origins"
echo "       from the \`known_external_origins\` list."
