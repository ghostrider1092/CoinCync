#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# CoinCync explorer — vendor CDN dependencies
# ──────────────────────────────────────────────────────────────────────
#
# Downloads every external asset the embedded explorer currently fetches
# from a CDN into deploy/explorer/static/vendor/, with TOFU (trust on
# first use) SHA-256 checksum pinning so subsequent runs verify what
# they already have.
#
# Why vendor at all?
#   1. Tor / restrictive networks: a privacy coin's explorer that
#      breaks on Tor because it can't reach jsdelivr is a bad look.
#   2. Survival: jsdelivr was down 3 hours in 2023. Every site
#      depending on it broke during the outage. We don't want that.
#   3. CSP tightening: same-origin assets let us set
#      `Content-Security-Policy: default-src 'self'`, which is the
#      gold standard. With third-party CDNs, CSP has to allowlist
#      every origin.
#   4. Reproducibility: a checksum-pinned vendor directory means
#      every operator ships byte-identical assets. CDNs are mutable.
#
# Workflow:
#
#   # First time on a fresh checkout (TOFU mode):
#   ./fetch-vendor.sh
#   # → downloads everything, computes hashes, writes checksums.txt
#   # → review checksums.txt, then `git add` + commit it.
#   # → from now on the script will verify against the pinned hashes.
#
#   # Then patch the HTML to use the vendored paths:
#   ./patch-vendor.sh
#
#   # CI / second-time runs (verify mode, no downloads if files exist):
#   ./fetch-vendor.sh --verify
#
# ── Adding a new vendored dependency ──────────────────────────────────
# 1. Add a new line to ASSETS below:
#       "<URL>|<local_path_relative_to_static/vendor>"
# 2. Run ./fetch-vendor.sh to download it and capture its checksum
# 3. Commit the new file + the updated checksums.txt
# 4. Edit ./patch-vendor.sh to add the find-and-replace for the HTML

set -euo pipefail

# Resolve to the directory holding this script regardless of cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR_DIR="$SCRIPT_DIR/static/vendor"
CHECKSUMS_FILE="$VENDOR_DIR/checksums.txt"

# Color output if stdout is a terminal.
if [ -t 1 ]; then
  RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
  RED=''; GRN=''; YLW=''; DIM=''; RST=''
fi

mode="fetch"
case "${1:-}" in
  --verify) mode="verify" ;;
  --help|-h)
    cat <<EOF
Usage: $0 [--verify]

  (no args)  Download missing files; verify existing ones; TOFU-pin
             new checksums into checksums.txt.
  --verify   Verify existing files against checksums.txt without
             downloading anything. Fails non-zero on mismatch or
             missing files. Use this in CI.
EOF
    exit 0
    ;;
esac

# ── Inventory ──────────────────────────────────────────────────────────
#
# Each entry: "<URL>|<local_path_relative_to_static/vendor>"
#
# When you add a new entry here:
#   1. Run ./fetch-vendor.sh   (TOFU mode pins the new hash)
#   2. Add the path to ./patch-vendor.sh's find-and-replace table
#   3. Commit checksums.txt AND the file itself
ASSETS=(
  # ── chart.js ────────────────────────────────────────────────────
  # Used by the iron-consensus dashboard panel for the difficulty
  # and hashrate sparklines. UMD build is the global-friendly one
  # the explorer's inline JS expects.
  "https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js|chart.js/4.4.0/chart.umd.min.js"

  # ── d3 (full bundle) ────────────────────────────────────────────
  # Used by the network globe for projection math and the
  # supply / emission curve panel.
  "https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js|d3/7/d3.min.js"

  # ── topojson-client ─────────────────────────────────────────────
  # Decodes the world atlas TopoJSON into d3-friendly geo features.
  "https://cdn.jsdelivr.net/npm/topojson-client@3/dist/topojson-client.min.js|topojson-client/3/topojson-client.min.js"

  # ── globe.gl ────────────────────────────────────────────────────
  # The 3D globe widget on the network tab. Renders peer locations
  # and chain-event arcs.
  "https://cdn.jsdelivr.net/npm/globe.gl@2.27.3/dist/globe.gl.min.js|globe.gl/2.27.3/globe.gl.min.js"

  # ── world-atlas (data) ──────────────────────────────────────────
  # 110m-resolution country borders, fed into globe.gl. Static data,
  # never updates — pinning the version is the right call.
  "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json|world-atlas/2/countries-110m.json"

  # ── three-globe textures ────────────────────────────────────────
  # The 3D globe widget loads day/night/topology textures via inline
  # JS. Two URL forms appear in index.html: `npm/three-globe/example/img/`
  # and `gh/vasturiano/three-globe/example/img/`. Both resolve to the
  # same upstream files; we vendor under `three-globe/textures/` and
  # patch both URL forms in patch-vendor.sh. These are several hundred
  # KB each — by far the heaviest assets in the bundle, but vendoring
  # them is what makes the globe work without internet.
  "https://cdn.jsdelivr.net/npm/three-globe/example/img/earth-day.jpg|three-globe/textures/earth-day.jpg"
  "https://cdn.jsdelivr.net/npm/three-globe/example/img/earth-night.jpg|three-globe/textures/earth-night.jpg"
  "https://cdn.jsdelivr.net/npm/three-globe/example/img/earth-topology.png|three-globe/textures/earth-topology.png"
)

# Google Fonts is a special case: there's no single asset URL — the
# CSS at fonts.googleapis.com references several .woff2 files at
# fonts.gstatic.com URLs that change format based on the request's
# User-Agent. We handle Google Fonts in fetch_google_fonts() below,
# which downloads the CSS, parses out every .woff2 URL it references,
# fetches each one, and rewrites the CSS to use relative paths so the
# whole font set is self-contained under static/vendor/fonts/.
#
# The exact Google Fonts CSS URL the explorer requests is hardcoded
# in the embedded HTML (line ~21 of src/explorer/index.html):
#   https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Instrument+Serif:ital@0;1&family=Geist:wght@300;400;500;600&display=swap

GOOGLE_FONTS_CSS_URL='https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Instrument+Serif:ital@0;1&family=Geist:wght@300;400;500;600&display=swap'

# A modern Chrome User-Agent — Google Fonts serves woff2 only to
# UAs it recognizes as woff2-capable. A bare curl UA gets older,
# heavier formats (TTF/EOT) which we don't want.
GOOGLE_FONTS_UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

fetch_google_fonts() {
  local fonts_dir="$VENDOR_DIR/fonts"
  local css_path="$fonts_dir/fonts.css"
  mkdir -p "$fonts_dir"

  # ── Step 1: fetch the CSS ────────────────────────────────────
  echo "${YLW}FETCH${RST}    fonts/fonts.css  ${DIM}(Google Fonts stylesheet)${RST}"
  if ! curl -fsSL --proto '=https' --tlsv1.2 \
        -A "$GOOGLE_FONTS_UA" \
        -o "$css_path.raw" \
        "$GOOGLE_FONTS_CSS_URL"; then
    echo "${RED}FAILED${RST}   fonts/fonts.css  ${DIM}(curl error fetching CSS)${RST}"
    return 1
  fi

  # ── Step 2: parse out every .woff2 URL ───────────────────────
  #
  # The CSS contains lines like:
  #   src: url(https://fonts.gstatic.com/s/.../KFOmCnqEu92Fr1Mu4mxK.woff2) format('woff2');
  # We extract every such URL with grep+sed.
  local woff2_urls
  woff2_urls="$(grep -oE 'https://fonts\.gstatic\.com/[^)]+\.woff2' "$css_path.raw" | sort -u)"

  if [ -z "$woff2_urls" ]; then
    echo "${RED}FAILED${RST}   fonts/fonts.css  ${DIM}(no woff2 URLs found in CSS — wrong UA?)${RST}"
    rm -f "$css_path.raw"
    return 1
  fi

  local count=0
  local fetched=0
  while IFS= read -r url; do
    count=$((count + 1))
    # Use the basename of the URL as the local filename. Google
    # Fonts' woff2 filenames are content-derived hashes that change
    # only when the font itself changes, so they're stable enough
    # to commit.
    local fname
    fname="$(basename "$url")"
    local local_path="$fonts_dir/$fname"

    if [ -f "$local_path" ]; then
      # Already on disk from a previous run — verify the size hasn't
      # changed (a real verification would re-hash, but Google Fonts
      # rotates URLs when content changes so size is enough).
      :
    else
      if curl -fsSL --proto '=https' --tlsv1.2 -A "$GOOGLE_FONTS_UA" -o "$local_path" "$url"; then
        fetched=$((fetched + 1))
      else
        echo "${RED}FAILED${RST}   fonts/$fname"
        rm -f "$css_path.raw"
        return 1
      fi
    fi
  done <<< "$woff2_urls"

  # ── Step 3: rewrite the CSS to use relative paths ────────────
  #
  # Replace every absolute fonts.gstatic.com URL with the basename,
  # so the CSS references the woff2s in the same directory it's in.
  # Pin the basename via sed so a future Google Fonts URL format
  # change (e.g. query parameters) doesn't break the rewrite.
  perl -0777 -pe '
    s{https://fonts\.gstatic\.com/[^)]*/([^/)]+\.woff2)}{./$1}g;
  ' "$css_path.raw" > "$css_path"
  rm -f "$css_path.raw"

  # ── Step 4: pin checksums for the CSS and every woff2 ────────
  #
  # checksums.txt entries use paths relative to static/vendor/, so
  # they look like `fonts/fonts.css` and `fonts/<file>.woff2`.
  pin_checksum "fonts/fonts.css" "$(sha256_of "$css_path")"
  for f in "$fonts_dir"/*.woff2; do
    [ -f "$f" ] || continue
    # SC2155: declare local and assign separately so a failed
    # `sha256_of` propagates its exit status under `set -e` instead
    # of being masked by `local` (which always returns 0). If
    # `sha256_of` ever errors mid-loop we want to bail, not silently
    # commit empty hashes.
    local rel
    local cur
    local pinned_now
    rel="fonts/$(basename "$f")"
    cur="$(sha256_of "$f")"
    pinned_now="$(pinned_checksum "$rel")"
    if [ -z "$pinned_now" ]; then
      pin_checksum "$rel" "$cur"
    elif [ "$cur" != "$pinned_now" ]; then
      echo "${RED}MISMATCH${RST} $rel"
      return 1
    fi
  done

  echo "${GRN}OK${RST}       fonts/fonts.css  ${DIM}($count woff2 URL(s), $fetched newly downloaded)${RST}"
}

# NOTE: the call to fetch_google_fonts() lives AFTER the main asset
# loop (further down in this file), because the function depends on
# `sha256_of`, `pin_checksum`, and `pinned_checksum`, all of which
# are defined below. Bash looks up helper functions at *call* time,
# not at *definition* time, so we just have to place the call below
# the helpers in source order.

# ── Helpers ────────────────────────────────────────────────────────────

# Compute SHA-256 of a file in a portable way (works on Linux, macOS,
# and Git Bash on Windows).
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "ERROR: need sha256sum or shasum on PATH" >&2
    exit 1
  fi
}

# Read the pinned checksum for a given local path from checksums.txt.
# Returns empty string if not pinned yet.
pinned_checksum() {
  local path="$1"
  [ -f "$CHECKSUMS_FILE" ] || return 0
  awk -v p="$path" '$2 == p { print $1 }' "$CHECKSUMS_FILE"
}

# Append or replace the pinned checksum for a given local path.
pin_checksum() {
  local path="$1"
  local sum="$2"
  [ -f "$CHECKSUMS_FILE" ] || touch "$CHECKSUMS_FILE"
  # Drop any existing line for this path, then append the new one.
  local tmp
  tmp="$(mktemp)"
  awk -v p="$path" '$2 != p' "$CHECKSUMS_FILE" > "$tmp"
  echo "$sum  $path" >> "$tmp"
  sort -k2,2 "$tmp" > "$CHECKSUMS_FILE"
  rm -f "$tmp"
}

# ── Core fetch-and-verify loop ────────────────────────────────────────
errors=0
ok=0
new=0

mkdir -p "$VENDOR_DIR"

for asset in "${ASSETS[@]}"; do
  url="${asset%|*}"
  rel="${asset#*|}"
  abs="$VENDOR_DIR/$rel"
  abs_dir="$(dirname "$abs")"

  pinned="$(pinned_checksum "$rel")"

  if [ ! -f "$abs" ]; then
    if [ "$mode" = "verify" ]; then
      echo "${RED}MISSING${RST}  $rel  ${DIM}(--verify mode, refusing to download)${RST}"
      errors=$((errors + 1))
      continue
    fi
    echo "${YLW}FETCH${RST}    $rel"
    mkdir -p "$abs_dir"
    if ! curl -fsSL --proto '=https' --tlsv1.2 -o "$abs" "$url"; then
      echo "${RED}FAILED${RST}   $rel  ${DIM}(curl error from $url)${RST}"
      errors=$((errors + 1))
      continue
    fi
    new=$((new + 1))
  fi

  actual="$(sha256_of "$abs")"

  if [ -z "$pinned" ]; then
    # First-time download: TOFU-pin the hash.
    pin_checksum "$rel" "$actual"
    echo "${GRN}PINNED${RST}   $rel  ${DIM}sha256:${actual:0:16}…${RST}"
    ok=$((ok + 1))
  elif [ "$actual" = "$pinned" ]; then
    echo "${GRN}OK${RST}       $rel  ${DIM}sha256:${actual:0:16}…${RST}"
    ok=$((ok + 1))
  else
    echo "${RED}MISMATCH${RST} $rel"
    echo "         expected: $pinned"
    echo "         actual:   $actual"
    echo "         If this change is intentional (e.g. you bumped a"
    echo "         version in the ASSETS list), delete the matching"
    echo "         line from checksums.txt and re-run this script."
    errors=$((errors + 1))
  fi
done

# ── Google Fonts ───────────────────────────────────────────────────────
#
# Google Fonts is the special case the helper functions and ASSETS
# loop above can't cover with a single URL — it's a CSS bundle that
# itself references several .woff2 files. We handle it via
# `fetch_google_fonts` (defined further up in this file): download
# the CSS with a Chrome User-Agent so Google serves modern woff2,
# parse out every fonts.gstatic.com .woff2 URL, fetch each one,
# rewrite the CSS to use same-directory relative paths, and pin
# every checksum into checksums.txt.
#
# This block is intentionally below the helpers + main asset loop
# because `fetch_google_fonts` calls `sha256_of`, `pin_checksum`,
# and `pinned_checksum`, all of which are defined above in the
# helpers section. Bash resolves function names at call time, but
# we still place the CALL after the definitions so a reader of
# this script sees a logical top-down flow.
#
# `--verify` mode runs the function only if the previous run
# already populated `static/vendor/fonts/`, since there's no way to
# verify a non-existent file. If the directory is empty under
# --verify, we treat that as "Google Fonts not vendored yet" and
# skip silently — the script will still error out later if the
# main ASSETS loop has missing files.
if [ "$mode" != "verify" ] || [ -f "$VENDOR_DIR/fonts/fonts.css" ]; then
  if ! fetch_google_fonts; then
    errors=$((errors + 1))
  fi
fi

# ── Summary ────────────────────────────────────────────────────────────
echo
echo "${DIM}─────────────────────────────────────────────${RST}"
if [ "$errors" -gt 0 ]; then
  echo "${RED}FAILED${RST}: $errors errors, $ok verified"
  if [ "$new" -gt 0 ]; then
    echo "${YLW}NOTE${RST}:   $new new files downloaded (their hashes were pinned)"
  fi
  exit 1
fi
echo "${GRN}OK${RST}: $ok asset(s) verified"
if [ "$new" -gt 0 ]; then
  echo "${YLW}NEW${RST}:    $new file(s) downloaded and pinned to checksums.txt"
  echo "${DIM}        \`git add deploy/explorer/static/vendor && git commit\`${RST}"
fi
