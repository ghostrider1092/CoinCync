#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# CoinCync documentation — build + (optional) deploy
# ──────────────────────────────────────────────────────────────────────
#
# Builds the mdBook documentation under `docs/src/` and (optionally)
# rsyncs the output to the NYC landing host where Caddy serves it
# at https://docs.coincync.network.
#
# Usage:
#
#   ./docs/build.sh              # local build only → docs/book/
#   ./docs/build.sh --deploy     # build + rsync to NYC
#   ./docs/build.sh --serve      # build + open a local preview server
#                                  at http://localhost:3000
#
# Requirements:
#   mdbook 0.4 or newer  →  `cargo install mdbook`
#   rsync                →  for --deploy
#   ssh access to NYC     →  for --deploy
#
# The deploy target is the /var/www/docs/ bind-mount on NYC. The
# matching server block is in deploy/landing/Caddyfile (the docs
# server section).

set -euo pipefail

# ── Paths ──────────────────────────────────────────────────────────────
DOCS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOOK_DIR="$DOCS_DIR/book"

# Deploy target — change these if your host layout differs.
DEPLOY_HOST="${COINCYNC_DOCS_HOST:-root@docs.coincync.network}"
DEPLOY_PATH="${COINCYNC_DOCS_PATH:-/var/www/docs/}"

# ── Color output ───────────────────────────────────────────────────────
if [ -t 1 ]; then
    RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
    RED=''; GRN=''; YLW=''; DIM=''; RST=''
fi

mode="build"
case "${1:-}" in
    --deploy) mode="deploy" ;;
    --serve)  mode="serve" ;;
    --help|-h)
        cat <<EOF
Usage: $0 [--deploy|--serve]

  (no args)  Build the book under docs/book/ and exit.
  --deploy   Build the book and rsync it to the NYC docs host.
  --serve    Build the book and open a local preview at
             http://localhost:3000 (uses 'mdbook serve').

Environment variables (--deploy mode):
  COINCYNC_DOCS_HOST   ssh target          (default: root@docs.coincync.network)
  COINCYNC_DOCS_PATH   remote dir          (default: /var/www/docs/)
EOF
        exit 0
        ;;
esac

# ── Pre-flight ─────────────────────────────────────────────────────────
if ! command -v mdbook >/dev/null 2>&1; then
    echo "${RED}error${RST}: mdbook not found on PATH"
    echo "  install with: ${DIM}cargo install mdbook${RST}"
    exit 1
fi

if [ "$mode" = "deploy" ] && ! command -v rsync >/dev/null 2>&1; then
    echo "${RED}error${RST}: rsync not found on PATH (required for --deploy)"
    exit 1
fi

# ── Build ──────────────────────────────────────────────────────────────
echo "${YLW}building${RST}  $DOCS_DIR  →  $BOOK_DIR"
cd "$DOCS_DIR"

# Clean old output to make sure stale files don't leak through. mdbook's
# default behavior keeps the build directory; we want a clean tree so
# the rsync --delete is meaningful.
rm -rf "$BOOK_DIR"

mdbook build

if [ ! -d "$BOOK_DIR" ]; then
    echo "${RED}error${RST}: mdbook build did not produce $BOOK_DIR"
    exit 1
fi

# Sanity check: every chapter in SUMMARY.md should have produced an
# .html file. mdbook's default behavior is silent on missing chapters
# (we set create-missing=false in book.toml so it errors loudly), so
# this is just a belt-and-suspenders check.
chapter_count=$(grep -cE '^\s*-\s*\[' "$DOCS_DIR/src/SUMMARY.md" || true)
html_count=$(find "$BOOK_DIR" -name '*.html' -not -name 'index.html' -not -name '404.html' -not -name 'print.html' | wc -l | tr -d ' ')
echo "${DIM}        $chapter_count chapter(s) in SUMMARY.md, $html_count .html file(s) generated${RST}"

if [ "$mode" = "build" ]; then
    echo "${GRN}done${RST}     local build at $BOOK_DIR"
    echo "${DIM}         preview with: \`mdbook serve --open\` from $DOCS_DIR${RST}"
    exit 0
fi

# ── Serve ──────────────────────────────────────────────────────────────
if [ "$mode" = "serve" ]; then
    echo "${YLW}serving${RST}   on http://localhost:3000 (Ctrl-C to stop)"
    cd "$DOCS_DIR"
    exec mdbook serve --open
fi

# ── Deploy ─────────────────────────────────────────────────────────────
if [ "$mode" = "deploy" ]; then
    echo "${YLW}deploying${RST} $BOOK_DIR/  →  $DEPLOY_HOST:$DEPLOY_PATH"
    echo
    echo "${DIM}Pre-flight: confirm you can ssh to $DEPLOY_HOST without a${RST}"
    echo "${DIM}password (key-based auth). If the rsync prompts for a${RST}"
    echo "${DIM}password, your ssh agent isn't loaded — fix that first.${RST}"
    echo

    # rsync flags:
    #   -a   archive (preserves perms, times, etc.)
    #   -v   verbose (per-file output)
    #   -z   compress in transit
    #   --delete       remove files on the remote that aren't in the source
    #   --chmod        force readable perms (Caddy runs as a non-root user)
    rsync -avz --delete --chmod=D755,F644 \
          "$BOOK_DIR/" "$DEPLOY_HOST:$DEPLOY_PATH"

    echo
    echo "${GRN}deployed${RST}  https://docs.coincync.network/"
    echo "${DIM}          (Caddy serves the new files immediately;${RST}"
    echo "${DIM}           the HTML cache is 5 minutes so worldwide${RST}"
    echo "${DIM}           rollout completes in ≤ 5 min.)${RST}"
fi
