#!/usr/bin/env bash
# build-in-docker.sh — wrap docker/builder.Dockerfile to produce
# release binaries in `./out/` from the current git checkout.
#
# Usage:
#   ./scripts/build-in-docker.sh                  # default
#   ./scripts/build-in-docker.sh --rust 1.83.0    # pin a different Rust
#   ./scripts/build-in-docker.sh --tag my-tag     # name the image
#
# Output:
#   out/coincync          — full node binary
#   out/coincync-wallet   — CLI wallet
#   out/coincync-rig      — RandomX miner (`run-solo` + bench)
#   out/coincync-tui-miner — TUI miner
#   out/SHA256SUMS        — sha256sum -c verifies all of above
#
# Disclaimer about reproducibility: see docs/operations/REPRODUCIBLE_BUILDS.md.
# Two clean clones of the same git commit, run through this script,
# produce byte-identical binaries on the same host CPU architecture.
# Cross-arch (x86_64 vs arm64) builds are NOT byte-identical.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUST_VERSION="1.85.0"
IMAGE_TAG="coincync-build:HEAD"
OUT_DIR="$REPO_ROOT/out"

while [ $# -gt 0 ]; do
  case "$1" in
    --rust)   RUST_VERSION="$2"; shift 2 ;;
    --tag)    IMAGE_TAG="$2"; shift 2 ;;
    --out)    OUT_DIR="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *)
      echo "ERROR: unknown arg: $1" >&2
      exit 1 ;;
  esac
done

cd "$REPO_ROOT"

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker not installed. Install from https://docs.docker.com/get-docker/" >&2
  exit 1
fi

echo "==> CoinCync reproducible build"
echo "    repo:     $REPO_ROOT"
echo "    Rust:     $RUST_VERSION"
echo "    image:    $IMAGE_TAG"
echo "    out:      $OUT_DIR"
echo ""

# Warn (but don't fail) on dirty tree — the Dockerfile also warns.
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
  echo "WARN: working tree has uncommitted changes."
  echo "      The Dockerfile will note this; the build will succeed but"
  echo "      the resulting binary will not match a clean checkout of HEAD."
  echo ""
fi

mkdir -p "$OUT_DIR"

echo "==> docker build"
docker build \
  --build-arg "RUST_VERSION=$RUST_VERSION" \
  -f docker/builder.Dockerfile \
  -t "$IMAGE_TAG" \
  .

echo ""
echo "==> docker run (extracts artifacts to $OUT_DIR)"
docker run --rm \
  -v "$OUT_DIR:/out" \
  "$IMAGE_TAG"

echo ""
echo "==> Done"
echo ""
ls -la "$OUT_DIR"
echo ""
echo "Verify with:"
echo "    cd $OUT_DIR && sha256sum -c SHA256SUMS"
