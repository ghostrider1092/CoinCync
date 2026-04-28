#!/bin/bash
# bundle-binaries.sh — Copy CoinCync binaries into the Tauri sidecar directory
#
# Run this before `npm run tauri build` to bundle the node, wallet CLI,
# and miner inside the desktop wallet app.
#
# Usage:
#   ./scripts/bundle-binaries.sh [platform]
#
# Platform: linux, macos, windows (auto-detected if not specified)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WALLET_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TAURI_DIR="$WALLET_DIR/src-tauri"
BIN_DIR="$TAURI_DIR/binaries"
RELEASE_DIR="$(cd "$WALLET_DIR/../target/release" 2>/dev/null && pwd || echo "")"

# Auto-detect platform
PLATFORM="${1:-}"
if [ -z "$PLATFORM" ]; then
    case "$(uname -s)" in
        Linux*)  PLATFORM="linux";;
        Darwin*) PLATFORM="macos";;
        MINGW*|MSYS*|CYGWIN*) PLATFORM="windows";;
        *) PLATFORM="linux";;
    esac
fi

echo "Bundling CoinCync binaries for $PLATFORM"
mkdir -p "$BIN_DIR"

# Determine binary names
case "$PLATFORM" in
    windows)
        NODE="coincync-node.exe"
        WALLET="coincync-wallet.exe"
        MINER="coincync-miner.exe"
        # Tauri sidecar naming: binary-name-x86_64-pc-windows-msvc.exe
        SUFFIX="-x86_64-pc-windows-msvc.exe"
        ;;
    macos)
        NODE="coincync-node"
        WALLET="coincync-wallet"
        MINER="coincync-miner"
        SUFFIX="-x86_64-apple-darwin"
        ;;
    linux)
        NODE="coincync-node"
        WALLET="coincync-wallet"
        MINER="coincync-miner"
        SUFFIX="-x86_64-unknown-linux-gnu"
        ;;
esac

# Copy binaries with Tauri sidecar naming convention
for BIN in "$NODE" "$WALLET" "$MINER"; do
    BASE="${BIN%.exe}"
    SRC=""

    # Check release directory
    if [ -n "$RELEASE_DIR" ] && [ -f "$RELEASE_DIR/$BIN" ]; then
        SRC="$RELEASE_DIR/$BIN"
    # Check system PATH
    elif command -v "$BASE" &>/dev/null; then
        SRC="$(command -v "$BASE")"
    fi

    if [ -n "$SRC" ]; then
        DEST="$BIN_DIR/${BASE}${SUFFIX}"
        cp "$SRC" "$DEST"
        chmod +x "$DEST" 2>/dev/null || true
        echo "  Copied: $SRC → $DEST ($(du -h "$DEST" | cut -f1))"
    else
        echo "  MISSING: $BIN — build it first with: cargo build --release --features testnet"
    fi
done

echo ""
echo "Done. Now run: npm run tauri build"
