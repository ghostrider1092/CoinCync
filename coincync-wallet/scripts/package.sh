#!/bin/bash
# package.sh — Create a Monero-style distribution folder
#
# Output: coincync-wallet-v1.0.0-{platform}/
#   coincync-wallet.exe    (GUI app)
#   coincync-node.exe      (auto-starts in background)
#   coincync-miner.exe     (one-click mining)
#   coincync-cli.exe       (CLI wallet for advanced users)
#
# Users download one zip, extract, double-click coincync-wallet.exe.
# Everything just works.

set -euo pipefail

VERSION="1.0.0"
PLATFORM="${1:-windows}"
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WALLET_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$WALLET_DIR/dist/coincync-wallet-v${VERSION}-${PLATFORM}"

echo "Packaging CoinCync Wallet v${VERSION} for ${PLATFORM}"

mkdir -p "$OUT"

case "$PLATFORM" in
  windows)
    # Copy Tauri-built wallet GUI
    TAURI_BIN="$WALLET_DIR/src-tauri/target/release/coincync-wallet.exe"
    if [ ! -f "$TAURI_BIN" ]; then
      echo "Building wallet GUI..."
      cd "$WALLET_DIR" && npm run tauri build 2>&1 | tail -3
    fi
    cp "$TAURI_BIN" "$OUT/CoinCync Wallet.exe" 2>/dev/null || echo "GUI binary not found — run 'npm run tauri build' first"

    # Copy core binaries
    cp "$PROJECT_ROOT/target/release/coincync-node.exe" "$OUT/" 2>/dev/null || echo "coincync-node.exe not found"
    cp "$PROJECT_ROOT/target/release/coincync-miner.exe" "$OUT/" 2>/dev/null || echo "coincync-miner.exe not found"
    cp "$PROJECT_ROOT/target/release/coincync-wallet.exe" "$OUT/coincync-cli.exe" 2>/dev/null || echo "coincync-wallet.exe (CLI) not found"
    ;;

  linux)
    cp "$PROJECT_ROOT/target/release/coincync-node" "$OUT/" 2>/dev/null || true
    cp "$PROJECT_ROOT/target/release/coincync-miner" "$OUT/" 2>/dev/null || true
    cp "$PROJECT_ROOT/target/release/coincync-wallet" "$OUT/coincync-cli" 2>/dev/null || true
    chmod +x "$OUT/"* 2>/dev/null || true
    ;;

  macos)
    cp "$PROJECT_ROOT/target/release/coincync-node" "$OUT/" 2>/dev/null || true
    cp "$PROJECT_ROOT/target/release/coincync-miner" "$OUT/" 2>/dev/null || true
    cp "$PROJECT_ROOT/target/release/coincync-wallet" "$OUT/coincync-cli" 2>/dev/null || true
    chmod +x "$OUT/"* 2>/dev/null || true
    ;;
esac

# Add README
cat > "$OUT/README.txt" << 'EOF'
CoinCync Wallet v1.0.0
======================

Private by law. Private by math.

QUICK START:
  Double-click "CoinCync Wallet" (or coincync-wallet.exe on Windows)
  Everything starts automatically — no terminal needed.

WHAT'S INCLUDED:
  CoinCync Wallet    — GUI wallet (this app)
  coincync-node      — Full node (auto-starts in background)
  coincync-miner     — CPU miner (one-click from the Mining tab)
  coincync-cli       — Command-line wallet (for advanced users)

FIRST TIME:
  1. Open CoinCync Wallet
  2. Create a new wallet (writes down your 24-word seed)
  3. The node syncs automatically
  4. You're ready to send, receive, and mine

MINING:
  1. Go to the Mining tab
  2. Enter your address
  3. Set thread count
  4. Click Start Mining

SUPPORT:
  Explorer:  https://explorer.coincync.network
  GitHub:    https://github.com/CoinCync/Coincync-Testnet-

22 privacy features. 0% dev tax. 100M CYNC cap. CPU-only RandomX.
EOF

echo ""
echo "Package created: $OUT/"
ls -lh "$OUT/"
echo ""
echo "To distribute: zip -r coincync-wallet-v${VERSION}-${PLATFORM}.zip $(basename $OUT)/"
