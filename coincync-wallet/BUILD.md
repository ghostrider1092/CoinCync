# CoinCync Wallet — Build Guide

## What the user gets

A single installer that includes:
- **CoinCync Wallet** (GUI)
- **CoinCync Node** (auto-starts in background)
- **CoinCync Miner** (one-click mining)
- **CoinCync Wallet CLI** (for advanced operations)

No terminal. No PATH setup. No separate downloads. Install and run.

## Quick Build

```bash
# 1. Build the core binaries
cd coincync-1.0
cargo build --release --features testnet

# 2. Bundle binaries into the wallet app
cd coincync-wallet
chmod +x scripts/bundle-binaries.sh
./scripts/bundle-binaries.sh

# 3. Build the desktop app
npm install
npm run tauri build
```

## What happens when the user opens the wallet

1. Wallet launches
2. Auto-detects bundled `coincync-node` binary
3. Starts the node in the background (connects to testnet seed nodes)
4. Waits for node to sync
5. User creates or unlocks their wallet
6. Wallet scans the chain for their outputs (using `coincync-wallet scan`)
7. Balance appears. Ready to send/receive/mine.

## Platform-specific outputs

### Windows
```
src-tauri/target/release/bundle/msi/CoinCync Wallet_1.0.0_x64_en-US.msi
```
Includes: coincync-node.exe, coincync-wallet.exe, coincync-miner.exe

### Linux
```
src-tauri/target/release/bundle/deb/coincync-wallet_1.0.0_amd64.deb
src-tauri/target/release/bundle/appimage/coincync-wallet_1.0.0_amd64.AppImage
```
The .AppImage is portable — no install needed. Just download and run.

### macOS
```
src-tauri/target/release/bundle/dmg/CoinCync Wallet_1.0.0_x64.dmg
```

For Apple Silicon:
```bash
./scripts/bundle-binaries.sh macos
npm run tauri build -- --target aarch64-apple-darwin
```

## Development

```bash
cd coincync-wallet
npm install
npm run tauri dev
```

In dev mode, set `MOCK = true` in `src/utils/rpc.js` to use simulated data.
Set `MOCK = false` when you have a node running on 127.0.0.1:28081.

## Architecture

```
┌─────────────────────────────────────────┐
│           CoinCync Wallet GUI           │
│         (React + Vite + Tauri)          │
├─────────────────────────────────────────┤
│           Tauri Rust Backend            │
│  ┌───────────┐ ┌──────────┐ ┌────────┐ │
│  │ Auto-start│ │ Wallet   │ │ Miner  │ │
│  │ Node      │ │ CLI      │ │ Binary │ │
│  │ (sidecar) │ │ (sidecar)│ │(sidecar│ │
│  └─────┬─────┘ └────┬─────┘ └───┬────┘ │
│        │             │           │      │
│        ▼             ▼           ▼      │
│  ┌──────────────────────────────────┐   │
│  │     CoinCync Node (background)   │   │
│  │  RPC on 127.0.0.1:28081          │   │
│  │  P2P on 0.0.0.0:28080            │   │
│  └──────────────────────────────────┘   │
└─────────────────────────────────────────┘
```
