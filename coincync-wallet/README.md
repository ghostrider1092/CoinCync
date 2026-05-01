# CoinCync Wallet v1.0

Privacy wallet for CoinCync — 22 privacy features across 4 independent layers.

*Private by law. Private by math.*

## What's included

### Privacy pages
- **Privacy page** — all 22 features documented with 4 collapsible layer panels
- **Dashboard** — live 3D globe with node locations, privacy feature matrix, 4th Amendment
- **Send** — ring-11, uniform 2-in-2-out shape, traffic shaping displayed
- **Keys** — time-scoped view keys, FROST multi-sig (k-of-n), plausible deniability
- **Settings** — auto-churn (Poisson intervals), dead man's switch, constitutional locks

### Core features
Wallet setup wizard, lock screen, real QR codes, live RPC, fee estimation,
address validation, tx detail modal, CSV export, dark/light theme, notifications,
live mining stats, settings persistence.

## Run

**Desktop app (recommended):** from this folder run **`npm start`** (same as `npx tauri dev`). On Windows you can double‑click **`Open-CoinCync-Wallet.bat`** — it installs dependencies if needed, then opens the **CoinCync Wallet** window. Use that window for balances, unlock, mining, and Send (not a normal browser tab on `/`).

```bash
npm install
npm start
```

## Install (production)

Official installers bundle the **node**, **wallet CLI**, and **TUI miner** next to the app so end users do not install Rust or run separate downloads.

1. **From GitHub (recommended):** open **Actions → “Build CoinCync Wallet”**, pick a successful run, and download the artifact for your OS (`windows-x64`, `linux-x64`, `macos-x64`, or `macos-arm64`). Inside you will find **`.msi` / NSIS `.exe`** (Windows), **`.deb` / `.AppImage`** (Linux), or **`.dmg`** (macOS). Run the installer like any normal desktop app.
2. **Releases:** when maintainers attach those same files to a **GitHub Release** (often triggered by a `v*` tag on this repo), download the installer for your platform from the **Releases** page and run it.

After install, launch **CoinCync Wallet** from the Start menu / Applications folder. Use that window for the full wallet (not only a browser tab on `http://localhost:1420`).

## Build installers locally

You need a **release** build of the three chain binaries from the **repository root**, then the wallet frontend + Tauri bundle.

```bash
# From repo root (parent of coincync-wallet/)
cargo build --release --features "randomx testnet" --bin coincync-node --bin coincync-wallet --bin coincync-tui-miner

# Then from coincync-wallet/
cd coincync-wallet
npm install
npm run pack
```

Or one shot from `coincync-wallet/`: **`npm run build:release`** (runs `build:chain` then `npm run tauri build`). The `beforeBuildCommand` copies binaries into `src-tauri/resources/binaries/` and Tauri includes them in the installer.

### Auto-updater (optional)

- **Tauri updater** is scaffolded in `src-tauri/tauri.conf.json` with `"active": false`. To ship updates safely:
  1. Install the Tauri CLI and run **`tauri signer generate -w ~/.tauri/coincync-wallet.key`** (or your path). Store the **public** key string in `tauri.conf.json` → `updater.pubkey`. Put the **private** key in CI as secret **`TAURI_PRIVATE_KEY`** (file contents or key string per Tauri docs) and optional **`TAURI_KEY_PASSWORD`**.
  2. On each release, build with those env vars set (see `.github/workflows/build-wallet.yml`, which forwards the secrets to `tauri-apps/tauri-action`). Upload the generated `.sig` files and bundles to your CDN or GitHub Releases.
  3. Host a **version JSON** that matches your `updater.endpoints` template. Tauri v1 expects a document shaped like:

```json
{
  "version": "1.0.1",
  "notes": "Release notes (markdown allowed).",
  "pub_date": "2026-04-29T18:00:00Z",
  "platforms": {
    "windows-x86_64": {
      "signature": "Content of the .msi.zip.sig or bundle.sig file from tauri signer",
      "url": "https://your.cdn.example/coincync-wallet_1.0.1_x64_en-US.msi.zip"
    }
  }
}
```

  4. Set **`"active": true`** only after the endpoint returns valid JSON for the client’s `{{target}}` / `{{arch}}` / `{{current_version}}` substitution pattern.

## Privacy layers

| Layer | Features | Description |
|-------|----------|-------------|
| L1 Cryptographic | 7 | CLSAG ring-11, stealth, Pedersen, BP+, memos, view tags, key images |
| L2 Network | 4 | Dandelion++, Noise_XX, traffic shaping, constant-rate padding |
| L3 Wallet | 7 | Uniform decoys, time-scoped keys, plausible deniability, auto-churn, dead man's switch, uniform shape, FROST |
| L4 Constitutional | 4 | Mandatory privacy (Art III), no surveillance (Art IX), no balance lookup, 4th Amendment |

## Coin specification

- **Ticker:** CYNC
- **Decimals:** 12
- **Supply cap:** 100,000,000 (asymptotic curve)
- **Block time:** 120 seconds
- **Consensus:** RandomX CPU-only PoW
- **Fee burn:** 30% normal, 50% congested
- **Tail emission:** 0.6 CYNC/block (perpetual)
- **Dev tax:** 0% (Constitution Article II)
