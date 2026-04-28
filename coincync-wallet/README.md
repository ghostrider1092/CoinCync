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

```bash
npm install
npm run tauri dev
```

## Build (distributable binary)

```bash
npm run tauri build
```

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
