# CoinCync Testnet Release

## Contents

| File | Description |
| --- | --- |
| `coincync-node` | Full node — syncs and validates the chain |
| `coincync-miner` | CPU miner (RandomX) |
| `coincync-wallet` | CLI wallet (create, scan, send) |
| `coincync-wallet-gui.exe` | Desktop GUI wallet (Windows) |
| `SHA256SUMS.txt` | Checksums for all binaries |
| `coincync-node.service` | systemd service template (testnet P2P 28080, RPC 127.0.0.1:28081) |
| `coincync.conf.example` | Optional reference (CLI is authoritative for the node binary today) |
| `verify-community-bootstrap.sh` | Operator check: DNS seeds + TCP to hardcoded peers |
| `install-testnet-node.sh` | Linux helper: install systemd unit from repo layout |
| `README.md` | This file |

## Verify Downloads

```bash
sha256sum -c SHA256SUMS.txt
```

## Quick Start

```bash
# Extract
tar xzf coincync-1.0.0-testnet-linux-x86_64.tar.gz

# Install
sudo cp coincync-node coincync-miner coincync-wallet /usr/local/bin/

# Run node
coincync-node --network testnet

# Create wallet
coincync-wallet create -p YOUR_PASSWORD

# Mine
coincync-miner --address YOUR_tCYNC_ADDRESS --threads 4 --node 127.0.0.1:28081
```

## Testnet Info

- Block time: 120 seconds
- PoW: RandomX (CPU-only)
- Ring size: 11 minimum
- Ports: P2P 28080, RPC 28081
- Faucet: <https://explorer.coincync.network/faucet.html>

Testnet coins have zero monetary value.
