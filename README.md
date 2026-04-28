# CoinCync 1.0

A privacy-first cryptocurrency with mandatory shielding, auditable supply, and constitutional protections.

**Status:** Public Testnet  
**Network:** Nodes across 6 continents  
**Launch:** Mainnet October 2026  
**Discord:** [Join the community](https://discord.gg/5tYNSCsqzy)

## Privacy Features (22 total, all mandatory)

**Cryptographic (Layer 1):** CLSAG Ring-16 signatures, stealth addresses, Pedersen commitments, Bulletproofs+ range proofs, encrypted memos, key images, view tags

**Network (Layer 2):** Dandelion++ relay, Noise_XX P2P encryption, traffic shaping, constant-rate padding

**Wallet (Layer 3):** Uniform decoys, time-scoped view keys, plausible deniability, auto-churn, dead man's switch, uniform tx shape, FROST multi-sig

**Constitutional (Layer 4):** Mandatory privacy, no surveillance hooks, no balance lookup, 4th Amendment enforcement

## Quick Start

```bash
# Download
wget https://explorer.coincync.network/releases/v1.0.0-testnet/coincync-1.0.0-testnet-linux-x86_64.tar.gz
tar xzf coincync-1.0.0-testnet-linux-x86_64.tar.gz

# Run a node
./coincync-node --network testnet

# Create wallet
./coincync-wallet create -p YOUR_PASSWORD

# Mine
./coincync-miner --testnet --address YOUR_tCYNC_ADDRESS --threads 4 --node 127.0.0.1:28081
```

See [Getting Started](docs/pages/GETTING_STARTED.md) for full instructions.

## Testnet

Nodes across 6 continents: London, San Francisco, Sydney, New York, Frankfurt, Toronto, Richmond, Atlanta, Amsterdam.

```bash
# Auto-discovers peers via DNS seeds
./coincync-node --network testnet
```

## Monetary Policy

- **Supply cap:** 100,000,000 CYNC (asymptotic, never reached)
- **Block time:** 120 seconds
- **Genesis reward:** ~50 CYNC/block
- **Tail emission:** 0.6 CYNC/block (perpetual)
- **Fee burn:** 30% normal, 50% congested
- **Dev tax:** 0% (constitutional prohibition)

## Security

- Comprehensive automated test suite with historical attack reproductions
- MESS hybrid reorg defense
- Chain verification (Bitcoin Core verifychain style)
- Consensus specification for audit

See [SECURITY.md](SECURITY.md) for vulnerability disclosure process.

## Building from Source

```bash
# Requirements: Rust 1.75+, cmake, clang
cargo build --release --features "randomx testnet"

# Run tests
cargo test --release
```

## Documentation

- [Getting Started](docs/pages/GETTING_STARTED.md)
- [Consensus Specification](docs/pages/CONSENSUS_SPECIFICATION.md)
- [Security Fixes](docs/pages/SECURITY_FIXES.md)
- [Audit Scope](docs/pages/AUDIT_SCOPE.md)
- [Constitution](CONSTITUTION.md)
- [API Reference](docs/API.md)

## License

MIT
