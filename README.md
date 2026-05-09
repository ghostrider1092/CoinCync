# CoinCync 1.0

A privacy-first cryptocurrency with mandatory shielding, auditable supply, and constitutional protections.

> **Privacy money that doesn't depend on permission to participate. CYNC↔BTC atomic swaps are a constitutional mainnet-launch commitment, not a roadmap item to be deferred. Whether this combination works is what testnet and mainnet are for.**

**Status:** Public Testnet  
**Network:** Active public testnet fleet across North America and Europe  
**Launch:** Mainnet October 2026  
**Discord:** [Join the community](https://discord.gg/5tYNSCsqzy)

> Current network scope: Orchard and Lelantus Spark are **not enabled** on the
> live public testnet. Phase-2 shielded modules remain compile-time gated and
> inactive in consensus until a future activation decision.
>
> Public binaries and operator defaults are testnet-first. Mainnet code remains
> in-repo for release readiness but is not a live public network yet.

## Privacy Features (22 total, all mandatory)

**Cryptographic (Layer 1):** CLSAG Ring-16 signatures¹, stealth addresses, Pedersen commitments, Bulletproofs+ range proofs, encrypted memos, key images, view tags

¹ During the first 10,000 blocks of any network (mainnet or testnet), the ring size is 11 (the constitutional `BOOTSTRAP_MIN_RING_SIZE`). A young chain doesn't have enough on-chain outputs to form a 16-member anonymity set without decoy reuse, so the protocol relaxes the minimum during bootstrap and snaps to Ring-16 at block 10,000. The script `scripts/verify-privacy.ps1` is height-aware and reports which ring is expected for any given tx.

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
./coincync-miner --address YOUR_tCYNC_ADDRESS --threads 4 --node 127.0.0.1:28081
```

See [Getting started docs](docs/src/getting-started/build.md) for full instructions.

## Testnet

Three seed nodes across three continents &mdash; New Jersey (US-East), Amsterdam (Europe), Tokyo (Asia-Pacific). Resolved via DNS at `seed1/2/3.coincync.network`. Community-run seeds welcome &mdash; open a PR to add yours.

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

## Workspace structure

The repository is a Cargo workspace. The main crate is the
node + wallet (`coincync-node`, `coincync-wallet`); supporting
crates ship privacy-adjacent infrastructure that's gated behind
feature flags and only pulled in by the binaries that need it:

| Crate | Purpose | Status |
| --- | --- | --- |
| (root) | Full node + wallet + miner | Production-ready, public testnet |
| `crates/bridge` | Cross-stack byte-only types | Stable |
| `crates/coincync-rig` | Mining rig binary | Production-ready |
| `crates/coincync-faucet` | Testnet faucet service | Deployed |
| `crates/coincync-frost-coordinator` | FROST M-of-N signing relay (CIP-008) | State machine, auth, persistence, WSS server, operator CLI all shipped; integration tests pass. Ships `coord` (server) and `coord-cli` (operator) binaries. |
| `crates/coincync-rolling-finality` | Miner-signed soft-finality (CIP-009.D) | State machine, ed25519 verifier, wire codec all shipped; integration tests pass with real ed25519 throughout. `validate_block` integration queued for activation per CIP-011. |
| `crates/coincync-swap` | CYNC↔BTC atomic swap (CIP-001) | Protocol state machine, handshake state machine, state persistence shipped; CLI `cyncswap` operational. Real adaptor signatures + transport queued for the audit window. |

Each multi-phase crate's `tests/` directory has a focused
integration test that composes every layer; see
[`tests/README.md`](tests/README.md) for the full catalog.

## Documentation

- [Getting Started](docs/src/getting-started/build.md)
- [Consensus Specification](docs/src/protocol/consensus.md)
- [Privacy Model](docs/src/protocol/privacy-model.md)
- [Node Operations](docs/src/operations/deployment.md)
- [Constitution](CONSTITUTION.md)
- [API Reference](docs/API.md)
- [CIP register](docs/cip/) — CIP-001 (atomic swap), CIP-007 (hard-fork activation policy), CIP-008 (FROST coordinator), CIP-009 + CIP-009.D (reorg defense + miner-signed rolling checkpoints), CIP-010 (testnet hard-fork rehearsal), CIP-011 (rolling-finality activation), CIP-012 (FROST coordinator deployment)
- [Operational runbooks](docs/operations/) — incident response, status page design, reproducible builds, continuous fuzzing, DNS failover, checkpoint procedure

## License

MIT
