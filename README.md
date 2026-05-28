# CoinCync 1.0

**Privacy money that requires no permission.**

A proof-of-work cryptocurrency with mandatory privacy at the consensus layer, an auditable supply curve, and constitutional protections against admin authority, federations, governance tokens, and compliance hooks.

**Status:** Public testnet · v1.0.8-testnet
**Network:** 5-node fleet across US-East / EU / Asia-Pacific
**Mainnet:** targeted Q4 2026 (gated on security audit + atomic-swap implementation)
**Discord:** [join](https://discord.gg/5tYNSCsqzy)

---

## Project state

CoinCync is **early-stage infrastructure software on public testnet**. Honest read of what works and what doesn't:

**What's solid:**

- Full node + wallet + CPU miner ship clean and run continuously across the fleet
- All 22 privacy features active in production: CLSAG ring signatures, Bulletproofs+, stealth addresses, Dandelion++, Noise XX, cover traffic, view tags, encrypted memos, FROST multi-sig, dead-man's-switch, auto-churn
- Reproducible Docker builds; consensus-critical files protected by SHA-256 lockfile
- Prometheus `/metrics` endpoint with hot-path histograms
- 80-entry hardcoded testnet checkpoint list for long-range-attack defense

**What's not yet enabled:**

- Phase-2 shielded modules (Orchard / Lelantus Spark / MimbleWimble kernels) — storage-side rewind machinery shipped feature-gated; trees remain `None` at chain construction until a future activation hard fork
- CYNC↔BTC atomic swaps — state machine + handshake + persistence shipped; real adaptor-signature crypto pending the audit window
- CIP-009.D rolling soft-finality — machinery shipped behind `rolling-finality` feature flag, default OFF; activation at testnet height 50,000

**What's known rough:**

- 5/5 fleet nodes hosted on a single cloud provider (correlated failure mode acknowledged)
- Single-miner network most of the time; difficulty-adjustment behaviour at low hashrate is its own thing to watch
- Test coverage is high (700+ tests) but several integration tests assume specific fleet state
- Wallet UX is mid-refactor; some pages still feel utilitarian

Use at your own risk. Testnet coins have no real value. Mainnet binaries are not yet a live public network.

---

## Quick Start

```bash
# Download the v1.0.8 testnet release
wget https://github.com/ghostrider1092/Coincync-Testnet-/releases/download/v1.0.8-testnet/coincync-linux-x86_64.tar.gz
tar xzf coincync-linux-x86_64.tar.gz

# Verify checksums (always)
wget https://github.com/ghostrider1092/Coincync-Testnet-/releases/download/v1.0.8-testnet/SHA256SUMS.txt
sha256sum -c SHA256SUMS.txt

# Run a node (binds 0.0.0.0:28080 P2P, 127.0.0.1:28081 RPC)
./coincync-node --network testnet

# Create wallet
./coincync-wallet create --password YOUR_PASSWORD

# Mine — RandomX, CPU only
./coincync-rig run-solo --node http://127.0.0.1:28081 --address YOUR_tCYNC_ADDRESS --threads 0
```

Full walkthrough: [docs/src/getting-started/build.md](docs/src/getting-started/build.md).

---

## How it works

CoinCync ships **22 mandatory privacy features across 4 layers**. None are opt-in; the protocol rejects transactions that try to bypass them.

| Layer | Surface | Highlights |
| --- | --- | --- |
| L1 Cryptographic | Every transaction | CLSAG Ring-16 ¹, stealth addresses, Pedersen commitments, Bulletproofs+, view tags |
| L2 Network | Every packet | Dandelion++ stem/fluff, Noise XX P2P, jitter + size-normalisation + constant-rate cover traffic |
| L3 Wallet | User-side | Uniform decoy selection, time-scoped view keys, plausible deniability, auto-churn, dead-man's switch, FROST multi-sig |
| L4 Constitutional | Compile-time | Mandatory privacy, no surveillance hooks, no balance-lookup RPC, 4th Amendment enforcement |

Full per-feature detail (with file:line citations + status): [docs/PRIVACY_FEATURES.md](docs/PRIVACY_FEATURES.md).

¹ For the first 10,000 blocks of any network, ring size is 11 (the constitutional `BOOTSTRAP_MIN_RING_SIZE` — a young chain doesn't have enough on-chain outputs to form a 16-member anonymity set without decoy reuse). Snaps to Ring-16 at height 10,000. [`scripts/verify-privacy.ps1`](scripts/verify-privacy.ps1) is height-aware.

---

## Testnet

Three DNS-resolved seed nodes: `seed1.coincync.network` (New Jersey), `seed2` (Amsterdam), `seed3` (Tokyo). Auto-discovered when you run `coincync-node --network testnet`. Community-run seeds welcome — open a PR.

---

## Monetary policy

- **Supply cap:** 100,000,000 CYNC (asymptotic, never reached)
- **Block time:** 120 seconds
- **Genesis reward:** ~50 CYNC/block, decaying
- **Tail emission:** 0.6 CYNC/block, perpetual
- **Fee burn:** 30% normal, 50% congested
- **Dev tax:** 0% (constitutional prohibition — Article II)

---

## Versioning

`v1.0.x-testnet` releases are the stable codebase for the pre-mainnet testnet. Breaking consensus changes during this sequence are coordinated via documented hard forks (e.g., `MIN_OUTPUT_AGE` 10 → 100 in v1.0.10) so node operators have explicit activation-height-gated upgrade windows. v1.0 mainnet ships **October 1, 2026** — at that point the codebase is frozen against breaking changes per strict SemVer. Anything that requires a breaking change post-mainnet becomes v2.0.

**Tag-cut discipline:**

- Every release passes through a release candidate (`v1.0.X-rcN-testnet`) before the headline tag, with at least 24-72h of soak before promotion. This is what saved the v1.0.9 release from a Windows-only-binaries regression (the auto-publish workflow was added after).
- Pre-release qualifiers (`-testnet`, `-pre-audit`, `-rcN`) are SemVer-compliant and signal what's NOT yet finished. Read them as load-bearing, not decoration.
- A tag without a qualifier means "audited, mainnet-ready, no known regressions." We don't have one of those yet.

---

## Security

- Comprehensive test suite (700+ tests) including historical attack reproductions
- Hybrid reorg defense — Tier 1 (Nakamoto longest-chain ≤10 deep) + Tier 2 (MESS exponential cost 11-100 deep) + Tier 3 (hard cap, currently 1000 on testnet)
- Hardcoded checkpoint list (80 entries, h=50..4000 step 50) for long-range-attack defense
- Chain verification — Bitcoin Core `verifychain`-style consistency check on startup
- Per-CIP consensus specifications targeted at audit firms
- NLnet (NGI0 Commons Fund) grant application in flight; once approved, the funded audit will be a Cypher Stack / OSTIF / Teserakt scope

Vulnerability disclosure: [SECURITY.md](SECURITY.md).

---

## Building from source

```bash
# Requirements: Rust 1.75+, cmake, clang
cargo build --release --features "randomx testnet"

# Run tests
cargo test --release --features "randomx testnet"

# Reproducible Docker build (byte-identical binaries on the same host CPU arch)
bash scripts/build-in-docker.sh
```

---

## Workspace structure

Cargo workspace. Root crate is the node + wallet + miner; sister crates ship privacy-adjacent infrastructure gated behind feature flags.

| Crate | Purpose | Status |
| --- | --- | --- |
| (root) | Node, wallet CLI, mining rig, FROST/swap state machines | Production-ready, public testnet |
| `crates/bridge` | Cross-stack byte-only types | Stable |
| `crates/coincync-rig` | RandomX CPU miner (`run-solo` + `bench`) | Production-ready |
| `crates/coincync-faucet` | Testnet faucet service | Deployed |
| `crates/coincync-frost-coordinator` | FROST M-of-N signing relay (CIP-008) | State machine, auth, persistence, WSS server, operator CLI all shipped. Ships `coord` + `coord-cli` binaries. |
| `crates/coincync-rolling-finality` | Miner-signed soft-finality (CIP-009.D) | State machine, ed25519 verifier, wire codec all shipped. `validate_block` integration shipped behind `rolling-finality` cargo feature (default OFF). Activates per CIP-011 schedule. |
| `crates/coincync-swap` | CYNC↔BTC atomic swap (CIP-001) | State machine + handshake + persistence shipped. Real adaptor signatures + BTC RPC client queued for audit window. NLnet-funded. |

Each multi-phase crate's `tests/` directory composes every layer in a focused integration test — see [`tests/README.md`](tests/README.md) for the catalog.

---

## Documentation

- [Getting started](docs/src/getting-started/build.md)
- [Consensus specification](docs/src/protocol/consensus.md)
- [Privacy model](docs/src/protocol/privacy-model.md)
- [Privacy features (per-feature detail)](docs/PRIVACY_FEATURES.md)
- [Node operations](docs/src/operations/deployment.md)
- [API reference](docs/API.md)
- [Constitution](CONSTITUTION.md) — the 19-article + 15-rights compile-time-enforced posture
- [CIP register](docs/cip/) — 12 CIPs covering atomic swap, reorg defense, rolling finality, FROST, hard-fork activation policy
- [Blockchain roadmap](docs/BLOCKCHAIN_ROADMAP.md) — forward-looking, organized by release phase
- [Operational runbooks](docs/operations/) — incident response, status page design, reproducible builds, continuous fuzzing, DNS failover, checkpoint procedure

---

## Manifesto

> Privacy money that doesn't depend on permission to participate. CYNC↔BTC atomic swaps are a constitutional mainnet-launch commitment, not a roadmap item to be deferred. Whether this combination works is what testnet and mainnet are for.
>
> *Privacy money that requires no permission.*

---

## License

MIT
