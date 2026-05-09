# CoinCync Aggressive Test Battery

**947 tests. 0 mocks. Real crypto. Real attacks.**

A comprehensive adversarial test suite for privacy-focused blockchains. Originally built for CoinCync but designed to be adapted by any CryptoNote-family, Monero-fork, or privacy coin project.

## Test Tiers

| Tier | File | Tests | What It Attacks |
|------|------|-------|-----------------|
| 1 | `adversarial.rs` | 20 | Validation bypass — malformed blocks, wrong magic, height manipulation |
| 2 | `consensus_edges.rs` | 19 | Consensus rule boundaries — activation heights, ring size cutover |
| 3a | `p2p_adversarial.rs` | 15 | P2P attacks — garbage deserialization, slow peers, eclipse attempts |
| 3b | `network_adversarial.rs` | 13 | Network layer — subnet diversity, peer banning, memory budgets |
| 4a | `crypto_properties.rs` | 20 | Cryptographic invariants — random-input property testing |
| 4b | `crypto_adversarial_corpora.rs` | 23 | Crypto boundary values — zero scalars, group order, identity points |
| 5 | `tier5_chain_reorg.rs` | 12 | Chain state — orphan handling, rollback, height consistency |
| 6 | `tier6_dos_resource.rs` | 10 | DoS — mempool flooding, capacity limits, fee bypass |
| 7 | `tier7_wallet_attacks.rs` | 10 | Wallet — key derivation, mnemonic integrity, view-key isolation |
| 8 | `tier8_rpc_security.rs` | 10 | RPC — garbage input, extreme values, deserialization safety |
| 9 | `tier9_timing_sidechannel.rs` | 8 | Side-channels — constant-time operations, timing oracle resistance |
| 10 | `tier10_integration_adversarial.rs` | 11 | Full-stack — multi-component attack chains, complete lifecycle |
| 11 | `tier11_brutal_attacks.rs` | 15 | Brutal — inflation, forgery, fee bypass, type confusion, overflow |
| 12 | `tier12_crypto_warfare.rs` | 8 | Crypto warfare — Pedersen binding, proof portability, CLSAG linkability |
| 13 | `tier13_historical_attacks.rs` | 24 | Historical — 10 real blockchain incidents with CVE citations |
| 14 | `tier14_reorg_defense.rs` | 17 | MESS reorg defense — exponential cost verification |
| — | `full_pipeline_real_crypto.rs` | 13 | Full crypto pipeline — real CLSAG + Bulletproofs through mempool |
| — | `phase1_critical.rs` | 47 | Launch blockers — range proofs, double-spend, EAE, dust |
| — | `regression_critical.rs` | 7 | Regression — 7 historical bugs that can never return |
| — | `security_critical.rs` | 25 | Security — double-spend, subaddresses, wallet, emission |
| — | `crypto_integration.rs` | 6 | Crypto integration — keypair roundtrip, signing hash |
| — | `wallet_roundtrip.rs` | 6 | Wallet — persistence, mnemonic, CLSAG formula |
| — | `dandelion_multi_node.rs` | 6 | Dandelion++ propagation — multi-node graph behavior (stem fan-out, embargo timeout, fluff completion) |
| — | Supporting tests | ~580+ | Unit tests in src/ modules |

### Total in main crate: 953 tests

### Workspace-member integration tests

Each multi-phase workspace crate has its own integration test exercising the entire layered stack (state machine, persistence, runtime / crypto) as a unit. These compose the lib's public surface in realistic flows and adversarial cases.

| Crate | File | Tests | What It Covers |
| --- | --- | --- | --- |
| `coincync-frost-coordinator` | `tests/integration_full_flow.rs` | 8 | Full 2-of-3 FROST signing flow with invitation tokens and persistence: cross-session token replay, expired tokens, unattached-participant rejection, double-submit rejection, terminal stickiness through reload, crash recovery, MAC binds all fields |
| `coincync-rolling-finality` | `tests/integration_full_flow.rs` | 11 | Real ed25519 signing throughout — end-to-end: sign → encode → decode → verify → apply → finalize. Adversarial: cross-signed forgery, tampered fields, malformed wire bytes, below-quorum, fork double-voting, inactive miners, verifier substitution |
| `coincync-swap` | `tests/integration_full_flow.rs` | 10 | Full atomic-swap composition: protocol state machine, handshake, and state persistence. Refund safety from every lock state, crash recovery, terminal stickiness, unsafe-timeout rejection at both layers |

### Total in workspace-member crates: 29 integration tests + 158 unit / property tests = 187

### Workspace-member crate test totals

| Crate | Lib | Bins | Integration | Total |
| --- | --- | --- | --- | --- |
| `coincync-frost-coordinator` | 38 | 13 | 8 | 59 |
| `coincync-rolling-finality` | 36 | 0 | 11 | 47 |
| `coincync-swap` | 42 | 0 | 10 | 52 |
| `coincync-rig` | n/a | n/a | n/a | (project miner; not adversarial) |
| `bridge` | n/a | n/a | n/a | (cross-stack types; lib-only) |
| `coincync-faucet` | n/a | n/a | n/a | (deployment service) |
| `coincync-status-probe` | n/a | n/a | n/a | (post-launch — not yet authored) |

### Workspace grand total: 1140+ tests (953 main + 187 workspace-member)

### Running the test suite

```bash
# Main crate (releases use this for the regression baseline)
cargo test --release

# Multi-node Dandelion++ harness (needs a real Tokio runtime)
cargo test --release --test dandelion_multi_node

# FROST coordinator (default features = state machine only)
cargo test --release -p coincync-frost-coordinator

# FROST coordinator with all features (server + cli + invitations + persistence)
cargo test --release -p coincync-frost-coordinator --all-features

# Rolling finality (default = state machine; needs ed25519+wire-codec for integration)
cargo test --release -p coincync-rolling-finality --features ed25519,wire-codec

# Atomic swap (default features cover everything)
cargo test --release -p coincync-swap

# Everything across the workspace
cargo test --release --workspace --all-features
```

## Historical Attack Tests

Each test in `tests/historical_attacks/` reproduces a named, dated, real-world blockchain attack:

| Date | Chain | Attack | CVE | File |
|------|-------|--------|-----|------|
| 2010-08 | Bitcoin | Value overflow (184B BTC) | CVE-2010-5139 | `bitcoin_2010_value_overflow.rs` |
| 2018-09 | Bitcoin | Duplicate input inflation | CVE-2018-17144 | `bitcoin_2018_inflation.rs` |
| 2017-04 | Monero | Key image validation bypass | — | `monero_2017_key_image.rs` |
| 2019-11 | Monero | check_money_overflow | CVE-2019-18936 | `monero_2019_overflow.rs` |
| 2020-07 | Monero | Janus attack (subaddress linking) | — | `monero_2020_janus.rs` |
| 2018-09 | Monero | Burning bug (unspendable outputs) | — | `monero_2018_burning_bug.rs` |
| 2018-04 | Verge | Timestamp → difficulty manipulation | — | `verge_2018_timestamp.rs` |
| 2019-01 | ETC | 100+ block deep reorg ($1.1M) | — | `etc_2019_deep_reorg.rs` |
| 2017 | Monero | Ring traceability (academic) | — | `monero_ring_linkability.rs` |
| 2018-03 | Zcash | Groth16 counterfeiting flaw | — | `zcash_2018_proof_forgery.rs` |

## How to Adapt for Your Project

### If you're a CryptoNote/Monero fork:

Most tests work directly. Replace imports:
```rust
// Change this:
use coincync::crypto::{SecretScalar, PedersenCommitment, ...};
use coincync::mempool::Mempool;

// To your crate:
use your_crate::crypto::{SecretScalar, PedersenCommitment, ...};
use your_crate::mempool::Mempool;
```

### If you're any PoW blockchain:

These tiers are universally applicable:
- **Tier 5** (chain state) — any chain with reorgs
- **Tier 6** (DoS) — any chain with a mempool
- **Tier 8** (RPC) — any chain with an API
- **Tier 11** (brutal attacks) — overflow, type confusion, fee bypass
- **Tier 13** (historical) — Bitcoin CVEs apply to everyone
- **Tier 14** (reorg defense) — any low-hashrate PoW chain

### If you use ring signatures:

These are directly relevant:
- **Tier 4** (crypto properties/adversarial)
- **Tier 9** (timing side-channels for CLSAG)
- **Tier 12** (crypto warfare — linkability, key image determinism)
- Historical: `monero_2017_key_image.rs`, `monero_ring_linkability.rs`, `monero_2020_janus.rs`

### If you use Bulletproofs/range proofs:

- **Tier 12** (`attack_bulletproof_only_proves_committed_value`, `attack_truncated_range_proof_rejected`)
- Historical: `zcash_2018_proof_forgery.rs` (proof portability)
- `full_pipeline_real_crypto.rs` (range proof corruption tests)

## Design Principles

1. **No mocks.** Every test uses real cryptographic operations.
2. **Named attacks.** Historical tests cite the CVE, date, chain, and impact.
3. **Failure messages explain the vulnerability.** If a test fails, the assertion message tells you exactly what attack just succeeded.
4. **Defense in depth.** Critical properties are tested at multiple layers (structural validation, crypto verification, mempool policy).
5. **Regression permanence.** Once a bug is found and fixed, the test ensures it never returns.

## Running

```bash
# All tests
cargo test --release

# Specific tier
cargo test --release --test tier11_brutal_attacks

# Historical attacks only
cargo test --release --test tier13_historical_attacks

# Full crypto pipeline (no skip_crypto)
cargo test --release --test full_pipeline_real_crypto
```

## Adding New Historical Attacks

When a new incident occurs on any blockchain:

1. Create `tests/historical_attacks/<chain>_<year>_<name>.rs`
2. Add doc comment with date, chain, CVE, citation, impact
3. Write 2-3 tests reproducing the attack pattern
4. Add `#[path]` include to `tier13_historical_attacks.rs`
5. Update `tests/historical_attacks/README.md` table

## License

These tests are part of the CoinCync project. Use them freely to secure your own chain.
