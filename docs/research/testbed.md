<!-- markdownlint-disable MD036 MD013 -->
# CoinCync as a PoW Privacy Primitives Testbed

**Audience:** developers of other PoW privacy chains (or any project shipping novel cryptographic primitives) looking for a reference implementation, an adversarial testing corpus, or a live testbed to exercise primitives in production-shaped conditions.

---

## The gap this fills

PoS smart-contract crypto has well-known testnets — Sepolia, Holesky, base-sepolia, optimism-sepolia. Researchers and dApp developers point at these to test contracts against real network conditions before shipping to mainnet. The infrastructure is shared, the tooling is standardized, and the social conventions are clear.

**PoW privacy crypto has no equivalent.** Monero's testnet exists but is scoped to Monero's roadmap. Zcash's testnet runs Zcash's specific protocol. There's no neutral PoW chain where someone working on a new range proof scheme, a new ring signature variant, a new stealth-address mechanism, or a new commitment-encoding scheme can test the primitive against an adversarial corpus, live consensus conditions, and the kind of edge cases only real PoW operation surfaces.

CoinCync v1.0 is positioned to be that gap-filler — by accident at first (because it's open source and modular), by design afterward (because positioning matters).

This document is the public-facing statement of that positioning and the concrete on-ramps for adoption.

---

## What CoinCync provides today

### 1. Live PoW privacy testnet

Public, free, always-on. Mining is open. The faucet drips test-CYNC to anyone who asks. The chain runs the full v1.0 privacy stack — CLSAG ring sigs, stealth addresses, Bulletproofs+, Dandelion++, encrypted memos, view-tag scanning, view-key scoping, plausible-deniability wallets, FROST multi-sig.

- **Testnet RPC:** `https://api.coincync.network/rpc/testnet` (JSON-RPC 2.0)
- **Explorer:** [explorer.coincync.network](https://explorer.coincync.network)
- **Faucet:** [coincync.network/faucet](https://coincync.network/faucet) (10 tCYNC per address, 1-hour rate limit)
- **Network specs:** RandomX, 120s blocks, 100M asymptotic supply cap, CLSAG ring-16

Existing today. Adoption-ready.

### 2. Modular Rust crates (status-pending publication)

Each cryptographic surface is its own workspace member, designed for cross-chain extraction. Same Rust toolchain (1.85+ stable), same dependency stack (curve25519-dalek, merlin, serde, borsh), same audit-prep posture.

| Crate | Purpose | Current status | Adoption-ready? |
|---|---|---|---|
| [`coincync-rolling-finality`](../../crates/coincync-rolling-finality/) | CIP-009 miner-signed rolling soft-finality, time-warp immune | Workspace member, feature-gated `--features rolling-finality` | After v1.0 audit |
| [`coincync-swap`](../../crates/coincync-swap/) | CIP-001 trustless CYNC↔BTC atomic swaps (Schnorr adaptor sigs, strict-binding cross-curve DLEQ, joint-key CLSAG) | Audit-input frozen | v1.1 audit pending |
| [`coincync-frost-coordinator`](../../crates/coincync-frost-coordinator/) | CIP-008 FROST M-of-N threshold Schnorr coordination (RFC 9591) | Workspace member | After v1.0 audit |
| [`orchard-side`](../../crates/orchard-side/) | Phase-2 Halo2 / Orchard shielded-pool wrapper | Workspace member, CIP-013 activation pending | Post-Phase-2 audit |
| [`bridge`](../../crates/bridge/) | Cross-chain bridge primitives (not active in v1.0 — Article XIII prohibits external trust) | Workspace member, structural placeholder | Not applicable to v1.0 |

After the base-chain audit clears, each crate is publishable to crates.io with a tracked semver. Adopting one in another chain is a `Cargo.toml` line + the cross-chain integration glue (UTXO vs account-model adapters live downstream).

### 3. Adversarial audit suite

CoinCync's [`audit-suite/`](../../audit-suite/) is a Python toolkit modeled on what Trail of Bits, NCC Group, Halborn, Zellic, and Cure53 actually run against privacy coins and PoW chains. The suite is two layers:

- **JS / Hardhat layer** — EVM-shaped targets (out of scope for CoinCync; documented as NOT_APPLICABLE)
- **Native layer** — privacy coins and non-EVM swaps, tested against real binaries over RPC

The native layer has **20+ modules** covering Orchard / Halo2, CLSAG, stealth & confidential transactions, RandomX PoW, atomic swap (CIP-001), crypto primitives, consensus / chain, P2P wire (framer cancel-safety, IBD wedge), mempool / relay, wallet Tauri IPC, JSON-RPC API, state DB, mining stack, FROST coordinator, sidechannel / integer overflow, info-leaks / observability.

The corpus + reporter + differential-testing infrastructure are already built. Once we publish a slim public-facing version of the suite, other PoW privacy projects can run their primitives through the same adversarial machinery the v1.0 audit firm will see.

**Status:** internal today; public release scheduled with v1.0 audit handoff so we don't leak in-flight findings.

### 4. Sandbox for experimental primitives

The `audit-suite/sketches/` tree is the home for **experimental primitives that may someday graduate** to the main chain. Currently:

- [`audit-suite/sketches/bulletproofs-plus-plus/`](../../audit-suite/sketches/bulletproofs-plus-plus/) — Bulletproofs++ (Eagen 2022, IACR ePrint 2022/510). Phase 1a wrapper around `bp-pp` (distributed-lab, secp256k1) is working: real prove → verify roundtrips, 16-output aggregation, malformed-proof rejection. Phase 1b (port to Ristretto255 to match CoinCync's curve) is the next sandbox step. Possible v1.2 ship.

The pattern: any new privacy primitive enters as a sandbox crate, runs through Phase 0 (scaffolding) → Phase 1 (working impl) → Phase 2 (benchmarks) → Phase 3 (integration test) → Phase 4 (adversarial validation in `audit-suite/modules/`) → Phase 5 (audit and possible promotion to a tracked sketch crate). Same pipeline another chain's developer can follow against their own primitive, using CoinCync's existing infrastructure as the reference.

---

## On the roadmap

### Research RPC namespace (target: v1.1 / v1.2)

A planned **`research_*` namespace** on the JSON-RPC API, gated behind a `--enable-research-api` node flag (off by default; on for the testnet endpoint at `api.coincync.network`).

Provisional surface:

```
research_proveRange(value, blinding)            → BulletproofsPlus proof
research_verifyRange(commitment, proof)         → bool
research_proveCLSAG(message, ring, witness)     → CLSAG signature
research_verifyCLSAG(message, ring, signature)  → bool
research_proveStealth(view_key, scan_index)     → stealth address
research_verifyStealth(address, ephemeral)      → bool
research_proveBulletproofsPlusPlus(...)         ← post-Phase-1b
research_proveDLEQ(...)                         ← cyncswap-side
research_verifyDLEQ(...)
```

Rate-limited, logged, no consensus impact. External developers can point their PoW-privacy projects at our research endpoint and exercise each primitive without standing up their own infrastructure.

Spec lands as **CIP-014 — Research RPC Namespace** when the v1.1 work begins.

### Public audit-suite release (target: post-v1.0 audit handoff)

Slim version of [`audit-suite/`](../../audit-suite/) published as its own repository, with internal-findings stripped, ready for outside contributors. Other PoW privacy projects can pull modules and run them against their own binaries.

---

## How to adopt a CoinCync primitive

Until the v1.0 audit clears and the crates land on crates.io, the canonical adoption path is from-source:

```toml
# In your project's Cargo.toml
[dependencies]
coincync-frost-coordinator = { git = "https://github.com/ghostrider1092/Coincync-Testnet-", tag = "v1.0.9-testnet-pre-audit" }
```

This pins to a specific release tag — frozen, reproducible, and audit-prep-aligned. Don't pin to `main` for any cross-chain integration work; main moves fast during the audit-prep window.

Once a crate is audited and published:

```toml
[dependencies]
coincync-frost-coordinator = "1.0"   # or whatever the audited semver lands at
```

For each crate that ships, expect:

1. A short top-level `README.md` explaining what it does and minimum dependencies
2. A `docs/adoption.md` explaining how to integrate into UTXO-model vs account-model chains
3. A `tests/` corpus that includes adversarial inputs (subset of `audit-suite/corpus/`)
4. SemVer-pinned API stability — breaking changes only on major version bumps

---

## How to engage

- **Reference a primitive in your own paper / project:** great, link back to the relevant CIP and tag. No permission needed (MIT-licensed).
- **Found a bug in our crypto:** file a GitHub issue or, for security-sensitive bugs, follow [`SECURITY.md`](../../SECURITY.md).
- **Adopting a crate in production:** keep us in the loop via a GitHub issue so we can flag breaking changes early. (Optional, not required — we don't gate adoption.)
- **Want a new `research_*` RPC method:** open an issue tagged `research-rpc` describing the primitive and the API shape you'd want. The CIP-014 spec process is open.
- **Testing your own privacy primitive against CoinCync:** the testnet is public. Mine to fund your test wallets. Submit transactions that exercise your primitive. The `audit-suite/sketches/` pattern is also open — submit a PR with your sandbox crate under `audit-suite/sketches/<your-primitive>/` if you want it to live alongside ours.

---

## Honest caveats

- **Pre-audit.** v1.0 base-chain audit is scheduled for ~July 2026 (NLnet outreach to Cypher Stack / OSTIF / Teserakt in progress). Don't ship a CoinCync crate to production until that audit closes. Sandbox / research use is fine.
- **APIs evolve.** Pre-mainnet means breaking changes are still possible. Pin to tags, not to `main`.
- **No cross-chain testnet bridge.** The "testbed" is reference / inspiration, not technical integration. You don't deploy your chain's contracts to CoinCync; you adopt CoinCync's primitives into your chain's source code. (CIP-014 research RPC is the closest thing to "use CoinCync from your chain" we plan to support.)
- **No paid testbed-as-a-service.** Article XII of the Constitution prohibits the chain from having admin authority — there's no permission gate to charge for. Adoption is free and always will be.
- **We do not endorse** projects that adopt our crates. Adoption is unilateral. We will note adoption (with the project's permission) but won't co-sign their security claims.

---

## Why this matters

PoW privacy crypto is its own discipline. RingCT, CLSAG, stealth addresses, Bulletproofs+, RandomX, Dandelion++ — none of them came out of the EVM-PoS world; all of them came out of UTXO-style PoW chains and adjacent research. The discipline has thinned out over the last few years as the loudest crypto-research voices migrated to zk-SNARK land. CoinCync's existence is a small bet that the discipline still matters.

Being open-source is necessary but not sufficient to make that bet pay off. The bet pays off when other projects can *actually use* the work — when a new privacy chain doesn't have to re-implement CLSAG, when a research paper can cite a working production reference, when a developer can audit a primitive against a real adversarial corpus rather than synthetic toys.

That's what this document is for.
