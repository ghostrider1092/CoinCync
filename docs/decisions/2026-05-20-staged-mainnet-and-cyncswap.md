# Staged mainnet: v1.0 base chain first, v1.1 cyncswap after audit

**Date:** 2026-05-20
**Status:** Accepted
**Supersedes:** the implicit prior position that atomic swaps were a v1.0 mainnet blocker (see prior wording in [BLOCKCHAIN_ROADMAP.md](../BLOCKCHAIN_ROADMAP.md) item 10 and the prior Phase-5 framing on the public site).

---

## Decision

Ship the base chain to mainnet as **v1.0** without cyncswap. Ship cyncswap as **v1.1** after the base chain is live on mainnet and cyncswap has cleared its own dedicated audit.

The Orchard shielded pool (Phase-2 activation) follows the same pattern: it ships in its own release after its own audit, not bundled into v1.0.

---

## Context

By 2026-05-20 the cyncswap implementation was substantially complete:

- 346 tests pass with `--features strict-dleq`
- Schnorr adaptor signatures over both BIP-340 secp256k1 and Ristretto255
- Cross-curve DLEQ + Noether 2018 strict-binding variant
- BTC + CYNC RPC clients, BTC lock/claim/refund tx construction
- Coordinator transport: Plain TCP + Noise XX + SOCKS5/Tor, with DoS-hardened filtered-listen variants
- 6 CLI orchestration handlers, operator-driven dual-testnet smoke harness
- Mutation score 100% on audit-critical files
- Line coverage ~97% on the audit perimeter
- Criterion benches: prove ≈ 133ms, verify ≈ 172ms
- 27-target fuzz harness with libFuzzer + AddressSanitizer, 24-hour overnight runs clean

Cyncswap is therefore audit-ready in isolation. The question was sequencing.

## Considered options

### Option A — Bundle cyncswap into v1.0 mainnet

Single audit covers base chain + cyncswap. Mainnet ships with atomic swaps from day one.

**Drawback:** the audit firm picks the scope; bundling adds 3-6 months to the audit window for code the base chain does not depend on. The base chain blocks on cyncswap audit findings. Two unrelated cryptographic perimeters in one audit also raises the per-firm cost.

### Option B — Stage them: v1.0 base chain, v1.1 cyncswap

Two separate audits, two separate releases. Base chain ships when its own audit clears; cyncswap ships when its own audit clears.

**Drawback:** users wait longer for atomic swaps. Two audit kickoffs instead of one.

## Decision rationale

Chose **Option B (staged)**.

The base chain mainnet is what users have been waiting for since the testnet went live. It does not depend on cyncswap. Bundling them turns a base-chain audit into a base-chain-plus-novel-crypto audit, which adds months for no consensus-level reason.

This is the same staging Monero used: launched in 2014 with ring signatures and stealth addresses; Bulletproofs, CLSAG, and other novel primitives shipped later, each behind its own audit. The chain established itself first, then the privacy stack hardened around it.

Specific reasons:

- **Audit scope discipline.** A cyncswap-only audit produces a cleaner report than a bundled audit. The audit firm reviews one cryptographic perimeter at a time.
- **Mainnet schedule.** v1.0 mainnet can target October 1, 2026 (the public-facing genesis date). A bundled audit slips that by 3-6 months.
- **Risk isolation.** If the cyncswap audit finds something serious, it does not block the base chain. Users on mainnet keep using the chain; the swap layer ships later when fixed.
- **Cost.** Two focused audits frequently total less than one bundled audit at a top-tier firm, because the firm prices per-perimeter complexity rather than per-LOC.
- **One headline per release** (the Apple-style discipline from [roadmap.md](../roadmap.md)). v1.0 = base chain shipping to mainnet. v1.1 = atomic swaps. Each release has one identity.

## Consequences

### What changes

- `docs/BLOCKCHAIN_ROADMAP.md` — atomic swap moves out of the "Mainnet blockers — must ship before tag" section. It becomes a v1.1 item with its own audit gate.
- `docs/roadmap.md` — v1.0 reframed from "testnet shipped" to "testnet live, mainnet next (base chain only)". v1.1 reframed as "cyncswap, post-mainnet, post-audit".
- `website/index.html` — Phase 5 ("Atomic Swaps & Signed Releases") splits: signed releases stay in mainnet prep, atomic swaps move to a new post-mainnet phase.
- Wallet v2 ships v1.0 with base-chain features only. The Trade tab is hidden behind a build flag for v1.0 and unhides in v1.1.

### What does NOT change

- The cyncswap codebase itself. Implementation continues. Audit prep continues.
- The constitutional commitments. Article XV still requires atomic-swap support; it just requires it on the chain, not on the genesis block.
- Phase-2 (Orchard) sequencing. Was already planned as its own release; this decision reinforces that pattern.

### Open follow-ups

- Schedule the base-chain audit (was already in motion; now explicitly base-chain scope, not bundled).
- Schedule the cyncswap audit (target: kickoff ~30 days after v1.0 mainnet ships).
- Update the public site to reflect the staged phases (done in this commit).
