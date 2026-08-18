# CoinCync — Audit Readiness Dossier

**Status:** living document, 2026-08-17. **Purpose:** give an external security
auditor or grant reviewer (e.g. NLnet NGI0) a single, honest, code-grounded map
of what CoinCync is, what has been hardened, what is *proven*, and what is still
open — so a review can start from evidence rather than a cold read.

> **Honesty first.** This document lists open items and known-broken-but-gated
> surfaces alongside the fixes. Nothing below is a marketing claim; every item
> cites the commit, test, or spec section that backs it, and the code is the
> ground truth (see [`CONSENSUS_SPEC.md`](./CONSENSUS_SPEC.md)).

---

## 1. What is under review

CoinCync is a fair-launch, CPU-only (RandomX) proof-of-work privacy
cryptocurrency in the Monero lineage: RingCT with CLSAG ring signatures,
Bulletproofs+ range proofs, Pedersen commitments, and stealth addresses.
Privacy is mandatory (no transparent mode). Emission is a fixed, transparent
schedule with **0% developer tax, no premine, no ICO**.

The consensus-critical surface is small and integrity-locked. These **8
hash-locked files** (`critical_files.lock`, SHA-256 over LF-normalized bytes;
the build fails on any mismatch) are where consensus behavior lives — an auditor
should concentrate here:

- `src/consensus/validation.rs` — block + transaction validity
- `src/consensus/difficulty.rs` — ASERT difficulty
- `src/consensus/pow.rs` — RandomX proof-of-work
- `src/emission/curve.rs` — emission curve
- `src/constants.rs` — all consensus constants
- `src/testnet.rs` — testnet genesis/params
- `CONSTITUTION.md`, `docs/BILL_OF_RIGHTS.md` — governance text

The full rule-by-rule specification, each rule cited to its enforcement site, is
in **[`CONSENSUS_SPEC.md`](./CONSENSUS_SPEC.md)** — the recommended entry point
for a consensus review.

---

## 2. Reproducible build — verified

Release binaries are built by a pinned container
(`scripts/build-in-docker.sh` → `docker/builder.Dockerfile`, Rust 1.88.0,
`--locked`, `SOURCE_DATE_EPOCH` from git, stripped). **Byte-identity is verified,
not aspirational:** two independent from-scratch builds of the same commit (one
forced `--no-cache`) produced identical SHA-256 sums for all six artifacts.

**Reproduce it yourself:** run `bash scripts/build-in-docker.sh` twice into
different output dirs and `diff` the `out/SHA256SUMS`. Every release also carries
a Sigstore build-provenance attestation and a signed Git tag. (Threshold signing
across multiple maintainer keys is a documented future enhancement, not yet in
force — see Bill of Rights XIII.)

---

## 3. Hardening record (2026-08 pre-mainnet campaign)

18 commits this cycle. The highest-value work, by class:

### Consensus determinism (the fork-risk class)
Three bugs of one shape — an accumulated value that depended on a node's *reorg
history* rather than only on canonical chain content — were found and fixed at
the root. Two honest nodes on the same tip could otherwise diverge and fork.

- `total_difficulty` path-dependence — fixed (base-1 fork walk + recompute-on-
  load self-heal).
- `total_outputs_ever → ring-size` — fixed to
  `total_outputs_ever − reorg_disconnects_total` (`8ac98e87`); **property-tested
  across 400 random reorg histories** and verified to fail against the raw
  counter (`tests/property_invariants_determinism.rs`, `1b161fa8`).
- Self-recorded checkpoint-hash gate — removed at the root as path-dependent
  (`83ef0554`); deterministic height-floor finality retained.

A dedicated determinism sweep then enumerated *every* accumulated/persisted
consensus value and confirmed no other member of the class remains. The
contract is documented in `CONSENSUS_SPEC.md` §6.

### Reorg correctness
- Post-reorg double-spend / inflation (fork tip skipped UTXO re-validation) —
  fixed (REORG-TIP-VALIDATE) with a **real-PoW end-to-end regression test**
  proven to fail without the fix (`tests/reorg_double_spend_e2e.rs`, `60326165`).
- Reorg self-deadlock + MTP-from-fork-lineage — fixed.

### Networking / mainnet readiness
- **LB-1**: mainnet P2P bootstrap was silently using the testnet-defaulted config
  (would find zero mainnet peers) — fixed with a network-aware `BootstrapConfig`
  (`9fd1d562`).
- Dead/decommissioned seed IPs removed; dead second bootstrap path and dead
  `MainnetConfig` / duplicate constants deleted (`bc15a1db`, `69a9f9a5`).
- **M-5**: a partial `[p2p.encryption]` config silently allowed plaintext P2P —
  fixed (`bc15a1db`).

### Wallet fund-safety
- **W-B**: the "subaddresses disabled on mainnet" gate was incomplete (covered
  only the generation subcommand); address parsing, send-to-subaddress, and the
  v2 `--subaddress` flag were ungated. Closed at the parse + send boundary
  (`09bc504a`) and **live-verified on the built binary**. See §5 for the
  underlying open item (W-A).

### Documentation / claims accuracy
Aligned every public and in-code claim to the implementation: privacy features
that are disabled/dormant no longer advertised as "Live"; the supply model
corrected everywhere to the real 100M **asymptote** (not a hard cap), including a
full rewrite of an obsolete "250M mountain-curve" mdbook; honest reproducible-
build and release-signing wording; `total_burned`/circulating-supply telemetry
completed. (`11418320`, `105cc7a0`, `13a50c75`, `0ac53153`, `e1fcad5d`.)

---

## 4. Test & verification coverage

- **49 integration test files** + lib unit tests (~1,768 passing), including
  historical-attack suites (Monero/ETC/BTC incident replays), reorg-defense
  tiers, RPC endpoint, and security-critical suites.
- **7 cargo-fuzz targets** (protocol/deserialization surface).
- **Property tests** for determinism (reorg-history invariance), difficulty,
  amounts, addresses, hashes, keys, memos.
- **Real-PoW E2E** reorg double-spend test + a `total_difficulty`
  history-independence test (extend matches the canonical `1 + Σ dft` formula;
  a losing fork's work does not leak) (slow, `#[ignore]`,
  `tests/reorg_double_spend_e2e.rs`).
- **Independent review passes** this cycle: full-codebase audit, pre-mainnet
  review, P2P/reorg hunt, mainnet-surface audit, remote-DoS scan, determinism
  sweep, dead-code/wiring audit, docs-accuracy audit, and a final regression +
  correctness sweep — all findings verified against source before action.
- **Live regtest end-to-end** (2026-08-17): node + real RandomX mining + block
  validation + ASERT difficulty response + wallet scan/detect/balance + real
  ring-16 CLSAG send → mine → receive + `get_supply_info` + the W-B gate — all
  exercised on the current binary.

---

## 5. Known open items (honest)

- **W-A (deferred, mitigated): subaddress *spend* is broken.** Subaddress-received
  outputs are unspendable because the spend-side key-image derivation omits the
  per-subaddress offset `m_i`. **Mitigation:** subaddresses are now
  comprehensively **disabled on mainnet** (W-B, §3), so this cannot cause fund
  loss at launch. The real fix (thread `(account,index)` +
  `compute_subaddress_spend_secret`, gated behind a receive→spend round-trip
  test) is a post-launch item. Subaddresses remain enabled on testnet/regtest.
- **Bootstrap ring-member relaxation (blocks 1–99).** Below
  `STRICT_RING_MEMBER_HEIGHT`, an unknown ring member is allowed — a mint window.
  Closed **operationally** at launch by the genesis-bootstrap runbook (self-mine
  ≥100 blocks with `--no-peers` before opening), not in code.
- **Dormant / feature-gated (inert in production):** Lelantus Spark & MimbleWimble
  stores, rolling-finality, CIP-007 activation registry, `CONSENSUS_CHECKPOINTS`
  (empty), `insecure-fast-sync` (default off). None are on the live consensus
  path; each is a future-activation item that must be re-audited when wired.
- **Not yet done:** external professional audit (this document exists to enable
  it); mainnet seed-fleet + DNS provisioning (operator infra). The
  `total_difficulty` determinism guard now has a dedicated E2E test (extend +
  losing-fork invariance, above); the *reorg-recompute* leg is covered by the
  reorg double-spend E2E + the recompute-on-load self-heal rather than a
  standalone fuzz, since constructing a deterministic heavier fork at the
  difficulty floor is timing/tiebreak-sensitive.

See `CONSENSUS_SPEC.md` §8 for the full divergences/dormant list.

---

## 6. Suggested audit focus

In descending order of leverage:

1. **The determinism contract** (`CONSENSUS_SPEC.md` §6): confirm no accumulated
   or persisted value that feeds a consensus verdict is path-dependent. This is
   the class that produced three separate bugs here.
2. **Coinbase emission + fee accounting** (`validation.rs` max-coinbase / balance
   binding): confirm a miner cannot over-claim and that declared fees are
   cryptographically bound.
3. **The reorg engine** (`chain.rs` add_block reorg path): fork-block and tip
   re-validation against the reorged UTXO set; MESS depth policy; the height
   finality floor.
4. **RingCT crypto** (`clsag.rs`, `bulletproofs.rs`, `stealth.rs`): fail-closed
   verification, identity/subgroup checks, signing-hash binding.
5. **Wallet spend/scan** including the deferred subaddress path (W-A).

---

*This dossier is generated from the repository's own state and commit history.
It is updated as findings are closed. Corrections that reconcile it to the code
are always in order.*
