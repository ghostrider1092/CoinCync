# CoinCync — Audit Readiness Dossier

**Status:** living document, updated 2026-10-19 (supersedes the 2026-08-17
revision, which predated the shielded-pool work and the audit-surface
narrowing). **Purpose:** give an external security auditor or grant reviewer
(e.g. NLnet NGI0) a single, honest, code-grounded map of what CoinCync is, what
has been hardened, what is *proven*, and what is still open — so a review can
start from evidence rather than a cold read.

> **Honesty first.** This document lists open items and known-broken-but-gated
> surfaces alongside the fixes. Nothing below is a marketing claim; every item
> cites the commit, test, spec section, or `file:line` that backs it, and the
> code is the ground truth (see [`CONSENSUS_SPEC.md`](./CONSENSUS_SPEC.md)).

---

## 1. What is under review

CoinCync is a fair-launch, CPU-only (RandomX) proof-of-work privacy
cryptocurrency in the Monero lineage: RingCT with CLSAG ring signatures,
Bulletproofs+ range proofs, Pedersen commitments, and stealth addresses.
Privacy is mandatory (no transparent mode). Emission is a fixed, transparent
schedule with **0% developer tax, no premine, no ICO**.

**The production perimeter is the `default` build (`default = ["randomx"]`).**
This is the critical framing for a review: every shielded/Spark, atomic-swap,
cross-chain, fee-reservoir, rolling-finality, and sketch-CIP surface named in
this document is behind a non-default Cargo feature and is **cfg-stripped out of
a production binary** — it is not merely dormant, it is not compiled. What an
auditor runs on mainnet is RingCT + the consensus engine below.

The consensus-critical surface is integrity-locked. The **17 hash-locked files**
(`critical_files.lock`, SHA-256 over LF-normalized bytes; the build fails on any
mismatch) are where consensus behavior lives — an auditor should concentrate
here:

- `src/consensus/validation.rs` — block + transaction validity
- `src/consensus/difficulty.rs` — ASERT difficulty
- `src/consensus/pow.rs` — RandomX proof-of-work
- `src/consensus/header.rs`, `src/consensus/block.rs` — header/block structure
- `src/consensus/finality.rs` — height-floor finality
- `src/consensus/mod.rs` — consensus module wiring
- `src/emission/curve.rs`, `src/emission/mod.rs`, `src/emission/supply.rs` — emission + supply
- `src/constants.rs`, `src/config.rs` — all consensus constants + activation heights
- `src/testnet.rs`, `src/mainnet.rs` — per-network genesis/params
- `src/primitives/hash.rs` — hashing/merkle
- `CONSTITUTION.md`, `docs/BILL_OF_RIGHTS.md` — governance text

The full rule-by-rule specification, each rule cited to its enforcement site, is
in **[`CONSENSUS_SPEC.md`](./CONSENSUS_SPEC.md)** — the recommended entry point
for a consensus review.

**The shielded (Lelantus Spark) pool is a separate, gated track** with its own
dossier: **[`docs/audit/SHIELDED_AUDIT_READINESS.md`](./audit/SHIELDED_AUDIT_READINESS.md)**.
It is feature-gated (`sketch-gk-proof` + `libspark-ffi`) **and**
activation-gated (`SHIELDED_TX_ACTIVATION_HEIGHT = u64::MAX` on testnet/mainnet),
so it is off on both counts in production. It is code-complete and live-exercised
on a dedicated **beta** network, but nothing shielded reaches mainnet consensus
until it passes its own audit. See §3 and §5.

---

## 2. Reproducible build — verified

Release binaries are built by a pinned container
(`scripts/build-in-docker.sh` → `docker/builder.Dockerfile`, Rust 1.88.0,
`--locked`, `SOURCE_DATE_EPOCH` from git, stripped). **Byte-identity is verified,
not aspirational:** two independent from-scratch builds of the same commit (one
forced `--no-cache`) produced identical SHA-256 sums for all artifacts.

**Reproduce it yourself:** run `bash scripts/build-in-docker.sh` twice into
different output dirs and `diff` the `out/SHA256SUMS`. Every release also carries
a Sigstore build-provenance attestation and a signed Git tag. (Threshold signing
across multiple maintainer keys is a documented future enhancement, not yet in
force — see Bill of Rights XIII.)

---

## 3. Hardening record

### 3a. Pre-mainnet campaign (2026-08)

The highest-value work of this cycle, by class:

**Consensus determinism (the fork-risk class).** Three bugs of one shape — an
accumulated value that depended on a node's *reorg history* rather than only on
canonical chain content — were found and fixed at the root. Two honest nodes on
the same tip could otherwise diverge and fork.

- `total_difficulty` path-dependence — fixed (base-1 fork walk + recompute-on-
  load self-heal).
- `total_outputs_ever → ring-size` — fixed to
  `total_outputs_ever − reorg_disconnects_total` (`8ac98e87`); **property-tested
  across 400 random reorg histories** and verified to fail against the raw
  counter (`tests/property_invariants_determinism.rs`, `1b161fa8`).
- Self-recorded checkpoint-hash gate — removed at the root as path-dependent
  (`83ef0554`); deterministic height-floor finality retained.

A dedicated determinism sweep then enumerated *every* accumulated/persisted
consensus value and confirmed no other member of the class remains
(`CONSENSUS_SPEC.md` §6).

**Reorg correctness.** Post-reorg double-spend / inflation (fork tip skipped
UTXO re-validation) — fixed (REORG-TIP-VALIDATE) with a **real-PoW end-to-end
regression test** proven to fail without the fix
(`tests/reorg_double_spend_e2e.rs`, `60326165`). Reorg self-deadlock +
MTP-from-fork-lineage — fixed.

**Networking / mainnet readiness.** LB-1: mainnet P2P bootstrap silently used a
testnet-defaulted config (zero mainnet peers) — fixed with a network-aware
`BootstrapConfig` (`9fd1d562`). M-5: a partial `[p2p.encryption]` config silently
allowed plaintext P2P — fixed (`bc15a1db`). Dead seed IPs + duplicate
`MainnetConfig` constants deleted.

**Wallet fund-safety.** W-B: the "subaddresses disabled on mainnet" gate was
incomplete (covered only generation); address parsing, send-to-subaddress, and
the v2 `--subaddress` flag were ungated. Closed at the parse + send boundary
(`09bc504a`), live-verified on the built binary. **Superseded:** the underlying
W-A spend bug has since been fixed (per-subaddress `m_i` offset) and this
mainnet-disable gate *lifted* — subaddresses are now fully spendable (§5a, W-A
RESOLVED).

### 3b. Shielded pool — Lelantus Spark v2 (2026-09 → 2026-10)

The Phase-2 shielded pool was brought to **code-complete, live-exercised, and
gated**. It is Lelantus Spark v2 (`SparkPayload` v2, vendored Firo libspark via
the `spark-connector` FFI). Highlights:

- **Full value triad wired end-to-end:** shield-in (transparent → pool),
  shielded transfer (pool → pool), and unshield (pool → transparent,
  value-revealing zero-blinding exit, commit `02dddb3a`). Wallet CLI
  (`shielded-mint`/`shielded-send`/`shielded-unshield`), RPC, mempool admission
  (4 gates), block connect/apply (v2 paths), reorg, and restart all wired.
- **Fee system bound to consensus (no new fee market):** size-based miner-paid
  fee; `verify_block_spark_v2` binds `value_balance == bundle_fee` (inflation
  guard); the transparent bridge ties `tx.fee == value_balance`. Supply
  conservation documented and verified (same emission/burn path as transparent
  fees). A free (`tx.fee = 0`) shielded transfer is **not mineable** (the
  block-level dynamic-fee floor has no shielded exemption), so "free" was never
  possible — surfaced and documented rather than papered over.
- **Cover-set grouping:** the Grootle one-of-many proof is over exactly the
  cover-set size; the pool is bucketed into N-sized groups by `cover_set_id` so
  it scales past one group (`9c58cb47`), with adversarial/property tests and
  multi-group batch-verify coverage.
- **Live bug-hunt on beta found and fixed 7 distinct bug-classes** that unit
  tests did not catch — mempool admission bypass (4 gates), three v1-only
  block-connect/apply paths mis-decoding a v2 payload, spent-note exclusion in
  balance, mempool eviction of mined/unminable shielded txs, restart checkpoint
  divergence, and a tip-extend self-heal path. All fixed and re-verified live.

**The shielded pool stays gated OFF (`u64::MAX`) on testnet and mainnet pending
its own external audit.** Detail + the remaining audit-critical crypto fill-ins
are tracked in `docs/audit/SHIELDED_AUDIT_READINESS.md`.

### 3c. Audit-surface narrowing (2026-10)

Deliberate pre-audit shrink toward **one** shielded engine (the "narrow, don't
sprawl" strategy — one audited Spark pool, not multiple interoperating privacy
engines):

- Deleted the dead `orchard-side` + `auxpow` crates — 6,164 lines, never wired
  (`440b7101`, completed `d823ad9c`).
- Removed the native Groth-Kohlweiss **v1** shielded engine entirely — 3,871
  lines (`consensus/{shielded,shielded_pipeline,shielded_connector}.rs`,
  `storage/shielded.rs`) — leaving Spark v2 as the single shielded format
  (`80138fb4`). Value-neutral: v1 was activation-gated `u64::MAX` on every
  network, so there is no fork, migration, or behavioral change — a build before
  and after validates byte-identically.

Net effect: ~10k fewer lines of unaudited code, a single-engine shielded design,
and a smaller consensus/crypto perimeter to review.

---

## 4. Test & verification coverage

- **72 integration test files** + lib unit tests (**~2,256 passing** in the
  shielded-feature build; ~2,000 in the default build), including historical-
  attack suites (Monero/ETC/BTC incident replays), reorg-defense tiers, RPC
  endpoint, and security-critical suites.
- **7 cargo-fuzz targets** (protocol/deserialization surface).
- **Property tests** for determinism (reorg-history invariance), difficulty,
  amounts, addresses, hashes, keys, memos, and Spark/MW
  (`tests/property_invariants_spark_mw.rs`).
- **Real-PoW E2E** reorg double-spend test + a `total_difficulty`
  history-independence test (slow, `#[ignore]`, `tests/reorg_double_spend_e2e.rs`).
- **Shielded soaks:** a 24h in-block libspark soak at the ratified N=512 (0
  anomalies) and a grouped (`POOL_MULT`) reorg-coverage soak, both via
  `soak_shielded_in_block_consensus`.
- **Live regtest E2E** (2026-08): node + real RandomX mining + ASERT + wallet
  scan/detect/balance + ring-16 CLSAG send → mine → receive + `get_supply_info` +
  the W-B gate — all on the current binary.
- **Live beta E2E** (2026-10): full shielded loop — shield-in → mine →
  shielded-balance → shielded-send → mine → recipient receives exact amount,
  change returned, fee shown, 0 consensus faults — including a node restart on
  the same data dir (0 divergence panics) and in-session repeat sends.
- **Independent review passes:** full-codebase audit, pre-mainnet review,
  P2P/reorg hunt, mainnet-surface audit, remote-DoS scan, determinism sweep,
  dead-code/wiring audit, docs-accuracy audit, and a gap/stub inventory — all
  findings verified against source before action.

> **No CI.** The repository intentionally has no CI (pre-audit, single-driver
> discipline). Quality rests on running the **full** affected test surface green
> before every commit plus the soaks above. This is a stated process risk, not a
> code defect — but an auditor should know gating is human-driven.

---

## 5. Known open items (honest, categorized by exposure)

The useful cut for a reviewer is **what is on the live `default`-build path vs.
what is cfg-stripped or activation-gated out of production.** Most of the long
list below is the latter.

### 5a. On the LIVE production path (default build)

These touch a default/mainnet binary and are the short list that matters most:

- **~~W-A: subaddress spend broken~~ — RESOLVED (fix + gate lift).** The
  spend-side one-time-secret / key-image derivation now applies the
  per-subaddress offset `m_i`, so subaddress-received funds are spendable,
  including on mainnet; the prior mainnet-disable arm (W-B) was removed. Verified
  by the receive→spend→validate round-trip test
  `real_crypto_subaddress_output_spendable_e2e` (`legacy.rs:1067`). No longer an
  open item.
- **~~Bootstrap ring-member relaxation (blocks 1–99)~~ — RESOLVED in code
  (#219).** A ring member absent from both the live UTXO set and the permanent
  output index is now rejected at **every** height (`validation.rs:2186-2213`),
  not just ≥ `STRICT_RING_MEMBER_HEIGHT`. The old blocks-1–99 escape hatch (warn
  and fall through) is gone; the comment documents it as a strict tightening, not
  a chain split (coinbase maturity 100 from genesis means no pre-100 spend could
  legitimately reach the check anyway). **Follow-up: reconcile `CONSENSUS_SPEC.md
  §8.1`**, which still lists this as an operational-only mitigation.
- **~~`total_burned` not accumulated~~ — RESOLVED; it is accumulated and
  reorg-correct.** `CONSENSUS_SPEC.md §8.4` is stale: `ChainStats.total_burned`
  is a persisted `u128` running total moved by `block_fee_burn()` at every
  connect / disconnect / fork-apply / fork-undo site (`chain.rs:1508/2050/2659/
  2903/3069/3267/3358`), with `checked_add`/`checked_sub` underflow panics, the
  consensus invariant `total_burned ≤ total_supply`, `circulating =
  total_supply − total_burned`, and symmetric-reorg tests
  (`total_burned_apply_disconnect_is_symmetric_and_reorg_correct`,
  `rollback_to_height_unwinds_total_burned_through_the_real_disconnect_site`).
  It also feeds the supply **digest**. **Follow-up: reconcile `CONSENSUS_SPEC.md
  §8.4`** to drop the obsolete "not accumulated" divergence.
- **Merkle duplication malleability (CVE-2012-2459).** `primitives/hash.rs`
  `merkle_root`: `root([A,B,C]) == root([A,B,C,C])`. Consensus-frozen; relies on
  downstream block checks. Acknowledged (`findings.md` INFO-1).
- **H4 orphan-flood residual (partially mitigated, deferred).** Instant-ban on
  bad PoW + a bounded orphan pool (`MAX_ORPHAN_BLOCKS = 1000`, LRU, 30-min TTL)
  are live. Residual: valid-PoW-but-unconnectable bodies can LRU-evict honest
  orphans. The full GETDATA-response-gate fix is deliberately deferred —
  `MAX_ORPHANS_PER_PEER = usize::MAX` on purpose (any finite cap caused the
  2026-06-22 18h partition). Accepted residual (`findings.md` H4).
- **Node-internal miner is a stub.** `src/mining/miner.rs` `Miner::start` is a
  no-op by design — real mining is external (pools / `coincync-rig`). Reachable
  but intentionally does nothing.
- **Light-wallet fork-point finder — v1.1 shipped; residual is a wallet-v2
  stub.** The node RPC `find_fork_point` (`rpc/handlers/chain.rs:148`) already
  runs the journal-based v1.1 algorithm (`parse_journal_hex` →
  `fork_point_in_journal`, deepest canonical ancestor, journal-size-capped), and
  the legacy CLI wallet (`legacy.rs:3309`) already sends its journal to it. Two
  loose ends remain, neither on the shipped reorg-recovery path: the superseded
  v1.0 `LightWalletServer::find_fork_point` (`lightwallet.rs:420`, returns
  `None`) is dead code; and the wallet-v2 `BlockFetcher::find_fork_point`
  (`background_sync.rs:560`) still has an unimplemented default on the old
  single-pair signature. Clean-up + wallet-v2 wiring are follow-ups.
- **`create_deniable_wallet` disabled.** `wallet/persistence.rs:2480` returns a
  distinct error rather than ship a knowingly-broken deniability primitive (three
  structural bugs, C37/C38/C39). Mitigation = fully disabled; restore only after
  redesign + fresh audit.
- **Standardized-fee-tier helper unwired.** `wallet/send/fee.rs:150`
  `round_up_to_fee_tier` is built + tested but `#[allow(dead_code)]`, not on the
  default send path (testnet-only / mainnet-parked).
- **Storage atomicity gaps (documented, self-healing).** Assorted true
  kill-mid-op / reorg-commit fault-injection paths are deferred for want of a
  harness (`db/mod.rs`, `storage/kernels.rs`); mitigated by recompute-on-load
  self-heal. Over-count-on-reorg class is fixed with live guards.

### 5b. Activation-gated consensus rules (dormant at `u64::MAX`)

Compiled into production but **no-op until a coordinated hard fork sets a finite
activation height**. Each tightens rules; none can activate accidentally.

- **Ring-size bump v2 (11→13).** `config.rs` `*_ring_bump*` = `u64::MAX`
  everywhere; raising the constant naively would fork the chain, so it needs
  `RING_BUMP_ACTIVATION_HEIGHT` (testnet ~10000, mainnet TBD). KNOWN_ISSUES
  Bump #1; `validation.rs:1582`.
- **v1.0.12 duplicate-stealth rejection.** `validation.rs:778`; active on
  mainnet/regtest from genesis, testnet at height 13,000.
- **`MIN_OUTPUT_AGE` 10→100 hard fork.** `config.rs:245`; `u64::MAX` on
  testnet/regtest/beta (mainnet uses 100 from genesis).
- **Fee-burn activation.** `chain.rs:3887` `block_fee_burn` — no-op below
  activation (miners claim all fees today).
- **Supply-commitment enforcement.** `emission/supply.rs:390` — no-op below
  `supply_commitment_enforce_height`.
- **Shielded (Spark) tx activation.** `SHIELDED_TX_ACTIVATION_HEIGHT = u64::MAX`
  on testnet/mainnet; reachable only on beta (≥5) / regtest.

### 5c. Feature-gated OFF by default (cfg-stripped from production)

Not compiled in a `default`/`mainnet` build. Each must be re-audited when wired.

- **`sketch-gk-proof` + `libspark-ffi`** — the entire shielded Spark pool
  (`SparkPoolStore`, `spark_payload`, `groth_kohlweiss`, `spark_balance`,
  shielded wallet CLI, treasury-audit/`compliance.rs`). Tracked in
  `SHIELDED_AUDIT_READINESS.md`.
- **`crosschain-onramp`** — `consensus/crosschain_onramp.rs`: DESIGN SCAFFOLD,
  fail-closed (`FailClosedAttestor` rejects everything); header states "NOT
  sound and MUST NOT be activated."
- **`rolling-finality`** (CIP-009.D) — adapter compiled only under the feature;
  `Chain.rolling_finality` is `None` otherwise; backing crate ships a
  Noop/stub verifier ("Phase 2 ships a real verifier").
- **`fee-reservoir`** — a pure charge/discharge/decay rule built for modelling;
  not wired into coinbase claim, header commitment, or reorg state.
- **`sketch-lelantus-spark`, `sketch-cut-through`, `sketch-block-aggregation`,
  `sketch-kernel-offsets`, `sketch-privacy-manifold`** — post-mainnet CIP
  sketches, explicitly "not part of the production audit perimeter."
- **`insecure-fast-sync`** — compile-time checkpoint-crypto-skip; off by default;
  release artifacts built with it must be rejected.
- **`test-fast-pow`, `shielded-soak-stub`, `hardware`, `metrics`, `cyncswap`** —
  test/ops/desktop-only feature gates, off by default.

### 5d. Intentional fail-closed stubs / skeleton crates (inert)

- **`crates/cynchub`** — a SKELETON; every op returns `Error::NotImplemented`.
  Excluded from the workspace entirely.
- **`crates/coincync-swap`** — atomic swap, "substantially implemented but gated
  OFF pending audit" (`is_implemented() == false`); reachable only via its own
  `cyncswap` binary, no core-wallet dependency. Residual phase-3 stubs.
- **`spark-connector` `StubBackend`** — the default shielded backend; every op
  errors (`NotWired`). This is the shipped default and is required to fail-closed
  (tested: `spend_payload_is_fail_closed_under_stub_backend`).
- **`privacy_connector.rs` `convert_value`** — cross-scheme value converter,
  doc-marked "STUB — NOT A REAL CONVERTER," hard-disabled behind
  `CONNECTOR_AUDITED = false`; no real equal-value ZK protocol exists.
- **Fully-distributed CLSAG-FROST** (`crypto/clsag_multisig.rs`) — explicitly NOT
  IMPLEMENTED (documentation-only stub); the threshold path in use is the
  coordinator variant.

### 5e. Not yet done (process / infra)

- **External professional audit** — this document exists to enable it (the
  shielded track has its own).
- **Mainnet seed-fleet + DNS provisioning** — operator infra.
- **Documentation reconciliation:** the per-subsystem checklists under
  `docs/audit/test-plan/` (esp. `crypto.md`, `wallet.md`) are **stale** — they
  flag behaviors as missing that are in fact implemented/tested — and
  `findings.md`'s Medium/Low register is not yet fully triaged. These must be
  regenerated before use as a gap list; this dossier + the sweep it was built
  from are the current ground truth.

See `CONSENSUS_SPEC.md` §8 for the full consensus divergences/dormant list.

---

## 6. Suggested audit focus

In descending order of leverage (production perimeter):

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

The **shielded (Spark) pool** is a separate review governed by
`docs/audit/SHIELDED_AUDIT_READINESS.md` — it should not be folded into the
production-perimeter review, since it is both feature-gated and activation-gated
off in every shipped binary.

---

*This dossier is generated from the repository's own state, commit history, and a
file-grounded gap sweep. It is updated as findings are closed. Corrections that
reconcile it to the code are always in order.*
