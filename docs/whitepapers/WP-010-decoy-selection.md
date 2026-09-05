# WP-010 · Decoy Selection
### Gamma sampling, generation awareness, and poison exclusion

**Status:** Shipped · **Layer:** Privacy · **Series:** [CoinCync Whitepapers](README.md)

---

## 1. Motivation

In a ring-signature chain, the ring is the anonymity. A spend hides among
decoys — other outputs from the chain that could plausibly be the one being
spent. If the decoys are chosen badly, the ring is decorative: statistical
analysis recovers the real input and the privacy guarantee collapses without any
cryptography being broken.

This is not a theoretical concern. Monero's decoy-selection algorithm has been
patched repeatedly in response to published traceability research, and the
early-chain period — when few outputs exist — is when selection is weakest and
users are most exposed. Decoy selection is where a privacy chain most often fails
quietly.

---

## 2. Threat addressed

| Attack | Assumption it needs | What we removed |
|---|---|---|
| **Age-distribution analysis** — real spends are recent, decoys are uniformly old | Decoy ages drawn from a distribution unlike real spending | Gamma-distributed sampling matched to realistic output-age behaviour |
| **Poisoned / unusable decoy** — an output that the verifier will reject, revealing the ring as malformed or failing the spend | Every output in the canonical set is a usable ring member | Identity-point outputs (the genesis placeholder) excluded from candidacy |
| **Cross-transaction correlation** — the same decoy reused across a wallet's rings links them | Decoys chosen independently per input | Transaction-wide unique allocation: no output appears twice across a transaction's rings |
| **Chain-state race** — decoys chosen against a stale view resolve differently for the verifier | The chain does not move during transaction construction | Generation-aware selection bound to a committed snapshot |
| **Immature/unspendable decoy** — a decoy the verifier deems ineligible narrows the effective ring | Any recent output is a valid decoy | Age and lock-height eligibility enforced at selection |

---

## 3. Design

### 3.1 Ring size: fixed, not chosen

Ring size is **16** (`RING_SIZE`), enforced by consensus — not a user setting.
Below height 10,000 a bootstrap minimum of 11 (`BOOTSTRAP_MIN_RING_SIZE`) applies
because the output set is genuinely too small to fill larger rings.

Making ring size fixed is a privacy decision, not a convenience one: every
user-selectable parameter is a fingerprint that partitions the anonymity set. See
WP-011.

### 3.2 Gamma-distributed age sampling

Decoys are drawn by sampling an *age* from a gamma distribution (shape and scale
tuned to realistic spend behaviour), converting that age to a height, and
selecting an output at that height. The goal is that the age profile of a ring's
decoys is statistically indistinguishable from the age profile of real spends —
because any systematic difference is exactly what a traceability analysis
exploits.

Sampling is conditioned on the real output's own eligibility window so that the
real spend is not an outlier within its own ring.

### 3.3 Committed-snapshot selection

Selection runs against a **committed decoy snapshot**: a distribution of output
counts by height, bound to a snapshot height, hash, and policy version. The
wallet requests candidates by locator (height, ordinal) against that snapshot,
and the response is validated to match the request before use.

This binding matters because the chain advances while a transaction is being
built. Without it, the wallet and the verifier can resolve the same locator to
different outputs — a correctness failure that also leaks information.

### 3.4 Transaction-wide unique allocation

Decoys are allocated across **all** of a transaction's rings at once, with
uniqueness enforced on public keys, so no output is used twice within a
transaction. Per-input independent selection would allow collisions that
correlate the inputs of a single spend.

### 3.5 Eligibility filtering

A candidate is excluded unless it satisfies every rule the *verifier* will apply:

- not one of the transaction's real outputs,
- at or below the maximum decoy height,
- past its lock height at the spend height,
- past the minimum output age, and
- **not an identity-point output.**

### 3.6 Poison exclusion — why the last rule exists

The genesis coinbase is a placeholder whose public key and commitment are
all-zero: the identity point. It sits in the canonical output set like any other
output, so the sampler could legitimately draw it. But the ring-signature
verifier rejects identity ring members outright — a correct and necessary guard,
since an identity member collapses part of the verification equation and is the
ring-signature analogue of a small-subgroup input.

The result was an intermittent, hard-to-diagnose failure: a valid wallet building
a valid transaction would occasionally produce a ring the network refused, with
the frequency *highest on a young chain* where the eligible pool is small and
genesis is a large fraction of it — precisely the launch window.

The allocator now mirrors the verifier's guard: any candidate whose public key or
commitment is the identity point is filtered out before it can enter a ring. The
general principle is the transferable one — **selection must enforce every rule
verification enforces**, or the wallet will build transactions the network
rejects.

---

## 4. Security analysis

**What holds.** Rings are fixed-size, uniquely allocated, age-distributed, bound
to a committed chain snapshot, and filtered by the full verifier eligibility set.
A ring built this way is not distinguishable by size, by internal reuse, or by
containing a member the verifier would reject.

**Validation.** The poison exclusion carries a regression test
(`allocation_excludes_identity_point_decoys`) plus live confirmation: 20
consecutive sends on a fresh, small-pool chain with zero failures, on a chain
state where the bug previously reproduced intermittently.

**What this does not protect against.**

- **Statistical analysis is an arms race, not a solved problem.** Gamma sampling
  narrows the gap between decoy and real age distributions; it does not prove
  indistinguishability. Monero's history shows this parameter needs revisiting as
  real spending behaviour is observed.
- **A small chain has a small anonymity set.** No selection algorithm creates
  anonymity that the output set does not contain. Early-chain privacy is
  structurally weaker, and users should be told so.
- **Chain-analysis heuristics beyond age** (timing, amounts on the transparent
  edges, network-level origin) are addressed elsewhere — WP-011 (uniformity),
  WP-012 (traffic shaping), WP-020 (Dandelion++) — not here.
- **Dust/poisoned-output tracing** at the *wallet* level is a separate, currently
  **unbuilt** defence — see WP-018 (dust quarantine, Proposed).

---

## 5. Implementation

| Component | Location |
|---|---|
| Gamma sampling, eligibility, snapshot validation | `src/wallet/decoy_selection/` (`sampling.rs`, `types.rs`) |
| Transaction-wide unique allocation + identity exclusion | `src/wallet/decoy_selection/allocation.rs` |
| Ring-size rules (`RING_SIZE = 16`, bootstrap 11, `ring_size_at_height`) | `src/constants.rs` |
| Verifier-side identity guard | `src/crypto/clsag.rs` |
| Verifier-side ring/eligibility checks | `src/consensus/validation.rs` |

**Tests.** `allocation_excludes_identity_point_decoys`, gamma-conditioning and
uniqueness tests, snapshot/locator binding tests (12 in the decoy suite).

**Failure record.** WP-100 §5.1 — the genesis-placeholder poison, discovered on a
live chain rather than by review.

---

## 6. Known limits

- Gamma parameters are **tuned, not proven**. They should be re-derived against
  observed spend data once the chain has meaningful history.
- The bootstrap ring size of 11 below height 10,000 is an explicit, temporary
  weakening for a chain that cannot yet fill rings of 16.
- Selection quality is bounded by output-set size; see §4.
- This paper covers *choosing* decoys. The soundness of the ring signature itself
  is inherited (CLSAG) and subject to external audit.

---

## 7. References

- Möser et al., *An Empirical Analysis of Traceability in the Monero Blockchain*
  (2018).
- Monero decoy-selection patch history — the canonical record of this being an
  iterative problem.
- Internal: [WP-011 Uniformity](WP-011-transaction-uniformity.md),
  [WP-018 Dust quarantine](WP-018-dust-quarantine.md),
  [WP-100 §5.1](WP-100-solved-issues-ledger.md).
