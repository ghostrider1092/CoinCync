<!-- markdownlint-disable MD036 -->
# Underground — Depth-Anonymity Model

**Status:** Design note (idea stage — pre-CIP)
**Type:** Standards Track candidate (consensus + wallet policy)
**Created:** 2026-09-09
**Layer:** Consensus (spend-eligibility rule) + Wallet (decoy selection + UX)
**Depends on:** [CIP-005 — Lelantus Spark](../cip/CIP-005-lelantus-spark.md) (the accumulator this builds on)
**Status of crypto:** No new cryptographic primitive. This is a *policy, guarantee, and UX* layered on the existing Spark accumulator.

---

## Abstract

"Underground" reframes CoinCync's privacy around a single property no mainstream privacy coin makes first-class: **a coin's anonymity is a measured quantity that only grows the longer the coin stays buried, and never decays.** The deeper a coin sits under later blocks, the larger the set of coins it is indistinguishable from.

Concretely this is three things stacked on the Spark accumulator we already ship:

1. **Privacy maturity (consensus rule)** — a shielded coin cannot be spent until it is buried under `D_min` blocks. This gives every spend a *guaranteed minimum* anonymity set: all coins minted in that window.
2. **Depth-stratified decoy selection (wallet)** — decoys are drawn so the ring is indistinguishable by coin age, defeating the "the real coin is the newest one in the ring" heuristic.
3. **A measured, surfaced guarantee (wallet UX)** — the wallet shows burial depth → anonymity-set size, and lets the user pick a target privacy level expressed as a target depth.

The name is not decoration: "deeper = more private" is the actual protocol guarantee, which is what makes Underground its own coin rather than a themed Monero/Firo fork.

---

## Motivation

### The differentiation problem

CoinCync's cryptographic stack is borrowed by design — CLSAG rings and RandomX from Monero's family, the one-out-of-many proof from Firo's Lelantus/Spark. A theme layered on borrowed primitives is a reskin, not a distinct coin. Distinctiveness in this space comes from a **property, mechanism, or threat-model advantage that is provable**, not from branding.

Depth-anonymity is the cheapest such property to state honestly, because it needs **no new cryptography** — only a spend-eligibility rule, a decoy-selection policy, and a UX that measures what the accumulator already makes true.

### What competitors do *not* guarantee

- **Monero (CLSAG-16):** the anonymity set is *frozen* at 16 ring members, forever, regardless of how long you wait. Waiting buys you nothing.
- **Firo (Spark):** the anonymity set is large (up to `SPARK_ANON_SET_MAX = 16_384`) but *static per spend* — chosen at spend time, not a monotone function of depth, and not surfaced as a guarantee the user can plan around.
- **Nobody** treats anonymity as a **monotonically non-decreasing, measured** quantity, or enforces a **minimum** anonymity floor at the consensus layer the way coins enforce coinbase maturity for value.

### The real heuristic this defends against

Naive decoy selection leaks the real spend: in a mixed-age ring, the *newest* output is disproportionately likely to be the one actually being spent (people spend coins they just received). Monero mitigates this with a tuned decoy-age distribution. Underground makes **depth the organizing principle**: the maturity rule removes the newest coins from eligibility entirely, and stratified selection matches decoys to the real coin's depth band, so age stops being a signal.

---

## The property (what we claim)

Let a shielded coin `c` be minted at accumulator index `i(c)` (equivalently, at block height `h(c)`). Define its **burial depth** at height `H` as `depth(c, H) = H − h(c)`.

**Privacy-maturity rule.** `c` is spend-eligible only once `depth(c, H) ≥ D_min`.

**Anonymity floor.** At the moment `c` becomes spend-eligible, define
`A(c) = |{ coins minted in blocks (h(c), h(c) + D_min] }|` — the coins that matured alongside it.

**Guarantee.** A valid Underground spend of `c` proves membership in a set of size ≥ `A(c)`, and because the accumulator is append-only, the pool from which that set is drawn is **non-decreasing in `H`** — so a spender who waits can only ever spend into a *larger* set, never a smaller one. Privacy compounds with depth; it never decays.

This is a statement about **anonymity-set size**, and it is genuinely provable from the accumulator. See *Honest limits* for what it does **not** claim.

---

## Mechanism

### 1. Privacy maturity (consensus)

A new consensus rule, analogous to coinbase maturity but for the shielded pool: a Spark note is rejected at spend time unless `current_height − note.height ≥ D_min`. `D_min` is a network constant (candidate: a few hundred blocks — enough to guarantee a meaningful floor without making the pool feel "frozen"). This is the only consensus change and it is a single inequality check at verification.

### 2. Depth-stratified decoy selection (wallet)

`SparkAccumulator::build_anon_set` today draws `n ∈ [SPARK_ANON_SET_MIN, SPARK_ANON_SET_MAX]` decoys uniformly from the whole accumulator, real coin included, then shuffles (`src/crypto/lelantus_spark.rs`). Underground changes the *draw*, not the proof:

- Restrict candidates to coins that are themselves ≥ `D_min` deep (so the ring never contains an ineligible, obviously-not-the-spend coin).
- Draw decoys with a **depth distribution centred on the real coin's depth band**, so the ring is not separable by age. The real coin is then one of many coins at a similar depth, not the conspicuous newcomer.
- Preserve the position-hiding guarantee already proven in the module (issue #49): the real index is never encoded, and selection RNG stays on `OsRng`.

This is a policy change inside the existing, tested prover — the one-out-of-many proof and the completed public verifier are untouched.

### 3. Measured guarantee (wallet UX)

The wallet turns the abstract floor into a number the user can act on:

- Per coin: **burial depth** (blocks) and the resulting **anonymity-set size** `A(c)`, updated live as the chain grows.
- A **target-privacy control**: the user picks "hide among ≥ N coins" and the wallet reports the depth (and rough wait time) required — privacy expressed as confirmations, but for anonymity instead of finality.
- The "Underground" surface: a depth gauge, not a hashrate number; the shielded pool visualised as strata, your coin sinking through them.

---

## What code it touches

| Area | Change | Risk |
|------|--------|------|
| `src/constants.rs` | add `SPARK_PRIVACY_MATURITY_DEPTH` (`D_min`) | trivial |
| consensus spend verify | reject Spark spend if `height − note.height < D_min` | small, one check; needs a consensus-rules test + activation gating |
| `SparkAccumulator::build_anon_set` | depth-restricted, depth-stratified draw | medium; privacy-critical selection, needs statistical tests |
| wallet / `tools/miner-top` GUI, wallet CLI | depth → anonymity readout, target-depth control | UX only |
| this doc → a CIP | graduate to `CIP-021` once the rule + `D_min` are settled | process |

No change to the Spark proof system, the serial-tag double-spend detector, or the just-completed public verifier.

---

## Honest limits (what this does *not* claim)

- **Set size ≠ effective anonymity.** A floor on ring size does not defend against *amount* correlation, *timing* correlation, or a spender who deanonymizes themselves off-chain. It bounds one axis (the decoy set), which is necessary, not sufficient.
- **Garbage decoys still count as decoys.** The floor counts coins minted in a window; it does not weight them by how plausible each is as a real spend. Depth-stratified selection helps, but "large set" is a weaker claim than "large *effective* set."
- **It is not new cryptography, and that is the point.** The novelty is the guarantee + policy + UX. Anyone claiming this is a cryptographic breakthrough is overselling it; claiming it is a distinct, defensible privacy *model* is fair.
- **`D_min` is a real tradeoff.** Too small and the floor is weak; too large and the shielded pool feels illiquid (you wait to spend). This is an economic parameter, not a free lunch.
- **Depends on Spark shipping.** All of this rides on CIP-005, which is still `Sketch` and gated `sketch-lelantus-spark`, off by default, and the hand-rolled composition still needs external audit before any turn-on.

---

## Open questions

1. **`D_min` value.** What burial gives a meaningful floor at realistic mint rates without making spends feel frozen? Needs a look at testnet mint-per-block data.
2. **Stratified draw shape.** What depth distribution makes the ring provably age-indistinguishable? (Monero's gamma is the reference point to beat / adapt.)
3. **Interaction with CLSAG spends.** Underground is a Spark-pool property. Do CLSAG-16 spends stay as-is, or does the shielded pool become Spark-only under this model?
4. **Graduation.** When does this become `CIP-021` with a formal activation path, versus staying a wallet-policy + soft rule?

---

## Next steps

1. Pull testnet mint-rate data to propose a concrete `D_min`.
2. Prototype the depth-stratified `build_anon_set` behind the existing feature flag, with statistical tests that the ring is not age-separable.
3. Draft the security claim precisely enough to hand to the same reviewer track as the Spark spend proof.
