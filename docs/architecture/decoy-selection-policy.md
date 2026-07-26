# Decoy-Selection Policy

**Status:** Authoritative policy · **Scope:** ring-member (decoy) selection for
CoinCync transactions · **Owner decision:** 2026-07-24 (owner + co-founder)

> **This document is the single source of truth for decoy selection.** Wallets,
> tests, tooling, and other docs MUST defer to it. Where it names a concrete
> parameter, the **code constant is authoritative** and this doc points at it —
> numbers are not duplicated here, so they cannot drift. If code and this policy
> disagree, that is a bug in one of them; open an issue rather than guessing.
>
> Addresses [issue #24](../../README.md) — "Specify and unify the mainnet
> decoy-selection policy."

---

## 1. Policy in one paragraph

Every non-coinbase input is signed in a ring of size
[`RING_SIZE`](../../src/constants.rs) (bootstrap floor
[`BOOTSTRAP_MIN_RING_SIZE`](../../src/constants.rs)). The real spend is hidden
among decoys whose **ages follow a population-wide gamma law** matched to the
real-spend age distribution (Möser et al. 2018), so a chain analyst cannot pick
the real member out by its age. The gamma shaping is applied **once, at the
source**, over the whole eligible UTXO set; the ring assembler then draws
**uniformly** from that already-shaped pool. Selection is a **pure, stateless
function of the current UTXO set**, so it is automatically correct across
reorganizations.

---

## 2. Where the policy lives (the anti-drift map)

There is exactly **one** place age-shaping happens and **one** place the ring is
assembled. Everything else consumes these.

| Concern | Authoritative code | Role |
|---|---|---|
| **Age shaping (the gamma)** | [`storage::UtxoSet::select_decoys`](../../src/storage/utxos.rs) | Draws decoys from the full eligible set with gamma-distributed ages. **This is where the privacy comes from.** |
| Gamma parameters | [`DECOY_GAMMA_SHAPE`, `DECOY_GAMMA_SCALE`](../../src/storage/utxos.rs) | shape + scale constants |
| Node entry point | [`chain::get_decoy_outputs`](../../src/chain.rs) → the `get_decoys` RPC | Serves the shaped pool to wallets |
| **Ring assembly** | [`crypto::RingSelector::select_decoys`](../../src/crypto/ring_selection.rs) | Picks final members + the real position, **uniformly, from the pool it is given** |
| Ring size / age floor | [`RING_SIZE`, `BOOTSTRAP_MIN_RING_SIZE`, `min_output_age_at_height`](../../src/constants.rs) | consensus parameters |

**Rule:** the assembler must **not** re-impose an age distribution — that would
double-bias an already-shaped pool. Its uniform draw is correct *because* the
pool is already gamma-shaped upstream.

---

## 3. The model, and why the bias is at the source

Real spends are overwhelmingly *recent* — people move coins days or weeks after
receiving them. If decoys were drawn uniformly over all history, a young real
input would be the obvious age outlier in its ring (Miller et al. 2017; Möser et
al. 2018 measured ~85% real-spend identification on early, pre-gamma Monero).
Matching decoy ages to the real-spend law removes that signal.

A decoy's age is drawn as `age_seconds = exp(Gamma(shape, scale))`, converted to
blocks via [`TARGET_BLOCK_TIME`](../../src/constants.rs), and mapped to the
nearest eligible output through the height index (O(log n), no linear scan).

**Why at the source, not in the assembler:** a population-wide age law needs the
*whole* age distribution to sample from. A downstream shuffle over a pre-sampled
candidate pool cannot reconstruct a distribution the pool does not already carry.
(This is the exact point the 2026-07-02 note made when arguing the *opposite*
direction; it is applied here in reverse.) So shaping happens once, over the full
UTXO set, and the assembler stays uniform.

---

## 4. Eligibility

An output is an eligible decoy iff, at the spending height, all hold:

1. **Age ≥ minimum** — older than `min_output_age_at_height(height)` blocks
   ([`constants.rs`](../../src/constants.rs)). This is a consensus-relevant
   maturity floor, not just a heuristic.
2. **Unlocked** — any `lock_height` has passed.
3. **Distinct** — the real output is excluded, and duplicates are not offered.

Coinbase-maturity and ring-member-validity (including references to
already-spent outputs via the permanent output index) are enforced separately at
[`consensus/validation`](../../src/consensus/validation.rs) — selection produces
candidates; consensus validates them.

## 5. Correctness across reorganizations

Jun #24 requires the policy to remain correct across reorgs. It does, **by
construction**:

- **Selection is stateless.** `select_decoys` is a pure function of `(current
  height, live UTXO set, RNG)`. There is **no persisted decoy-selection cache or
  index** anywhere (verified: no `decoy_*` persisted state), so there is nothing
  that could diverge across restart or reorg paths — the recurring failure mode
  behind the earlier `total_difficulty` divergence class.
- **It reads only live state.** The `height_index` and `outputs` maps are updated
  atomically on connect/disconnect (`apply_batch` / disconnect on reorg), so a
  selection always reflects the current tip. Outputs disconnected by a reorg
  simply stop being eligible.
- **Ring *validity* after a reorg** is a consensus concern, not a selection one:
  a ring built against outputs that a later reorg removes is validated against
  the permanent output index ([`storage::UtxoSet`](../../src/storage/utxos.rs)),
  which retains entries across spends and is only pruned on reorg. Selection does
  not need reorg-specific logic because it never persists a decision.

**Invariant:** the same `(height, UTXO set)` always yields the same *distribution*
of decoys (not the same sample — the RNG differs), and never references state
that outlives a reorg.

## 6. Threat model and the accepted trade-off

- **Defends against:** output-age regression — an analyst measuring the age
  profile of each ring to find the real spend. Gamma-matched decoys deny that
  signal for the common case.
- **Accepted residual (explicit):** a genuinely *old* real output is an age
  outlier in a recent-biased ring. Population-wide gamma protects the vast
  majority of (recent) spends at the cost of this tail. This is a deliberate
  "lesser of two evils" choice; see §8.
- **Not in scope here:** sender/receiver/amount hiding (CLSAG, stealth
  addresses, Bulletproofs+), network-layer linkability (Dandelion++, Noise). See
  [PRIVACY.md](PRIVACY.md).

## 7. Decision history

- **≤ 2026-07-01** — gamma-based selection (pre-existing).
- **2026-07-02** — moved to uniform selection at both layers (logged as SEV-A;
  argued uniform was the safer default; a regression test asserted uniform).
- **2026-07-24** — owner + co-founder reversed to gamma **with full knowledge of
  the 2026-07-02 decision**, applied at the source with uniform assembly, and
  flipped the regression test to assert the gamma recency signature. This
  document is the unified policy that reversal produced.

## 8. Roadmap — closing the tail

The old-output residual (§6) is not closed by tuning the distribution; it is
closed by a larger anonymity set. The long-term direction (grand-roadmap, not
scheduled) is a major upgrade that grows the effective ring from
[`RING_SIZE`](../../src/constants.rs) into the thousands via zero-knowledge
membership proofs (in the spirit of Lelantus Spark / zk-SNARK set membership),
at which point per-output age ceases to be a distinguishing signal at all. Until
then, population-wide gamma is the policy.

## 9. Conformance checklist for changes

Any change touching decoy selection MUST:

- keep shaping in `storage::UtxoSet::select_decoys` and assembly uniform in
  `RingSelector` — do not move the bias into the assembler;
- keep selection a pure function of the live UTXO set — introduce **no** persisted
  selection state;
- update the gamma regression test
  ([`test_decoy_selection_is_gamma_recent_biased`](../../src/storage/utxos.rs)) if
  the distribution changes, and keep it asserting the intended shape;
- update **this document** in the same change, since it is the source of truth.
