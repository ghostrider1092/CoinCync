# Empirical (histogram-tracking) decoy selection

**Status:** implemented, tested, **off by default** (audit-gated); wallet-side,
non-consensus.
**Idea family:** "small hidden things" — the privacy quality that lives in a
sampling curve nobody looks at.

## Problem

Ring-signature privacy quality lives in decoy selection. CoinCync (like Monero)
samples decoy ages from a **fixed** `Gamma(19.28, 1/1.61)` over log-seconds
(`src/wallet/decoy_selection/sampling.rs`, `sample_candidate_locators`), then
snaps the sampled age to the nearest eligible height. Two weaknesses:

1. A **fixed** gamma drifts from the network's **actual** output-age
   distribution over the chain's life — a known Monero critique. The further the
   selection law is from reality, the more a chain-analyst can down-weight
   ring members that don't fit real spend behavior.
2. "Snap to nearest eligible height" **over-selects isolated outputs** in sparse
   age regions: an output alone in a thin age band is chosen whenever the gamma
   lands nearby, making it a distinguishable (poor) decoy.

The wallet already receives the full per-height output-count histogram
(`DecoyDistributionSnapshot` → `ValidatedDecoySnapshot`), so it can sample
against the real distribution with no new data.

## Non-consensus (confirmed)

`src/consensus/validation.rs` §11/§12 validate only that each ring member (a)
exists on chain with the claimed commitment, (b) is mature and unlocked, and
that the ring is (c) the right size and (d) internally unique. **Nothing
validates how decoys were selected.** So changing the selection law is
wallet-only and cannot fork the chain — a transaction built with any
distribution validates identically.

## Design

`sample_candidate_locators_empirical` (alongside the gamma sampler): draws each
decoy's **height in proportion to its on-chain output count** (`WeightedIndex`
over the histogram), then a unique ordinal at that height (reusing `pick_ordinal`).
Same eligibility (`min_age`), uniqueness, exact-fit and insufficient-pool
semantics as the gamma path — only the age law differs. Attempts are bounded so
a degenerate snapshot can't loop.

Tests (`decoy_selection/tests.rs`): a non-uniform histogram where a heavy height
holds ~93% of outputs is selected ~93% of the time (a uniform-by-height law
would give ~20%), proving it tracks the supplied histogram; and a min-age +
uniqueness test.

## Why it is OFF by default

Making this the default is a **privacy change** that deserves review before it
ships: the empirical law tracks output **creation** density, which is related to
but not identical to the real **spend-age** model the gamma encodes, and a
poorly-chosen law can *reduce* anonymity. Consistent with the project's
testnet-only / mainnet-parked-pending-audit posture, this lands **built +
tested + not wired into the default spend path** (`build_covered_request` still
calls the gamma sampler). It is exposed as public API for opt-in experiments and
for the eventual audited switch.

## Portability (help other chains)

Every ring-signature chain with a fixed decoy law has this latent drift.
"Sample decoys against the chain's own output-age histogram instead of a frozen
curve" is a small, portable privacy improvement — and shipping it behind a
review gate, with a test that proves it tracks a supplied histogram, is a safe
template for adopting it.
