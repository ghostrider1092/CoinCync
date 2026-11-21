# Bobtail Multi-Sample PoW — Low-Variance Block Timing for CoinCync

**Status:** analysis + proposal. **No code change is proposed here.** This is a
deep consensus change — a new PoW *acceptance rule* and block format — and is a
**hard fork**: post-audit, testnet flag-day first, the full ceremony (bigger
than the shielded activation). This document records the motivation, the
measured/modelled payoff, the design for CoinCync, the security argument, the
costs, and the rollout. It is deliberately a design note to be refined, not a
spec to implement.

Related: `difficulty-oscillation-analysis.md` (why the *difficulty algorithm*
cannot fix this), `src/consensus/pow.rs` (RandomX, hash-locked),
`src/consensus/difficulty.rs` (dual-anchor ASERT, hash-locked).

## 1. The problem the DAA cannot touch

PoW block discovery is a Poisson process: inter-block times are
**exponentially distributed**, which means a coefficient of variation of
**CV = 1** — some blocks seconds apart, some tens of minutes apart — at *any*
hashrate and under *any* difficulty algorithm. Difficulty controls only the
*mean*; it cannot reduce the *spread*. `difficulty-oscillation-analysis.md`
establishes this empirically for CoinCync: on the live testnet only ~28–39% of
blocks land in a 60–180 s band, with a worst gap of ~14 min per 1000 blocks,
and every ASERT-parameter fix tested makes it the same or worse. The variance
is structural, not a bug in the retarget.

So smoothing block *timing* (as opposed to difficulty) requires changing the
PoW acceptance rule itself. The only published, peer-reviewed way to do that
without changing the mean or the security model is **multi-sample mining**.

## 2. Bobtail in one paragraph

Bobtail (Bissias & Levine, *"Bobtail: Improved Blockchain Security with
Low-Variance Mining"*, NDSS 2020) changes block validity from *"one hash below
target"* to *"the **k lowest** hash samples since the parent have a **mean**
below target."* Mining is unchanged (keep hashing); what changes is that the
block carries the `k` smallest proof-of-work samples instead of a single nonce,
and is valid when their mean clears the target. For `k = 1` this is exactly
today's Nakamoto PoW.

## 3. Why it works — the result (modelled + validated)

Under Bobtail the inter-block time is proportional to the sum of the `k`
smallest order statistics of the hash stream, which (for a large hash count per
block) converges to a weighted sum of exponentials:

```
T  ∝  S_k = Σ_{m=1}^{k} m · E_m            E_m ~ iid Exp(1)
E[S_k] = k(k+1)/2        Var[S_k] = k(k+1)(2k+1)/6
```

giving an exact coefficient of variation

```
CV(k) = sqrt( 2(2k+1) / (3 k (k+1)) )   ≈  2 / sqrt(3k)
```

`CV(1) = 1` (recovers today). A finite-N Monte-Carlo of the *actual* k-lowest-
mean stopping rule confirms the closed form (k=10: sim 0.363 vs formula 0.357).
At a 120 s target mean:

| k | CV | std | p90 gap | blocks in 60–180 s | worst gap / 1000 blocks |
|---|----|-----|---------|--------------------|-------------------------|
| **1 (today)** | 1.00 | 120 s | 277 s | **39%** | **822 s (~14 min)** |
| 5  | 0.50 | 60 s | 200 s | 72% | 403 s |
| **10** | 0.36 | 43 s | 176 s | **86%** | 300 s (5 min) |
| **20** | 0.26 | 31 s | 161 s | **95%** | 242 s (4 min) |
| 40 | 0.18 | 22 s | 149 s | 99% | 201 s |

**k = 10–20 is the knee.** It takes the on-target-band fraction from 39% to
86–95% and collapses the worst-gap-per-1000 from ~14 min to ~4 min — with the
**same mean** and (see §6) the **same 51% security bound**. No difficulty
algorithm can produce any of these numbers.

**Fit for CoinCync.** Small / low-hashrate chains suffer Poisson variance the
*most*, so the payoff here is larger than for Bitcoin. Integrating a proven
primitive to close a gap others leave open is squarely on-mission (vs. inventing
a new one). PoW is orthogonal to the Spark/shielded layer, so this composes with
the privacy work cleanly.

## 4. Design for CoinCync

### 4.1 Hash function — unchanged
RandomX stays the hash function. Miners hash exactly as today; the only change
is that a miner reports its *low samples* rather than stopping at the first hash
below target. `coincync-rig` keeps its RandomX core; its submit path changes.

### 4.2 Block format
The block commits to `k` **proof-shares** instead of one nonce. Each share is a
tuple `(nonce, miner_output_key, hash)` — a distinct RandomX solution over the
block's pre-header. A block is valid iff:
1. each share's RandomX hash verifies over the canonical pre-header,
2. the shares are distinct and are the `k` presented smallest,
3. `mean(hash_1 … hash_k) ≤ target`,
4. the single lowest share (the **proposer proof**) belongs to the miner that
   assembled the block body (tx set, coinbase).

Fork choice stays on cumulative work; a Bobtail block's work is accounted as the
difficulty it cleared (the k-mean threshold), so the existing chain-work
comparison is reused.

### 4.3 Proof-share gossip
Between blocks, miners broadcast low samples below a **share threshold**
(looser than the block target) so the network accumulates a pool of candidate
low samples. The proposer selects the `k` lowest it has seen (its own + peers').
This is a consensus-layer analogue of a stratum share stream. Shares are small;
the message rate is bounded by the share threshold (set so the expected shares
per block is a small multiple of `k`). Spam is bounded by requiring shares to
clear the share threshold (real work) and by a per-peer rate cap in the mesh
(reuse the existing REST/P2P rate-limit posture).

### 4.4 Difficulty retarget — reuse dual-ASERT
The retarget math (dual-anchor ASERT in `difficulty.rs`) is **reused unchanged**;
only the quantity it targets changes — from "expected hashes for one sub-target
hash" to "expected hashes for the k-mean condition." The conversion is a fixed
function of `k` (the k-mean threshold that yields the same expected hash count),
so the ASERT dynamics, windows, and clamp carry over. This is important: we are
**not** re-opening the ASERT parameter question (`difficulty-oscillation-
analysis.md` §7 settled it) — we keep V0 and change only the acceptance rule.

### 4.5 Reward split — the real economic decision
To incentivise miners to *share* their low samples (rather than hoard them),
Bobtail splits the block reward among the `k` proof contributors. Options,
to be decided:
- **(a) Equal split** across the `k` contributors — simplest, maximally
  incentivises sharing, but produces `k` coinbase outputs per block.
- **(b) Proposer-weighted** — the lowest-sample proposer takes a majority
  share, the rest split the remainder; fewer effective payouts, still
  incentive-compatible.
- **(c) Winner-take-all with a share-fee market** — proposer keeps the reward,
  pays sharers a fee; most flexible, most complex.
This interacts with `emission/curve.rs` (the coinbase amount is unchanged; its
*division* changes) and with privacy: more coinbase outputs per block. Coinbase
outputs are transparent today; whether contributor payouts are transparent or
shielded is a privacy-design sub-question. **Recommendation: start from (b)** —
it bounds the extra coinbase outputs while preserving the incentive.

## 5. Interactions

- **Spark / shielded pool:** none at the consensus level — PoW is independent of
  the privacy layer. The only touch-point is coinbase output count (§4.5).
- **Difficulty / DAA:** reused (§4.4); the Bobtail change and the (rejected)
  ASERT-tuning question are independent.
- **Consensus fingerprint:** the PoW acceptance rule is a consensus parameter →
  **the fingerprint changes** → this is a genuine flag-day fork, not a soft
  update.
- **Low hashrate / few miners:** the order-statistics reduction holds even for a
  single miner (its own k-lowest over the inter-block period). Fewer share
  sources slightly raises share-propagation latency but does not break the
  variance reduction — and small chains are exactly where it helps most.
- **Miner (`coincync-rig`) / stratum:** the rig must submit low samples
  continuously rather than one winning nonce; the stratum/solo submit protocol
  gains a share message. Existing pool code is a useful starting point.

## 6. Security

Bobtail's headline result is that it **preserves the Nakamoto honest-majority
bound**: an adversary still needs > 50% of hashrate to control the chain, the
same as single-sample PoW. Its effect on **depth-based** attacks (selfish mining,
d-confirmation double-spend) is **neutral, not an improvement** — those depend on
the block-*finder* sequence (Bernoulli in hashrate share), which block-time
variance does not touch, so the thresholds are unchanged (confirmed in §12.1; an
earlier draft of this note said "slightly improves" — that was wrong). Where
multi-sample genuinely helps is **time-based finality** (§12.2). The adversarial
surface specific to the new mechanism — **share withholding** (no proposer
advantage, §10.2) and **share spam** — is bounded; the base security bound is not
weakened. This is a published, reviewed result; we are validating and adapting it,
not asserting new cryptography.

## 7. Open questions / risks (settle before a spec)

1. **Reward split (§4.5)** — the central economic + privacy decision.
2. **Share-withholding** — model whether hoarding low samples profitably biases
   proposer selection; design the share threshold + selection rule to neutralise
   it.
3. **Gossip cost** — quantify share traffic at CoinCync hashrates; cap rate.
4. **Difficulty conversion constant (§4.4)** — derive the exact k-mean threshold
   that preserves the current expected-hash accounting, so the fork does not
   silently change effective difficulty.
5. **Coinbase privacy** — transparent vs shielded contributor payouts.
6. **Parameter `k`** — 10–20 by the model (§3); confirm against the gossip/latency
   budget (larger `k` ⇒ more shares to propagate per block).
7. **Finite-N vs asymptotic** — the model's closed form is the large-hash-count
   limit; re-check at the lowest realistic per-block hash counts.

## 8. Rollout (right-way sequence)

- **Phase A — model (DONE).** Closed-form + Monte-Carlo variance reduction (§3).
  Scripts: `scratchpad/bobtail_sim.py`.
- **Phase B — design.** This note → resolve §7 → full spec (block format,
  wire format for shares, retarget conversion, reward split).
- **Phase C — adversarial simulation.** Share-withholding, share-spam, selfish
  mining under low variance; confirm the §6 bounds hold with the chosen params.
- **Phase D — gated reference implementation.** Inert / feature-flagged, off a
  far activation height; full `--features testnet` suite; `critical_files.lock`
  regen; **fingerprint change is expected and intended** here.
- **Phase E — testnet flag-day.** Height-gated activation, coordinated like the
  h29000 shielded fork; soak; measure realised block-time CV against §3.
- **Phase F — mainnet, post-audit.** Never unilateral; audited; the biggest
  consensus change the project will have shipped.

## 9. Recommendation

The model proves the win is real and large (k = 20 → 95% of blocks on-band,
~4-min worst gap, same mean, same security). It is the *only* lever that smooths
the Poisson floor — difficulty tuning provably cannot, and faster block time
only trades timing variance for orphan/reorg risk. It is also a deep, high-ceremony
fork. **Recommendation:** treat Bobtail as a post-audit flagship consensus
upgrade; the immediate next step is resolving §7 (reward split first) and writing
the §4 items up as a full spec — no consensus code until Phase C/D.

## 10. Phase C — early results (2026-11-20)

Two of §7's gates are now settled by derivation + simulation
(`scratchpad/bobtail_sim2.py`):

**10.1 Difficulty-conversion constant (§7.4) — resolved.** To preserve the *same
work per block* as today's single-hash target `T` (and therefore the same 51 %
honest-majority bound), the k-mean acceptance threshold is

```
tau = T * (k + 1) / 2
```

The ASERT retarget keeps computing `T` exactly as it does now; only the
acceptance rule changes — it compares the mean of the k lowest samples against
`tau`. Simulation of the real k-lowest-mean stopping rule confirms the expected
hashes per block is preserved to within noise at every k (ratio ~1.00× for
k = 1…20), while the block-time CV falls from ~1.00 to ~0.26 at k = 20. So the
fork smooths the variance **without** silently changing effective difficulty or
weakening security — the property that makes it safe to activate.

**10.2 Share-withholding (§7.2) — no proposer advantage.** The block proposer is
whoever holds the single global-minimum sample, which is uniform over all
hashers. An attacker that hoards its non-minimum low samples cannot change who
holds that minimum, so its block-proposal rate equals its hashrate share and no
more (simulated: share 0.10/0.30/0.45 → proposal rate 0.101/0.302/0.452).
Hoarding only forfeits the attacker's own reward share. Full selfish-mining
under low variance still needs modelling (rest of Phase C), but the withholding
vector shows no first-order gain.

**Remaining before a spec:** the gossip-cost bound (§7.3) and the full
selfish-mining-under-low-variance model (rest of Phase C).

## 11. Reward split (§4.5) — resolved by simulation (2026-11-20)

`scratchpad/reward_split_sim.py` (200k blocks, k=10, a realistically skewed
miner set) measures each candidate on fairness, coinbase-output count, and
payout variance:

| split rule | fairness error | outputs/block | payout CV (40% / 2% miner) |
|---|---|---|---|
| **equal split** | 0.09 % | ~4.87 | **0.39 / 2.2** (lowest) |
| proposer-weighted 60/40 | 0.05 % | ~4.87 | 0.75 / 4.3 |
| single-output lottery | 0.18 % | **1.00** | 1.22 / 7.0 (highest) |

**11.1 All candidates are fair and incentive-compatible** (reward share =
hashrate share to ≤0.18 %; every shared sample pays > 0, so hoarding is never
rational). Fairness therefore does not decide it.

**11.2 Proposer-weighting is rejected.** An earlier hunch was that weighting the
proposer would bound the output count. The simulation disproves it: it yields the
*same* ~4.87 distinct outputs as equal split **and raises payout variance**
(0.75 vs 0.39 for a large miner; 4.3 vs 2.2 for a small one). It costs variance
and buys nothing.

**11.3 The real axis is output-count vs payout-variance** — equal split ~5
outputs at the lowest variance, lottery 1 output at the highest. For a *privacy*
chain the output-count concern is linkability, which is better answered by
*shielding* the payouts than by reducing them.

**11.4 Recommendation: equal split across the k contributors, paid as SHIELDED
coinbase outputs into the Spark pool.** Perfect fairness, lowest variance, ~5
recipients/block; the payouts leak nothing (no miner linkability) *and grow the
anonymity set*, so the extra-output "cost" becomes a privacy benefit — mining
itself becomes private. Incentive-compatible (R/k > 0 per share). It builds on
the already-live shielded mint; the cost is coinbase complexity and faster
(shielded) chain growth. **Fallback if chain size is the binding constraint:** a
single-output *grinding-resistant* lottery (winner = `H(sorted k samples) mod k`,
so the proposer cannot pick itself), also shielded — 1 private output/block, fair
in expectation, higher payout variance. A lighter interim is transparent outputs
to one-time stealth addresses. This lives entirely in the gated acceptance/coinbase
module (Observe→Enforce), never touching the RandomX core.

## 12. Security under multi-sample — modelled (2026-11-20)

`scratchpad/selfish_mining_sim.py`.

**12.1 Depth-based attacks: unchanged (not weakened, not improved).** Selfish
mining and the d-confirmation double-spend depend only on *who finds each block*
— Bernoulli in hashrate share — so block-time variance cannot change them. The
double-spend catch-up simulation matches the Nakamoto gambler's-ruin
`P = (α/(1-α))^z` exactly (α=0.10/0.30/0.45, z=6 → 0.0000/0.0062/0.2992 vs
formula 0.0000/0.0062/0.3000). These thresholds are **identical at every k**, so
multi-sample does not weaken the hard security bound — the non-negotiable for a
consensus change. (It also does *not* improve them; §6's earlier "slightly
improves" was wrong and is corrected.)

**12.2 Time-based finality: genuinely improved.** The benefit is in the *time*
domain. A merchant waiting a fixed 12 minutes receives a random number of
confirmations; low variance makes that count reliable:

| k | mean confs | p1 | p99 | P(< 3 confirmations) |
|---|-----------|----|-----|----------------------|
| **1 (today)** | 6.0 | 1 | 12 | **6.3 %** |
| 10 | 5.6 | 4 | 8 | **0 %** |
| 20 | 5.5 | 4 | 7 | **0 %** |

Today ~6 % of 12-minute waits silently yield fewer than 3 confirmations — unsafe
for time-based acceptance, and the slow-gap window a time-based attacker exploits.
Under multi-sample that tail vanishes (never below 4), so a time-based acceptance
rule becomes a reliable guarantee and the exploitable slow-gap window collapses.

**Net:** security-neutral on the hard thresholds (not weakened), strictly better
on time-based finality.

## 13. Gossip-cost bound (§7.3) — Phase C complete (2026-11-20)

`scratchpad/gossip_sim.py`. Miners broadcast every hash below a share threshold
`tau_share`, set so the expected shares per block is a safety multiple of k.
Because `tau_share` scales with the block target, shares/block is constant in k
and **independent of hashrate** (more hashrate → higher difficulty → same count).

| k | safety c | E[shares]/block | P(≥k shares) | P(captures true k-lowest) | KB/block |
|---|---------|-----------------|--------------|---------------------------|----------|
| 10 | 2 | 20 | 0.995 | 0.995 | 1.6 |
| 10 | **3** | 30 | **1.000** | **1.000** | 2.3 |
| 20 | 3 | 60 | 1.000 | 1.000 | 4.7 |

With **c = 3** the k-lowest are present and captured with probability 1.000. The
traffic is ~3k shares/block (~2–5 KB per 120 s block, ~20–40 B/s per node,
flood-deduped) — negligible against block propagation (KB–MB). Spam is
self-limiting: every share is real work (`hash < tau_share`), so an attacker's
share rate is bounded by its hashrate, and the mesh's existing per-peer rate cap
backstops it. No amplification.

**Phase C is complete.** All gates pass: conversion constant (§10.1),
share-withholding (§10.2), reward split (§11), security/finality (§12), gossip
cost (§13). The design is ready to spec — see `bobtail-spec.md`.
