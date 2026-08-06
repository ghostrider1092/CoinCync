# Difficulty Oscillation on a Small / Low-Hashrate Chain — Analysis & Options

**Status:** analysis + proposal. **No code change is proposed here** — the
difficulty algorithm lives in `src/consensus/difficulty.rs`, which is
hash-locked and consensus-critical. Any change is a **hard fork** and must be
validated by offline simulation first (see §5). This document records the
problem, the measured evidence, the root-cause hypothesis, and the candidate
fixes with trade-offs so the change can be designed deliberately rather than
hacked in.

## 1. Symptom

After the testnet sat idle ~22 days and mining resumed (2026-08-04), block
times did not settle to the 120 s target. Difficulty **oscillates** and block
intervals swing wildly instead of converging.

## 2. Measured evidence (testnet, ~h14,460–14,477)

```text
height   gap(s)   difficulty
14461      328     131072   (2^17)
14462       20     262144   (2^18)
14463      228     262144
14464      118     262144
14465      178     262144
14466       38     524288   (2^19)
14467      454     524288
14468      213     524288
14469      131     524288
14470     1430     524288
14471      437     524288
14472      458     524288
14473      176     262144
14474      314     262144
14475      188     131072
14476       59     131072
14477      203     131072
```

- **Block-gap stats:** min 20 s, max 1430 s, avg **293 s** — 2.4× the 120 s
  target, with ~70× spread between fastest and slowest.
- **Difficulty is a power-of-2 sawtooth** between `2^17` and `2^19` — a 4× band
  it climbs and falls in exact doubling/halving steps.

## 3. Root-cause hypothesis (evidence-based; validate by simulation)

The algorithm already has swing limits: `MAX_DIFFICULTY_ADJ = 2/1` (at most
double per step) and `MIN_DIFFICULTY_ADJ = 1/2` (at most halve per step), on top
of a dual-window ASERT (short 8-block @70%, long 144-block @30%,
`ASERT_HALFLIFE = 3600 s`) and a `MIN_DIFFICULTY` floor.

The exact power-of-2 ladder in §2 is the tell: **the per-step clamp is binding
on almost every block.** At low hashrate the per-block time is a high-variance
Poisson process (mean ≫ target here), so the ASERT error term each block is
large enough that ASERT *wants* to move difficulty by more than 2× / ½. It
therefore rails to the clamp bound every block — up on a fast block, down on a
slow one — and rings between the bounds. The clamp, intended to damp swings, is
instead the thing being hit repeatedly, which **manufactures** the sawtooth
rather than preventing it. The short window at 70% weight makes the response
dominated by the noisiest signal.

This is a **window-reactivity** problem, **not** a missing clamp (the earlier
"difficulty-drop clamp" note predates seeing that per-step clamps already exist).
Precise framing (to be settled by §5, not asserted here): inter-block time is a
Poisson process with CV≈1 at *any* hashrate, so the raw last-interval signal is
always noisy; mature chains damp it with **long** windows (Monero LWMA-60,
Bitcoin 2016-block), whereas CoinCync's **8-block window at 70% weight** tracks
that noise closely and rails the clamp. So the ring may be largely
hashrate-*independent* and inherent to the short/heavy window — the idle→resume
episode is what made it *visible*, and low absolute hashrate may amplify it but
is not confirmed to be the primary driver. The simulator in §5 measures the
hashrate-dependence directly instead of assuming it.

## 4. Candidate fixes (each is a consensus hard fork — trade-offs noted)

1. **Tighten the per-step clamp** (e.g. 1.25× / 0.8× instead of 2× / ½).
   Smaller steps → lower sawtooth amplitude, but slower legitimate response to a
   real hashrate change. Cheapest change; may just shrink, not remove, the ring.
2. **Re-weight / widen the short window** (drop the 70% short weight, or grow
   the 8-block window). Less variance sensitivity; slower to track real change.
3. **Median / dampened input** — feed ASERT a rolling median of recent solve
   times instead of the raw last interval, to reject single-block outliers
   (the 20 s and 1430 s spikes).
4. **Idle-resume special case** — allow one larger correction on the first
   block after a gap ≫ target, then revert to normal steps, so the chain
   re-baselines difficulty in one move instead of laddering for hours.
5. **Testnet-only relaxation** ("20-minute rule" style) — on testnet, permit
   min-difficulty after a long gap so a single home CPU can always make
   progress; keep mainnet strict. Isolates the operational pain to testnet.

## 5. Recommendation

- **Do not change `difficulty.rs` yet.** Build an **offline simulator** that
  replays the ASERT + clamp math against synthetic low-hashrate block-time
  sequences (Poisson at 45 H/s … 2 kH/s) and the real §2 sequence, and score
  each option in §4 on: steady-state block-time variance, time-to-converge after
  an idle gap, and response lag to a genuine 2× hashrate change.
- Only after simulation picks a winner: implement behind a **height-gated hard
  fork**, re-lock `difficulty.rs`, and activate on testnet first.
- **Owner decision required** on whether to invest in this pre-mainnet — every
  real idle period reproduces §2, so mainnet with intermittent early hashrate
  will hit it. Tracks with the small-operator / single-miner reality noted in
  the runaway-fork and no-cloud-mining constraints.

## 6. Operational note (no fork)

Independent of any algorithm change: keeping ≥1 miner continuously online (so the
chain never goes idle long enough to enter the variance-dominated regime) avoids
the trigger entirely. The idle→collapse→overshoot→ring cycle only starts after a
long production gap.
