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

## 7. Simulation results (2026-09-02) — the §5 simulator was built

An offline f64 behavioural simulator of `calculate_difficulty` (dual-window ASERT
+ per-step clamp + emergency drop) was run against: fresh-chain startup, Poisson
steady-state (45 H/s … 20 kH/s), a genuine 2× hashrate step, idle-resume, and the
recorded §2 gap sequence. It reproduces V0's ~4–5× steady-state ring qualitatively
(matching §2). Two findings change the recommendation:

**7.1 The §4 candidate parameter fixes do NOT help — several destabilise.**
Measured startup overshoot (Dpeak / equilibrium, single home CPU):

| variant | startup overshoot | steady ring | 2× step lag |
|---|---|---|---|
| V0 current (8@70 / 144@30, clamp 2×/½) | **3.0×** | 5.4× | 17 blk |
| V1 tighten clamp 1.25×/0.8× | 3.0× (no change) | 5.4× | 17 blk |
| V2 flip weights 30/70 | 7.3× (worse) | 171× | 23 blk |
| V3 widen short 24 @50/50 | 12× (worse) | unstable | 44 blk |
| V4 median input | 36× (worse) | 492× | 17 blk |

The per-step clamp is a **no-op** for the overshoot: during a smooth ramp the
per-block move is < 2×, so the clamp never binds — tightening it changes nothing.
De-weighting / widening the short window or feeding a median *increases* startup
overshoot and steady-state variance (added lag), and destabilises the ring. **An
ASERT-parameter hard fork is therefore not supported by evidence and is likely
harmful.** This supersedes the §4 hypotheses.

**7.2 The overshoot is a genesis-calibration problem, and the driver is the
strictly-increasing-integer-timestamp rule** (`validation.rs`: a block's timestamp
must be strictly greater than its parent's, at 1-second resolution). When a fresh
chain's initial difficulty is far below the miner's actual capability, early blocks
solve in ≪ 1 s and their timestamps are forced to `parent+1s`, feeding ASERT a
*pinned* "1 s/block" signal — 120× faster than the 120 s target — for a long run.
That laggy, sustained error is what drives the large ramp and the subsequent
stall/emergency-drop overshoot. Simulator evidence (integer timestamps):

- Initial difficulty **matched to launch hashrate** (`H × 120 s`) → overshoot is a
  constant, benign **2.6×** at *every* hashrate tested (200 H/s → 20 kH/s), then
  converges; worst single inter-block gap ~20 min during convergence.
- Initial difficulty left far too low (4 800) → overshoot **grows with hashrate**
  (2.6× → 4.9× in sim; the live 2026-09-02 regtest hit ~25× because sub-second
  bursts compress even harder than the steady-rate model).

**7.3 Recommendation (revised).**
1. **Do NOT hard-fork the ASERT parameters.** The current V0 params are at or near
   the best of the tested set; the proposed tweaks make things worse.
2. **Calibrate the genesis/initial difficulty of any fresh chain to the expected
   launch hashrate** (`≈ H_launch × 120 s`). This is a *genesis parameter* set once
   for a new chain (testnet `TESTNET_INITIAL_DIFFICULTY`, mainnet initial target),
   **not** a mid-chain consensus fork — so it carries none of the hard-fork risk of
   editing the ASERT math. It removes the amplified overshoot; the residual 2.6× is
   inherent and settles quickly.
3. Combine with §6 (keep ≥1 miner online) to avoid the idle-resume ring.
4. If, after (2)+(3), the residual steady-state ring is still judged too high for
   mainnet, revisit only *then* — and model integer-timestamp compression + real
   bursty hashrate first, since the ideal model under-predicts real overshoot.

**Caveats.** The simulator is a behavioural f64 model, not the bit-exact
fixed-point path; it is validated to reproduce the §2 ring qualitatively but
under-predicts real overshoot magnitude (it uses steady, not bursty, hashrate).
Scripts: `scratchpad/difficulty_sim.py` (variants) and `difficulty_sim2.py`
(integer timestamps + genesis-calibration test).

## 8. Implemented (2026-09-03) — genesis calibration + ASERT startup grace

Three changes landed after a live testnet soak of §7's genesis-calibration
recommendation exposed a residual dip:

1. **Genesis-difficulty calibration** — `TESTNET_INITIAL_DIFFICULTY` and
   `MAINNET_INITIAL_DIFFICULTY` set to 64,000 (≈ a single home-CPU RandomX
   equilibrium × 120 s). Not an ASERT change; just a genesis parameter.
2. **Fresh genesis timestamp** — the testnet genesis timestamp was bumped to the
   chain's actual start. A stale genesis timestamp defeats (1): ASERT anchored on
   genesis for the first ~144 blocks, and a large genesis→first-block gap made
   the chain look catastrophically slow, collapsing difficulty to the
   `MIN_DIFFICULTY` floor before recovery (confirmed live: 64k → 500 → ramp).
3. **ASERT startup grace** — `get_anchor` now advances the anchor past the
   genesis block (height 0) to the first mined block, so `time_error` is always
   computed over real inter-block timestamps and the genesis timestamp never
   feeds a retarget. `difficulty_sim3.py` scored the options: this
   "no-genesis-anchor" grace removes the dip for genesis gaps from 2 min to
   135 days with fast (~17-block) convergence, and beats warmup-hold; it is
   deterministic (consensus-safe) and only differs from the old behaviour while
   genesis is inside the window (~first long-window blocks), so mature
   steady-state difficulty is unchanged.

Net: (1)+(3) together mean a fresh chain no longer overshoots high on a fast
single miner NOR collapses to the floor on a stale/late-start genesis, regardless
of the genesis→first-block gap. §6's "keep a miner online" remains good
operational practice but is no longer required to avoid the startup pathology.
The §4 ASERT-parameter tweaks were NOT adopted (§7.1 showed they don't help /
destabilise).
