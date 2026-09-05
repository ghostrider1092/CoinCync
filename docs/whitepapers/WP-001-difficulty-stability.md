# WP-001 · Difficulty Stability
### Dual-anchor ASERT, genesis calibration, and the startup grace

**Status:** Shipped · **Layer:** Consensus · **Series:** [CoinCync Whitepapers](README.md)

---

## 1. Motivation

A small proof-of-work chain lives or dies on its difficulty controller. Too slow
to react and a hashrate departure freezes the chain for hours; too eager and it
oscillates, which is itself an attack surface (hash-hopping) and a terrible user
experience. The failure mode that actually kills young chains is not gradual
drift — it is the **startup transient**: the first hours of a chain, when there
is no hashrate history, the genesis parameters are guesses, and a single miner's
behaviour dominates the signal.

This paper documents the controller CoinCync ships, and — more usefully — the
two things we learned by trying to fix it the obvious way and failing.

---

## 2. Threat addressed

| Attack | Assumption it needs | What we removed |
|---|---|---|
| **Difficulty oscillation / hash-hopping** — mine when difficulty is low, leave when it rises | A controller that over-corrects, producing an exploitable sawtooth | Dual-window damping + per-step clamp + a floor; validated by simulation rather than intuition |
| **Startup stall** — a fresh chain overshoots difficulty and halts | That the controller can absorb an arbitrary genesis/hashrate mismatch | Genesis calibration: start *at* the expected equilibrium |
| **Stale-genesis collapse** — difficulty crashes to the floor on a chain whose genesis predates mining | That the genesis timestamp is a valid production-rate observation | Startup grace: genesis is never an ASERT anchor |
| **Timestamp manipulation** — lie about block times to move difficulty | Loose time bounds | Strictly-increasing timestamps, median-time-past, and a future-drift cap |

---

## 3. Design

### 3.1 Dual-anchor ASERT

The controller is an ASERT (absolutely scheduled exponentially rising target)
variant computed over **two windows simultaneously**:

- a **short window** (8 blocks, 70% weight) for responsiveness, and
- a **long window** (144 blocks, 30% weight) for stability,

each producing a target via
`new_target = base × 2^((actual_elapsed − expected_elapsed) / halflife)`
with a halflife of 3600 s, then combined by weight. All arithmetic is integer
`u128` with saturating multiplication and a fixed-point `2^x` — there is no
floating point anywhere in consensus.

Three safety rails bound the result:

1. **Per-step clamp** — the target may move at most 2× easier or ½× harder per
   block.
2. **`MIN_DIFFICULTY` floor** — a consensus floor below which the target may not
   go, keeping block production from outrunning propagation.
3. **Emergency drop** — if the chain has visibly stalled (a 12-block window
   exceeding 10× its expected duration), the controller is permitted a larger
   easing step, so a chain that loses its hashrate can recover without waiting
   out a long ramp.

### 3.2 Genesis calibration

Initial difficulty is set to **`expected_launch_hashrate × target_block_time`**,
so the very first blocks land near the 120 s target and the controller has
essentially nothing to correct.

This is a *genesis parameter*, not an algorithm change — which is the point. It
is set once per chain, carries none of the risk of a mid-chain consensus change,
and is the highest-leverage difficulty decision a new chain makes.

### 3.3 Startup grace: genesis is never an anchor

ASERT measures elapsed time between an anchor block and the tip. During the first
long-window of a chain's life the anchor is necessarily near genesis — and the
genesis timestamp is **a constant chosen by the chain's authors, not an
observation of mining**. If the first block is mined an hour, a day, or four
months after that constant, ASERT reads the gap as catastrophically slow
production and drives difficulty to the floor.

The grace is one rule: **`get_anchor` advances past the genesis block (height 0)
to the first *mined* block.** Every `time_error` is then computed over real
inter-block timestamps, and the genesis timestamp never feeds a retarget.

Properties:
- **Deterministic** — all nodes see identical block heights, so all compute the
  identical anchor. Consensus-safe.
- **Scoped** — it differs from the naive behaviour only while genesis is inside
  the difficulty window (roughly the first 144 blocks). Mature steady-state
  difficulty is bit-for-bit unchanged.
- **Total** — it removes the failure for *any* genesis→first-block gap, rather
  than requiring the gap to be small.

### 3.4 Single-source rule

The expected target is computed in exactly one place and consumed by the miner,
block validation, fork validation, and header validation alike. This is a
correctness requirement, not tidiness: a consensus rule implemented twice will
eventually disagree with itself (see WP-100 §4.4, where it did).

### 3.5 Timestamp discipline

Difficulty is only as trustworthy as its time input. Block timestamps must be
strictly increasing, must exceed the median of recent blocks (median-time-past),
and may not exceed a bounded drift into the future.

---

## 4. Security analysis

**What we validated, and how.** Because a difficulty change is a hard fork and
intuition about controllers is unreliable, we built an offline simulator that
replays the exact algorithm — dual-window ASERT, clamp, floor, emergency drop —
against synthetic Poisson block-time sequences at hashrates from 200 H/s to
20 kH/s, a genuine 2× hashrate step, an idle-resume gap, and a recorded
real-world oscillation trace.

**Finding 1 — the obvious fixes are wrong.** The standard advice for an
oscillating controller (tighten the clamp, reweight or widen the windows, feed a
median instead of the raw interval) was scored against the baseline:

| Variant | Startup overshoot | Steady-state ring | 2× step response |
|---|---|---|---|
| Shipped (8@70 / 144@30, clamp 2×/½) | **3.0×** | 5.4× | 17 blocks |
| Tighter clamp (1.25×/0.8×) | 3.0× *(no change)* | 5.4× | 17 blocks |
| Flipped weights (30/70) | 7.3× *(worse)* | 171× | 23 blocks |
| Widened short window (24 @50/50) | 12× *(worse)* | unstable | 44 blocks |
| Median input | 36× *(worse)* | 492× | 17 blocks |

The tighter clamp is a **no-op** because during a smooth ramp the per-block move
never approaches the clamp — it does not bind. The other variants add lag, and
lag is what produces overshoot. **We therefore did not retune ASERT.** A
whitepaper that recommended LWMA-style retuning here would be recommending a
regression.

**Finding 2 — the real driver is calibration, not the controller.** With initial
difficulty matched to launch hashrate, overshoot is a constant, benign ~2.6× at
*every* hashrate tested (200 H/s through 20 kH/s) and then converges. With
initial difficulty far too low, overshoot *grows with hashrate* (2.6× → 4.9× in
simulation, ~25× observed live) because sub-second early blocks are
time-compressed by the one-second timestamp resolution into a pinned "1 s/block"
signal — a sustained, laggy error the controller then chases.

**Finding 3 — calibration alone is fragile; the grace makes it total.** A third
simulation of grace candidates against genesis gaps from 2 minutes to 135 days:

| Grace | Floor dip | Convergence | Sensitive to gap? |
|---|---|---|---|
| None (baseline) | drops to floor (500) | 158 blocks | **yes — worse with larger gap** |
| Warmup-hold | no floor, but dips to ~19k | 148 blocks | no |
| **No-genesis-anchor (shipped)** | **none — holds at start** | **17 blocks** | **no — identical at 2 min and 135 days** |

**What this does not protect against.** A determined majority-hashrate actor can
still move difficulty within the clamp bounds; the controller is a stability
mechanism, not a 51% defence (that is WP-005). Nor does it prevent a chain from
being slow if its miners genuinely leave — the emergency drop shortens that
recovery but cannot eliminate it. And on a chain with a *single* miner, block
intervals remain a high-variance Poisson process; a controller cannot remove
variance that is inherent to the process.

---

## 5. Implementation

| Component | Location |
|---|---|
| Dual-anchor ASERT, clamp, floor, emergency drop | `src/consensus/difficulty.rs` |
| Startup grace (`get_anchor`) | `src/consensus/difficulty.rs` |
| Single-source expected target | `Chain::expected_next_target`, `src/chain.rs` |
| Header-path consumer | `src/network/node/dispatch/headers.rs` |
| Genesis calibration | `src/testnet.rs`, `src/mainnet.rs` |
| Timestamp rules | `src/consensus/validation.rs` |

**Tests.** `startup_grace_ignores_a_stale_genesis_timestamp` (30-day-stale
genesis, on-target blocks, asserts difficulty does not collapse); 28 difficulty
unit tests total; overflow/saturation boundary proofs.

**Simulators.** `difficulty_sim.py` (variant scoring), `difficulty_sim2.py`
(integer-timestamp effects + calibration), `difficulty_sim3.py` (grace
candidates).

**Live validation.** On a running chain with a deliberately stale genesis,
pre-grace difficulty collapsed 64,000 → 500 and ramped back over ~144 blocks;
post-grace it held near the calibrated value and climbed to the hardware
equilibrium with no floor excursion. A separate two-node live test confirmed the
single-source rule: before the fix, peers rejected every header; after, a fresh
node synced to tip in lockstep.

**Analysis of record.** [difficulty-oscillation-analysis.md](../design/difficulty-oscillation-analysis.md)
— §7 (simulation results, superseding the earlier §4 hypotheses) and §8
(implemented outcome).

---

## 6. Known limits

- The simulator is a **behavioural f64 model**, not the bit-exact fixed-point
  path. It reproduces the observed oscillation qualitatively and under-predicts
  real overshoot magnitude (it models steady, not bursty, hashrate). It is
  evidence for *ranking* designs, not a proof of the shipped arithmetic.
- Calibration requires an **estimate of launch hashrate**. A large
  underestimate re-opens a bounded ramp (not the stall — the grace covers the
  floor case). This is a launch decision, not a code property.
- The residual ~2.6× startup transient is inherent to a controller starting with
  no history. We damp it; we do not remove it.
- The steady-state oscillation on a very small chain is bounded but real. It is
  a variance property of low-hashrate Poisson mining, and the recorded
  mitigation is operational (keep at least one miner online) as much as
  algorithmic.

---

## 7. References

- ASERT / `aserti3-2d` difficulty algorithm (Bitcoin Cash) — the canonical
  formulation this variant departs from (we anchor on the tip target, not the
  anchor target, and combine two windows).
- LWMA difficulty algorithm write-ups and small-chain post-mortems.
- Bitcoin Cash EDA retrospective — difficulty oscillation as an exploitable
  condition.
- Internal: [WP-100 §4](WP-100-solved-issues-ledger.md) — the three difficulty
  failures and their removals.
