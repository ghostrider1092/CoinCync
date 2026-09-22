//! Closed-loop difficulty replay — a control-loop test of the dual-anchor ASERT
//! algorithm.
//!
//! The unit tests in `consensus/difficulty.rs` are single-shot: they build a
//! fixed block list, call `calculate_difficulty` once, and check the direction
//! of the result. This test instead drives the algorithm as a **feedback loop**:
//! each block's target is the algorithm's own output for the chain so far, and a
//! hashrate model turns that target into the next block's spacing. We then change
//! the network hashrate mid-run and assert the algorithm *converges* the realized
//! block time back to `TARGET_BLOCK_TIME` — the property that actually matters on
//! a live chain and that a single-shot test cannot observe.
//!
//! Uses only the crate's public API (no access to internals, no consensus files
//! touched), so it is an integration test with zero hash-locked-file churn.

use coincync::consensus::{calculate_difficulty, target_to_difficulty, DifficultyBlock};
use coincync::constants::{DIFFICULTY_LONG_WINDOW, TARGET_BLOCK_TIME};
use coincync::primitives::Hash;

/// A non-saturated starting target (~2^112 in the top 128 bits), the same
/// "realistic" magnitude difficulty.rs uses so the algorithm exercises its real
/// arithmetic rather than u128 saturation at the max target. Its difficulty is
/// ~65536 — comfortably above the MIN_DIFFICULTY floor and below saturation, so
/// it can rise or fall by large factors without hitting a clamp.
fn realistic_target() -> Hash {
    let mut b = [0u8; 32];
    b[1] = 0x01;
    Hash::from_bytes(b)
}

/// A hashrate-driven block-time simulator over the real `calculate_difficulty`.
///
/// Hashrate `h` is expressed in the same units as `target_to_difficulty`. The
/// model is the ASERT fixed point itself: expected spacing =
/// `TARGET_BLOCK_TIME * difficulty / hashrate`, so when the algorithm has driven
/// difficulty to equal the hashrate, spacing equals the target. When hashrate
/// exceeds difficulty, blocks come faster (spacing < target) and the algorithm
/// should raise difficulty; and vice-versa.
struct Sim {
    blocks: Vec<DifficultyBlock>,
    ts: u64,
}

impl Sim {
    /// Seed a chain at perfect target spacing so the loop starts at equilibrium.
    fn warmed_up(n: u64) -> Self {
        let target = realistic_target();
        let blocks = (0..n)
            .map(|i| DifficultyBlock {
                height: i,
                timestamp: i * TARGET_BLOCK_TIME,
                target,
            })
            .collect();
        Sim {
            blocks,
            ts: (n.saturating_sub(1)) * TARGET_BLOCK_TIME,
        }
    }

    /// Mine one block: ask the algorithm for the next target, convert it to a
    /// spacing under the given hashrate, and append. Returns the realized spacing.
    fn step(&mut self, hashrate: u128) -> u64 {
        let height = self.blocks.len() as u64;
        let next_target = calculate_difficulty(&self.blocks, height);
        let difficulty = target_to_difficulty(&next_target);
        let spacing = (TARGET_BLOCK_TIME as u128 * difficulty / hashrate).max(1) as u64;
        self.ts += spacing;
        self.blocks.push(DifficultyBlock {
            height,
            timestamp: self.ts,
            target: next_target,
        });
        spacing
    }

    /// Run `count` blocks at a fixed hashrate, returning every realized spacing.
    fn run_regime(&mut self, hashrate: u128, count: usize) -> Vec<u64> {
        (0..count).map(|_| self.step(hashrate)).collect()
    }

    fn tip_difficulty(&self) -> u128 {
        target_to_difficulty(&self.blocks.last().unwrap().target)
    }
}

fn mean(xs: &[u64]) -> f64 {
    xs.iter().map(|&x| x as f64).sum::<f64>() / xs.len() as f64
}

#[test]
fn asert_converges_to_target_block_time_across_hashrate_regimes() {
    // Warm up well past the long window so both ASERT anchors are populated.
    let mut sim = Sim::warmed_up(DIFFICULTY_LONG_WINDOW + 8);
    let d0 = sim.tip_difficulty();
    assert!(d0 > 1_000, "sanity: starting difficulty {d0} well above the floor");

    const REGIME: usize = 600;
    const TAIL: usize = 150; // window over which we judge the settled state
    let target = TARGET_BLOCK_TIME as f64;

    // Regime 0: hashrate == starting difficulty. Already at equilibrium; the
    // loop must simply *hold* target spacing.
    let r0 = sim.run_regime(d0, REGIME);
    let m0 = mean(&r0[REGIME - TAIL..]);
    eprintln!("regime0 (H=d0) settled mean spacing = {m0:.1}s (target {target})");
    assert!(
        (m0 - target).abs() / target < 0.10,
        "at equilibrium the loop must hold target spacing; got {m0:.1}s"
    );

    // Regime 1: hashrate doubles. First block after the jump must come in FAST
    // (difficulty still lags), then the algorithm must pull spacing back to
    // target and difficulty must roughly double.
    let h1 = d0 * 2;
    let r1 = sim.run_regime(h1, REGIME);
    assert!(
        r1[0] < TARGET_BLOCK_TIME,
        "right after a hashrate doubling, blocks must arrive faster than target; got {}s",
        r1[0]
    );
    let m1 = mean(&r1[REGIME - TAIL..]);
    let d1 = sim.tip_difficulty();
    eprintln!(
        "regime1 (H=2·d0) first spacing = {}s, settled mean = {m1:.1}s, difficulty {d0} -> {d1}",
        r1[0]
    );
    assert!(
        (m1 - target).abs() / target < 0.12,
        "loop must re-converge to target after a 2x hashrate step; got {m1:.1}s"
    );
    assert!(
        (d1 as f64) > 1.5 * d0 as f64,
        "difficulty must climb toward the doubled hashrate; {d0} -> {d1}"
    );

    // Regime 2: hashrate collapses to a quarter of the current level. First block
    // must come in SLOW, then re-converge, and difficulty must fall.
    let h2 = h1 / 4;
    let r2 = sim.run_regime(h2, REGIME);
    assert!(
        r2[0] > TARGET_BLOCK_TIME,
        "right after a hashrate collapse, blocks must arrive slower than target; got {}s",
        r2[0]
    );
    let m2 = mean(&r2[REGIME - TAIL..]);
    let d2 = sim.tip_difficulty();
    eprintln!(
        "regime2 (H=h1/4) first spacing = {}s, settled mean = {m2:.1}s, difficulty {d1} -> {d2}",
        r2[0]
    );
    assert!(
        (m2 - target).abs() / target < 0.12,
        "loop must re-converge to target after a hashrate collapse; got {m2:.1}s"
    );
    assert!(
        (d2 as f64) < 0.75 * d1 as f64,
        "difficulty must fall toward the reduced hashrate; {d1} -> {d2}"
    );

    // Convergence, not just direction: the settled tail must track target far
    // more tightly than the transient immediately after each shock.
    let transient1 = mean(&r1[..TAIL]);
    assert!(
        (m1 - target).abs() < (transient1 - target).abs(),
        "settled spacing ({m1:.1}) must be closer to target than the post-shock transient ({transient1:.1})"
    );
}
