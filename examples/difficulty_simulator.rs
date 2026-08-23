//! Offline difficulty-retarget simulator (audit H-1).
//!
//! Purpose: quantify the difficulty oscillation and validate the **anchor-base**
//! fix BEFORE any consensus hard fork, exactly as
//! `docs/design/difficulty-oscillation-analysis.md` §5 recommends ("build an
//! offline simulator ... only after simulation picks a winner: implement behind
//! a height-gated hard fork").
//!
//! This is NOT consensus code. It uses `f64` for clarity and reproduces the
//! retarget *shape* (dual-window ASERT + per-step clamp) rather than the exact
//! integer arithmetic in `src/consensus/difficulty.rs`. The point is to compare
//! candidate retarget algorithms on identical synthetic block-time sequences.
//!
//! Candidates:
//!   - Current   : base = TIP difficulty, full-window exponent (audit H-1 — the
//!                 shipped algorithm; each solvetime deviation is re-applied for
//!                 ~W blocks while the block stays in the window → compounding).
//!   - AnchorBase: base = ANCHOR difficulty (true aserti3-2d; no compounding).
//!   - TightClamp: Current, but per-step clamp 0.8x..1.25x instead of 0.5x..2x.
//!
//! Run: `cargo run --release --example difficulty_simulator`

const TARGET: f64 = 120.0; // TARGET_BLOCK_TIME
const HALFLIFE: f64 = 3600.0; // ASERT_HALFLIFE (seconds)
const SHORT_W: usize = 8; // DIFFICULTY_SHORT_WINDOW
const LONG_W: usize = 144; // DIFFICULTY_LONG_WINDOW
const SHORT_WT: f64 = 0.70; // DIFFICULTY_SHORT_WEIGHT
const LONG_WT: f64 = 0.30; // DIFFICULTY_LONG_WEIGHT

#[derive(Clone, Copy)]
struct Blk {
    time: f64, // cumulative timestamp
    diff: f64, // difficulty in force for this block
}

#[derive(Clone, Copy, PartialEq)]
enum Variant {
    Current,
    AnchorBase,
    TightClamp,
}

impl Variant {
    fn name(self) -> &'static str {
        match self {
            Variant::Current => "Current (tip-base)",
            Variant::AnchorBase => "AnchorBase (fix)",
            Variant::TightClamp => "TightClamp",
        }
    }
    fn clamp(self) -> (f64, f64) {
        match self {
            Variant::TightClamp => (0.8, 1.25),
            _ => (0.5, 2.0),
        }
    }
}

/// One window's ASERT output. `base` is the difficulty the exponent multiplies:
/// the TIP difficulty for the shipped algorithm, the ANCHOR difficulty for the
/// fix. The exponent is the whole-window time error.
fn asert_window(base_diff: f64, t_tip: f64, t_anchor: f64, n_blocks: f64) -> f64 {
    let ideal = n_blocks * TARGET;
    let error = (t_tip - t_anchor) - ideal;
    // Slow window (error > 0) lowers difficulty; fast raises it.
    base_diff * 2f64.powf(-error / HALFLIFE)
}

/// Next difficulty from the block history (oldest..=tip) for a variant.
fn next_difficulty(v: Variant, hist: &[Blk]) -> f64 {
    let n = hist.len();
    if n < 2 {
        return hist.last().map(|b| b.diff).unwrap_or(1.0);
    }
    let tip = hist[n - 1];
    let short_anchor = hist[n.saturating_sub(SHORT_W + 1).max(0)];
    let long_anchor = hist[n.saturating_sub(LONG_W + 1).max(0)];
    let short_n = (n - 1 - n.saturating_sub(SHORT_W + 1).max(0)) as f64;
    let long_n = (n - 1 - n.saturating_sub(LONG_W + 1).max(0)) as f64;

    let (short, long) = match v {
        Variant::AnchorBase => (
            asert_window(short_anchor.diff, tip.time, short_anchor.time, short_n),
            asert_window(long_anchor.diff, tip.time, long_anchor.time, long_n),
        ),
        // Current / TightClamp: base on the TIP difficulty (the bug).
        _ => (
            asert_window(tip.diff, tip.time, short_anchor.time, short_n),
            asert_window(tip.diff, tip.time, long_anchor.time, long_n),
        ),
    };
    let combined = SHORT_WT * short + LONG_WT * long;
    let (lo, hi) = v.clamp();
    combined.clamp(tip.diff * lo, tip.diff * hi).max(1.0)
}

/// Deterministic exponential sample (mean `mean`) from a uniform in [0,1).
fn exp_sample(mean: f64, u: f64) -> f64 {
    // inverse-CDF; guard u→1
    -mean * (1.0 - u).ln().max(-50.0)
}

/// Tiny deterministic LCG so runs are reproducible without extra deps.
struct Lcg(u64);
impl Lcg {
    fn next_f64(&mut self) -> f64 {
        // Numerical Recipes LCG
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ((self.0 >> 11) as f64) / ((1u64 << 53) as f64)
    }
}

/// Run a sim. `hashrate(block_index)` returns the network hashrate for that
/// block. Difficulty is in units where equilibrium difficulty = hashrate*TARGET
/// (so at the correct difficulty the mean solvetime is TARGET). Returns the
/// per-block solvetimes and difficulties (after `warmup` blocks of history).
fn run(v: Variant, blocks: usize, seed: u64, hashrate: impl Fn(usize) -> f64) -> (Vec<f64>, usize) {
    let mut rng = Lcg(seed);
    let d0 = hashrate(0) * TARGET;
    let mut hist: Vec<Blk> = vec![Blk { time: 0.0, diff: d0 }];
    let mut solvetimes = Vec::with_capacity(blocks);
    let mut clamp_hits = 0usize;
    for i in 1..blocks {
        let cur = *hist.last().unwrap();
        let hr = hashrate(i);
        // Mean solvetime scales with how far difficulty sits above the true
        // difficulty for the current hashrate.
        let mean = TARGET * (cur.diff / (hr * TARGET));
        let st = exp_sample(mean, rng.next_f64()).max(1.0);
        solvetimes.push(st);
        let next = next_difficulty(v, &hist);
        // Count clamp hits (next railed to a per-step bound).
        let (lo, hi) = v.clamp();
        if next >= cur.diff * hi * 0.999 || next <= cur.diff * lo * 1.001 {
            clamp_hits += 1;
        }
        hist.push(Blk { time: cur.time + st, diff: next });
    }
    (solvetimes, clamp_hits)
}

fn cv(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    let mean = xs.iter().sum::<f64>() / xs.len() as f64;
    if mean == 0.0 {
        return 0.0;
    }
    let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / xs.len() as f64;
    var.sqrt() / mean
}

fn mean(xs: &[f64]) -> f64 {
    if xs.is_empty() { 0.0 } else { xs.iter().sum::<f64>() / xs.len() as f64 }
}

fn main() {
    let variants = [Variant::Current, Variant::AnchorBase, Variant::TightClamp];
    let n = 2000usize;

    println!("Difficulty retarget simulator (audit H-1) — TARGET={TARGET}s, halflife={HALFLIFE}s, short={SHORT_W}@{SHORT_WT}, long={LONG_W}@{LONG_WT}\n");

    // --- Scenario 1: steady hashrate (measures inherent oscillation) ---
    println!("== Scenario 1: steady hashrate ==");
    println!("{:<22} {:>12} {:>14} {:>12}", "variant", "solvetime CV", "mean solvetime", "clamp-hit %");
    for &v in &variants {
        let (st, clamp) = run(v, n, 0xC0FFEE, |_| 1.0);
        let warm = &st[st.len() / 4..];
        println!(
            "{:<22} {:>12.3} {:>12.1}s {:>11.1}%",
            v.name(),
            cv(warm),
            mean(warm),
            100.0 * clamp as f64 / n as f64
        );
    }

    // --- Scenario 2: 2x hashrate step at block n/2 (measures response) ---
    println!("\n== Scenario 2: 2x hashrate step at block {} ==", n / 2);
    println!("{:<22} {:>14} {:>16}", "variant", "post-step CV", "blocks-to-settle");
    for &v in &variants {
        let step = n / 2;
        let (st, _) = run(v, n, 0xBEEF, move |i| if i >= step { 2.0 } else { 1.0 });
        let post = &st[step..];
        // blocks-to-settle: first index after the step where a 16-block rolling
        // mean solvetime is within 10% of TARGET and stays there.
        let mut settle = post.len();
        for k in 0..post.len().saturating_sub(16) {
            let window = &post[k..k + 16];
            if (mean(window) - TARGET).abs() / TARGET <= 0.10 {
                settle = k;
                break;
            }
        }
        println!("{:<22} {:>14.3} {:>16}", v.name(), cv(post), settle);
    }

    // --- Scenario 3: idle gap (one very long block), measure re-baseline ---
    println!("\n== Scenario 3: idle gap (100x target at block {}) ==", n / 2);
    println!("{:<22} {:>18}", "variant", "blocks-to-rebaseline");
    for &v in &variants {
        // Reuse steady run but inject a huge solvetime by dropping hashrate to
        // ~0 for one block, then restore. Approximate via a hashrate dip.
        let dip = n / 2;
        let (st, _) = run(v, n, 0x1D1E_5EED, move |i| if i == dip { 0.01 } else { 1.0 });
        let post = &st[dip..];
        let mut settle = post.len();
        for k in 1..post.len().saturating_sub(16) {
            let window = &post[k..k + 16];
            if (mean(window) - TARGET).abs() / TARGET <= 0.10 {
                settle = k;
                break;
            }
        }
        println!("{:<22} {:>18}", v.name(), settle);
    }

    println!("\nLower is better on every metric. If AnchorBase shows materially");
    println!("lower steady-state CV and clamp-hit % than Current, it confirms the");
    println!("audit H-1 root cause (tip-base compounding) and the fix direction.");
}
