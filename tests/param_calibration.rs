//! Parameter-calibration simulator — a fast, mining-free guard on the economic
//! and difficulty parameters that a chain MUST get right before mainnet.
//!
//! Drives the REAL `calculate_difficulty` (ASERT) and `calculate_block_reward`
//! over synthetic scenarios and asserts they behave. This is the class of guard
//! that would have caught the ASERT unit-confusion incident (S1 — a testnet
//! wipe): if the retarget consumes the wrong time unit (or inverts the sign),
//! the DIRECTION of adjustment flips, and the assertions below fail loudly at
//! CI time instead of on a live network.
//!
//! Pure arithmetic — runs in milliseconds, no PoW.

use coincync::config::NetworkType;
use coincync::consensus::{calculate_difficulty, DifficultyBlock};
use coincync::constants::{MAX_SUPPLY, TARGET_BLOCK_TIME};
use coincync::emission::calculate_block_reward;
use coincync::primitives::Hash;

/// Simulate the difficulty trajectory over `n` blocks spaced `spacing` seconds
/// apart, starting from `start`. Returns per-block difficulty (higher = harder).
fn simulate_difficulty(spacing: u64, n: u64, start: Hash) -> Vec<u64> {
    let base = 1_000_000u64;
    // Seed two blocks at the start target so ASERT has a full anchor window.
    let mut db = vec![
        DifficultyBlock { height: 0, timestamp: base, target: start },
        DifficultyBlock { height: 1, timestamp: base + spacing, target: start },
    ];
    let mut out = Vec::new();
    for h in 2..=n + 1 {
        let t = calculate_difficulty(&db, h);
        out.push(t.to_difficulty());
        db.push(DifficultyBlock { height: h, timestamp: base + h * spacing, target: t });
    }
    out
}

/// S1 GUARD: on-schedule spacing keeps difficulty stable; too-fast RAISES it and
/// too-slow LOWERS it. A unit/sign error in the retarget flips a direction.
#[test]
fn difficulty_retarget_direction_and_stability_s1() {
    coincync::consensus::bind_randomx_genesis_for_network(NetworkType::Testnet);
    let start = Hash::from_difficulty(100_000);

    // On-schedule (spacing == TARGET_BLOCK_TIME): must not run away or collapse.
    let on = simulate_difficulty(TARGET_BLOCK_TIME, 60, start);
    let mid = *on.last().unwrap();
    let (lo, hi) = (*on.iter().min().unwrap(), *on.iter().max().unwrap());
    assert!(
        hi <= lo.saturating_mul(4).max(lo + 10),
        "on-schedule difficulty must stay bounded (lo={lo} hi={hi}) — instability/oscillation"
    );

    // Direction: too-fast blocks (came in 8x too quickly) must make it HARDER;
    // too-slow blocks must make it EASIER. This is exactly what a wrong time
    // unit / inverted sign breaks.
    let fast = *simulate_difficulty(TARGET_BLOCK_TIME / 8, 60, start).last().unwrap();
    let slow = *simulate_difficulty(TARGET_BLOCK_TIME * 8, 60, start).last().unwrap();
    assert!(
        fast >= mid,
        "too-fast blocks must not LOWER difficulty (fast={fast} mid={mid}) — ASERT unit/sign bug (S1)"
    );
    assert!(
        slow <= mid,
        "too-slow blocks must not RAISE difficulty (slow={slow} mid={mid}) — ASERT unit/sign bug (S1)"
    );
}

/// Per-block difficulty change must stay inside the sanity clamp — no single
/// block can swing difficulty arbitrarily (defends against a timestamp attacker
/// forcing a huge retarget in one step).
#[test]
fn difficulty_per_block_change_is_clamped() {
    coincync::consensus::bind_randomx_genesis_for_network(NetworkType::Testnet);
    let start = Hash::from_difficulty(100_000);
    // Extreme too-fast spacing (1s) — the clamp must still bound each step.
    let seq = simulate_difficulty(1, 40, start);
    let mut prev = 100_000u64;
    for (i, &d) in seq.iter().enumerate() {
        let up = d as f64 / prev as f64;
        let down = prev as f64 / d.max(1) as f64;
        assert!(
            up <= 4.5 && down <= 4.5,
            "block {i}: difficulty changed {up:.2}x up / {down:.2}x down in one step — clamp breached"
        );
        prev = d;
    }
}

/// EMISSION: reward is non-increasing (halvings), cumulative supply never
/// exceeds MAX_SUPPLY, and the schedule actually emits.
#[test]
fn emission_is_monotone_and_bounded_by_the_supply_cap() {
    let mut cum: u128 = 0;
    let mut prev = u128::MAX;
    let mut emitted_blocks = 0u64;
    for h in 0..3_000_000u64 {
        let r = calculate_block_reward(h).as_atomic() as u128;
        assert!(r <= prev, "reward must be non-increasing across halvings (height {h}: {r} > {prev})");
        prev = r;
        cum = cum.checked_add(r).expect("cumulative emission overflowed u128");
        assert!(
            cum <= MAX_SUPPLY,
            "cumulative emission {cum} exceeded MAX_SUPPLY {MAX_SUPPLY} by height {h}"
        );
        if r > 0 {
            emitted_blocks += 1;
        }
    }
    assert!(emitted_blocks > 0, "the emission schedule must actually pay a subsidy");
    assert!(cum > MAX_SUPPLY / 2, "most of the supply should be emitted within 3M blocks");
}
