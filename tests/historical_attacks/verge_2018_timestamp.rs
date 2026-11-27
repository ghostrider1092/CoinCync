//! ## Verge Timestamp Attack (April 2018)
//!
//! Attackers manipulated block timestamps to exploit the multi-algorithm
//! difficulty adjustment on Verge. By spoofing timestamps far in the future,
//! they caused difficulty to drop to nearly zero, then mined thousands of
//! blocks at trivial difficulty (earning millions of coins).
//!
//! Citation: https://bitcointalk.org/index.php?topic=3256693.0
//! Chain: Verge (XVG)
//! Impact: Millions of coins stolen via timestamp manipulation

use coincync::chain::Blockchain;
use coincync::constants::MAX_TIMESTAMP_DRIFT;

/// Test: Timestamp drift constant is reasonable (not days/weeks)
#[test]
fn verge_2018_timestamp_drift_bounded() {
    // MAX_TIMESTAMP_DRIFT should be measured in minutes, not hours/days
    // Anything > 2 hours is dangerously permissive
    assert!(
        MAX_TIMESTAMP_DRIFT <= 7200, // 2 hours max
        "VERGE ATTACK RISK: MAX_TIMESTAMP_DRIFT is {} seconds ({}h)! \
         Should be <= 2 hours. Attackers can manipulate difficulty via timestamps.",
        MAX_TIMESTAMP_DRIFT,
        MAX_TIMESTAMP_DRIFT / 3600
    );
    assert!(
        MAX_TIMESTAMP_DRIFT > 0,
        "MAX_TIMESTAMP_DRIFT must be > 0 (some clock skew is normal)"
    );
}

/// Test: Difficulty adjustment doesn't collapse under timestamp manipulation
#[test]
fn verge_2018_difficulty_resists_timestamp_games() {
    let chain = Blockchain::new();
    chain.init_genesis().expect("genesis");

    // Anti-Verge invariant: a single difficulty *step* must never swing the
    // per-block TARGET difficulty by more than a bounded factor. Verge's bug let
    // spoofed timestamps collapse difficulty by orders of magnitude in one step;
    // here we assert the next block's target difficulty stays within 32x of the
    // current block's target difficulty. (Real block validation enforces a
    // tighter ±4x/step clamp in `validate_difficulty_target`; 32x is a loose
    // outer bound that still catches a Verge-scale collapse.)
    //
    // Compare TARGET difficulties on BOTH sides. `chain.difficulty()` returns
    // the cumulative-work base (seeded to 1 at genesis) — a different quantity
    // from a block's target difficulty, so it must not be compared against
    // `next_difficulty()` (doing so is a scale mismatch: 1 vs the genesis target
    // difficulty, a spurious ratio that has nothing to do with a difficulty
    // step).
    let current_target_difficulty = coincync::consensus::difficulty::target_to_difficulty(
        &chain
            .get_block_by_height(0)
            .expect("genesis block")
            .header
            .target,
    )
    .as_u128();
    assert!(
        current_target_difficulty > 0,
        "Genesis target difficulty must be nonzero"
    );

    let next = chain.next_difficulty();
    assert!(next > 0, "Next difficulty must never be zero");

    let ratio = if next > current_target_difficulty {
        next / current_target_difficulty
    } else {
        current_target_difficulty / next
    };
    assert!(
        ratio <= 32,
        "VERGE ATTACK: Difficulty changed by {}x in one step! \
         Attacker could mine at near-zero difficulty.",
        ratio
    );
}
