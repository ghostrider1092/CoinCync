//! # Finality & reorg-acceptance policy
//!
//! CoinCync does **not** ship a separate voted-checkpoint or BFT-overlay
//! finality layer. Reorg defense is a six-layer system; this module owns the
//! **pure reorg-acceptance policy** — the depth caps and the MESS
//! work-multiplier decision — and remains the stable home for any future
//! BFT/voted-finality work. The chain-mutation side (block connect/disconnect,
//! UTXO/state application, reorg execution) lives in [`crate::chain`], which
//! re-exports the items below so existing `crate::chain::{...}` import paths
//! keep working unchanged. The authoritative prose description of the shipped
//! defense lives in
//! [`docs/security/reorg-defense.md`](../../docs/security/reorg-defense.md)
//! (use that for the threat model and parameter justifications). The short
//! version, anchored to the code in THIS module:
//!
//! 1. **Tier-1 Nakamoto** (≤ 10): unconditional longest-work
//!    (`REORG_UNCONDITIONAL_DEPTH = 10`).
//! 2. **Tier-2 MESS** (11–100 mainnet / 11–1000 testnet): fork must carry
//!    `2^((depth-10)/20)` more work — defeats single-burst rental attacks
//!    (`MESS_EXPONENT_DIVISOR = 20`, `evaluate_reorg_acceptability`).
//! 3. **Tier-3 hard cap** (> mainnet=100, testnet=1000): rejected outright;
//!    operator intervention required for deeper legitimate forks
//!    (`max_reorg_depth_for`).
//! 4. **Per-node rolling checkpoints**: each node refuses to reorg below its
//!    own `last_checkpoint` (`CHECKPOINT_INTERVAL = 144` in
//!    [`crate::constants`]).
//! 5. **Hardcoded consensus checkpoints** (CIP-009 Path B, shipped
//!    2026-05-08): `CONSENSUS_CHECKPOINTS` table in [`crate::constants`],
//!    populated post-launch via the release process.
//! 6. **Miner-signed rolling finality** (CIP-009.D, queued post-launch):
//!    feature-gated in [`crate::consensus::rolling_finality`]; not
//!    consensus-gating today.
//!
//! A separate voted-finality module will be added pre-mainnet only if the
//! post-public-testnet attack-surface review shows the layers above leave
//! residual rental-hashrate risk above what the audit accepts.

use crate::config::NetworkType;

/// Returns the max reorg depth for a given network.
/// Absolute maximum reorg depth. Beyond this, reorg is rejected outright.
/// This is the final safety net — hard finality.
pub fn max_reorg_depth_for(network: NetworkType) -> u64 {
    match network {
        NetworkType::Testnet | NetworkType::Regtest => 1000,
        NetworkType::Mainnet => 100,
    }
}

/// Returns the absolute maximum reorg depth for the current network.
///
/// SECURITY (2026-07-05 audit F31 — SEV-A): The previous implementation
/// used `#[cfg(feature = "testnet")]` (compile-time) to select 1000 vs
/// 100. But **network selection is a runtime decision** — the `network:
/// NetworkType` field on `Blockchain` is set from the `--network` CLI
/// flag / config, not from the build's feature flags. Result: a binary
/// built without `--features testnet` would use the 100-block mainnet
/// hard-finality cap EVEN WHEN CONFIGURED TO RUN ON TESTNET. That
/// misconfiguration contributed to the 2026-07-04 partition where the
/// fleet was running on testnet but hitting the 100-block cap that
/// belongs to mainnet — the ideal testnet cap is 1000, deliberately
/// higher so testnet can survive stress-test deep reorgs like the
/// 628-block one randomx-2 delivered.
///
/// Post-fix: the free-function version is deprecated in favor of
/// `max_reorg_depth_for(NetworkType)` which is unambiguous. This
/// wrapper still exists (and defaults to the safer Testnet=1000
/// interpretation) so any pre-audit caller compiles, but new code
/// should ALWAYS pass the actual network explicitly.
///
/// See `project_hard_finality_partition_2026_07_04.md` in the memory
/// index for the incident this closes.
#[deprecated(
    since = "1.0.11",
    note = "Uses compile-time feature flags for what should be a runtime \
            decision. Callers with access to a `Blockchain` should use \
            `blockchain.max_reorg_depth()` (method); free-function callers \
            should use `max_reorg_depth_for(network)` explicitly."
)]
pub fn max_reorg_depth() -> u64 {
    // Fall back to the safer testnet interpretation (1000) rather than
    // the pre-fix cfg-based mix. Callers who need the actual value MUST
    // migrate to the network-taking variant.
    max_reorg_depth_for(NetworkType::Testnet)
}

// ═══ HYBRID REORG DEFENSE (H-16 FIX) ═══════════════════════════════════════
//
// Three-tier defense against deep chain reorganizations:
//
// Tier 1 (depth ≤ 10): Unconditional acceptance if fork has more work.
//   Normal network jitter, race conditions, brief connectivity issues.
//   Standard Nakamoto longest-chain rule applies.
//
// Tier 2 (depth 11-100): MESS-style exponential cost multiplier.
//   Fork must demonstrate SIGNIFICANTLY more cumulative work to be accepted.
//   Required work multiplier = 2^((depth - 10) / 20)
//   At depth 30: fork needs 2x honest chain's work
//   At depth 50: fork needs 4x
//   At depth 70: fork needs 8x
//   At depth 90: fork needs 16x
//   This makes rental-hashrate attacks economically infeasible at depth.
//
// Tier 3 (depth > 100): Hard reject. Absolute finality.
//   No amount of work can reorg past this depth.
//   Combined with rolling checkpoints for defense in depth.
//
// Historical precedent:
//   - ETC 2019: 100+ block reorg, $1.1M double-spend
//   - Bitcoin Gold 2018: deep reorg, $18M stolen
//   - Horizen 2018: deep reorg, $550K stolen
//   All were low-hashrate PoW chains without progressive reorg resistance.
//
// Reference: Ethereum Classic MESS (EIP-ECIP-1100)

/// The depth below which reorgs are unconditionally accepted (standard Nakamoto rule).
pub const REORG_UNCONDITIONAL_DEPTH: u64 = 10;

/// The exponent divisor for MESS-style cost scaling.
/// Work multiplier = 2^((depth - REORG_UNCONDITIONAL_DEPTH) / MESS_EXPONENT_DIVISOR)
/// Higher divisor = gentler curve. 20 means doubling every 20 blocks above threshold.
pub const MESS_EXPONENT_DIVISOR: u64 = 20;

/// Tier-2 MESS is disabled below this tip height. During chain bootstrap every
/// box that boots independently can mine its own h=1 at floor difficulty, and
/// the work-multiplier defense would permanently lock those parallel forks in
/// place because none of them can ever satisfy 2^x of the others. Matches the
/// shape of the ring-size bootstrap relaxation (`BOOTSTRAP_MIN_RING_SIZE`): a
/// young chain has too little cumulative work for MESS to be meaningful, and
/// the per-DB checkpoint plus Tier-3 hard cap still bound how far an attacker
/// can reach.
pub const BOOTSTRAP_MESS_HEIGHT: u64 = 1000;

/// Evaluate whether a reorg at `depth` with `fork_work` cumulative work should
/// be accepted given `honest_work` on the current chain. `current_height` is the
/// caller's current tip; below `BOOTSTRAP_MESS_HEIGHT` we skip Tier-2 MESS.
///
/// `max_depth` is the network-specific hard-finality cap. Callers who have a
/// `Blockchain` should use `blockchain.max_reorg_depth()`; callers without
/// should compute `max_reorg_depth_for(network)` from the runtime network.
///
/// SECURITY (2026-07-05 audit F31 — SEV-A): The pre-fix signature omitted
/// `max_depth` and internally called `max_reorg_depth()` which used
/// compile-time cfg feature flags. Runtime network vs compile-time features
/// could diverge (see doc-comment on `max_reorg_depth`). The 2026-07-04
/// partition trap was exacerbated by this: fleet binary compiled without
/// `--features testnet` used max=100 (mainnet) even though runtime network
/// was testnet — testnet is supposed to allow 1000-deep reorgs so it can
/// survive the exact 628-block reorg that got trapped.
///
/// Returns `Ok(())` if the reorg is acceptable, `Err(reason)` if rejected.
pub fn evaluate_reorg_acceptability(
    depth: u64,
    fork_work: u128,
    honest_work: u128,
    current_height: u64,
    max_depth: u64,
) -> std::result::Result<(), String> {
    // Tier 3: Hard reject beyond absolute max depth
    if depth > max_depth {
        return Err(format!(
            "Reorg depth {} exceeds absolute maximum {} (hard finality)",
            depth, max_depth
        ));
    }

    // Tier 1: Unconditional acceptance for shallow reorgs.
    //
    // Accepts EQUAL work (`>=`), not only strictly-greater. The sole caller
    // (add_block's take_fork) reaches here for an equal-work fork ONLY when the
    // fork's tip hash is strictly SMALLER than the current tip — the
    // deterministic hash-lex tiebreak (see the take_fork comment). That gate
    // makes an equal-work reorg monotonic: a node only ever moves toward a
    // smaller tip hash, so every honest node converges to the same tie-winning
    // chain regardless of block arrival order (the point of the
    // network-deterministic tiebreak). Deep equal-work reorgs are still rejected
    // by the MESS tier below (only shallow ties resolve by hash).
    if depth <= REORG_UNCONDITIONAL_DEPTH {
        if fork_work >= honest_work {
            return Ok(());
        } else {
            return Err(format!(
                "Fork at depth {} has less work ({} < {})",
                depth, fork_work, honest_work
            ));
        }
    }

    // Bootstrap phase: skip Tier-2 MESS, fall back to plain longest-chain.
    // Equal work (`>=`) is accepted for the same monotonic hash-tiebreak reason
    // as Tier 1 above.
    if current_height < BOOTSTRAP_MESS_HEIGHT {
        if fork_work >= honest_work {
            return Ok(());
        } else {
            return Err(format!(
                "Fork at depth {} has less work ({} < {}) (bootstrap phase, MESS disabled)",
                depth, fork_work, honest_work
            ));
        }
    }

    // Tier 2: MESS — exponential cost multiplier
    // Required: fork_work > honest_work * 2^((depth - 10) / 20)
    let exponent = (depth - REORG_UNCONDITIONAL_DEPTH) / MESS_EXPONENT_DIVISOR;
    // Cap exponent to prevent overflow (2^40 is already absurdly high)
    let capped_exponent = exponent.min(40);
    let multiplier: u128 = 1u128 << capped_exponent;

    let required_work = honest_work.saturating_mul(multiplier);

    if fork_work > required_work {
        tracing::warn!(
            "MESS: Accepting deep reorg at depth {} (fork_work {} > required {} = honest {} * 2^{})",
            depth, fork_work, required_work, honest_work, capped_exponent
        );
        Ok(())
    } else {
        Err(format!(
            "MESS rejection: depth {} requires {}x work (2^{}). Fork has {} but needs {} (honest={})",
            depth, multiplier, capped_exponent, fork_work, required_work, honest_work
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reorg_acceptability_shallow_accepts_equal_or_more_work() {
        // Shallow reorgs accept EQUAL-or-more work. The sole caller (take_fork)
        // only reaches here for an equal-work fork when its tip hash wins the
        // deterministic hash-lex tiebreak, so accepting equal work is the
        // monotonic, network-deterministic convergence rule (all honest nodes
        // pick the same tie-winner). Strictly-less work is still rejected.
        let h = BOOTSTRAP_MESS_HEIGHT + 1; // post-bootstrap, full rules apply
        let max = max_reorg_depth_for(NetworkType::Testnet);
        assert!(evaluate_reorg_acceptability(3, 101, 100, h, max).is_ok());
        assert!(evaluate_reorg_acceptability(3, 100, 100, h, max).is_ok()); // equal — hash-tiebreak
        assert!(evaluate_reorg_acceptability(3, 99, 100, h, max).is_err()); // strictly less
    }

    #[test]
    fn test_reorg_acceptability_mess_multiplier() {
        // At depth 50, exponent = (50-10)/20 = 2 => required multiplier 4x.
        let h = BOOTSTRAP_MESS_HEIGHT + 1; // post-bootstrap
        let max = max_reorg_depth_for(NetworkType::Testnet);
        let err = evaluate_reorg_acceptability(50, 399, 100, h, max).unwrap_err();
        assert!(err.contains("requires 4x work"));
        assert!(evaluate_reorg_acceptability(50, 401, 100, h, max).is_ok());
    }

    #[test]
    fn test_reorg_acceptability_hard_depth_cap() {
        // F31: use the network-taking form so this test doesn't rely on the
        // deprecated compile-time free function. Verify both networks so the
        // caps are pinned by tests to their intended values.
        let testnet_max = max_reorg_depth_for(NetworkType::Testnet);
        let mainnet_max = max_reorg_depth_for(NetworkType::Mainnet);
        assert_eq!(testnet_max, 1000, "testnet hard-finality cap must be 1000");
        assert_eq!(mainnet_max, 100, "mainnet hard-finality cap must be 100");

        let err_testnet = evaluate_reorg_acceptability(
            testnet_max + 1,
            u128::MAX,
            1,
            BOOTSTRAP_MESS_HEIGHT + 1,
            testnet_max,
        )
        .unwrap_err();
        assert!(err_testnet.contains("exceeds absolute maximum"));
        assert!(
            err_testnet.contains("1000"),
            "testnet error must cite testnet cap"
        );

        let err_mainnet = evaluate_reorg_acceptability(
            mainnet_max + 1,
            u128::MAX,
            1,
            BOOTSTRAP_MESS_HEIGHT + 1,
            mainnet_max,
        )
        .unwrap_err();
        assert!(err_mainnet.contains("exceeds absolute maximum"));
        assert!(
            err_mainnet.contains("100"),
            "mainnet error must cite mainnet cap"
        );
    }

    #[test]
    fn test_reorg_acceptability_bootstrap_bypass() {
        // Below BOOTSTRAP_MESS_HEIGHT, Tier-2 MESS is skipped and only the
        // longest-chain rule applies even at deep reorg depths. This is the
        // launch convergence fix: a young fleet whose nodes diverge at low
        // heights must be able to converge once one chain pulls ahead.
        let bootstrap_h = BOOTSTRAP_MESS_HEIGHT / 2;
        let max = max_reorg_depth_for(NetworkType::Testnet);
        // Depth 50 with only slightly-more work: rejected post-bootstrap,
        // accepted during bootstrap.
        assert!(evaluate_reorg_acceptability(50, 101, 100, bootstrap_h, max).is_ok());
        // Equal work is accepted during bootstrap too (same monotonic
        // hash-tiebreak reason as Tier 1); strictly-less work still loses.
        assert!(evaluate_reorg_acceptability(50, 100, 100, bootstrap_h, max).is_ok());
        let err = evaluate_reorg_acceptability(50, 99, 100, bootstrap_h, max).unwrap_err();
        assert!(err.contains("bootstrap phase"));
        // Tier-3 hard cap still enforced during bootstrap.
        assert!(evaluate_reorg_acceptability(max + 1, u128::MAX, 1, bootstrap_h, max).is_err());
    }
}
