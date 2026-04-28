//! # IronConsensus Node Integration Helpers
//!
//! Helper functions for wiring IronConsensus events from the P2P layer.
//! These are convenience wrappers around `IronInput` sends that handle
//! the `Option<Sender>` pattern (no-op when iron isn't initialized).
//!
//! # Classification discipline (see `IronVerdict` + `classify_block_error`)
//!
//! The single most important design decision in this module is the mapping
//! from `crate::error::Error` to peer-reputation action. The prior incident
//! (commit 2bad0bb) was caused by striking peers for too many error classes
//! — specifically, for presenting valid blocks on weaker forks. The rule
//! encoded here is:
//!
//!   **Conservative by default. Unknown errors never strike.**
//!
//! The `classify_block_error` match uses an explicit allow-list for Bad /
//! Fork / Orphan, and a catch-all `_ => Neutral`. New error variants added
//! to `crate::error::Error` in the future will silently fall into Neutral,
//! which is the fail-safe direction. False negatives (missing strikes) are
//! a metrics issue. False positives (wrong strikes) take down the network.

use crate::network::peer::PeerId;
use crate::primitives::Hash;
use super::engine::IronInput;

/// Peer-level verdict for a block-processing outcome from `chain.add_block()`.
///
/// This is the central policy decision for what IronConsensus should do
/// about the peer who delivered a given block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IronVerdict {
    /// Unambiguous consensus violation — strike the peer.
    /// Reserved for things that are only possible if the peer is malicious
    /// or broken: forged crypto, bad PoW, double-spends, supply cap
    /// violations, structural limits, timestamp/version games.
    Bad,
    /// Valid block on a weaker/parallel fork — do NOT strike.
    /// Presenting a valid fork block is normal reorg behavior, not abuse.
    Fork,
    /// Parent not found yet — do NOT strike.
    /// The block may connect after we download its ancestors. Until then
    /// the peer has done nothing wrong.
    Orphan,
    /// Our own fault (DB/IO/internal) or fully ambiguous. Do not touch
    /// the peer's reputation — we can't tell whether the peer is at fault.
    Neutral,
}

/// Classify a `crate::error::Error` (as returned from `chain.add_block()`)
/// into an `IronVerdict`.
///
/// ## Policy
/// - **Bad**: explicitly listed consensus violations only.
/// - **Fork**: `InvalidPreviousHash`, `ReorgTooDeep`.
/// - **Orphan**: `OrphanBlock`, `BlockNotFound`.
/// - **Neutral**: everything else, including the catch-all `_`.
///
/// See the module docs for the rationale behind the conservative default.
pub fn classify_block_error(e: &crate::error::Error) -> IronVerdict {
    use crate::error::Error::*;
    match e {
        // ── Unambiguous consensus violations — STRIKE ──────────────────
        // Forged cryptography
        RingSignatureInvalid
        | RangeProofInvalid
        | InvalidAssetSurjectionProof
        | InvalidSignature(_)
        | CommitmentMismatch
        | InvalidSupplyCommitment
        | InvalidCheckpointVote
        // Bad PoW / anchor / algorithm
        | InvalidProofOfWork
        | PowValidation(_)
        | SolutionExpired { .. }
        | InvalidAnchor(_)
        | InvalidAlgorithm { .. }
        // Double-spend, balance, supply
        | DuplicateKeyImage(_)
        | AmountsNotBalanced
        | TransactionUnbalanced { .. }
        | AmountOverflow
        | AmountUnderflow
        | InvalidCoinbaseReward { .. }
        | MissingCoinbase
        // Structural limits (post wire-level acceptance)
        | BlockTooLarge { .. }
        | TransactionTooLarge { .. }
        | TransactionTooSmall { .. }
        | InvalidInputCount { .. }
        | InvalidOutputCount { .. }
        | InvalidRingSize { .. }
        | InvalidMerkleRoot
        | InsufficientDecoys { .. }
        | OutputTooYoung { .. }
        | OutputTooSmall { .. }
        | FeeTooLow { .. }
        // Timestamp / difficulty games
        | InvalidTimestamp(_)
        | FutureBlock
        | InvalidDifficulty
        // Version games
        | InvalidBlockVersion(_)
        | InvalidTxVersion(_)
        | BlockVersionTooNew { .. }
        | BlockVersionDowngrade { .. }
        | ForkNotActive { .. }
        // Asset fraud
        | InvalidAssetIssuance(_)
        | AssetAlreadyExists(_)
        | InsufficientAssetBalance { .. }
        | ThresholdNotMet { .. }
        | DuplicateMultisigSignature { .. }
        // Checkpoint violation
        | ViolatesCheckpoint(_)
        // Catch-all for tx validation
        | InvalidTransaction(_)
        => IronVerdict::Bad,

        // ── Valid block on a weaker/parallel fork — NO STRIKE ──────────
        InvalidPreviousHash
        | ReorgTooDeep { .. }
        => IronVerdict::Fork,

        // ── Parent not found — NO STRIKE (may connect later) ───────────
        OrphanBlock
        | BlockNotFound(_)
        => IronVerdict::Orphan,

        // ── Everything else — NO STRIKE (our fault or ambiguous) ───────
        // This is the critical catch-all. DO NOT convert this to a
        // per-variant whitelist. New Error variants added in the future
        // must default to Neutral so false strikes are impossible.
        _ => IronVerdict::Neutral,
    }
}

/// Dispatch a block-level verdict for a specific peer to IronConsensus.
/// No-op when iron is not initialized or the verdict is Neutral.
pub async fn iron_on_block_verdict(
    iron_tx: &Option<tokio::sync::mpsc::Sender<IronInput>>,
    peer:    PeerId,
    verdict: IronVerdict,
) {
    let Some(tx) = iron_tx else { return };
    let input = match verdict {
        IronVerdict::Bad    => IronInput::PeerBadBlock(peer),
        IronVerdict::Fork   => IronInput::PeerForkBlock(peer),
        IronVerdict::Orphan => IronInput::PeerOrphan(peer),
        IronVerdict::Neutral => return, // explicit no-op — don't touch reputation
    };
    let _ = tx.send(input).await;
}

/// Send a peer handshake event to IronConsensus.
pub async fn iron_on_peer_handshake(
    iron_tx:    &Option<tokio::sync::mpsc::Sender<IronInput>>,
    peer:       PeerId,
    height:     u64,
    tip:        Hash,
    total_diff: u128,
) {
    if let Some(tx) = iron_tx {
        let _ = tx.send(IronInput::PeerHandshake {
            peer,
            height,
            tip,
            total_diff,
        }).await;
    }
}

/// Send a block-accepted event (confirms peer's proven height).
pub async fn iron_on_block_accepted(
    iron_tx:  &Option<tokio::sync::mpsc::Sender<IronInput>>,
    peer:     PeerId,
    height:   u64,
) {
    if let Some(tx) = iron_tx {
        let _ = tx.send(IronInput::PeerHeightUpdate { peer, height }).await;
    }
}

/// Send a block-rejected event (bad block strike).
pub async fn iron_on_block_rejected(
    iron_tx: &Option<tokio::sync::mpsc::Sender<IronInput>>,
    peer:    PeerId,
) {
    if let Some(tx) = iron_tx {
        let _ = tx.send(IronInput::PeerBadBlock(peer)).await;
    }
}

/// Send a peer timeout event.
pub async fn iron_on_peer_timeout(
    iron_tx: &Option<tokio::sync::mpsc::Sender<IronInput>>,
    peer:    PeerId,
) {
    if let Some(tx) = iron_tx {
        let _ = tx.send(IronInput::PeerTimeout(peer)).await;
    }
}

/// Send a peer disconnect event.
pub async fn iron_on_peer_gone(
    iron_tx: &Option<tokio::sync::mpsc::Sender<IronInput>>,
    peer:    PeerId,
) {
    if let Some(tx) = iron_tx {
        let _ = tx.send(IronInput::PeerGone(peer)).await;
    }
}

/// Send an orphan block event.
pub async fn iron_on_peer_orphan(
    iron_tx: &Option<tokio::sync::mpsc::Sender<IronInput>>,
    peer:    PeerId,
) {
    if let Some(tx) = iron_tx {
        let _ = tx.send(IronInput::PeerOrphan(peer)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[tokio::test]
    async fn noop_without_tx() {
        iron_on_peer_gone(&None, [0u8; 32]).await;
        iron_on_block_rejected(&None, [1u8; 32]).await;
        iron_on_peer_timeout(&None, [2u8; 32]).await;
        iron_on_peer_orphan(&None, [3u8; 32]).await;
        iron_on_block_verdict(&None, [4u8; 32], IronVerdict::Bad).await;
        iron_on_block_verdict(&None, [5u8; 32], IronVerdict::Fork).await;
        iron_on_block_verdict(&None, [6u8; 32], IronVerdict::Orphan).await;
        iron_on_block_verdict(&None, [7u8; 32], IronVerdict::Neutral).await;
    }

    // Classification matrix pinning — this test is intentionally exhaustive
    // on the Bad/Fork/Orphan arms. If you add a new Bad variant, add it here.
    // If the test fails after editing classify_block_error, STOP and review
    // whether the change widens the strike surface — that's the exact class
    // of change that caused the commit 2bad0bb incident.
    #[test]
    fn classifier_unambiguous_bad_errors_strike() {
        let bad: &[Error] = &[
            Error::RingSignatureInvalid,
            Error::RangeProofInvalid,
            Error::InvalidAssetSurjectionProof,
            Error::InvalidSignature("forged".into()),
            Error::CommitmentMismatch,
            Error::InvalidSupplyCommitment,
            Error::InvalidCheckpointVote,
            Error::InvalidProofOfWork,
            Error::PowValidation("bad anchor".into()),
            Error::SolutionExpired { time_since: 30, max: 15 },
            Error::InvalidAnchor("zero".into()),
            Error::InvalidAlgorithm { expected: 0, got: 1 },
            Error::DuplicateKeyImage("ki".into()),
            Error::AmountsNotBalanced,
            Error::TransactionUnbalanced { inputs: 100, outputs: 99 },
            Error::AmountOverflow,
            Error::AmountUnderflow,
            Error::InvalidCoinbaseReward { got: 51, expected: 50 },
            Error::MissingCoinbase,
            Error::BlockTooLarge { size: 9_000_000, max: 2_000_000 },
            Error::TransactionTooLarge { size: 600_000, max: 500_000 },
            Error::TransactionTooSmall { size: 100, min: 500 },
            Error::InvalidInputCount { count: 200, max: 128 },
            Error::InvalidOutputCount { count: 20, max: 16 },
            Error::InvalidRingSize { expected: 11, got: 2 },
            Error::InvalidMerkleRoot,
            Error::InsufficientDecoys { available: 5, needed: 11 },
            Error::OutputTooYoung { age: 1, min: 10 },
            Error::OutputTooSmall { amount: 0, min: 1 },
            Error::FeeTooLow { fee: 0, min: 1000 },
            Error::InvalidTimestamp("before prev".into()),
            Error::FutureBlock,
            Error::InvalidDifficulty,
            Error::InvalidBlockVersion(99),
            Error::InvalidTxVersion(99),
            Error::BlockVersionTooNew { version: 99, height: 1, expected: 1 },
            Error::BlockVersionDowngrade { prev_version: 2, new_version: 1 },
            Error::ForkNotActive { fork_number: 1, height: 0, activation_height: 1000 },
            Error::InvalidAssetIssuance("bad sig".into()),
            Error::AssetAlreadyExists("id".into()),
            Error::InsufficientAssetBalance { asset_id: "id".into(), have: 0, need: 1 },
            Error::ThresholdNotMet { have: 1, need: 2 },
            Error::DuplicateMultisigSignature { signer_index: 0 },
            Error::ViolatesCheckpoint(1000),
            Error::InvalidTransaction("malformed".into()),
        ];
        for e in bad {
            assert_eq!(
                classify_block_error(e),
                IronVerdict::Bad,
                "expected Bad for {:?}",
                e
            );
        }
    }

    #[test]
    fn classifier_fork_errors_do_not_strike() {
        assert_eq!(classify_block_error(&Error::InvalidPreviousHash), IronVerdict::Fork);
        assert_eq!(
            classify_block_error(&Error::ReorgTooDeep { depth: 500, max: 100 }),
            IronVerdict::Fork
        );
    }

    #[test]
    fn classifier_orphan_errors_do_not_strike() {
        assert_eq!(classify_block_error(&Error::OrphanBlock), IronVerdict::Orphan);
        assert_eq!(
            classify_block_error(&Error::BlockNotFound("deadbeef".into())),
            IronVerdict::Orphan
        );
    }

    #[test]
    fn classifier_internal_errors_are_neutral() {
        // Our own fault — must NEVER strike the peer.
        let neutral: &[Error] = &[
            Error::DatabaseError("sled write failed".into()),
            Error::Corruption("block 7 missing".into()),
            Error::SerializationError("borsh".into()),
            Error::Internal("bug".into()),
            Error::NotImplemented("feature X".into()),
            Error::InvalidState("race".into()),
            Error::Timeout,
            Error::NotSynchronized,
            Error::MempoolFull,
            Error::OutputNotFound,
            Error::CryptoError("dalek".into()),
            Error::KeyDerivationFailed("bad path".into()),
            Error::VdfFailed("stuck".into()),
            Error::UpgradeRequired { fork_number: 2, blocks_remaining: 100 },
            Error::MinerBanned { until: 10000 },
        ];
        for e in neutral {
            assert_eq!(
                classify_block_error(e),
                IronVerdict::Neutral,
                "expected Neutral for {:?}",
                e
            );
        }
    }
}
