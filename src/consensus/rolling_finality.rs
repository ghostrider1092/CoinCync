//! Consensus-layer adapter for CIP-009.D rolling soft-finality.
//!
//! This is the **phase 3** integration that CIP-011 §"Code changes"
//! point #2 specifies: a thin adapter that wraps the already-shipped
//! `coincync-rolling-finality` crate (the `FinalityTracker` state
//! machine, the `Ed25519Verifier`, and the `wire-codec`) and exposes
//! the two queries the rest of the node needs — the reorg-rule check
//! and the soft-final-height readout.
//!
//! ## Off by default — changes nothing until explicitly enabled
//!
//! The entire module is gated behind the `rolling-finality` Cargo
//! feature, which is **off by default**. With the feature disabled
//! the module does not compile in, the `coincync-rolling-finality`
//! dependency is not pulled, and node behaviour is byte-identical to
//! a build without this file. The feature exists so the integration
//! can be built, reviewed, and tested ahead of the CIP-011 activation
//! decision without touching consensus-locked files.
//!
//! ## What this module does NOT do
//!
//! - It does **not** wire the reorg rule into `validate_block`. That
//!   hook lands in `src/consensus/validation.rs` (a consensus-locked
//!   file) and only after the CIP-011 activation decision is made.
//!   This module just provides the query the hook will call.
//! - It does **not** define the activation heights. Those are the
//!   `ROLLING_FINALITY_*` constants destined for `src/constants.rs`
//!   (also consensus-locked). The *caller* uses those heights to
//!   decide *when* to invoke this adapter; the adapter itself is
//!   height-agnostic.
//! - It does **not** persist. Per CIP-011, on node restart the
//!   tracker is rebuilt by replaying accepted blocks from
//!   `chain_tip - WINDOW` forward — `on_accepted_block` is the
//!   replay primitive as well as the live-path primitive.
//! - It does **not** locate the attestation within a coinbase. The
//!   `find_attestation` helper scans for the wire magic; the caller
//!   passes the coinbase `extra` bytes and the adapter finds the
//!   attestation sub-slice (or reports there isn't one).
//!
//! ## Ordering invariant
//!
//! Inside [`RollingFinality::on_accepted_block`], `record_block` is
//! called **before** `apply_attestation`. Reason: `record_block`
//! advances the tracker's `chain_tip`, and `apply_attestation`'s
//! future-target check (`target_height <= chain_tip`) and stale
//! pruning both depend on the tip being current for the block being
//! processed. The block is part of the chain first; the attestation
//! it carries is processed against that updated chain state second.
//! This matches CIP-011's wording and the `FinalityTracker` module
//! docs.
//!
//! A natural consequence of the `ActiveMinerSet` design: a miner's
//! attestations do not count until roughly `LAG` blocks after their
//! first block (their `first_seen_height` is after the
//! `target_height` of their early attestations, so `is_active`
//! returns `false` for those). This "warm-up" is intentional — a
//! miner must have been a chain participant for `LAG` blocks before
//! their finality voice counts — and is handled entirely inside the
//! crate; the adapter neither needs nor adds special-casing for it.

use parking_lot::RwLock;

use coincync_rolling_finality::{
    codec, ApplyOutcome, Ed25519Verifier, FinalityError, FinalityStats, FinalityTracker, WireError,
    WIRE_MAGIC,
};

/// Outcome of feeding one accepted block through the adapter.
///
/// Distinguishes the four cases the caller (and the operator, via
/// logs) cares about: the block carried no attestation at all, it
/// carried a structurally-malformed one, it carried a well-formed
/// one the tracker rejected, or it carried one the tracker accepted
/// (with or without a finality advance).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OnBlockOutcome {
    /// No CIP-009.D attestation found in the coinbase extra. During
    /// the ENABLE phase this is the normal, backward-compatible case
    /// for a block from an un-upgraded miner. During the ENFORCE
    /// phase the validator (not this adapter) rejects such a block.
    NoAttestation,

    /// The coinbase extra carried the `CIP9` wire magic but the body
    /// failed structural decode (bad version, truncated, wrong
    /// signature length). The attestation contributes nothing to the
    /// tracker. The validator decides whether this rejects the block
    /// (ENFORCE phase) or is merely logged (ENABLE phase).
    Malformed(WireError),

    /// A structurally-valid attestation that the tracker rejected:
    /// bad ed25519 signature, future / stale target height, miner
    /// not in the active set, or a duplicate. Contributes nothing to
    /// the tracker state.
    Rejected(FinalityError),

    /// Attestation accepted; the soft-final height did not advance.
    Recorded,

    /// Attestation accepted **and** the soft-final height advanced to
    /// `height`. This is the signal the consensus layer uses to lock
    /// in finality at that height.
    NewlyFinalized { height: u64, hash: [u8; 32] },
}

/// The per-node rolling-finality adapter.
///
/// Holds the singleton [`FinalityTracker`] behind an `RwLock` (block
/// acceptance takes the write lock; the reorg-rule and status queries
/// take the read lock) and a stateless [`Ed25519Verifier`].
///
/// Construct one at node startup, rebuild it by replaying recent
/// blocks (see module docs), and share it (`Arc<RollingFinality>`)
/// between the block-processing path and the reorg validator.
pub struct RollingFinality {
    tracker: RwLock<FinalityTracker>,
    verifier: Ed25519Verifier,
}

impl RollingFinality {
    /// Construct with the CIP-009.D defaults (`WINDOW` = 10000,
    /// `LAG` = 100, `MIN_QUORUM` = 5).
    pub fn new_default() -> Self {
        RollingFinality {
            tracker: RwLock::new(FinalityTracker::new_default()),
            verifier: Ed25519Verifier::new(),
        }
    }

    /// Construct with explicit tracker parameters. For tests and any
    /// future tuning; production uses [`Self::new_default`].
    pub fn with_params(window: u64, lag: u64, min_quorum: usize, stale_horizon: u64) -> Self {
        RollingFinality {
            tracker: RwLock::new(FinalityTracker::with_params(
                window,
                lag,
                min_quorum,
                stale_horizon,
            )),
            verifier: Ed25519Verifier::new(),
        }
    }

    /// Process one accepted block.
    ///
    /// `block_height` is the height of the accepted block;
    /// `coinbase_extra` is the raw bytes of that block's coinbase
    /// `extra` field. The adapter scans the extra for the CIP-009.D
    /// wire magic; if found, it decodes the attestation, records the
    /// block's miner in the active set, and applies the attestation
    /// to the tracker.
    ///
    /// This is both the live-path primitive (call it once per block
    /// as the chain extends) and the restart-replay primitive (call
    /// it for each block from `chain_tip - WINDOW` forward to rebuild
    /// the in-memory tracker).
    ///
    /// Idempotency: the underlying tracker is idempotent on
    /// `record_block` for a repeated `(miner, height)` pair, but
    /// `apply_attestation` rejects a repeated `(miner, height, hash)`
    /// with [`FinalityError::DuplicateAttestation`]. Replaying the
    /// *same* block twice therefore yields `Rejected(Duplicate...)`
    /// the second time — replay logic must feed each block exactly
    /// once.
    pub fn on_accepted_block(&self, block_height: u64, coinbase_extra: &[u8]) -> OnBlockOutcome {
        let attestation_bytes = match find_attestation(coinbase_extra) {
            Some(slice) => slice,
            None => return OnBlockOutcome::NoAttestation,
        };

        let attestation = match codec::decode(attestation_bytes) {
            Ok(att) => att,
            Err(e) => return OnBlockOutcome::Malformed(e),
        };

        let mut tracker = self.tracker.write();

        // Ordering invariant (see module docs): record the block —
        // which advances `chain_tip` and adds the miner to the active
        // set — BEFORE applying the attestation that block carries.
        tracker.record_block(attestation.miner_pubkey, block_height);

        match tracker.apply_attestation(&attestation, &self.verifier) {
            Ok(ApplyOutcome::Accepted) => OnBlockOutcome::Recorded,
            Ok(ApplyOutcome::NewlyFinalized { height, hash }) => {
                OnBlockOutcome::NewlyFinalized { height, hash }
            }
            Err(e) => OnBlockOutcome::Rejected(e),
        }
    }

    /// The reorg-rule query for the validator.
    ///
    /// Returns `true` if reorganising the chain such that the fork
    /// point sits at `proposed_fork_height` would walk back a
    /// soft-final block — i.e. the reorg violates CIP-009.D and the
    /// validator must reject it.
    ///
    /// Returns `false` when no height is soft-final yet (the common
    /// case during the ENABLE phase and on a freshly-bootstrapped
    /// chain). The `validate_block` hook only consults this once the
    /// ENFORCE height is reached; before that, the rule does not
    /// fire regardless of what this returns.
    pub fn would_reorg_violate_finality(&self, proposed_fork_height: u64) -> bool {
        self.tracker
            .read()
            .would_reorg_violate_finality(proposed_fork_height)
    }

    /// Current soft-final height, if any. `None` until the first
    /// height crosses the 2/3 quorum threshold. Consumed by the RPC
    /// surface, the status page, and metrics.
    pub fn current_soft_final_height(&self) -> Option<u64> {
        self.tracker.read().soft_final_height()
    }

    /// Snapshot of tracker state for observability (RPC
    /// `get_finality_status`, status page, Prometheus metrics).
    pub fn stats(&self) -> FinalityStats {
        self.tracker.read().stats()
    }
}

impl Default for RollingFinality {
    fn default() -> Self {
        Self::new_default()
    }
}

/// Locate a CIP-009.D attestation inside a coinbase `extra` field.
///
/// The coinbase `extra` field is a general-purpose byte string; an
/// attestation, when present, is a `WIRE_MAGIC`-prefixed blob
/// somewhere inside it. This helper scans for the 4-byte magic and
/// returns the sub-slice from the magic to the end of `extra` (the
/// `codec::decode` call that follows is strict and will reject any
/// trailing bytes, so the slice does not need a precise end bound
/// here — a malformed/over-long slice surfaces as
/// [`OnBlockOutcome::Malformed`], not a silent mis-parse).
///
/// Returns `None` if the magic does not appear at all — the normal
/// "this block carries no attestation" case.
fn find_attestation(extra: &[u8]) -> Option<&[u8]> {
    if extra.len() < WIRE_MAGIC.len() {
        return None;
    }
    extra
        .windows(WIRE_MAGIC.len())
        .position(|w| w == WIRE_MAGIC)
        .map(|offset| &extra[offset..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use coincync_rolling_finality::{codec, FinalityAttestation};
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    /// Build a signed attestation plus the signing key that produced
    /// it, so tests can drive the real `Ed25519Verifier`.
    fn signed_attestation(
        target_height: u64,
        target_hash_byte: u8,
    ) -> (SigningKey, FinalityAttestation) {
        let signing = SigningKey::generate(&mut OsRng);
        let mut att = FinalityAttestation {
            miner_pubkey: signing.verifying_key().to_bytes(),
            target_height,
            target_hash: [target_hash_byte; 32],
            signature: vec![0u8; 64],
        };
        att.signature = signing.sign(&att.signing_bytes()).to_bytes().to_vec();
        (signing, att)
    }

    /// Wrap encoded attestation bytes in a plausible coinbase `extra`
    /// — some leading filler, the attestation, nothing after (the
    /// codec is strict about trailing bytes).
    fn extra_with_attestation(att: &FinalityAttestation) -> Vec<u8> {
        let mut extra = vec![0xAB, 0xCD, 0xEF];
        extra.extend_from_slice(&codec::encode(att));
        extra
    }

    #[test]
    fn no_magic_in_extra_is_no_attestation() {
        let rf = RollingFinality::new_default();
        let outcome = rf.on_accepted_block(1_000, &[0x00, 0x11, 0x22, 0x33]);
        assert_eq!(outcome, OnBlockOutcome::NoAttestation);
    }

    #[test]
    fn empty_extra_is_no_attestation() {
        let rf = RollingFinality::new_default();
        assert_eq!(
            rf.on_accepted_block(1_000, &[]),
            OnBlockOutcome::NoAttestation
        );
    }

    #[test]
    fn malformed_body_after_good_magic_is_malformed() {
        let rf = RollingFinality::new_default();
        // Magic present, body truncated.
        let mut extra = WIRE_MAGIC.to_vec();
        extra.push(1); // version
        extra.extend_from_slice(&[0u8; 4]); // not a full body
        match rf.on_accepted_block(1_000, &extra) {
            OnBlockOutcome::Malformed(_) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn find_attestation_locates_magic_after_filler() {
        let (_sk, att) = signed_attestation(900, 0xAA);
        let extra = extra_with_attestation(&att);
        let slice = find_attestation(&extra).expect("magic should be found");
        // The located slice must decode back to the same attestation.
        let decoded = codec::decode(slice).expect("decode of located slice");
        assert_eq!(decoded, att);
    }

    #[test]
    fn well_formed_attestation_from_lapsed_miner_is_rejected() {
        // A miner whose only block is the one being processed has a
        // `first_seen_height` equal to `block_height`, which is after
        // the attestation's `target_height` — so the tracker's
        // active-set check rejects it (`MinerNotActive`). This is the
        // documented warm-up behaviour, surfaced here as a Rejected
        // outcome rather than silently dropped.
        let rf = RollingFinality::with_params(
            /* window */ 1_000, /* lag */ 100, /* min_quorum */ 5,
            /* stale_horizon */ 1_000,
        );
        let (_sk, att) = signed_attestation(900, 0xAA);
        let extra = extra_with_attestation(&att);
        // Block at height 1000 carries an attestation to height 900.
        // The miner's first_seen is 1000 > 900, so not active at 900.
        match rf.on_accepted_block(1_000, &extra) {
            OnBlockOutcome::Rejected(FinalityError::MinerNotActive { height }) => {
                assert_eq!(height, 900);
            }
            other => panic!("expected Rejected(MinerNotActive), got {other:?}"),
        }
    }

    #[test]
    fn bad_signature_is_rejected() {
        let rf = RollingFinality::new_default();
        let (_sk, mut att) = signed_attestation(900, 0xAA);
        att.signature[0] ^= 0xFF; // corrupt the signature
        let extra = extra_with_attestation(&att);
        match rf.on_accepted_block(1_000, &extra) {
            OnBlockOutcome::Rejected(FinalityError::InvalidSignature) => {}
            other => panic!("expected Rejected(InvalidSignature), got {other:?}"),
        }
    }

    #[test]
    fn quorum_of_warmed_up_miners_advances_soft_final_height() {
        // Exercise the full happy path: five miners that have each
        // been mining since well before the attestation target, all
        // attesting to the same (height, hash), cross the 2/3
        // threshold and advance the soft-final height.
        let rf = RollingFinality::with_params(
            /* window */ 10_000, /* lag */ 100, /* min_quorum */ 5,
            /* stale_horizon */ 10_000,
        );

        // Five distinct miners. Each one mines an early block (so
        // their `first_seen_height` precedes the attestation target),
        // then later mines the block that carries their attestation.
        let miners: Vec<SigningKey> = (0..5).map(|_| SigningKey::generate(&mut OsRng)).collect();

        // Warm-up: each miner mines a block at heights 100..105 with
        // no attestation payload, establishing `first_seen`.
        for (i, _sk) in miners.iter().enumerate() {
            // A no-attestation extra still needs the miner recorded;
            // emulate that by recording via a self-targeted, far-past
            // attestation would be circular — instead drive the
            // tracker directly is not possible from here, so we mine
            // an *attested* warm-up block whose target is itself
            // stale enough to be Recorded-or-Rejected but still calls
            // record_block. Simpler: mine the warm-up block carrying
            // an attestation to a height the miner is already active
            // for is impossible at genesis. So we accept that the
            // first real attestation per miner is the warm-up: it is
            // Rejected(MinerNotActive) but `record_block` still ran.
            let warmup_height = 100 + i as u64;
            let mut att = FinalityAttestation {
                miner_pubkey: miners[i].verifying_key().to_bytes(),
                target_height: warmup_height.saturating_sub(1),
                target_hash: [0x01; 32],
                signature: vec![0u8; 64],
            };
            att.signature = miners[i].sign(&att.signing_bytes()).to_bytes().to_vec();
            let extra = extra_with_attestation(&att);
            // record_block(miner, warmup_height) runs regardless of
            // whether the attestation is accepted.
            let _ = rf.on_accepted_block(warmup_height, &extra);
        }

        // Advance the chain tip well past the warm-up so all five
        // miners are established and the attestation target (height
        // 5000) is one they were all active for.
        // Each miner now mines a block carrying an attestation to
        // (5000, 0xAA). The blocks are at heights 5100..5105 so the
        // LAG-100 relationship holds and the target is in-window.
        let target_height = 5_000u64;
        let target_hash = [0xAAu8; 32];
        let mut finalized_at = None;
        for (i, sk) in miners.iter().enumerate() {
            let block_height = 5_100 + i as u64;
            let mut att = FinalityAttestation {
                miner_pubkey: sk.verifying_key().to_bytes(),
                target_height,
                target_hash,
                signature: vec![0u8; 64],
            };
            att.signature = sk.sign(&att.signing_bytes()).to_bytes().to_vec();
            let extra = extra_with_attestation(&att);
            if let OnBlockOutcome::NewlyFinalized { height, hash } =
                rf.on_accepted_block(block_height, &extra)
            {
                finalized_at = Some((height, hash));
            }
        }

        assert_eq!(
            finalized_at,
            Some((target_height, target_hash)),
            "five warmed-up miners attesting the same height should finalize it"
        );
        assert_eq!(rf.current_soft_final_height(), Some(target_height));
        // The reorg rule now fires for fork points at or below 5000.
        assert!(rf.would_reorg_violate_finality(target_height));
        assert!(rf.would_reorg_violate_finality(target_height - 1));
        assert!(!rf.would_reorg_violate_finality(target_height + 1));
    }

    #[test]
    fn no_finality_means_no_reorg_violation() {
        let rf = RollingFinality::new_default();
        // Fresh tracker: nothing is soft-final, so no reorg violates.
        assert!(!rf.would_reorg_violate_finality(0));
        assert!(!rf.would_reorg_violate_finality(1_000_000));
        assert_eq!(rf.current_soft_final_height(), None);
    }
}
