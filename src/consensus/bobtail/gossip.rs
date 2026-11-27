//! Proof-share gossip: the parent-bound share pool + admission control.
//!
//! This is the node-side plumbing the (feature-gated, Observe-phase) P2P layer
//! calls. It admits gossiped `ShareProof`s into a pool bound to the current tip:
//! each share's PoW is verified below `tau_share` **before** relay (admission
//! control), duplicates and stale-parent shares are dropped, and the pool is
//! capped against flooding (`retain_lowest`). It never gates block validity —
//! shares are advisory until a post-audit Enforce height. Pure except for an
//! injected hasher, so it unit-tests without the RandomX VM.
//!
//! **Wiring (next increment — deliberately NOT in this slice):** register
//! `MessageType::ProofShares = PROOF_SHARES_MSG_TYPE` (+ its `TryFrom` arm) in
//! `network/protocol.rs`, OR [`CAP_BOBTAIL_SHARES`] into
//! `network/firework::local_capabilities` (so only capable peers ever receive
//! the message — old peers reject unknown types), and dispatch inbound frames to
//! [`SharePool::admit_batch`], relaying each share for which the verdict is
//! `Admit::Accepted { relay: true }`. Those are the minimal, reviewed edits to
//! the live network core; the substance — the pool and its safety rules — is here.

use super::shares::{ResolvedShare, ShareProof};
use crate::primitives::Hash;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Flare capability bit advertising that this node gossips Bobtail proof-shares.
/// Next free bit after `CAP_CHAINWORK = 1<<0` and `CAP_CONSENSUS_FINGERPRINT =
/// 1<<1`. Advertised only while the Observe phase is active; a peer without it
/// never receives the message. OR'd into `firework::local_capabilities` at wire
/// time.
pub const CAP_BOBTAIL_SHARES: u64 = 1 << 2;

/// Proposed `network::protocol::MessageType` discriminant for the proof-share
/// batch (registered in that enum + its `TryFrom` at wire time). Sits with the
/// other capability-gated Firework messages (Flare=50 … ConsensusFingerprint=52).
pub const PROOF_SHARES_MSG_TYPE: u8 = 53;

/// Hard cap on shares per gossip message, enforced on deserialize so a peer
/// cannot send an oversized batch. A node only ever needs the `K`-lowest, so a
/// generous ceiling well above the retained pool bounds a single message.
pub const MAX_SHARES_PER_MSG: usize = 256;

/// The wire payload: a batch of proof-shares for one parent tip.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ProofShareBatch {
    /// The parent (tip) these shares extend — binds the batch to one chain tip
    /// so a receiver drops shares meant for a stale/forked parent.
    pub prev_hash: Hash,
    pub shares: Vec<ShareProof>,
}

impl ProofShareBatch {
    /// Reject an empty or oversized batch before any work (wire hardening).
    pub fn is_well_formed(&self) -> bool {
        !self.shares.is_empty() && self.shares.len() <= MAX_SHARES_PER_MSG
    }
}

/// The outcome of admitting one gossiped share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admit {
    /// Admitted to the pool. `relay` is true iff the share is still within the
    /// retained cap after insertion (worth re-gossiping); false if it was
    /// immediately evicted as too high to ever enter a block.
    Accepted { relay: bool },
    /// Already held (same owner + nonce) — drop, no relay.
    Duplicate,
    /// Not for the current tip — drop, no relay (stale or forked parent).
    WrongParent,
    /// PoW is not below `tau_share` — drop, no relay (admission control).
    AboveThreshold,
}

/// A share pool bound to one chain tip. Holds the lowest `≤ cap` gossiped shares
/// for `parent`; everything else is dropped on arrival.
pub struct SharePool {
    parent: Hash,
    k: usize,
    cap: usize,
    shares: Vec<ResolvedShare>,
}

impl SharePool {
    /// New empty pool for `parent`, retaining the lowest
    /// `max_pool_size(k, c_share)` shares.
    pub fn new(parent: Hash, k: usize, c_share: u64) -> Self {
        Self {
            parent,
            k,
            cap: super::shares::max_pool_size(k, c_share),
            shares: Vec::new(),
        }
    }

    pub fn parent(&self) -> &Hash {
        &self.parent
    }
    pub fn len(&self) -> usize {
        self.shares.len()
    }
    pub fn is_empty(&self) -> bool {
        self.shares.is_empty()
    }

    /// Reset the pool to a new tip. Shares are parent-bound, so a tip change
    /// discards them all (the reorg / tip-change hardening, `bobtail-spec.md`
    /// §6.3). Returns true if the pool was cleared (i.e. the tip actually
    /// changed).
    pub fn on_tip_change(&mut self, new_parent: Hash) -> bool {
        if new_parent == self.parent {
            return false;
        }
        self.parent = new_parent;
        self.shares.clear();
        true
    }

    /// Admission control for one gossiped share. `hasher` resolves the share's
    /// RandomX hash (`|share, prev_hash| -> Hash`; wired to `compute_pow_hash` in
    /// production, mocked in tests). Order of checks is cheapest-first, and the
    /// PoW is verified **before** the share can ever be relayed. See [`Admit`].
    pub fn admit(
        &mut self,
        share: ShareProof,
        prev_hash: Hash,
        tau_share: &Hash,
        hasher: impl Fn(&ShareProof, &Hash) -> Hash,
    ) -> Admit {
        if prev_hash != self.parent {
            return Admit::WrongParent;
        }
        let ident = (*share.miner_pubkey.as_bytes(), share.nonce);
        if self.shares.iter().any(|s| s.ident() == ident) {
            return Admit::Duplicate;
        }
        let hash = hasher(&share, &prev_hash);
        if !hash.meets_difficulty(tau_share) {
            return Admit::AboveThreshold;
        }
        let rs = ResolvedShare { share, hash };
        self.shares.push(rs);
        super::shares::retain_lowest(&mut self.shares, self.cap);
        // Relay only if the share survived the cap (else it is above our floor
        // and could never enter a block — propagating it would be pure spread).
        let relay = self.shares.iter().any(|s| s.ident() == ident);
        Admit::Accepted { relay }
    }

    /// Admit a whole (well-formed) batch, returning the per-share verdict in
    /// order. Shares whose `prev_hash` ≠ the pool's tip come back `WrongParent`.
    pub fn admit_batch(
        &mut self,
        batch: &ProofShareBatch,
        tau_share: &Hash,
        hasher: impl Fn(&ShareProof, &Hash) -> Hash,
    ) -> Vec<Admit> {
        batch
            .shares
            .iter()
            .map(|s| self.admit(s.clone(), batch.prev_hash, tau_share, &hasher))
            .collect()
    }

    /// The read-only Observe snapshot for the current pool (what a Bobtail block
    /// would be right now), plus its health telemetry.
    pub fn observe(&self, target: &Hash) -> super::BobtailObservation {
        super::observe(&self.shares, target, self.k)
    }

    /// View-divergence of this node's pool against a block's claimed share set
    /// (the partial-view split early-warning, `bobtail-spec.md` §6.3.3).
    pub fn view_divergence(&self, block_set: &[ResolvedShare]) -> super::ViewDivergence {
        super::health::view_divergence(&self.shares, block_set, self.k)
    }

    /// The canonical `K`-lowest this node currently holds (what it would build).
    pub fn canonical(&self) -> Vec<ResolvedShare> {
        super::shares::canonical_k_lowest(&self.shares, self.k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::PublicKey;

    fn hb(b0: u8) -> Hash {
        let mut b = [0u8; 32];
        b[0] = b0;
        Hash::from_bytes(b)
    }
    fn pk(b: u8) -> PublicKey {
        PublicKey::from_bytes([b; 32])
    }
    fn sp(owner: u8, nonce: u64) -> ShareProof {
        ShareProof {
            miner_pubkey: pk(owner),
            nonce,
        }
    }
    /// Mock hasher: the share's hash is `nonce` in the top byte, so a test can
    /// place a share above or below `tau_share` by choosing its nonce.
    fn mock(s: &ShareProof, _prev: &Hash) -> Hash {
        hb(s.nonce as u8)
    }

    const PARENT: fn() -> Hash = || {
        let mut b = [0u8; 32];
        b[0] = 0xAA;
        Hash::from_bytes(b)
    };

    #[test]
    fn admits_a_below_threshold_share_and_relays() {
        let mut pool = SharePool::new(PARENT(), 20, 3);
        let tau = hb(0x80);
        let v = pool.admit(sp(1, 0x10), PARENT(), &tau, mock);
        assert_eq!(v, Admit::Accepted { relay: true });
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn rejects_wrong_parent() {
        let mut pool = SharePool::new(PARENT(), 20, 3);
        let v = pool.admit(sp(1, 0x10), hb(0xBB), &hb(0x80), mock);
        assert_eq!(v, Admit::WrongParent);
        assert!(pool.is_empty());
    }

    #[test]
    fn rejects_above_threshold_before_relay() {
        let mut pool = SharePool::new(PARENT(), 20, 3);
        // nonce 0x90 → hash 0x90 > tau 0x80 → not gossip-worthy.
        let v = pool.admit(sp(1, 0x90), PARENT(), &hb(0x80), mock);
        assert_eq!(v, Admit::AboveThreshold);
        assert!(pool.is_empty());
    }

    #[test]
    fn dedups_replayed_share() {
        let mut pool = SharePool::new(PARENT(), 20, 3);
        let tau = hb(0x80);
        assert_eq!(
            pool.admit(sp(1, 0x10), PARENT(), &tau, mock),
            Admit::Accepted { relay: true }
        );
        assert_eq!(
            pool.admit(sp(1, 0x10), PARENT(), &tau, mock),
            Admit::Duplicate
        );
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn caps_and_does_not_relay_an_evicted_share() {
        // k=2, c_share=1 → cap = 4*1*2 = 8.
        let mut pool = SharePool::new(PARENT(), 2, 1);
        let tau = hb(0x80);
        // 8 low shares (hashes 0x01..0x08), all accepted + relayed.
        for n in 1u64..=8 {
            assert_eq!(
                pool.admit(sp(1, n), PARENT(), &tau, mock),
                Admit::Accepted { relay: true }
            );
        }
        assert_eq!(pool.len(), 8, "at cap");
        // A 9th below threshold (0x7F) but higher than all retained → evicted,
        // so accepted-but-not-relayed, and the pool stays at the cap.
        let v = pool.admit(sp(1, 0x7F), PARENT(), &tau, mock);
        assert_eq!(v, Admit::Accepted { relay: false });
        assert_eq!(pool.len(), 8, "stays capped");
    }

    #[test]
    fn tip_change_clears_parent_bound_pool() {
        let mut pool = SharePool::new(PARENT(), 20, 3);
        pool.admit(sp(1, 0x10), PARENT(), &hb(0x80), mock);
        assert_eq!(pool.len(), 1);
        assert!(pool.on_tip_change(hb(0xCC)), "tip changed → cleared");
        assert!(pool.is_empty());
        assert_eq!(pool.parent(), &hb(0xCC));
        assert!(!pool.on_tip_change(hb(0xCC)), "same tip → no-op");
    }

    #[test]
    fn admit_batch_reports_per_share_verdicts() {
        let mut pool = SharePool::new(PARENT(), 20, 3);
        let batch = ProofShareBatch {
            prev_hash: PARENT(),
            shares: vec![sp(1, 0x05), sp(2, 0x90), sp(3, 0x06)],
        };
        assert!(batch.is_well_formed());
        let verdicts = pool.admit_batch(&batch, &hb(0x80), mock);
        assert_eq!(
            verdicts,
            vec![
                Admit::Accepted { relay: true },
                Admit::AboveThreshold,
                Admit::Accepted { relay: true },
            ],
        );
        assert_eq!(pool.len(), 2, "only the two below-threshold shares landed");
    }

    #[test]
    fn well_formed_rejects_empty_and_oversize() {
        let empty = ProofShareBatch {
            prev_hash: PARENT(),
            shares: vec![],
        };
        assert!(!empty.is_well_formed());
        let big = ProofShareBatch {
            prev_hash: PARENT(),
            shares: (0..(MAX_SHARES_PER_MSG as u64 + 1))
                .map(|n| sp(1, n))
                .collect(),
        };
        assert!(!big.is_well_formed());
    }

    #[test]
    fn observe_and_canonical_passthrough() {
        let mut pool = SharePool::new(PARENT(), 2, 3);
        let tau = hb(0x80);
        for n in 1u64..=4 {
            pool.admit(sp(n as u8, n), PARENT(), &tau, mock);
        }
        let canon = pool.canonical();
        assert_eq!(canon.len(), 2, "K-lowest of the pool");
        assert_eq!(canon[0].hash.as_bytes()[0], 0x01, "lowest first");
        // observe() reports a candidate against a lenient target.
        let obs = pool.observe(&hb(0x40));
        assert_eq!(obs.canonical_set.len(), 2);
        assert!(obs.health.is_some());
    }
}
