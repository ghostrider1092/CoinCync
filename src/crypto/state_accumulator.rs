//! # Rolling state accumulator — CIP-StateRoot SPIKE (gated OFF, inert)
//!
//! An incremental, commutative commitment to the chain state: the multiset of
//! all output commitments and the multiset of all spent key images. Built as an
//! elliptic-curve multiset hash (ECMH) over Ristretto — each member maps to a
//! curve point (via the project's canonical `crypto::curve::hash_to_point`) and
//! the accumulator is their group sum, so:
//!   * **O(1) per update** — add/remove is a single point addition/subtraction;
//!   * **order-independent** — group addition is commutative, so the root
//!     depends only on the SET of changes, never their sequence or batching;
//!   * **reorg-safe** — removing an output/key-image exactly inverts adding it.
//!
//! ## Why this exists
//!
//! A per-block state root committed in the block header would let a snapshot at
//! ANY height verify against the PoW header chain — with NO hardcoded checkpoint
//! and NO trusted signer (cf. [`crate::snapshot`] and
//! [`crate::network::snapshot_fetch`]). That is the trustless endgame for
//! fast-sync: download the headers, verify PoW, check the committed state root
//! at height H against the snapshot you fetched, done.
//!
//! This module is the **PURE rule ONLY**. It is deliberately NOT wired into the
//! block header, block validation, apply, or reorg state — binding it there
//! changes the header format and is a coordinated hard fork, which is the
//! activation-gated follow-up, not this spike. It compiles in only under the
//! off-by-default `state-accumulator` feature, so production builds are
//! byte-identical and NO consensus-locked file changes — the same discipline as
//! the `fee-reservoir` and `rolling-finality` spikes.
//!
//! ## Security note (spike honesty)
//!
//! ECMH over a prime-order group (Ristretto) is collision-resistant under the
//! discrete-log assumption — the standard primitive for an incremental set
//! commitment. The empty accumulator is the identity point; two distinct
//! members cannot cancel without exhibiting a dlog relation between independent
//! hash-to-point outputs. Domain tags keep the output and key-image multisets
//! disjoint. This is a sound foundation; the header-binding fork is where it
//! earns its own dedicated review.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;

use super::curve::hash_to_point;

/// Domain tags so an output commitment and a key image (both 32 bytes) can
/// never land on the same curve point.
const OUTPUT_TAG: &[u8] = b"coincync/state-acc/output/v1/";
const KEYIMAGE_TAG: &[u8] = b"coincync/state-acc/keyimage/v1/";

/// A rolling commitment to (all output commitments, all spent key images).
///
/// Clone is cheap (two curve points + two counters). The root is a 32-byte hash
/// — the value a future header field would carry.
#[derive(Clone)]
pub struct StateAccumulator {
    outputs: RistrettoPoint,
    spent: RistrettoPoint,
    n_outputs: u64,
    n_spent: u64,
}

impl Default for StateAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl StateAccumulator {
    /// Empty state: both multisets are the group identity.
    pub fn new() -> Self {
        Self {
            outputs: RistrettoPoint::identity(),
            spent: RistrettoPoint::identity(),
            n_outputs: 0,
            n_spent: 0,
        }
    }

    fn point(tag: &[u8], member: &[u8; 32]) -> RistrettoPoint {
        let mut buf = Vec::with_capacity(tag.len() + 32);
        buf.extend_from_slice(tag);
        buf.extend_from_slice(member);
        hash_to_point(&buf)
    }

    /// Add a new output commitment (block connect, new output).
    pub fn add_output(&mut self, commitment: &[u8; 32]) {
        self.outputs += Self::point(OUTPUT_TAG, commitment);
        self.n_outputs += 1;
    }

    /// Record a spent key image (block connect, input).
    pub fn spend(&mut self, key_image: &[u8; 32]) {
        self.spent += Self::point(KEYIMAGE_TAG, key_image);
        self.n_spent += 1;
    }

    /// Invert [`add_output`](Self::add_output) (block disconnect / reorg).
    pub fn remove_output(&mut self, commitment: &[u8; 32]) {
        self.outputs -= Self::point(OUTPUT_TAG, commitment);
        self.n_outputs = self.n_outputs.saturating_sub(1);
    }

    /// Invert [`spend`](Self::spend) (block disconnect / reorg).
    pub fn unspend(&mut self, key_image: &[u8; 32]) {
        self.spent -= Self::point(KEYIMAGE_TAG, key_image);
        self.n_spent = self.n_spent.saturating_sub(1);
    }

    pub fn output_count(&self) -> u64 {
        self.n_outputs
    }

    pub fn spent_count(&self) -> u64 {
        self.n_spent
    }

    /// 32-byte state root: a domain-separated BLAKE3 over the two compressed
    /// multiset points and their counts. Binding counts as well as points means
    /// the root also fixes the cardinality, not just the set sum.
    pub fn root(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"coincync/state-acc/root/v1");
        h.update(self.outputs.compress().as_bytes());
        h.update(self.spent.compress().as_bytes());
        h.update(&self.n_outputs.to_le_bytes());
        h.update(&self.n_spent.to_le_bytes());
        *h.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn empty_root_is_deterministic() {
        assert_eq!(StateAccumulator::new().root(), StateAccumulator::new().root());
        assert_eq!(StateAccumulator::new().output_count(), 0);
        assert_eq!(StateAccumulator::new().spent_count(), 0);
    }

    #[test]
    fn order_independent() {
        let mut a = StateAccumulator::new();
        a.add_output(&m(1));
        a.add_output(&m(2));
        a.spend(&m(3));

        let mut b = StateAccumulator::new();
        b.spend(&m(3));
        b.add_output(&m(2));
        b.add_output(&m(1));

        assert_eq!(a.root(), b.root(), "ECMH must be order-independent");
        assert_eq!(a.output_count(), 2);
        assert_eq!(a.spent_count(), 1);
    }

    #[test]
    fn reorg_inverse_restores_root() {
        let base = StateAccumulator::new().root();
        let mut a = StateAccumulator::new();
        a.add_output(&m(7));
        a.spend(&m(8));
        assert_ne!(a.root(), base, "adding state must change the root");

        // Disconnect the block: exactly invert the two changes.
        a.unspend(&m(8));
        a.remove_output(&m(7));
        assert_eq!(a.root(), base, "removing must exactly invert adding (reorg-safe)");
        assert_eq!(a.output_count(), 0);
        assert_eq!(a.spent_count(), 0);
    }

    #[test]
    fn sensitive_to_membership() {
        let mut a = StateAccumulator::new();
        a.add_output(&m(1));
        let mut b = StateAccumulator::new();
        b.add_output(&m(2));
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn output_and_keyimage_domains_are_separate() {
        // The same 32 bytes treated as an output vs a key image must produce
        // different roots — a key image can never be mistaken for an output.
        let mut as_out = StateAccumulator::new();
        as_out.add_output(&m(9));
        let mut as_ki = StateAccumulator::new();
        as_ki.spend(&m(9));
        assert_ne!(as_out.root(), as_ki.root());
    }

    #[test]
    fn counts_bind_into_root() {
        // Two accumulators with the same point sum but different cardinality
        // must differ — e.g. adding the identity-preimage twice vs once is not a
        // real collision, so we check the simpler property: a duplicate add
        // changes both count and root.
        let mut once = StateAccumulator::new();
        once.add_output(&m(5));
        let mut twice = StateAccumulator::new();
        twice.add_output(&m(5));
        twice.add_output(&m(5));
        assert_ne!(once.root(), twice.root());
        assert_eq!(twice.output_count(), 2);
    }
}
