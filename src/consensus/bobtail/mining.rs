//! Miner send-side: find the local node's proof-shares.
//!
//! A Bobtail share is `RandomX(prev_hash ‖ pubkey ‖ nonce) < tau_share` — a hash
//! deliberately independent of `tx_root`, so every miner's shares are comparable
//! on the same parent and the proposer (the global minimum) alone picks the body.
//! That is a *separate* grind from block mining (whose hash binds `tx_root`), so
//! the node runs this bounded share-grind in the Observe phase and broadcasts the
//! result. Pure (the RandomX hash is injected), so it unit-tests without the VM.

use super::shares::ShareProof;
use crate::primitives::{Hash, PublicKey};

/// Grind `budget` consecutive nonces from `nonce_start` for `pubkey` against
/// `prev_hash`, returning the shares whose resolved hash is below `tau_share`
/// (worth gossiping). `hasher` resolves each candidate's RandomX hash (wired to
/// `compute_pow_hash` in the node; mocked in tests). The node broadcasts the
/// result via `broadcast_proof_shares`.
pub fn collect_shares(
    prev_hash: &Hash,
    pubkey: PublicKey,
    nonce_start: u64,
    budget: u64,
    tau_share: &Hash,
    hasher: impl Fn(&ShareProof, &Hash) -> Hash,
) -> Vec<ShareProof> {
    let mut out = Vec::new();
    for i in 0..budget {
        let share = ShareProof {
            miner_pubkey: pubkey,
            nonce: nonce_start.wrapping_add(i),
        };
        if hasher(&share, prev_hash).meets_difficulty(tau_share) {
            out.push(share);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hb(b0: u8) -> Hash {
        let mut b = [0u8; 32];
        b[0] = b0;
        Hash::from_bytes(b)
    }

    /// Mock hasher: hash's top byte = nonce, so `tau_share` top byte sets the
    /// accept cutoff. prev_hash does not affect the mock (ownership is the nonce).
    fn mock(s: &ShareProof, _prev: &Hash) -> Hash {
        hb(s.nonce as u8)
    }

    #[test]
    fn collects_only_shares_below_tau() {
        let pk = PublicKey::from_bytes([7u8; 32]);
        let tau = hb(0x10);
        // Budget 0x20 nonces from 0 → nonces 0x00..=0x10 clear (≤ 0x10), 0x11.. fail.
        let shares = collect_shares(&hb(0xAA), pk, 0, 0x20, &tau, mock);
        assert_eq!(shares.len(), 0x11, "nonces 0x00..=0x10 are below tau");
        assert!(shares
            .iter()
            .all(|s| mock(s, &hb(0xAA)).meets_difficulty(&tau)));
        assert!(shares.iter().all(|s| s.miner_pubkey == pk));
    }

    #[test]
    fn empty_when_nothing_clears() {
        let pk = PublicKey::from_bytes([1u8; 32]);
        // tau top byte 0x05, nonces start at 0x80 → all hashes 0x80.. > 0x05.
        let shares = collect_shares(&hb(0), pk, 0x80, 16, &hb(0x05), mock);
        assert!(shares.is_empty());
    }

    #[test]
    fn zero_budget_is_empty() {
        let pk = PublicKey::from_bytes([1u8; 32]);
        assert!(collect_shares(&hb(0), pk, 0, 0, &hb(0xFF), mock).is_empty());
    }
}
