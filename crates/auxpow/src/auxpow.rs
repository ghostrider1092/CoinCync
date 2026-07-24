//! The AuxPoW proof and its commitment-chain verification.
//!
//! An [`AuxPow`] connects a child block hash to a parent block's transaction
//! Merkle root, proving that the parent miner pledged their solution to this
//! exact child block:
//!
//! ```text
//! child_hash ──aux_branch──▶ tag.merkle_root  (inside the parent coinbase)
//! coinbase   ──coinbase_branch──▶ parent_tx_merkle_root  (in the parent header)
//! ```
//!
//! This crate verifies **only that commitment chain**. It deliberately does not
//! check the parent's proof-of-work (`RandomX(seed, blob) ≤ target`) or that
//! `parent_tx_merkle_root` actually appears in a well-formed parent header —
//! both are parent-format- and RandomX-specific and belong to the consensus-
//! integration phase (see `docs/design/auxpow-governed-merge-mining.md` §6).

use borsh::{BorshDeserialize, BorshSerialize};

use crate::commitment::{AuxChainId, MergeMiningTag};
use crate::error::AuxPowError;
use crate::merkle::MerkleBranch;

/// Supplies the chain-specific hashing an AuxPoW verification needs.
///
/// Injecting these keeps the primitive direction-agnostic: the aux side uses
/// the *child* chain's node hash, while the coinbase side uses the *parent*
/// chain's tree hash and transaction hash.
pub trait CommitmentHasher {
    /// Internal-node hash for the aux (child) Merkle tree.
    fn aux_combine(&self, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32];
    /// Internal-node hash for the parent transaction Merkle tree.
    fn coinbase_combine(&self, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32];
    /// Hash of the parent coinbase transaction as a Merkle leaf.
    fn coinbase_leaf(&self, coinbase: &[u8]) -> [u8; 32];
}

/// An auxiliary proof-of-work commitment proof.
///
/// Serializable with borsh for on-the-wire / on-block transport. Field order is
/// stable; treat it as the wire format.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AuxPow {
    /// Parent-chain coinbase transaction bytes containing the merge-mining tag.
    pub parent_coinbase: Vec<u8>,
    /// Byte offset of the merge-mining tag within `parent_coinbase`.
    pub tag_offset: u32,
    /// Branch: child block hash → the tag's `merkle_root`.
    pub aux_branch: MerkleBranch,
    /// Branch: coinbase leaf → the parent block's tx Merkle root.
    pub coinbase_branch: MerkleBranch,
    /// The parent block header's transaction Merkle root (verified upstream to
    /// belong to a header whose PoW meets target — that check is Phase 2).
    pub parent_tx_merkle_root: [u8; 32],
}

impl AuxPow {
    /// Parse the merge-mining tag this proof points at.
    pub fn tag(&self) -> Result<MergeMiningTag, AuxPowError> {
        MergeMiningTag::parse(&self.parent_coinbase, self.tag_offset as usize)
    }

    /// Verify the full commitment chain binds `child_hash` to
    /// `parent_tx_merkle_root`.
    ///
    /// Steps:
    /// 1. parse the tag from the coinbase at `tag_offset`;
    /// 2. confirm the child sits at the tag's deterministic slot for `chain_id`
    ///    (anti-replay across conflicting child blocks);
    /// 3. fold `aux_branch` from `child_hash` to the tag's `merkle_root`;
    /// 4. fold `coinbase_branch` from the coinbase leaf to
    ///    `parent_tx_merkle_root`.
    pub fn verify_commitment<H: CommitmentHasher>(
        &self,
        child_hash: [u8; 32],
        chain_id: &AuxChainId,
        hasher: &H,
    ) -> Result<(), AuxPowError> {
        let tag = self.tag()?;

        // (2) anti-replay: the child must occupy the slot the tag assigns it.
        let expected = tag.expected_slot(chain_id);
        let actual = self.aux_branch.leaf_index();
        if actual != expected {
            return Err(AuxPowError::WrongMerkleSlot {
                expected,
                actual,
                nonce: tag.nonce,
                size: tag.merkle_size,
            });
        }

        // (3) child_hash is committed in the tag's Merkle root.
        let aux_root = self
            .aux_branch
            .fold(child_hash, |l, r| hasher.aux_combine(l, r))?;
        if aux_root != tag.merkle_root {
            return Err(AuxPowError::AuxBranchMismatch);
        }

        // (4) the coinbase carrying that tag is committed in the parent header.
        let coinbase_leaf = hasher.coinbase_leaf(&self.parent_coinbase);
        let coinbase_root = self
            .coinbase_branch
            .fold(coinbase_leaf, |l, r| hasher.coinbase_combine(l, r))?;
        if coinbase_root != self.parent_tx_merkle_root {
            return Err(AuxPowError::CoinbaseBranchMismatch);
        }

        Ok(())
    }
}

/// A blake3-everywhere [`CommitmentHasher`] — the reference hasher for
/// CoinCync-native trees and for tests. Real parent chains (e.g. Monero) plug
/// their own tree/tx hashing in at consensus-integration time.
#[derive(Clone, Copy, Debug, Default)]
pub struct Blake3Hasher;

impl Blake3Hasher {
    fn h2(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(left);
        h.update(right);
        *h.finalize().as_bytes()
    }
}

impl CommitmentHasher for Blake3Hasher {
    fn aux_combine(&self, l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
        Self::h2(l, r)
    }
    fn coinbase_combine(&self, l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
        Self::h2(l, r)
    }
    fn coinbase_leaf(&self, coinbase: &[u8]) -> [u8; 32] {
        *blake3::hash(coinbase).as_bytes()
    }
}
