//! Generic binary Merkle branch verification.
//!
//! A [`MerkleBranch`] proves a single leaf's membership in a binary Merkle
//! tree, *independently of the hash function*. The caller supplies the tree's
//! internal-node `combine` function, so the same branch machinery serves both
//! sides of an AuxPoW commitment:
//!
//! - the **aux** side (child block hash → merge-mining tag root), which uses
//!   the child chain's own node hash (blake3 for CoinCync), and
//! - the **coinbase** side (parent coinbase → parent tx-merkle-root), which
//!   uses the *parent* chain's node hash (e.g. Monero's tree hash).
//!
//! Keeping `combine` injected is what makes this crate direction-agnostic: no
//! chain-specific hashing is baked in.

use borsh::{BorshDeserialize, BorshSerialize};

use crate::error::AuxPowError;

/// Upper bound on a branch length. `2^32` leaves is far beyond any real Merkle
/// tree; the cap is a denial-of-service guard against a peer sending an
/// enormous branch to force unbounded hashing.
pub const MAX_BRANCH_LEN: usize = 32;

/// A Merkle inclusion branch for one leaf.
///
/// `hashes[i]` is the sibling node at level `i` (level 0 = adjacent to the
/// leaf). Bit `i` of `side_mask` records which side that sibling is on:
/// `0` = sibling on the **right** (our node is the left child at level `i`),
/// `1` = sibling on the **left** (our node is the right child).
///
/// Consequently the low `len()` bits of `side_mask` equal the leaf's index in
/// the tree — see [`MerkleBranch::leaf_index`].
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MerkleBranch {
    /// Sibling hashes, leaf-adjacent first.
    pub hashes: Vec<[u8; 32]>,
    /// Per-level side bits (see struct docs).
    pub side_mask: u32,
}

impl MerkleBranch {
    /// Number of levels in the branch (tree height).
    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// Whether the branch is empty (a single-leaf tree: leaf == root).
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// The leaf's index in the tree, derived from `side_mask`.
    ///
    /// Only the low `len()` bits are meaningful; higher bits are masked off so
    /// a caller cannot smuggle extra index bits past the branch length.
    pub fn leaf_index(&self) -> u32 {
        if self.hashes.len() >= 32 {
            self.side_mask
        } else {
            self.side_mask & ((1u32 << self.hashes.len()) - 1)
        }
    }

    /// Fold the branch from `leaf` up to the tree root using `combine`.
    ///
    /// `combine(left, right)` MUST be the tree's internal-node hash. Returns
    /// [`AuxPowError::BranchTooLong`] if the branch exceeds [`MAX_BRANCH_LEN`].
    pub fn fold<F>(&self, leaf: [u8; 32], combine: F) -> Result<[u8; 32], AuxPowError>
    where
        F: Fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
    {
        if self.hashes.len() > MAX_BRANCH_LEN {
            return Err(AuxPowError::BranchTooLong {
                len: self.hashes.len(),
                max: MAX_BRANCH_LEN,
            });
        }
        let mut acc = leaf;
        for (level, sibling) in self.hashes.iter().enumerate() {
            let sibling_on_left = (self.side_mask >> level) & 1 == 1;
            acc = if sibling_on_left {
                combine(sibling, &acc)
            } else {
                combine(&acc, sibling)
            };
        }
        Ok(acc)
    }
}

/// Build the Merkle branch for `index` and return `(branch, root)`.
///
/// `leaves.len()` must be a power of two and `index < leaves.len()`. Intended
/// for miners assembling a proof and for tests; validators only ever call
/// [`MerkleBranch::fold`].
///
/// # Panics
/// Panics if `leaves` is empty, not a power of two, or `index` is out of range
/// — these are programming errors on the proving side, not untrusted input.
pub fn build_branch<F>(leaves: &[[u8; 32]], index: usize, combine: F) -> (MerkleBranch, [u8; 32])
where
    F: Fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
{
    assert!(!leaves.is_empty(), "empty leaf set");
    assert!(leaves.len().is_power_of_two(), "leaf count must be 2^k");
    assert!(index < leaves.len(), "index out of range");

    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut idx = index;
    let mut hashes = Vec::new();
    let mut side_mask = 0u32;
    let mut lvl = 0u32;

    while level.len() > 1 {
        let sibling = idx ^ 1;
        hashes.push(level[sibling]);
        if idx & 1 == 1 {
            // our node is the right child → its sibling is on the left
            side_mask |= 1u32 << lvl;
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(combine(&pair[0], &pair[1]));
        }
        level = next;
        idx >>= 1;
        lvl += 1;
    }

    (MerkleBranch { hashes, side_mask }, level[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn combine(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(l);
        h.update(r);
        *h.finalize().as_bytes()
    }

    fn leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| {
                let mut b = [0u8; 32];
                b[0] = i as u8;
                b[1] = (i >> 8) as u8;
                b
            })
            .collect()
    }

    #[test]
    fn branch_folds_back_to_root_for_every_index() {
        for k in 0..6 {
            let n = 1usize << k;
            let ls = leaves(n);
            for idx in 0..n {
                let (branch, root) = build_branch(&ls, idx, combine);
                assert_eq!(branch.len(), k, "branch height == tree height");
                assert_eq!(branch.leaf_index(), idx as u32, "index recovered from side_mask");
                assert_eq!(branch.fold(ls[idx], combine).unwrap(), root, "fold reproduces root");
            }
        }
    }

    #[test]
    fn tampered_sibling_breaks_the_fold() {
        let ls = leaves(8);
        let (mut branch, root) = build_branch(&ls, 3, combine);
        branch.hashes[0][0] ^= 0xFF;
        assert_ne!(branch.fold(ls[3], combine).unwrap(), root);
    }

    #[test]
    fn wrong_leaf_breaks_the_fold() {
        let ls = leaves(8);
        let (branch, root) = build_branch(&ls, 3, combine);
        assert_ne!(branch.fold(ls[4], combine).unwrap(), root);
    }

    #[test]
    fn single_leaf_tree_has_empty_branch() {
        let ls = leaves(1);
        let (branch, root) = build_branch(&ls, 0, combine);
        assert!(branch.is_empty());
        assert_eq!(root, ls[0]);
        assert_eq!(branch.fold(ls[0], combine).unwrap(), ls[0]);
    }

    #[test]
    fn overlong_branch_is_rejected() {
        let branch = MerkleBranch {
            hashes: vec![[0u8; 32]; MAX_BRANCH_LEN + 1],
            side_mask: 0,
        };
        assert!(matches!(
            branch.fold([0u8; 32], combine),
            Err(AuxPowError::BranchTooLong { .. })
        ));
    }

    #[test]
    fn borsh_round_trip() {
        let ls = leaves(16);
        let (branch, _) = build_branch(&ls, 9, combine);
        let bytes = borsh::to_vec(&branch).unwrap();
        let back: MerkleBranch = borsh::from_slice(&bytes).unwrap();
        assert_eq!(branch, back);
    }
}
