//! End-to-end commitment-chain tests: assemble a full, valid AuxPoW the way a
//! miner would, verify it, then confirm every tampered link is rejected.

use auxpow::{
    build_branch, AuxChainId, AuxPow, Blake3Hasher, CommitmentHasher, MergeMiningTag,
};

fn h(seed: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = seed;
    b[1] = 0xAB;
    b
}

/// The canonical test chain id used to place and verify the child.
fn cid() -> AuxChainId {
    AuxChainId([0x11; 32])
}

/// A different chain id (for the wrong-chain-id case).
fn cid_other() -> AuxChainId {
    AuxChainId([0x22; 32])
}

/// Build a complete, valid AuxPoW committing `child_hash`, returning the proof
/// and the tag nonce used.
fn build_valid(child_hash: [u8; 32]) -> (AuxPow, u32) {
    let hasher = Blake3Hasher;

    // --- aux tree: place child_hash at its deterministic slot ---------------
    let merkle_size = 8u32;
    let nonce = 0x1234_5678u32;
    let tag_probe = MergeMiningTag {
        merkle_root: [0u8; 32],
        merkle_size,
        nonce,
    };
    let slot = tag_probe.expected_slot(&cid()) as usize;

    let mut aux_leaves: Vec<[u8; 32]> = (0..merkle_size as u8).map(|i| h(100 + i)).collect();
    aux_leaves[slot] = child_hash;
    let (aux_branch, aux_root) =
        build_branch(&aux_leaves, slot, |l, r| hasher.aux_combine(l, r));

    // --- parent coinbase carrying the tag -----------------------------------
    let tag = MergeMiningTag {
        merkle_root: aux_root,
        merkle_size,
        nonce,
    };
    let mut parent_coinbase = vec![0xEE; 7]; // arbitrary leading coinbase bytes
    let tag_offset = parent_coinbase.len() as u32;
    parent_coinbase.extend_from_slice(&tag.encode());
    parent_coinbase.extend_from_slice(&[0x11; 9]); // trailing bytes

    // --- parent tx tree: coinbase is one leaf among several -----------------
    let coinbase_leaf = hasher.coinbase_leaf(&parent_coinbase);
    let mut tx_leaves = vec![coinbase_leaf, h(200), h(201), h(202)];
    let cb_index = 0usize;
    tx_leaves[cb_index] = coinbase_leaf;
    let (coinbase_branch, parent_tx_merkle_root) =
        build_branch(&tx_leaves, cb_index, |l, r| hasher.coinbase_combine(l, r));

    (
        AuxPow {
            parent_coinbase,
            tag_offset,
            aux_branch,
            coinbase_branch,
            parent_tx_merkle_root,
        },
        nonce,
    )
}

#[test]
fn valid_commitment_chain_verifies() {
    let child = h(42);
    let (proof, _) = build_valid(child);
    proof
        .verify_commitment(child, &cid(), &Blake3Hasher)
        .expect("a well-formed commitment chain must verify");
}

#[test]
fn wrong_child_hash_is_rejected() {
    let child = h(42);
    let (proof, _) = build_valid(child);
    // A different child hash no longer folds to the committed aux root.
    let err = proof
        .verify_commitment(h(43), &cid(), &Blake3Hasher)
        .unwrap_err();
    assert_eq!(err, auxpow::AuxPowError::AuxBranchMismatch);
}

#[test]
fn wrong_chain_id_lands_on_wrong_slot() {
    let child = h(42);
    let (proof, _) = build_valid(child);
    // Verifying under a different chain id expects a different slot.
    let err = proof
        .verify_commitment(child, &cid_other(), &Blake3Hasher)
        .unwrap_err();
    assert!(matches!(err, auxpow::AuxPowError::WrongMerkleSlot { .. }));
}

#[test]
fn tampered_coinbase_breaks_parent_binding() {
    let child = h(42);
    let (mut proof, _) = build_valid(child);
    // Flip a trailing coinbase byte (outside the tag) → coinbase leaf changes,
    // so it no longer folds to the parent tx root.
    let last = proof.parent_coinbase.len() - 1;
    proof.parent_coinbase[last] ^= 0xFF;
    let err = proof
        .verify_commitment(child, &cid(), &Blake3Hasher)
        .unwrap_err();
    assert_eq!(err, auxpow::AuxPowError::CoinbaseBranchMismatch);
}

#[test]
fn tampered_tag_root_breaks_aux_binding() {
    let child = h(42);
    let (mut proof, _) = build_valid(child);
    // Corrupt the merkle_root bytes inside the embedded tag.
    let root_start = proof.tag_offset as usize + 4;
    proof.parent_coinbase[root_start] ^= 0xFF;
    let err = proof
        .verify_commitment(child, &cid(), &Blake3Hasher)
        .unwrap_err();
    // The tag now advertises a different root than the aux branch folds to.
    assert_eq!(err, auxpow::AuxPowError::AuxBranchMismatch);
}

#[test]
fn borsh_round_trip_preserves_verification() {
    let child = h(42);
    let (proof, _) = build_valid(child);
    let bytes = borsh::to_vec(&proof).unwrap();
    let restored: AuxPow = borsh::from_slice(&bytes).unwrap();
    assert_eq!(proof, restored);
    restored
        .verify_commitment(child, &cid(), &Blake3Hasher)
        .expect("round-tripped proof still verifies");
}
