// rustc 1.95 has an ICE in the dead-code warning renderer
// (annotate_snippets OOB on certain source patterns). Until all modules
// are wired together — at which point nothing here is dead — suppress
// the warning so the compiler never tries to render it. Remove once
// `coincync-rig run` consumes every public item below.
#![allow(dead_code)]

//! # PoW hasher — the inner loop of the miner.
//!
//! The cardinal rule of writing a miner: **the validator decides what a
//! valid block hash is, the miner just searches for one.** If the two
//! ever disagree by a single byte, the miner produces shares the
//! validator rejects, and the operator can't tell why. To make that
//! impossible by construction, this module does NOT reimplement the PoW
//! recipe — it calls `coincync::consensus::compute_pow_hash` directly.
//! Same hash function, same seed schedule, same blake3 pre-hash, same
//! RandomX cache.
//!
//! ## Why a wrapper at all?
//!
//! Two reasons the wrapper earns its keep even though it's a thin call:
//!
//! 1. **Type-level miner contract.** A miner does *one* thing: `Job +
//!    nonce → Hash`. Wrapping it in a [`Hasher`] type pins that contract
//!    so we can swap the underlying PoW recipe later (consensus change,
//!    benchmark mode, hash verifier) without rewriting every caller.
//!
//! 2. **Test surface.** `compute_pow_hash` lives behind the
//!    `randomx` feature flag in the parent crate. Our wrapper's
//!    correctness test [`tests::matches_consensus_hash`] is the
//!    canonical proof that this miner produces shares the validator
//!    accepts. If that test ever fails, the miner is broken even if it
//!    compiles.

use coincync::consensus::{compute_pow_hash, PowAlgorithm};
use coincync::primitives::Hash;

/// Inputs for one PoW attempt — exactly what the validator hashes.
///
/// `anchor`, `tx_root`, and `height` are fixed for a given block
/// template. `nonce` is what we vary on every attempt.
#[derive(Clone, Debug)]
pub struct HashInput {
    pub anchor: Hash,
    pub tx_root: Hash,
    pub height: u64,
}

/// Stateless miner-side hasher — wraps the validator's hash function so
/// the miner can never disagree with the validator about whether a
/// nonce is valid. RandomX VM caching is owned by the parent crate's
/// `randomx_cache` module, so creating a `Hasher` is free.
#[derive(Clone, Copy, Debug, Default)]
pub struct Hasher;

impl Hasher {
    /// Construct a fresh hasher. There's no per-instance state today
    /// (the RandomX VM cache is global in the parent crate), but a
    /// constructor lets us add per-instance state later — e.g. when we
    /// move to per-thread VMs sharing a dataset for parallel mining
    /// (Phase 3 in the design doc).
    pub fn new() -> Self {
        Self
    }

    /// Compute the PoW hash for one (input, nonce) pair.
    ///
    /// This is the only hash function the miner ever calls. Whatever
    /// recipe `compute_pow_hash` uses — blake3 pre-hash, RandomX with
    /// epoch-keyed VM, future consensus changes — comes through here
    /// automatically.
    pub fn hash(&self, input: &HashInput, nonce: u64) -> anyhow::Result<Hash> {
        compute_pow_hash(
            PowAlgorithm::RandomX,
            &input.anchor,
            nonce,
            &input.tx_root,
            input.height,
        )
        .map_err(|e| anyhow::anyhow!("compute_pow_hash failed: {e}"))
    }

    /// Convenience: does this (input, nonce) pair satisfy the target?
    /// Mirrors `BlockHeader::meets_target` so the miner uses the same
    /// difficulty check as the validator.
    pub fn meets_target(&self, hash: &Hash, target: &Hash) -> bool {
        hash.meets_difficulty(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    /// A single representative block-template input. We assert that
    /// going through `Hasher::hash` produces byte-identical output to
    /// calling `compute_pow_hash` directly. If this ever diverges the
    /// miner is silently broken.
    #[test]
    fn matches_consensus_hash() {
        let mut bytes_anchor = [0u8; 32];
        let mut bytes_tx_root = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes_anchor);
        rand::thread_rng().fill_bytes(&mut bytes_tx_root);
        let input = HashInput {
            anchor: Hash::from_bytes(bytes_anchor),
            tx_root: Hash::from_bytes(bytes_tx_root),
            height: 1399,
        };
        let nonce = 0xdead_beef_dead_beef_u64;

        let direct = compute_pow_hash(
            PowAlgorithm::RandomX,
            &input.anchor,
            nonce,
            &input.tx_root,
            input.height,
        )
        .expect("direct compute_pow_hash should succeed in randomx-enabled build");

        let via_hasher = Hasher::new()
            .hash(&input, nonce)
            .expect("hasher::hash should succeed");

        assert_eq!(
            direct.as_bytes(),
            via_hasher.as_bytes(),
            "miner-side hash diverged from validator-side hash — \
             this means coincync-rig will produce shares the validator rejects"
        );
    }

    /// A varying-nonce smoke test — the hash must change when only the
    /// nonce changes. Catches the worst-case bug where the wrapper
    /// accidentally ignores its nonce argument.
    #[test]
    fn nonce_actually_varies_output() {
        let input = HashInput {
            anchor: Hash::from_bytes([0x11; 32]),
            tx_root: Hash::from_bytes([0x22; 32]),
            height: 1,
        };
        let h1 = Hasher::new().hash(&input, 1).unwrap();
        let h2 = Hasher::new().hash(&input, 2).unwrap();
        assert_ne!(h1.as_bytes(), h2.as_bytes(), "nonce must affect hash output");
    }
}
