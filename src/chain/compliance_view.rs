//! A [`ChainView`](crate::compliance::ChainView) backed by a live
//! [`Blockchain`].
//!
//! This is the auditor-side seam that turns anchored disclosure verification
//! into a decision about *this node's* canonical chain state. An
//! [`AuditPackage`](crate::compliance::AuditPackage) is only trustworthy
//! relative to a trusted view of the chain; the in-memory view in
//! `compliance.rs` exists for tools and tests, and this one resolves the same
//! queries against real UTXO / key-image state.
//!
//! Read-only: every method is a `&self` getter over existing
//! [`Blockchain`] read APIs. It acquires no locks beyond those getters and
//! mutates nothing.

use super::Blockchain;
use crate::compliance::ChainView;
use crate::crypto::{ChainAnchor, DisclosureOutputRef, KeyImage};
use crate::error::Result;
use crate::primitives::Hash;

/// A [`ChainView`] that resolves disclosure output refs and key-image
/// spentness against a live [`Blockchain`]. Cheap to construct (borrows the
/// chain), so an auditor builds one per verification.
pub struct NodeChainView<'a> {
    chain: &'a Blockchain,
}

impl<'a> NodeChainView<'a> {
    pub fn new(chain: &'a Blockchain) -> Self {
        Self { chain }
    }
}

impl ChainView for NodeChainView<'_> {
    /// Resolve an output ref to its on-chain anchor: locate the transaction
    /// (height + index in its block), fetch the block, and read the output's
    /// commitment and stealth address. Returns `Ok(None)` when the output is
    /// not on the canonical chain — including the defensive case where the tx
    /// at the indexed location does not hash to the requested `tx_hash` (index
    /// staleness across a reorg), so a mis-indexed output can never anchor a
    /// proof.
    fn anchor(&self, output_ref: &DisclosureOutputRef) -> Result<Option<ChainAnchor>> {
        let (height, tx_index) = match self.chain.get_tx_location(output_ref.tx_hash.as_bytes()) {
            Some(loc) => loc,
            None => return Ok(None),
        };
        let block = match self.chain.get_block_by_height(height) {
            Some(b) => b,
            None => return Ok(None),
        };
        let tx = match block.transactions.get(tx_index as usize) {
            Some(t) => t,
            None => return Ok(None),
        };
        // Defensive: the location index must still point at the requested tx.
        if tx.hash() != output_ref.tx_hash {
            return Ok(None);
        }
        let output = match tx.outputs.get(output_ref.output_index as usize) {
            Some(o) => o,
            None => return Ok(None),
        };
        Ok(Some(ChainAnchor::new(
            output_ref.clone(),
            output.commitment,
            *output.stealth_address.as_bytes(),
            height,
        )))
    }

    fn key_image_spent(&self, key_image: &KeyImage) -> Result<bool> {
        // The disclosure suite's KeyImage (a curve point) and the node's spent
        // set (`primitives::KeyImage`, raw bytes) are two types for the same
        // compressed 32-byte key image; bridge by bytes.
        let node_ki = crate::primitives::KeyImage::from_bytes(key_image.to_bytes());
        Ok(self.chain.is_spent(&node_ki))
    }

    /// Batched anchoring: resolve each ref's `(height, tx_index)`, then fetch
    /// each DISTINCT block once (instead of once per ref). For an anonymity set
    /// whose members cluster into a few blocks this is a large win over the
    /// per-ref default.
    fn anchor_all(
        &self,
        refs: &[DisclosureOutputRef],
    ) -> Result<Vec<Option<ChainAnchor>>> {
        use std::collections::HashMap;
        // 1) Locate each ref (indexed lookup, cheap).
        let locs: Vec<Option<(u64, u32)>> = refs
            .iter()
            .map(|r| self.chain.get_tx_location(r.tx_hash.as_bytes()))
            .collect();
        // 2) Fetch each distinct block once.
        let mut blocks: HashMap<u64, Option<crate::consensus::block::Block>> = HashMap::new();
        for (h, _) in locs.iter().flatten() {
            blocks
                .entry(*h)
                .or_insert_with(|| self.chain.get_block_by_height(*h));
        }
        // 3) Resolve each ref against its (cached) block.
        let mut out = Vec::with_capacity(refs.len());
        for (r, loc) in refs.iter().zip(&locs) {
            let anchor = match loc {
                Some((h, tx_index)) => blocks.get(h).and_then(|b| b.as_ref()).and_then(|block| {
                    let tx = block.transactions.get(*tx_index as usize)?;
                    if tx.hash() != r.tx_hash {
                        return None;
                    }
                    let output = tx.outputs.get(r.output_index as usize)?;
                    Some(ChainAnchor::new(
                        r.clone(),
                        output.commitment,
                        *output.stealth_address.as_bytes(),
                        *h,
                    ))
                }),
                None => None,
            };
            out.push(anchor);
        }
        Ok(out)
    }

    fn tip_height(&self) -> Result<u64> {
        Ok(self.chain.height())
    }

    fn block_hash_at(&self, height: u64) -> Result<Option<[u8; 32]>> {
        Ok(self.chain.get_block_hash(height).map(|h| *h.as_bytes()))
    }
}

/// Hard cap on decoys returned by [`collect_anchorable_solvency_decoys`] in one
/// call (local DoS bound; mirrors the `get_solvency_decoys` RPC's param cap).
pub const MAX_SOLVENCY_DECOYS: usize = 256;

/// How far back (in blocks) the decoy sampler scans from the tip. Bounds the
/// work per call on a long chain while still drawing from a wide recent window.
const SOLVENCY_DECOY_WINDOW: u64 = 4096;

/// A decoy output offered to hide a treasury among real on-chain outputs for an
/// unlinkable-solvency proof: a ref the auditor can anchor, plus its commitment.
#[derive(Clone, Debug)]
pub struct SolvencyDecoy {
    pub tx_hash: Hash,
    pub output_index: u8,
    pub commitment: [u8; 32],
}

/// Sample up to `count` DISTINCT, anchorable on-chain outputs to serve as
/// unlinkable-solvency decoys, plus the chain tip the proof pins to
/// (`(decoys, tip_height, tip_hash)`).
///
/// INVARIANT — the fix for the intermittent `anchored_valid:false`: every
/// returned decoy is guaranteed to resolve through the SAME lookup
/// [`NodeChainView::anchor`] uses during verification (`get_tx_location` →
/// block → tx-hash match → output bounds), with a matching commitment. Block
/// enumeration alone can surface an output the tx-location index cannot later
/// resolve — a genesis coinbase (loaded outside the `add_block` indexing path),
/// or a tx orphaned by a reorg — and handing such an output to a prover yields a
/// package that fails anchoring on a draw-dependent basis. Those outputs are
/// filtered out here so the decoy sampler and the auditor's anchor path can
/// never disagree.
///
/// `exclude` (the prover's treasury ref) is never returned, so the treasury can
/// never collide with its own decoys and shrink the caller's distinct set below
/// the requested anonymity size. Candidates are de-duplicated, over-sampled,
/// then shuffled and truncated to `count` (clamped to [`MAX_SOLVENCY_DECOYS`]).
/// When the chain genuinely holds fewer than `count` distinct anchorable
/// outputs, fewer are returned — the caller fails closed rather than padding.
pub fn collect_anchorable_solvency_decoys(
    chain: &Blockchain,
    count: usize,
    exclude: Option<(Hash, u8)>,
) -> (Vec<SolvencyDecoy>, u64, Option<Hash>) {
    let tip = chain.height();
    let tip_hash = chain.get_block_hash(tip);
    let count = count.min(MAX_SOLVENCY_DECOYS);
    if count == 0 {
        return (Vec::new(), tip, tip_hash);
    }

    let start = tip.saturating_sub(SOLVENCY_DECOY_WINDOW);
    // Over-sample the anchorable pool so the final shuffle has variety.
    let target_pool = count.saturating_mul(8).max(64);

    // Draw the pool by RESERVOIR SAMPLING (Algorithm R) over EVERY anchorable
    // output in [start, tip], so the sample is uniform across the WHOLE window
    // rather than the oldest blocks that happen to fill it first. A "stop when
    // full" scan yields an aged band of decoys, which leaves a recently-created
    // treasury as the one output outside the decoys' height range — the exact
    // opposite of unlinkable. One pass, bounded memory.
    use rand::Rng;
    let mut rng = rand::rngs::OsRng;
    let mut seen: std::collections::HashSet<(Hash, u8)> = std::collections::HashSet::new();
    let mut reservoir: Vec<SolvencyDecoy> = Vec::with_capacity(target_pool);
    let mut n_eligible: usize = 0; // eligible outputs seen so far (0-indexed stream)

    let mut h = start;
    while h <= tip {
        if let Some(block) = chain.get_block_by_height(h) {
            for (tx_pos, tx) in block.transactions.iter().enumerate() {
                let txh = tx.hash();
                // Anchorability gate — equivalent to NodeChainView::anchor, but
                // without re-fetching the block per output: the location index
                // must resolve this tx to THIS canonical position. A genesis
                // coinbase that was never indexed, or a reorg-orphaned tx,
                // resolves elsewhere or not at all and is filtered, so the
                // sampler and the auditor's anchor path can never disagree. The
                // commitment then matches by construction (same canonical output).
                let Ok(tx_pos) = u32::try_from(tx_pos) else { continue };
                if chain.get_tx_location(txh.as_bytes()) != Some((h, tx_pos)) {
                    continue;
                }
                for (idx, o) in tx.outputs.iter().enumerate() {
                    // A DisclosureOutputRef indexes outputs with a `u8`; an
                    // output beyond 255 is unrepresentable, so never offer it.
                    let oi = match u8::try_from(idx) {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                    if exclude == Some((txh, oi)) {
                        continue; // never return the prover's treasury
                    }
                    if !seen.insert((txh, oi)) {
                        continue; // de-duplicate (a tx can recur across blocks)
                    }
                    let decoy = SolvencyDecoy {
                        tx_hash: txh,
                        output_index: oi,
                        commitment: o.commitment,
                    };
                    // Algorithm R: fill the reservoir, then replace a random
                    // slot with probability target_pool / (n_eligible + 1).
                    if reservoir.len() < target_pool {
                        reservoir.push(decoy);
                    } else {
                        let j = rng.gen_range(0..=n_eligible);
                        if j < target_pool {
                            reservoir[j] = decoy;
                        }
                    }
                    n_eligible += 1;
                }
            }
        }
        h += 1;
    }

    {
        use rand::seq::SliceRandom;
        reservoir.shuffle(&mut rng);
    }
    reservoir.truncate(count);
    (reservoir, tip, tip_hash)
}
