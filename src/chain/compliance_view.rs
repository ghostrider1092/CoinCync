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
}
