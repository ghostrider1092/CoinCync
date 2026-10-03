//! Block-application helpers, extracted from `chain.rs` (issue #108).
//!
//! This is the first `add_block` decomposition slice: the cheap pre-checks that
//! run at the very top of `add_block`, before any state mutation. As a child
//! module of `chain`, it reads `Blockchain`'s private fields directly.
//!
//! **Invariant preserved:** `classify_incoming` performs only reads
//! (`inner.read()`, `self.db`) plus the orphan-event record — it mutates no
//! chain state and does NOT touch `apply_lock`. `add_block` calls it
//! synchronously *after* taking `apply_lock`, in exactly the position the inline
//! checks occupied, so the lock lifetime and the read→decide→mutate ordering are
//! unchanged. Behavior is byte-for-behavior identical to the previous inline
//! form; the existing `add_block_duplicate_*` tests are the regression oracle.

use super::*;

/// Outcome of the pre-application checks at the top of `add_block`: either an
/// early terminal status, or "proceed to validation" carrying the resolved
/// parent (`None` only for the genesis block, height 0).
pub(crate) enum IncomingClass {
    /// Block is already in the in-memory cache or the DB.
    AlreadyKnown,
    /// No parent for a non-genesis block — cannot be applied yet.
    Orphan,
    /// Ready to validate; `parent` is the resolved parent block (`None` at genesis).
    Proceed { parent: Option<Block> },
}

impl Blockchain {
    /// Pre-application classification for an incoming block: already-known
    /// (in-memory cache or DB), orphan (no parent above genesis), or ready to
    /// validate (carrying the resolved parent).
    ///
    /// Pure reads plus the orphan-event record; NO state mutation, and it does
    /// not acquire or affect `apply_lock` (the caller already holds it). This is
    /// the exact sequence that used to run inline at the top of `add_block`.
    pub(crate) fn classify_incoming(&self, block: &Block, hash: &Hash) -> Result<IncomingClass> {
        // Already known — in-memory cache.
        {
            let inner = self.inner.read();
            if inner.blocks.contains_key(hash) {
                return Ok(IncomingClass::AlreadyKnown);
            }
        }
        // Already known — persisted store.
        if let Some(ref db) = self.db {
            if db.blocks.contains(hash)? {
                return Ok(IncomingClass::AlreadyKnown);
            }
        }

        // Resolve parent; a non-genesis block with no parent is an orphan.
        let parent = self.get_block(&block.header.prev_hash);
        if parent.is_none() && block.header.height > 0 {
            self.record_event(
                ChainEventType::OrphanReceived,
                block.header.height,
                hash,
                serde_json::json!({}),
            );
            return Ok(IncomingClass::Orphan);
        }

        Ok(IncomingClass::Proceed { parent })
    }
}
