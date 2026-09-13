//! Read-only chain query getters, extracted from `chain.rs` (issue #108).
//!
//! Every method here is a pure `&self` getter: it takes at most an
//! `inner.read()` or reads `self.db` — none acquire `apply_lock`, none mutate
//! state, none write the DB. Relocating them changes no lock scope and adds no
//! interleaving point, so consensus/observable behavior is byte-for-behavior
//! identical to the previous in-`chain.rs` definitions. As a child module of
//! `chain`, this file can read `Blockchain`'s private fields directly.

use super::*;

impl Blockchain {
    /// Get current height
    pub fn height(&self) -> u64 {
        self.inner.read().tip.height
    }

    /// Get current tip
    pub fn tip(&self) -> ChainTip {
        self.inner.read().tip.clone()
    }

    /// Number of unspent outputs currently tracked. Observability only
    /// (metrics/RPC) — not a consensus value.
    pub fn utxo_count(&self) -> usize {
        self.inner.read().utxos.output_count()
    }

    /// Look up a transaction's block height and index via the tx_index.
    pub fn get_tx_location(&self, tx_hash: &[u8]) -> Option<(u64, u32)> {
        self.db.as_ref().and_then(|db| db.get_tx_location(tx_hash))
    }

    /// Get tip hash
    pub fn tip_hash(&self) -> Hash {
        self.inner.read().tip.hash
    }

    /// Get the number of available (unspent) outputs in the UTXO set
    pub fn available_output_count(&self) -> usize {
        self.inner.read().utxos.output_count()
    }
}
