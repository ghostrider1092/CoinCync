//! Chain-event ring-buffer methods, extracted from `chain.rs` (issue #108).
//!
//! `record_event` appends to the bounded in-memory event buffer (an
//! `inner.write()`, but never `apply_lock` — it is called from inside the
//! already-locked apply path or standalone); `get_events` is a read-only getter.
//! Moving them changes no lock scope. The `ChainEvent` / `ChainEventType` types
//! stay in `chain.rs` (they are fields of `BlockchainInner`); this child module
//! reaches them and `MAX_CHAIN_EVENTS` via `use super::*`.

use super::*;

impl Blockchain {
    /// Record a chain event in the ring buffer (bounded, lock-free for readers).
    pub(super) fn record_event(
        &self,
        event_type: ChainEventType,
        height: u64,
        hash: &Hash,
        details: serde_json::Value,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let event = ChainEvent {
            event_type,
            height,
            hash: hash.to_hex(),
            timestamp: now,
            details,
        };
        let mut inner = self.inner.write();
        if inner.events.len() >= MAX_CHAIN_EVENTS {
            inner.events.pop_front();
        }
        inner.events.push_back(event);
    }

    /// Get recent chain events (for explorer).
    pub fn get_events(&self, limit: usize) -> Vec<ChainEvent> {
        let inner = self.inner.read();
        let limit = limit.min(inner.events.len());
        inner.events.iter().rev().take(limit).cloned().collect()
    }
}
