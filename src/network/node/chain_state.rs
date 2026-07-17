use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::primitives::Hash;

/// Coherent P2P-side shadow of the chain tip (issue #249).
///
/// Height and tip move together, while `seq` rejects detached updates that
/// complete out of publication order. Sequence, rather than height, is authoritative
/// because a legitimate heavier-chain reorg may lower height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ChainShadow {
    seq: u64,
    height: u64,
    tip: Hash,
}

/// Read-only capability for consumers that need the current handshake view.
#[derive(Clone)]
pub(super) struct ChainStateReader {
    shadow: Arc<RwLock<ChainShadow>>,
}

impl ChainStateReader {
    pub(super) async fn snapshot(&self) -> (u64, Hash) {
        let shadow = self.shadow.read().await;
        (shadow.height, shadow.tip)
    }
}

pub(super) struct ChainState {
    shadow: Arc<RwLock<ChainShadow>>,
    sequence: AtomicU64,
}

impl ChainState {
    pub(super) fn new(height: u64, tip: Hash) -> Self {
        Self {
            shadow: Arc::new(RwLock::new(ChainShadow {
                seq: 0,
                height,
                tip,
            })),
            sequence: AtomicU64::new(0),
        }
    }

    pub(super) fn next_sequence(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(super) async fn update(&self, seq: u64, height: u64, tip: Hash) -> bool {
        let mut shadow = self.shadow.write().await;
        if seq <= shadow.seq {
            return false;
        }
        *shadow = ChainShadow { seq, height, tip };
        true
    }

    pub(super) fn reader(&self) -> ChainStateReader {
        ChainStateReader {
            shadow: Arc::clone(&self.shadow),
        }
    }

    pub(super) async fn height(&self) -> u64 {
        self.shadow.read().await.height
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(first_byte: u8) -> Hash {
        let mut bytes = [0u8; 32];
        bytes[0] = first_byte;
        Hash::from_bytes(bytes)
    }

    #[tokio::test]
    async fn rejects_stale_updates_and_accepts_lower_height_reorg() {
        let initial = hash(0x11);
        let newer = hash(0xBB);
        let reorg = hash(0xAA);
        let state = ChainState::new(90, initial);

        assert!(state.update(2, 100, newer).await);
        assert!(!state.update(1, 99, reorg).await);
        assert_eq!(state.reader().snapshot().await, (100, newer));

        assert!(state.update(3, 80, reorg).await);
        assert_eq!(state.reader().snapshot().await, (80, reorg));
    }
}
