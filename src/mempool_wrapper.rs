pub use crate::mempool_impl::*;

use crate::chain::{Blockchain, SharedBlockchain};
use crate::error::{Error, Result};
use crate::primitives::Hash;
use crate::transaction::Transaction;
use std::ops::{Deref, DerefMut};

const MAX_CHAIN_GENERATION_ATTEMPTS: usize = 4;

trait GenerationSource {
    fn stable_generation(&self) -> Option<u64>;
}

impl GenerationSource for Blockchain {
    fn stable_generation(&self) -> Option<u64> {
        Blockchain::stable_generation(self)
    }
}

enum AdmissionAttempt<T> {
    Retry,
    Complete(Result<T>),
}

fn retry_stable_admission<C, F, T>(chain: &C, mut attempt: F) -> Result<T>
where
    C: GenerationSource,
    F: FnMut(u64) -> AdmissionAttempt<T>,
{
    for _ in 0..MAX_CHAIN_GENERATION_ATTEMPTS {
        let Some(generation) = chain.stable_generation() else {
            std::thread::yield_now();
            continue;
        };

        match attempt(generation) {
            AdmissionAttempt::Retry => std::thread::yield_now(),
            AdmissionAttempt::Complete(result) => return result,
        }
    }

    Err(Error::InvalidState(format!(
        "chain state changed during mempool admission after {} attempts; retry submission",
        MAX_CHAIN_GENERATION_ATTEMPTS
    )))
}

/// Thread-safe mempool with generation-aware chain admission.
pub struct SharedMempool {
    inner: crate::mempool_impl::SharedMempool,
}

impl SharedMempool {
    pub fn new() -> Self {
        Self {
            inner: crate::mempool_impl::SharedMempool::new(),
        }
    }

    pub fn add_with_chain(&self, tx: Transaction, chain: &SharedBlockchain) -> Result<Hash> {
        if tx.is_coinbase() {
            return Err(Error::InvalidMessage(
                "coinbase transactions cannot enter mempool".into(),
            ));
        }
        crate::consensus::validate_transaction_basic(&tx)?;
        crate::consensus::privacy_policy::check_tx_privacy(&tx)?;

        let mut pending = Some(tx);
        retry_stable_admission(chain.as_ref(), |generation| {
            let Some(tx) = pending.as_ref() else {
                return AdmissionAttempt::Complete(Err(Error::Internal(
                    "transaction consumed before mempool admission completed".into(),
                )));
            };
            let validation = chain.validate_transaction(tx);

            // The final generation check stays under the mempool write lock so
            // a later block cleanup cannot pass before this insertion.
            let mut mempool = self.inner.write();
            if chain.stable_generation() != Some(generation) {
                return AdmissionAttempt::Retry;
            }

            if let Err(error) = validation {
                return AdmissionAttempt::Complete(Err(error));
            }

            let Some(tx) = pending.take() else {
                return AdmissionAttempt::Complete(Err(Error::Internal(
                    "transaction consumed before mempool admission completed".into(),
                )));
            };
            AdmissionAttempt::Complete(mempool.add(tx))
        })
    }

    pub fn restore_orphaned(
        &self,
        orphaned_txs: Vec<Transaction>,
        chain: &SharedBlockchain,
    ) -> usize {
        let total = orphaned_txs.len();
        let mut restored = 0;
        for tx in orphaned_txs {
            match self.add_with_chain(tx, chain) {
                Ok(_) => restored += 1,
                Err(error) => tracing::debug!(
                    "Reorg-orphaned tx not restored to mempool (likely superseded): {}",
                    error
                ),
            }
        }
        if total > 0 {
            tracing::info!(
                "Reorg: restored {}/{} orphaned tx(s) to mempool",
                restored,
                total
            );
        }
        restored
    }

    pub async fn add_with_chain_async(
        self,
        tx: Transaction,
        chain: SharedBlockchain,
    ) -> Result<Hash> {
        tokio::task::spawn_blocking(move || self.add_with_chain(tx, &chain))
            .await
            .map_err(|error| {
                Error::Internal(format!(
                    "spawn_blocking join error in add_with_chain: {error}"
                ))
            })?
    }

    pub async fn get_block_transactions_async(
        self,
        max_size: usize,
        max_count: usize,
    ) -> Vec<Transaction> {
        tokio::task::spawn_blocking(move || {
            self.inner.get_block_transactions(max_size, max_count)
        })
        .await
        .unwrap_or_default()
    }
}

impl Deref for SharedMempool {
    type Target = crate::mempool_impl::SharedMempool;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for SharedMempool {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Clone for SharedMempool {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Default for SharedMempool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        retry_stable_admission, AdmissionAttempt, GenerationSource,
        MAX_CHAIN_GENERATION_ATTEMPTS,
    };
    use crate::error::Result;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    #[derive(Default)]
    struct FakeChain {
        generation: AtomicU64,
        updating: AtomicBool,
    }

    impl GenerationSource for FakeChain {
        fn stable_generation(&self) -> Option<u64> {
            if self.updating.load(Ordering::Acquire) {
                return None;
            }
            let generation = self.generation.load(Ordering::Acquire);
            if self.updating.load(Ordering::Acquire) {
                None
            } else {
                Some(generation)
            }
        }
    }

    #[test]
    fn retries_when_generation_changes_before_commit() {
        let chain = Arc::new(FakeChain::default());
        let validation_ready = Arc::new(Barrier::new(2));
        let update_done = Arc::new(Barrier::new(2));

        let update_chain = Arc::clone(&chain);
        let update_ready = Arc::clone(&validation_ready);
        let update_complete = Arc::clone(&update_done);
        let updater = std::thread::spawn(move || {
            update_ready.wait();
            update_chain.updating.store(true, Ordering::Release);
            update_chain.generation.fetch_add(1, Ordering::AcqRel);
            update_chain.updating.store(false, Ordering::Release);
            update_complete.wait();
        });

        let attempts = AtomicUsize::new(0);
        let committed_generation = AtomicU64::new(u64::MAX);
        let result: Result<()> = retry_stable_admission(chain.as_ref(), |generation| {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                validation_ready.wait();
                update_done.wait();
            }

            if chain.stable_generation() != Some(generation) {
                return AdmissionAttempt::Retry;
            }
            committed_generation.store(generation, Ordering::SeqCst);
            AdmissionAttempt::Complete(Ok(()))
        });

        updater.join().expect("updater thread panicked");
        result.expect("admission should succeed after retry");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(committed_generation.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn generation_retries_are_bounded() {
        let chain = FakeChain::default();
        let attempts = AtomicUsize::new(0);
        let result: Result<()> = retry_stable_admission(&chain, |_generation| {
            attempts.fetch_add(1, Ordering::SeqCst);
            chain.generation.fetch_add(1, Ordering::AcqRel);
            AdmissionAttempt::Retry
        });

        assert_eq!(
            attempts.load(Ordering::SeqCst),
            MAX_CHAIN_GENERATION_ATTEMPTS
        );
        assert!(matches!(result, Err(crate::error::Error::InvalidState(_))));
    }
}
