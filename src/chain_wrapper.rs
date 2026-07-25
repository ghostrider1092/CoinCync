pub use crate::chain_impl::*;

use crate::config::NetworkType;
use crate::consensus::Block;
use crate::db::Database;
use crate::error::{Error, Result};
use crate::primitives::{Hash, KeyImage};
use crate::transaction::Transaction;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

/// Chain state with a generation marker for concurrent mempool admission.
pub struct Blockchain {
    inner: crate::chain_impl::Blockchain,
    state_generation: AtomicU64,
    state_updates_in_progress: AtomicU32,
}

pub type SharedBlockchain = Arc<Blockchain>;

struct StateUpdate<'a> {
    chain: &'a Blockchain,
}

impl Drop for StateUpdate<'_> {
    fn drop(&mut self) {
        self.chain.state_generation.fetch_add(1, Ordering::Release);
        self.chain
            .state_updates_in_progress
            .fetch_sub(1, Ordering::Release);
    }
}

impl Blockchain {
    pub fn new() -> Self {
        Self::new_with_network(NetworkType::Testnet)
    }

    pub fn new_with_network(network: NetworkType) -> Self {
        Self::from_inner(crate::chain_impl::Blockchain::new_with_network(network))
    }

    pub fn with_database(db: Arc<Database>, network: NetworkType) -> Self {
        Self::from_inner(crate::chain_impl::Blockchain::with_database(db, network))
    }

    fn from_inner(inner: crate::chain_impl::Blockchain) -> Self {
        Self {
            inner,
            state_generation: AtomicU64::new(0),
            state_updates_in_progress: AtomicU32::new(0),
        }
    }

    fn begin_state_update(&self) -> StateUpdate<'_> {
        self.state_updates_in_progress.fetch_add(1, Ordering::AcqRel);
        StateUpdate { chain: self }
    }

    /// Return a generation only while the active chain is stable.
    pub fn stable_generation(&self) -> Option<u64> {
        if self.state_updates_in_progress.load(Ordering::Acquire) != 0 {
            return None;
        }

        let generation = self.state_generation.load(Ordering::Acquire);
        if self.state_updates_in_progress.load(Ordering::Acquire) == 0 {
            Some(generation)
        } else {
            None
        }
    }

    pub fn init_genesis(&self) -> Result<Hash> {
        let _update = self.begin_state_update();
        self.inner.init_genesis()
    }

    pub fn load_from_database(&self) -> Result<()> {
        let _update = self.begin_state_update();
        self.inner.load_from_database()
    }

    pub fn restore_state(
        &self,
        height: u64,
        tip_hash: Hash,
        total_difficulty: u128,
    ) -> Result<()> {
        let _update = self.begin_state_update();
        self.inner.restore_state(height, tip_hash, total_difficulty)
    }

    pub fn verify_tip_integrity(&self) -> Result<()> {
        let _update = self.begin_state_update();
        self.inner.verify_tip_integrity()
    }

    pub fn add_block(&self, block: Block) -> Result<BlockStatus> {
        let _update = self.begin_state_update();
        self.inner.add_block(block)
    }

    pub fn process_block(&self, block: Block) -> Result<BlockStatus> {
        let _update = self.begin_state_update();
        self.inner.process_block(block)
    }

    pub fn rollback_to_height(&self, target_height: u64) -> Result<Vec<Transaction>> {
        let _update = self.begin_state_update();
        self.inner.rollback_to_height(target_height)
    }

    pub fn validate_transaction(&self, tx: &Transaction) -> Result<()> {
        self.inner.validate_transaction(tx)
    }

    pub async fn add_block_async(self: Arc<Self>, block: Block) -> Result<BlockStatus> {
        tokio::task::spawn_blocking(move || self.add_block(block))
            .await
            .map_err(|error| {
                Error::Internal(format!("spawn_blocking join error in add_block: {error}"))
            })?
    }

    pub async fn process_block_async(self: Arc<Self>, block: Block) -> Result<BlockStatus> {
        tokio::task::spawn_blocking(move || self.process_block(block))
            .await
            .map_err(|error| {
                Error::Internal(format!("spawn_blocking join error in process_block: {error}"))
            })?
    }

    pub async fn get_block_async(self: Arc<Self>, hash: Hash) -> Option<Block> {
        tokio::task::spawn_blocking(move || self.inner.get_block(&hash))
            .await
            .unwrap_or(None)
    }

    pub async fn get_block_by_height_async(self: Arc<Self>, height: u64) -> Option<Block> {
        tokio::task::spawn_blocking(move || self.inner.get_block_by_height(height))
            .await
            .unwrap_or(None)
    }

    pub async fn validate_transaction_async(self: Arc<Self>, tx: Transaction) -> Result<()> {
        tokio::task::spawn_blocking(move || self.validate_transaction(&tx))
            .await
            .map_err(|error| {
                Error::Internal(format!(
                    "spawn_blocking join error in validate_transaction: {error}"
                ))
            })?
    }

    pub async fn is_spent_async(self: Arc<Self>, key_image: KeyImage) -> bool {
        tokio::task::spawn_blocking(move || self.inner.is_spent(&key_image))
            .await
            .unwrap_or(false)
    }
}

impl Deref for Blockchain {
    type Target = crate::chain_impl::Blockchain;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Blockchain {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Default for Blockchain {
    fn default() -> Self {
        Self::new()
    }
}
