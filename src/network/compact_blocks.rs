//! Compact block relay protocol (BIP 152 inspired)
//!
//! Reduces bandwidth by sending only transaction hashes instead of full transactions.
//! Receivers reconstruct blocks from their mempool.

use crate::primitives::Hash;
use crate::transaction::Transaction;
use crate::consensus::Block;
use borsh::{BorshSerialize, BorshDeserialize};
use std::collections::HashMap;

/// Short transaction ID (6 bytes) for compact blocks
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct ShortTxId([u8; 6]);

impl ShortTxId {
    /// Create from full transaction hash and nonce
    pub fn from_tx_hash(tx_hash: &Hash, nonce: u64) -> Self {
        use sha3::{Sha3_256, Digest};

        let mut hasher = Sha3_256::new();
        hasher.update(tx_hash.as_bytes());
        hasher.update(&nonce.to_le_bytes());
        let result = hasher.finalize();

        let mut short_id = [0u8; 6];
        short_id.copy_from_slice(&result[..6]);
        ShortTxId(short_id)
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

/// Prefilled transaction in compact block
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct PrefilledTx {
    /// Index in the block
    pub index: u16,
    /// Full transaction
    pub tx: Transaction,
}

/// Compact block representation
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct CompactBlock {
    /// Block header (always included)
    pub header: crate::consensus::BlockHeader,
    /// Nonce for short ID calculation
    pub nonce: u64,
    /// Short transaction IDs
    pub short_ids: Vec<ShortTxId>,
    /// Prefilled transactions (coinbase always included)
    pub prefilled_txs: Vec<PrefilledTx>,
}

impl CompactBlock {
    /// Create compact block from full block
    pub fn from_block(block: &Block) -> Self {
        use rand::Rng;

        // SECURITY: the compact-block nonce keys the SipHash short-ID mapping.
        // A predictable nonce enables collision attacks against the short-ID
        // set. Use OsRng (direct kernel entropy) rather than thread_rng so
        // the guarantee is tied to the OS CSPRNG, not rand's ThreadRng impl.
        let mut rng = rand::rngs::OsRng;
        let nonce: u64 = rng.r#gen();
        let mut short_ids = Vec::new();
        let mut prefilled_txs = Vec::new();

        for (i, tx) in block.transactions.iter().enumerate() {
            if i > u16::MAX as usize {
                break;
            }
            if tx.is_coinbase() || i == 0 {
                // Always prefill coinbase
                prefilled_txs.push(PrefilledTx {
                    index: i as u16,
                    tx: tx.clone(),
                });
            } else {
                // Use short ID for other transactions
                short_ids.push(ShortTxId::from_tx_hash(&tx.hash(), nonce));
            }
        }

        CompactBlock {
            header: block.header.clone(),
            nonce,
            short_ids,
            prefilled_txs,
        }
    }

    /// Get block hash
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    /// Get number of transactions
    pub fn tx_count(&self) -> usize {
        self.short_ids.len() + self.prefilled_txs.len()
    }

    /// Calculate bandwidth savings compared to full block
    pub fn savings_estimate(&self, avg_tx_size: usize) -> (usize, usize, f64) {
        // Compact block size (rough estimate)
        let header_size = 200; // Header + nonce
        let short_ids_size = self.short_ids.len() * 6;
        let prefilled_size = self.prefilled_txs.len() * avg_tx_size;
        let compact_size = header_size + short_ids_size + prefilled_size;

        // Full block size estimate
        let full_size = header_size + self.tx_count() * avg_tx_size;

        let savings = if full_size > 0 {
            1.0 - (compact_size as f64 / full_size as f64)
        } else {
            0.0
        };

        (compact_size, full_size, savings)
    }
}

/// Block reconstructor from compact block + mempool
pub struct BlockReconstructor {
    /// Short ID to transaction mapping from mempool
    mempool_index: HashMap<ShortTxId, Transaction>,
    /// Nonce used for short ID calculation
    nonce: u64,
}

impl BlockReconstructor {
    /// Create reconstructor with mempool transactions
    pub fn new(mempool_txs: &[Transaction], nonce: u64) -> Self {
        let mut mempool_index = HashMap::new();

        for tx in mempool_txs {
            let short_id = ShortTxId::from_tx_hash(&tx.hash(), nonce);
            mempool_index.insert(short_id, tx.clone());
        }

        BlockReconstructor {
            mempool_index,
            nonce,
        }
    }

    /// Try to reconstruct full block from compact block
    ///
    /// Returns Ok(Block) if successful, Err(missing_indices) if transactions are missing
    pub fn reconstruct(&self, compact: &CompactBlock) -> Result<Block, Vec<usize>> {
        // FIX #23: derive the compact-block tx ceiling from the same canonical
        // constant that validate_block enforces. Previously this was an
        // independent `const MAX_COMPACT_BLOCK_TXS: usize = 10_000` that
        // could drift from `MAX_TXS_PER_BLOCK` (currently 5000). Two
        // independent limits meant the reconstructor could either reject
        // valid blocks or accept ones the validator would reject.
        // SECURITY (A5-CB-01): memory exhaustion protection — reject
        // CompactBlocks with tx counts that exceed the consensus limit.
        let max_compact_block_txs = crate::constants::MAX_TXS_PER_BLOCK;
        let total_txs = compact.tx_count();
        if total_txs > max_compact_block_txs {
            return Err(vec![]);
        }
        let mut transactions: Vec<Option<Transaction>> = vec![None; total_txs];
        let mut missing = Vec::new();

        // v1.0.12: Reject malformed compact blocks at this layer
        // instead of silently dropping bad prefills and letting the
        // error surface as a merkle-root mismatch downstream.
        //
        // Two cases that the pre-fix code silently swallowed:
        //   1. prefilled.index >= total_txs (out-of-bound slot)
        //   2. two prefills targeting the same index (silent overwrite)
        //
        // Both produce a reconstructed block whose tx-order can't
        // match the real block's merkle root, but the failure was
        // late-bound (merkle check) — confusing to operators and
        // wasting the mempool-index lookup work in the loop below.
        // Returning Err(vec![]) here matches the "unrecoverable
        // compact block" signal used for tx-count-cap violations
        // above; the caller falls back to GetData for the full block.
        let mut prefilled_indices = std::collections::HashSet::with_capacity(
            compact.prefilled_txs.len()
        );
        for prefilled in &compact.prefilled_txs {
            let idx = prefilled.index as usize;
            if idx >= total_txs {
                return Err(vec![]);
            }
            if !prefilled_indices.insert(idx) {
                return Err(vec![]); // duplicate index in prefilled set
            }
            transactions[idx] = Some(prefilled.tx.clone());
        }

        // Fill in transactions from mempool using short IDs
        let mut short_id_idx = 0;
        for i in 0..total_txs {
            if transactions[i].is_none() {
                if short_id_idx < compact.short_ids.len() {
                    let short_id = &compact.short_ids[short_id_idx];
                    if let Some(tx) = self.mempool_index.get(short_id) {
                        transactions[i] = Some(tx.clone());
                    } else {
                        missing.push(i);
                    }
                    short_id_idx += 1;
                } else {
                    missing.push(i);
                }
            }
        }

        if missing.is_empty() {
            Ok(Block {
                header: compact.header.clone(),
                transactions: transactions.into_iter().flatten().collect(),
            })
        } else {
            Err(missing)
        }
    }

    /// Add a transaction to the index (for late arrivals)
    pub fn add_transaction(&mut self, tx: Transaction) {
        let short_id = ShortTxId::from_tx_hash(&tx.hash(), self.nonce);
        self.mempool_index.insert(short_id, tx);
    }
}

/// Request for missing transactions
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct GetBlockTxsRequest {
    /// Block hash
    pub block_hash: Hash,
    /// Indices of missing transactions
    pub indices: Vec<u16>,
}

/// Response with missing transactions
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct BlockTxsResponse {
    /// Block hash
    pub block_hash: Hash,
    /// Requested transactions
    pub transactions: Vec<Transaction>,
}

/// High bandwidth mode announcement
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct SendCompactRequest {
    /// Enable high bandwidth mode
    pub high_bandwidth: bool,
    /// Protocol version
    pub version: u32,
}

/// Compact block relay state for a peer
#[derive(Clone, Debug)]
pub struct CompactBlockState {
    /// Whether peer supports compact blocks
    pub supported: bool,
    /// High bandwidth mode enabled
    pub high_bandwidth: bool,
    /// Protocol version
    pub version: u32,
    /// Pending reconstruction
    pub pending_block: Option<(Hash, CompactBlock)>,
    /// Missing transaction indices
    pub missing_txs: Vec<usize>,
}

impl Default for CompactBlockState {
    fn default() -> Self {
        CompactBlockState {
            supported: false,
            high_bandwidth: false,
            version: 1,
            pending_block: None,
            missing_txs: Vec::new(),
        }
    }
}

impl CompactBlockState {
    /// Check if we should send compact blocks to this peer
    pub fn should_send_compact(&self) -> bool {
        self.supported && self.high_bandwidth
    }

    /// Set pending reconstruction
    pub fn set_pending(&mut self, hash: Hash, compact: CompactBlock, missing: Vec<usize>) {
        self.pending_block = Some((hash, compact));
        self.missing_txs = missing;
    }

    /// Clear pending
    pub fn clear_pending(&mut self) {
        self.pending_block = None;
        self.missing_txs.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::BlockHeader;
    use crate::transaction::{TxType, TxOutput};
    use crate::primitives::{PublicKey, Amount};

    fn make_test_tx(id: u8) -> Transaction {
        Transaction {
            version: 1,
            tx_type: if id == 0 { TxType::Coinbase } else { TxType::Transfer },
            inputs: Vec::new(),
            outputs: vec![TxOutput {
                stealth_address: PublicKey::from_bytes([id; 32]),
                tx_public_key: PublicKey::from_bytes([id; 32]),
                commitment: [0u8; 32],
                encrypted_amount: vec![0u8; 8],
                view_tag: id,
                lock_height: None,
                encrypted_memo: vec![],
            }],
            fee: Amount::ZERO,
            range_proof: Vec::new(),
            extra: Vec::new(),
        }
    }

    fn make_test_block() -> Block {
        let test_magic = crate::config::NetworkType::Testnet.magic_bytes();
        Block {
            header: BlockHeader {
                network_magic: test_magic,
                version: 1,
                height: 0,
                timestamp: 0,
                prev_hash: Hash::zero(),
                tx_root: Hash::zero(),
                anchor: Hash::zero(),
                algorithm: 0,
                nonce: 0,
                target: Hash::zero(),
                miner_pubkey: PublicKey::from_bytes([0u8; 32]),
                supply_commitment: [0u8; 32],
                checkpoint_vote: None,
                spark_set_root: [0u8; 32],
                mw_kernel_root: [0u8; 32],
            },
            transactions: vec![
                make_test_tx(0), // Coinbase
                make_test_tx(1),
                make_test_tx(2),
                make_test_tx(3),
            ],
        }
    }

    #[test]
    fn test_compact_block_creation() {
        let block = make_test_block();
        let compact = CompactBlock::from_block(&block);

        // Coinbase should be prefilled
        assert_eq!(compact.prefilled_txs.len(), 1);
        assert_eq!(compact.prefilled_txs[0].index, 0);

        // Other txs should have short IDs
        assert_eq!(compact.short_ids.len(), 3);
    }

    #[test]
    fn test_block_reconstruction() {
        let block = make_test_block();
        let compact = CompactBlock::from_block(&block);

        // Create reconstructor with mempool containing all txs
        let mempool_txs: Vec<_> = block.transactions[1..].to_vec();
        let reconstructor = BlockReconstructor::new(&mempool_txs, compact.nonce);

        // Should reconstruct successfully
        let result = reconstructor.reconstruct(&compact);
        assert!(result.is_ok());

        let reconstructed = result.unwrap();
        assert_eq!(reconstructed.transactions.len(), block.transactions.len());
    }

    #[test]
    fn test_missing_transactions() {
        let block = make_test_block();
        let compact = CompactBlock::from_block(&block);

        // Empty mempool
        let reconstructor = BlockReconstructor::new(&[], compact.nonce);

        // Should fail with missing indices
        let result = reconstructor.reconstruct(&compact);
        assert!(result.is_err());

        let missing = result.unwrap_err();
        assert_eq!(missing.len(), 3); // Missing 3 non-coinbase txs
    }

    #[test]
    fn test_short_tx_id() {
        let hash1 = Hash::from_bytes([1u8; 32]);
        let hash2 = Hash::from_bytes([2u8; 32]);
        let nonce = 12345u64;

        let id1 = ShortTxId::from_tx_hash(&hash1, nonce);
        let id2 = ShortTxId::from_tx_hash(&hash2, nonce);
        let id1_again = ShortTxId::from_tx_hash(&hash1, nonce);

        assert_ne!(id1, id2);
        assert_eq!(id1, id1_again);
    }

    #[test]
    fn test_short_id_collision() {
        // Different hashes with different nonces should produce different short IDs
        let nonce = 42u64;
        let mut ids = std::collections::HashSet::new();
        for i in 0..100u8 {
            let hash = Hash::from_bytes([i; 32]);
            let id = ShortTxId::from_tx_hash(&hash, nonce);
            ids.insert(id);
        }
        // With 6-byte IDs and 100 entries, collisions are astronomically unlikely
        assert_eq!(ids.len(), 100);
    }
}
