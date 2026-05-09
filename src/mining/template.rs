//! Block template for mining

use crate::consensus::BlockHeader;
use crate::transaction::Transaction;
use crate::primitives::{Amount, Hash};

// H-5 FIX: Complete header fields for external miners
pub struct BlockTemplate {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub total_fees: Amount,
    pub expected_reward: Amount,
    pub supply_commitment: [u8; 32],
    pub spark_set_root: [u8; 32],
    pub mw_kernel_root: [u8; 32],
    pub version: u8,
    pub anchor: Hash,
    pub checkpoint_vote: Option<Hash>,
}

impl BlockTemplate {
    pub fn new(header: BlockHeader, txs: Vec<Transaction>, fees: Amount, reward: Amount) -> Self {
        let supply_commitment = header.supply_commitment;
        let spark_set_root = header.spark_set_root;
        let mw_kernel_root = header.mw_kernel_root;
        let version = header.version;
        let anchor = header.anchor;
        let checkpoint_vote = header.checkpoint_vote.map(|(_, h)| h);
        BlockTemplate {
            header,
            transactions: txs,
            total_fees: fees,
            expected_reward: reward,
            supply_commitment,
            spark_set_root,
            mw_kernel_root,
            version,
            anchor,
            checkpoint_vote,
        }
    }
    
    pub fn update_nonce(&mut self, nonce: u64) { self.header.nonce = nonce; }
    pub fn update_timestamp(&mut self, ts: u64) { self.header.timestamp = ts; }
}

/// Build the JSON template consumed by the standalone miner via RPC
/// `get_block_template`.
///
/// The miner reconstructs a `BlockHeader` from `{height, prev_hash,
/// timestamp, target}`, builds its own coinbase to its configured
/// reward address, appends the mempool transactions returned here,
/// recomputes the merkle root, and searches for a valid nonce. The
/// node never handles miner reward keys — that's why this template
/// omits the coinbase.
pub fn build_template_json(
    chain: &crate::chain::SharedBlockchain,
    mempool: &crate::mempool::SharedMempool,
) -> serde_json::Value {
    let tip = chain.tip();
    let next_height = tip.height + 1;
    let next_target = chain.next_target();
    let next_difficulty = chain.next_difficulty();

    // Reserve headroom for the miner's coinbase (this RPC does not
    // build it). Mempool returns fee-sorted, key-image-conflict-free
    // txs up to the byte budget.
    const COINBASE_HEADROOM: usize = 10 * 1024;
    let budget = crate::constants::MAX_BLOCK_SIZE.saturating_sub(COINBASE_HEADROOM);
    let candidate_txs = mempool.get_block_transactions(budget, 4096);

    // Re-validate each mempool tx against current chain state before
    // including in the template. Mempool admission only runs structural
    // + crypto checks (no UTXO context); a tx whose ring members reference
    // time-locked or immature-coinbase outputs lands in the mempool fine
    // but gets rejected at block-validation time. Without this filter
    // every block template that picks such a tx fails submission, and
    // the chain stalls until the tx expires (288 blocks ~ 9.6h). Same
    // poison-template shape as the duplicate-key-image incident on
    // 2026-05-08; this filter is the belt-and-suspenders fix at the
    // miner layer (the matching admission-side fix would shadow-evict
    // on chain.set_height when a mempool tx becomes invalid — TBD).
    let mempool_txs: Vec<crate::transaction::Transaction> = candidate_txs
        .into_iter()
        .filter(|tx| match chain.validate_transaction(tx) {
            Ok(()) => true,
            Err(e) => {
                tracing::debug!(
                    "Template: skipping mempool tx {} (chain-invalid): {}",
                    tx.hash(), e
                );
                false
            }
        })
        .collect();

    let tx_hex: Vec<String> = mempool_txs
        .iter()
        .filter_map(|tx| borsh::to_vec(tx).ok().map(hex::encode))
        .collect();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Consensus requires `timestamp > prev.timestamp` strictly. After a long
    // chain stall difficulty collapses to ~0, miners find blocks in <1s, and
    // two blocks in the same second land at `timestamp == prev.timestamp`,
    // which fails validation. Bump the template timestamp to at least
    // `prev + 1` so the miner always has a valid candidate. The miner is free
    // to roll forward (header.update_timestamp) if its local clock catches up.
    let timestamp = now.max(tip.timestamp.saturating_add(1));

    let network_magic = chain.network().magic_bytes();

    serde_json::json!({
        "height":     next_height,
        "prev_hash":  hex::encode(tip.hash.as_bytes()),
        "timestamp":  timestamp,
        "network_magic": hex::encode(network_magic),
        "target":     hex::encode(next_target.as_bytes()),
        "difficulty": next_difficulty.to_string(),
        "transactions": tx_hex,
    })
}
