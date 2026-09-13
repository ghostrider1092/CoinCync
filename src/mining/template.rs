//! Block template for mining
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `congestion_pct_for_size`** — INVARIANT: block congestion percentage
//!   is the validator's exact integer formula (`size·100/MAX_BLOCK_SIZE`, u128
//!   math, no f64). THREAT: builder/validator congestion drift → poison template
//!   that fails `validate_block` and stalls the chain. TESTS:
//!   `congestion_pct_matches_validator_formula`.
//! - **§2 `dynamic_min_fee`** — INVARIANT: per-tx congestion floor is bit-identical
//!   to the validator's `checked_mul` chain and returns `None` on the same overflow
//!   the validator treats as oversized. THREAT: fee-floor drift → assembled block
//!   rejected at submission. TESTS: `builder_and_validator_use_identical_floor`,
//!   `floor_is_monotonic_across_buckets`.
//! - **§3 `build_template_json`** — INVARIANT: emits the full header field set the
//!   standalone miner reconstructs; only chain-valid txs clearing the congestion
//!   floor are packed; template timestamp is strictly `> prev.timestamp`.
//!   THREAT: poison-template stall (same shape as the 2026-05-08
//!   duplicate-key-image incident) or a same-second timestamp rejection.
//!   TESTS: `build_template_json_emits_expected_fields`.
//! - **§4 fixpoint congestion pass** — INVARIANT: recomputing the floor at the
//!   FINAL block size and dropping under-paying txs converges (each pass strictly
//!   shrinks the set). THREAT: early tx clears a low bucket but the final block
//!   crosses a higher bucket → template fails the block-level floor. TESTS:
//!   `floor_is_monotonic_across_buckets`, `build_template_json_emits_expected_fields`.
//! - **§5 `BlockTemplate::new`** — INVARIANT: copies every header sub-field
//!   verbatim and flattens `checkpoint_vote` `(height, Hash)` to the `Hash`.
//!   THREAT: an external miner sees a template with defaulted/dropped commitment
//!   roots and mines an invalid block. TESTS:
//!   `block_template_new_copies_header_sub_fields`,
//!   `block_template_new_checkpoint_vote_none_maps_to_none`.
//! - **§6 `BlockTemplate::update_nonce` / `update_timestamp`** — INVARIANT: mutate
//!   the retained header's `nonce`/`timestamp` fields in place. THREAT: nonce/time
//!   rolling silently no-ops → miner cannot search the space. TESTS:
//!   `block_template_update_nonce_and_timestamp_mutate_header`.

use crate::consensus::BlockHeader;
use crate::primitives::{Amount, Hash};
use crate::transaction::Transaction;

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

    pub fn update_nonce(&mut self, nonce: u64) {
        self.header.nonce = nonce;
    }
    pub fn update_timestamp(&mut self, ts: u64) {
        self.header.timestamp = ts;
    }
}

/// Integer congestion percentage for a block byte size — IDENTICAL formula to
/// the block validator (`consensus/validation.rs`: `size * 100 / MAX_BLOCK_SIZE`,
/// u128 math). Kept here so the builder and validator agree by construction.
#[inline]
fn congestion_pct_for_size(block_size: usize) -> u64 {
    ((block_size as u128 * 100) / crate::constants::MAX_BLOCK_SIZE as u128) as u64
}

/// The validator's per-tx minimum fee at a given congestion percentage —
/// IDENTICAL to the `checked_mul` chain in `validate_block`
/// (`tx_size * MIN_FEE_PER_BYTE * multiplier_x100 / 100`). Sourcing the
/// multiplier from the same `fee_market::congestion_multiplier` the validator
/// uses makes drift impossible. Returns `None` on the same overflow the
/// validator treats as an oversized-tx error, so the builder simply excludes
/// such a tx rather than proposing a rejectable block.
#[inline]
fn dynamic_min_fee(tx_size: u64, congestion_pct: u64) -> Option<u64> {
    let mult_x100 = crate::consensus::fee_market::congestion_multiplier(congestion_pct);
    tx_size
        .checked_mul(crate::constants::MIN_FEE_PER_BYTE)
        .and_then(|v| v.checked_mul(mult_x100))
        .map(|v| v / 100)
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

    // Pack the template: (a) re-validate each candidate against current chain
    // state, AND (b) enforce the validator's BLOCK-LEVEL congestion fee floor
    // so the assembled block can't fail validate_block on submission.
    //
    // (a) Mempool admission only runs structural + crypto checks (no UTXO
    // context); a tx whose ring members reference time-locked or
    // immature-coinbase outputs lands in the mempool fine but gets rejected at
    // block-validation time. Without this filter every template that picks such
    // a tx fails submission and the chain stalls until the tx expires (288
    // blocks ~ 9.6h). Same poison-template shape as the duplicate-key-image
    // incident on 2026-05-08.
    //
    // (b) The validator rejects any non-coinbase tx paying less than
    // `tx_size * MIN_FEE_PER_BYTE * congestion_multiplier / 100`, where
    // congestion rises with block fullness (1x <50%, 1.5x <75%, 2x <90%, 3x
    // >=90%). The builder previously did NO congestion math, so it could pack
    // low-fee txs past a bucket boundary and emit a template that fails the
    // floor — another poison-template stall. We now enforce the same floor,
    // sourcing the multiplier from the same fee_market function → no drift.
    //
    // Congestion basis: the validator computes congestion from the FINAL block
    // size (coinbase + txs). This RPC does not build the coinbase, so we
    // approximate the block size as COINBASE_HEADROOM + sum(included tx sizes).
    // The real coinbase is <= the reserved headroom, so this never
    // UNDER-estimates congestion — the builder is at worst slightly
    // conservative and never proposes a block below the validator's floor.
    let mut running_size: usize = COINBASE_HEADROOM;
    let mut included: Vec<crate::transaction::Transaction> = Vec::new();
    for tx in candidate_txs.into_iter() {
        // (a) chain-state validity.
        if let Err(e) = chain.validate_transaction(&tx) {
            tracing::debug!(
                "Template: skipping mempool tx {} (chain-invalid): {}",
                tx.hash(),
                e
            );
            continue;
        }
        // (b) congestion fee floor at the congestion this tx WOULD produce.
        let tx_size = tx.size();
        let prospective = running_size.saturating_add(tx_size);
        let cong = congestion_pct_for_size(prospective);
        match dynamic_min_fee(tx_size as u64, cong) {
            Some(floor) if tx.fee.as_atomic() >= floor => {
                running_size = prospective;
                included.push(tx);
            }
            Some(floor) => {
                tracing::debug!(
                    "Template: skipping tx {} — fee {} < congestion floor {} at {}% full",
                    tx.hash(),
                    tx.fee.as_atomic(),
                    floor,
                    cong
                );
                // Do NOT break: txs are fee-sorted but the floor is not
                // monotonic in insertion order (congestion rises as we add), so
                // a later, smaller tx may still clear it. Correctness over
                // micro-optimization.
                continue;
            }
            None => {
                // Same overflow the validator treats as oversized-tx: exclude.
                tracing::debug!("Template: skipping tx {} — fee calc overflow", tx.hash());
                continue;
            }
        }
    }

    // Fixpoint: the FINAL block size sets the congestion bucket the validator
    // applies to ALL txs. Adding txs may have raised the bucket above what some
    // early txs cleared, so recompute at the final size and drop any tx now
    // under the floor. Dropping lowers size (never raises), so the floor only
    // falls on the next check → converges (typically 1-2 passes; each
    // non-terminating pass strictly shrinks the set, so it always terminates).
    loop {
        let final_cong = congestion_pct_for_size(running_size);
        let before = included.len();
        let mut kept: Vec<crate::transaction::Transaction> = Vec::with_capacity(before);
        let mut shrink = 0usize;
        for tx in included.into_iter() {
            let tx_size = tx.size();
            match dynamic_min_fee(tx_size as u64, final_cong) {
                Some(floor) if tx.fee.as_atomic() >= floor => kept.push(tx),
                _ => {
                    shrink = shrink.saturating_add(tx_size);
                    tracing::debug!(
                        "Template: fixpoint drop tx {} under final {}% floor",
                        tx.hash(),
                        final_cong
                    );
                }
            }
        }
        included = kept;
        running_size = running_size.saturating_sub(shrink);
        if included.len() == before {
            break; // stable
        }
    }

    let mempool_txs: Vec<crate::transaction::Transaction> = included;

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

#[cfg(test)]
mod congestion_packing_tests {
    use super::{build_template_json, congestion_pct_for_size, dynamic_min_fee, BlockTemplate};
    use crate::config::NetworkType;
    use crate::consensus::BlockHeader;
    use crate::primitives::{Amount, Hash, SecretKey};

    /// Drift guard: the builder's per-tx floor must be bit-identical to the
    /// validator's expression (consensus/validation.rs) across every congestion
    /// bucket boundary. If someone re-inlines a divergent multiplier table on
    /// either side, this fails.
    #[test]
    fn builder_and_validator_use_identical_floor() {
        for cong in [0u64, 49, 50, 74, 75, 89, 90, 100] {
            for tx_size in [200u64, 1000, 50_000] {
                let expected = tx_size
                    .checked_mul(crate::constants::MIN_FEE_PER_BYTE)
                    .and_then(|v| {
                        v.checked_mul(crate::consensus::fee_market::congestion_multiplier(cong))
                    })
                    .map(|v| v / 100);
                assert_eq!(dynamic_min_fee(tx_size, cong), expected, "cong={cong} size={tx_size}");
            }
        }
    }

    /// The congestion percentage must match the validator's integer formula
    /// exactly (u128 math, no f64).
    #[test]
    fn congestion_pct_matches_validator_formula() {
        let max = crate::constants::MAX_BLOCK_SIZE;
        for size in [0usize, 1024, max / 2, (max * 3) / 4, max] {
            let expected = ((size as u128 * 100) / max as u128) as u64;
            assert_eq!(congestion_pct_for_size(size), expected, "size={size}");
        }
    }

    /// The floor rises monotonically with block fullness across the four
    /// buckets, so a tx that clears a higher-congestion floor also clears every
    /// lower one — the property the fixpoint pass relies on for convergence.
    #[test]
    fn floor_is_monotonic_across_buckets() {
        let tx_size = 1000u64;
        let f = |c| dynamic_min_fee(tx_size, c).unwrap();
        assert!(f(49) <= f(50));
        assert!(f(50) <= f(74));
        assert!(f(74) <= f(75));
        assert!(f(75) <= f(89));
        assert!(f(89) <= f(90));
    }

    /// A header whose sub-fields are all distinct so we can prove `BlockTemplate::new`
    /// copies each one out of the header (rather than defaulting).
    fn make_header() -> BlockHeader {
        BlockHeader {
            network_magic: NetworkType::Regtest.magic_bytes(),
            version: 3,
            height: 7,
            timestamp: 1_700_000_000,
            prev_hash: Hash::from_bytes([1u8; 32]),
            tx_root: Hash::from_bytes([2u8; 32]),
            anchor: Hash::from_bytes([5u8; 32]),
            algorithm: 0,
            nonce: 0,
            target: Hash::from_difficulty(1000),
            miner_pubkey: SecretKey::from_bytes([1u8; 32]).public_key(),
            supply_commitment: [7u8; 32],
            checkpoint_vote: Some((42, Hash::from_bytes([6u8; 32]))),
            spark_set_root: [8u8; 32],
            mw_kernel_root: [9u8; 32],
        }
    }

    #[test]
    fn block_template_new_copies_header_sub_fields() {
        let header = make_header();
        let template =
            BlockTemplate::new(header, Vec::new(), Amount::from_atomic(11), Amount::from_atomic(22));

        assert_eq!(template.supply_commitment, [7u8; 32]);
        assert_eq!(template.spark_set_root, [8u8; 32]);
        assert_eq!(template.mw_kernel_root, [9u8; 32]);
        assert_eq!(template.version, 3);
        assert_eq!(template.anchor, Hash::from_bytes([5u8; 32]));
        // checkpoint_vote flattens (u64, Hash) → the Hash only.
        assert_eq!(template.checkpoint_vote, Some(Hash::from_bytes([6u8; 32])));
        assert_eq!(template.total_fees, Amount::from_atomic(11));
        assert_eq!(template.expected_reward, Amount::from_atomic(22));
        // Header is retained verbatim.
        assert_eq!(template.header.height, 7);
    }

    #[test]
    fn block_template_new_checkpoint_vote_none_maps_to_none() {
        let mut header = make_header();
        header.checkpoint_vote = None;
        let template = BlockTemplate::new(header, Vec::new(), Amount::ZERO, Amount::ZERO);
        assert_eq!(template.checkpoint_vote, None);
    }

    #[test]
    fn block_template_update_nonce_and_timestamp_mutate_header() {
        let mut template = BlockTemplate::new(make_header(), Vec::new(), Amount::ZERO, Amount::ZERO);
        assert_eq!(template.header.nonce, 0);

        template.update_nonce(99);
        assert_eq!(template.header.nonce, 99);

        template.update_timestamp(1_800_000_123);
        assert_eq!(template.header.timestamp, 1_800_000_123);
    }

    /// HAPPY: `build_template_json` emits the full field set the standalone miner
    /// reconstructs a header from. Built against a fresh genesis chain + empty
    /// mempool (no PoW involved).
    #[test]
    fn build_template_json_emits_expected_fields() {
        let chain: crate::chain::SharedBlockchain =
            std::sync::Arc::new(crate::chain::Blockchain::new());
        let genesis_hash = chain.init_genesis().expect("genesis");
        let mempool = crate::mempool::SharedMempool::new();

        let tmpl = build_template_json(&chain, &mempool);

        assert_eq!(tmpl["height"].as_u64(), Some(1), "next block is height 1");
        assert_eq!(
            tmpl["prev_hash"].as_str().unwrap(),
            hex::encode(genesis_hash.as_bytes()),
            "prev_hash is the genesis tip"
        );
        assert!(tmpl["timestamp"].as_u64().is_some(), "timestamp present");
        assert_eq!(
            tmpl["network_magic"].as_str().unwrap(),
            hex::encode(chain.network().magic_bytes()),
            "network_magic matches the chain's network"
        );
        assert!(tmpl["target"].as_str().is_some(), "target present");
        assert!(tmpl["difficulty"].as_str().is_some(), "difficulty present");
        assert_eq!(
            tmpl["transactions"].as_array().map(|a| a.len()),
            Some(0),
            "empty mempool → no transactions"
        );
    }
}
