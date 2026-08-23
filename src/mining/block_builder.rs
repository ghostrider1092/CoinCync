//! Consensus-correct candidate-block builder — shared foundation for the
//! in-node mining surfaces (Stratum, Pool).
//!
//! # Why this exists
//!
//! The node hands miners a *coinbase-less* template (see [`build_template_json`]);
//! whoever holds the payout keys must build the coinbase, compute the anchor
//! and the real transaction merkle root, and assemble the full block. The
//! canonical, known-good version of that logic previously lived only in the
//! external `coincync-rig` crate (`build_header_from_template`). This module
//! brings it into the library so the in-process Stratum/Pool servers can
//! produce blocks that the validator accepts **byte-for-byte identically** to
//! a rig-mined block — same coinbase derivation, same anchor, same tx_root.
//!
//! Every field a [`CandidateBlock`] carries must match `src/consensus/header.rs`
//! and what `validation.rs` re-derives, or the daemon rejects the block. This
//! code is deliberately a faithful port; do not "improve" it without checking
//! the validator.

use serde_json::Value;

use crate::chain::SharedBlockchain;
use crate::config::NetworkType;
use crate::consensus::fee_market::distribute_fee;
use crate::consensus::fork_signal::{encode_coinbase_extra, SignalBits};
use crate::consensus::{compute_full_anchor, BlockHeader};
use crate::crypto::{coinbase_stealth_address, BlindingFactor, PedersenCommitment};
use crate::error::{Error, Result};
use crate::mempool::SharedMempool;
use crate::mining::template::build_template_json;
use crate::primitives::{merkle_root, Amount, Hash, PublicKey};
use rand::RngCore;
use crate::transaction::{Transaction, TxOutput, TxType};

/// A full block awaiting only a valid nonce. The header's `nonce` is `0`;
/// a miner searches for a nonce such that
/// `compute_pow_hash(RandomX, header.anchor, nonce, header.tx_root, header.height)`
/// meets `header.target`, then calls [`CandidateBlock::into_block`].
#[derive(Clone, Debug)]
pub struct CandidateBlock {
    /// Header with `nonce == 0`. `anchor`, `tx_root`, `target`, `height` are
    /// exactly what the miner must hash against and what the validator checks.
    pub header: BlockHeader,
    /// `[coinbase, ...mempool_txs]` in the order the tx_root was computed over.
    pub transactions: Vec<Transaction>,
}

impl CandidateBlock {
    /// The RandomX hashing inputs a miner needs: (anchor, tx_root, height).
    /// The PoW input is `hash_concat(anchor, nonce_le, tx_root)`.
    pub fn pow_inputs(&self) -> (Hash, Hash, u64) {
        (self.header.anchor, self.header.tx_root, self.header.height)
    }

    /// Finalize into a submittable [`Block`](crate::consensus::block::Block)
    /// with the winning `nonce` set on the header.
    pub fn into_block(mut self, nonce: u64) -> crate::consensus::block::Block {
        self.header.nonce = nonce;
        crate::consensus::block::Block {
            header: self.header,
            transactions: self.transactions,
        }
    }
}

/// Submit a mined block (a [`CandidateBlock`] finalized with a winning nonce)
/// through the SAME validated path a locally-mined block takes via the
/// `submit_block` RPC: `process_block`, then keep the mempool aligned — drop
/// confirmed txs, restore any reorg-orphaned txs, advance height, and
/// shadow-evict now-invalid txs. Returns the [`BlockStatus`](crate::chain::BlockStatus)
/// so the caller can distinguish `Accepted` / `AcceptedReorg` / `Invalid`.
///
/// P2P broadcast is intentionally NOT done here: not every mining surface holds
/// a p2p handle, and a caller that has one must broadcast the accepted block
/// itself — otherwise a locally-produced block stays local and the miner forks
/// away from its peers (the same reason the `submit_block` RPC broadcasts).
pub fn submit_mined_block(
    chain: &SharedBlockchain,
    mempool: &SharedMempool,
    block: crate::consensus::block::Block,
) -> Result<crate::chain::BlockStatus> {
    use crate::chain::BlockStatus;
    let block_txs = block.transactions.clone();
    let status = chain.process_block(block)?;
    let accepted = matches!(
        status,
        BlockStatus::Accepted | BlockStatus::AcceptedFork | BlockStatus::AcceptedReorg { .. }
    );
    if accepted {
        mempool.remove_confirmed(&block_txs);
        if let BlockStatus::AcceptedReorg { ref orphaned_txs } = status {
            mempool.restore_orphaned(orphaned_txs.clone(), chain);
        }
        mempool.set_height(chain.height());
        mempool.shadow_evict_invalid(chain.as_ref());
    }
    Ok(status)
}

/// Multi-threaded nonce search for a candidate block, used by the node's
/// built-in solo miner (`--mine`). Each of `threads` OS threads scans a slice
/// of the u64 nonce space (offset by `nonce_base`) via the pipelined batch PoW,
/// returning the first nonce whose `compute_pow_hash` meets `target`. Returns
/// `None` if `stop` is set first (the caller sets it when the tip changes, so
/// the miner abandons a superseded candidate). Blocking/CPU-bound — call it
/// from `spawn_blocking`, not a bare async task.
#[cfg(feature = "randomx")]
pub fn search_nonce(
    anchor: Hash,
    tx_root: Hash,
    height: u64,
    target: Hash,
    threads: usize,
    nonce_base: u64,
    stop: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Option<u64> {
    use crate::consensus::PowAlgorithm;
    use std::sync::atomic::Ordering;

    let n = threads.max(1);
    let slice = u64::MAX / n as u64;
    let (tx, rx) = std::sync::mpsc::channel::<u64>();
    let mut handles = Vec::with_capacity(n);
    for tid in 0..n {
        let start = (tid as u64).saturating_mul(slice).wrapping_add(nonce_base);
        let end = if tid + 1 == n {
            u64::MAX
        } else {
            ((tid + 1) as u64).saturating_mul(slice)
        };
        let stop = stop.clone();
        let tx = tx.clone();
        handles.push(std::thread::spawn(move || {
            const BATCH: u64 = 8;
            let mut nonce = start;
            while !stop.load(Ordering::Relaxed) && nonce < end {
                let batch_end = nonce.saturating_add(BATCH).min(end);
                let batch: Vec<u64> = (nonce..batch_end).collect();
                if batch.is_empty() {
                    break;
                }
                if let Ok(hashes) = crate::consensus::compute_pow_hash_batch(
                    PowAlgorithm::RandomX,
                    &anchor,
                    &batch,
                    &tx_root,
                    height,
                ) {
                    for (k, h) in hashes.iter().enumerate() {
                        if h.meets_difficulty(&target) {
                            let _ = tx.send(batch[k]);
                            return;
                        }
                    }
                }
                nonce = nonce.saturating_add(batch.len() as u64);
            }
        }));
    }
    drop(tx); // so rx closes when every worker exits (all senders dropped)
    let found = rx.recv().ok();
    stop.store(true, Ordering::Relaxed); // stop the other workers
    for h in handles {
        let _ = h.join();
    }
    found
}

/// Build a consensus-correct candidate block directly from the live chain +
/// mempool, paying the coinbase to `(payout_spend_pub, payout_view_pub)`.
///
/// This is [`build_template_json`] (the coinbase-less template) followed by
/// [`build_block_from_template`], and is the entry point the in-node mining
/// servers use.
pub fn build_candidate_block(
    chain: &SharedBlockchain,
    mempool: &SharedMempool,
    payout_spend_pub: &PublicKey,
    payout_view_pub: &PublicKey,
    fallback_network: NetworkType,
    signal_bits: SignalBits,
) -> Result<CandidateBlock> {
    let template = build_template_json(chain, mempool);
    build_block_from_template(
        &template,
        payout_spend_pub,
        payout_view_pub,
        fallback_network,
        signal_bits,
    )
}

/// Build a candidate block from a coinbase-less template JSON (as produced by
/// [`build_template_json`] / the `get_block_template` RPC). Faithful port of
/// the rig's `build_header_from_template` — keep it in lock-step.
pub fn build_block_from_template(
    template: &Value,
    payout_spend_pub: &PublicKey,
    payout_view_pub: &PublicKey,
    fallback_network: NetworkType,
    signal_bits: SignalBits,
) -> Result<CandidateBlock> {
    let height = template["height"]
        .as_u64()
        .ok_or_else(|| Error::Internal("template missing 'height'".into()))?;
    let prev_hash_hex = template["prev_hash"]
        .as_str()
        .ok_or_else(|| Error::Internal("template missing 'prev_hash'".into()))?;
    let timestamp = template["timestamp"]
        .as_i64()
        .ok_or_else(|| Error::Internal("template missing 'timestamp'".into()))? as u64;

    let prev_hash = Hash::from_hex(prev_hash_hex)
        .ok_or_else(|| Error::Internal(format!("template prev_hash {prev_hash_hex} is not hex")))?;

    // Use the exact target the daemon computed (dual-window ASERT) rather
    // than re-deriving from a difficulty number.
    let target = if let Some(target_hex) = template["target"].as_str() {
        Hash::from_hex(target_hex)
            .ok_or_else(|| Error::Internal(format!("template target {target_hex} is not hex")))?
    } else {
        let difficulty_str = template["difficulty"]
            .as_str()
            .ok_or_else(|| Error::Internal("template missing both 'target' and 'difficulty'".into()))?;
        let difficulty: u64 = difficulty_str
            .parse()
            .map_err(|_| Error::Internal(format!("difficulty {difficulty_str:?} is not a u64")))?;
        Hash::from_difficulty(difficulty)
    };

    // Sequential-padding anchor — must match the validator exactly.
    let anchor_result = compute_full_anchor(&prev_hash, height, timestamp)?;

    let mempool_txs = parse_template_transactions(template);

    // Fee-burn split per Constitution Article II (congestion-aware). Must match
    // validation.rs `max_coinbase` or the daemon rejects our own block. The
    // congestion input is the FINAL block size the validator will see (issue
    // #41): a provisional coinbase sizes the block (its serialized size is
    // independent of the fee value — the amount is a fixed 8-byte field), then we
    // compute the claimable fee from that size and build the real coinbase.
    let total_fees: u64 = mempool_txs.iter().map(|tx| tx.fee.as_atomic()).sum();
    let sizing_coinbase = build_coinbase_with_fees(
        height,
        payout_spend_pub,
        payout_view_pub,
        total_fees,
        signal_bits,
    )?;
    let block_size = assembled_block_size(&sizing_coinbase, &mempool_txs);
    let claimable_fees = claimable_fees_for_block_size(height, total_fees, block_size);
    let coinbase = build_coinbase_with_fees(
        height,
        payout_spend_pub,
        payout_view_pub,
        claimable_fees,
        signal_bits,
    )?;

    // tx_root = merkle root over [coinbase, ...mempool_txs].
    let mut all_txs = Vec::with_capacity(mempool_txs.len() + 1);
    all_txs.push(coinbase);
    all_txs.extend(mempool_txs);
    let tx_hashes: Vec<Hash> = all_txs.iter().map(|tx| tx.hash()).collect();
    let tx_root = merkle_root(&tx_hashes);

    let network_magic = resolve_network_magic(template, fallback_network)?;

    let header = BlockHeader {
        network_magic,
        version: 1,
        height,
        timestamp,
        prev_hash,
        tx_root,
        anchor: anchor_result.mixed_hash,
        algorithm: anchor_result.algorithm as u8,
        nonce: 0,
        target,
        miner_pubkey: *payout_spend_pub,
        supply_commitment: [0u8; 32],
        checkpoint_vote: None,
        spark_set_root: [0u8; 32],
        mw_kernel_root: [0u8; 32],
    };

    Ok(CandidateBlock {
        header,
        transactions: all_txs,
    })
}

/// Decode the hex-encoded mempool transactions carried in the template.
fn parse_template_transactions(template: &Value) -> Vec<Transaction> {
    let mut txs = Vec::new();
    if let Some(tx_array) = template["transactions"].as_array() {
        for tx_hex_val in tx_array {
            if let Some(tx_hex) = tx_hex_val.as_str() {
                if let Ok(tx_bytes) = hex::decode(tx_hex) {
                    if let Ok(tx) = borsh::from_slice::<Transaction>(&tx_bytes) {
                        txs.push(tx);
                    }
                }
            }
        }
    }
    txs
}

/// Fee the miner may claim in the coinbase, given the **final assembled block
/// size** in bytes. Before `FEE_DISTRIBUTION_HEIGHT` the miner claims all fees;
/// at/after, a congestion-dependent portion is burned per Constitution Article II.
///
/// SECURITY (issue #41): this is the single source of truth for the split, and
/// `block_size` MUST be the same quantity the validator uses —
/// `Block::size()` = 200-byte header + Σ `tx.size()` over `[coinbase, ...mempool]`.
/// Sizing on the mempool alone (omitting the coinbase and header overhead) let a
/// candidate near `CONGESTION_THRESHOLD` compute a different miner share than the
/// validator, so the builder overclaimed and the daemon rejected its own block.
pub fn claimable_fees_for_block_size(height: u64, total_fees: u64, block_size: usize) -> u64 {
    if total_fees == 0 {
        return 0;
    }
    if height < crate::constants::FEE_DISTRIBUTION_HEIGHT {
        return total_fees;
    }
    let congestion_pct = (block_size as u128 * 100) / crate::constants::MAX_BLOCK_SIZE as u128;
    let congested = congestion_pct >= crate::constants::CONGESTION_THRESHOLD as u128;
    distribute_fee(Amount::from_atomic(total_fees), congested)
        .to_miner
        .as_atomic()
}

/// The validator's block-size formula, so the builder can size a candidate the
/// exact same way: 200-byte header + every transaction (coinbase included).
/// Mirrors `Block::size()` in `consensus/block.rs`.
fn assembled_block_size(coinbase: &Transaction, mempool_txs: &[Transaction]) -> usize {
    let tx_sizes = std::iter::once(coinbase)
        .chain(mempool_txs.iter())
        .map(|tx| tx.size())
        .fold(0usize, |acc, s| acc.saturating_add(s));
    200usize.saturating_add(tx_sizes)
}

/// Build the coinbase tx — emission reward + claimable fees, paid to a fresh
/// stealth address for (spend_pub, view_pub, output_index=0).
///
/// PRIVACY (issue #46): the ephemeral secret is drawn from the OS CSPRNG, NOT
/// derived from the public view key. A public-key-derived secret is reproducible
/// by anyone who knows the payout address, which would let an observer link every
/// coinbase output to the miner. A random secret keeps the tx public key
/// unpredictable while the recipient still detects the output by the canonical
/// ECDH scan (`is_output_ours` on `tx_public_key`), so no deterministic
/// derivation is required. The view tag is the canonical sender-side ECDH tag
/// (`generate_view_tag`), not a value derivable from the public tx key.
fn build_coinbase_with_fees(
    height: u64,
    miner_spend_pub: &PublicKey,
    miner_view_pub: &PublicKey,
    total_fees: u64,
    signal_bits: SignalBits,
) -> Result<Transaction> {
    use zeroize::Zeroize;

    let reward = crate::emission::calculate_block_reward(height);
    let total_amount = reward.as_atomic().saturating_add(total_fees);

    let commitment = PedersenCommitment::commit(total_amount, &BlindingFactor::zero());

    // Unpredictable per-coinbase ephemeral material (issue #46) — never derived
    // from the public payout keys.
    let mut miner_secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut miner_secret);
    let (stealth_addr, tx_secret) =
        coinbase_stealth_address(miner_spend_pub, miner_view_pub, height, 0, &miner_secret)
            .map_err(|e| Error::Internal(format!("coinbase_stealth_address failed: {e}")))?;
    miner_secret.zeroize();

    // Canonical sender-side ECDH view tag (matches wallet-scanner derivation);
    // computable only by the view-key holder, unlike a public-tx-key hash.
    let view_tag = crate::wallet::scanner::generate_view_tag(miner_view_pub, &tx_secret, 0);

    let output = TxOutput {
        stealth_address: stealth_addr.public_key,
        tx_public_key: stealth_addr.tx_public_key,
        encrypted_amount: total_amount.to_le_bytes().to_vec(),
        commitment: commitment.to_bytes(),
        view_tag,
        lock_height: None,
        encrypted_memo: vec![],
    };

    Ok(Transaction {
        version: 1,
        tx_type: TxType::Coinbase,
        inputs: vec![],
        outputs: vec![output],
        fee: Amount::ZERO,
        range_proof: vec![],
        extra: encode_coinbase_extra(height, signal_bits),
    })
}

/// Resolve the network magic from the template, falling back to the local
/// network. Rejects an unknown magic (a cross-network template).
fn resolve_network_magic(template: &Value, fallback_network: NetworkType) -> Result<[u8; 4]> {
    if let Some(magic_hex) = template["network_magic"].as_str() {
        let bytes = hex::decode(magic_hex)
            .map_err(|_| Error::Internal(format!("network_magic {magic_hex:?} is not hex")))?;
        if bytes.len() != 4 {
            return Err(Error::Internal(format!(
                "network_magic length: expected 4 bytes, got {}",
                bytes.len()
            )));
        }
        let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if NetworkType::from_magic_bytes(magic).is_none() {
            return Err(Error::Internal(format!(
                "unknown network_magic {} — daemon and miner on different networks",
                hex::encode(magic)
            )));
        }
        Ok(magic)
    } else {
        Ok(fallback_network.magic_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> (PublicKey, PublicKey) {
        // Deterministic throwaway payout keypair.
        let spend = crate::primitives::SecretKey::from_bytes([7u8; 32]);
        let view = crate::primitives::SecretKey::from_bytes([9u8; 32]);
        (spend.public_key(), view.public_key())
    }

    fn make_template(height: u64) -> Value {
        serde_json::json!({
            "height": height,
            "prev_hash": hex::encode([0x11u8; 32]),
            "timestamp": 1_700_000_000i64,
            "target": hex::encode(Hash::from_difficulty(1000).as_bytes()),
            "network_magic": hex::encode(NetworkType::Regtest.magic_bytes()),
            "transactions": [],
        })
    }

    #[test]
    fn candidate_is_consensus_shaped() {
        crate::consensus::bind_randomx_genesis_for_network(NetworkType::Regtest);
        let (spend, view) = test_keys();
        let height = 100u64;
        let template = make_template(height);
        let candidate = build_block_from_template(
            &template,
            &spend,
            &view,
            NetworkType::Regtest,
            SignalBits(0),
        )
        .expect("build candidate");

        // Header basics.
        assert_eq!(candidate.header.height, height);
        assert_eq!(candidate.header.nonce, 0, "candidate leaves nonce for the miner");
        assert_eq!(candidate.header.prev_hash, Hash::from_bytes([0x11u8; 32]));
        assert_eq!(candidate.header.miner_pubkey, spend);

        // Exactly one tx (coinbase) since the template had no mempool txs.
        assert_eq!(candidate.transactions.len(), 1);
        let cb = &candidate.transactions[0];
        assert_eq!(cb.tx_type, TxType::Coinbase);
        assert!(cb.inputs.is_empty());
        assert_eq!(cb.outputs.len(), 1);

        // Coinbase pays exactly the emission reward (no fees in this template).
        let expected = crate::emission::calculate_block_reward(height).as_atomic();
        let paid = u64::from_le_bytes(cb.outputs[0].encrypted_amount[..8].try_into().unwrap());
        assert_eq!(paid, expected, "coinbase amount == block reward");

        // tx_root must be the merkle root the validator recomputes.
        let expect_root = merkle_root(&[cb.hash()]);
        assert_eq!(candidate.header.tx_root, expect_root, "tx_root binds the coinbase");

        // Anchor must equal the validator's compute_full_anchor for this block.
        let anchor = compute_full_anchor(&candidate.header.prev_hash, height, candidate.header.timestamp)
            .expect("anchor");
        assert_eq!(candidate.header.anchor, anchor.mixed_hash, "anchor matches consensus");

        // Assembling with a nonce yields a block whose merkle root verifies.
        let block = candidate.into_block(42);
        assert_eq!(block.header.nonce, 42);
        assert!(block.verify_merkle_root(), "assembled block merkle root is valid");
    }

    /// End-to-end proof of the Stage-2 block-production core: build a real
    /// candidate from a live (fresh) chain, MINE a valid nonce, submit it, and
    /// assert the chain accepts it and the tip advances. This is the "the pool
    /// can actually produce a block" guarantee that the Stratum/Pool servers
    /// were missing. `#[ignore]` because it builds a RandomX cache and mines a
    /// block (~seconds); run explicitly with:
    ///   cargo test -p coincync --features "randomx testnet" --lib -- --ignored build_mine_submit_roundtrip
    #[test]
    #[ignore]
    fn build_mine_submit_roundtrip() {
        std::env::set_var("COINCYNC_RANDOMX_LIGHT_MODE", "1");
        use crate::chain::{Blockchain, BlockStatus};
        use crate::consensus::{compute_pow_hash, PowAlgorithm};
        use std::sync::Arc;

        crate::consensus::bind_randomx_genesis_for_network(NetworkType::Testnet);
        let chain: SharedBlockchain = Arc::new(Blockchain::new());
        chain.init_genesis().expect("genesis");
        let mempool = crate::mempool::SharedMempool::new();
        let (spend, view) = test_keys();

        let candidate = build_candidate_block(
            &chain,
            &mempool,
            &spend,
            &view,
            NetworkType::Testnet,
            SignalBits(0),
        )
        .expect("build candidate");
        let (anchor, tx_root, height) = candidate.pow_inputs();
        assert_eq!(height, 1, "next block is height 1");
        let target = candidate.header.target;

        // Mine a valid nonce — difficulty is at the floor on a fresh chain.
        let mut nonce = 0u64;
        let winning = loop {
            let h = compute_pow_hash(PowAlgorithm::RandomX, &anchor, nonce, &tx_root, height)
                .expect("pow hash");
            if h.meets_difficulty(&target) {
                break nonce;
            }
            nonce += 1;
            assert!(nonce < 5_000_000, "must find a nonce at floor difficulty");
        };

        let block = candidate.into_block(winning);
        let status = submit_mined_block(&chain, &mempool, block).expect("submit");
        assert!(
            matches!(status, BlockStatus::Accepted),
            "chain must accept the mined block, got {status:?}"
        );
        assert_eq!(chain.height(), 1, "tip advanced to the mined block");
    }

    /// Issue #46: a coinbase output must stay detectable by the payout wallet
    /// (canonical ECDH scan) WITHOUT its derivation being predictable from the
    /// public payout keys. Two coinbases for the same (height, keys) must have
    /// different tx public keys, and an outsider must not be able to claim them.
    #[test]
    fn coinbase_is_detectable_but_not_publicly_linkable() {
        use crate::crypto::{is_output_ours, StealthAddress};

        let spend_secret = crate::primitives::SecretKey::from_bytes([7u8; 32]);
        let view_secret = crate::primitives::SecretKey::from_bytes([9u8; 32]);
        let spend_pub = spend_secret.public_key();
        let view_pub = view_secret.public_key();
        let height = 42u64;

        let cb1 = build_coinbase_with_fees(height, &spend_pub, &view_pub, 0, SignalBits(0))
            .expect("coinbase 1");
        let cb2 = build_coinbase_with_fees(height, &spend_pub, &view_pub, 0, SignalBits(0))
            .expect("coinbase 2");
        let out1 = &cb1.outputs[0];
        let out2 = &cb2.outputs[0];

        // Detectable by the owner via the canonical ECDH scan (no miner_secret).
        let stealth1 = StealthAddress {
            public_key: out1.stealth_address,
            tx_public_key: out1.tx_public_key,
        };
        assert!(
            is_output_ours(&stealth1, &view_secret, &spend_pub, 0),
            "payout wallet must detect its own coinbase output"
        );

        // Unpredictable: two coinbases for the SAME (height, keys) differ, so the
        // derivation is not reproducible from the public payout address.
        assert_ne!(
            out1.tx_public_key.as_bytes(),
            out2.tx_public_key.as_bytes(),
            "coinbase tx pubkey must not be predictable from public keys"
        );

        // An outsider (wrong view key) cannot claim the coinbase.
        let outsider_view = crate::primitives::SecretKey::from_bytes([3u8; 32]);
        assert!(
            !is_output_ours(&stealth1, &outsider_view, &spend_pub, 0),
            "an outsider must not detect the coinbase output"
        );
    }
}
