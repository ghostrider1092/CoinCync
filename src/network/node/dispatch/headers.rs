//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `header_history`** — INVARIANT: walks parent hashes back at most
//!   `DIFFICULTY_LONG_WINDOW` blocks and errors on a missing ancestor rather
//!   than silently truncating.
//!   THREAT: an unbounded or silently-short ancestor walk feeds a wrong
//!   difficulty window into validation, letting forged targets slip through.
//!   TESTS: `accepts_connected_header_with_valid_pow`,
//!   `rejects_header_without_known_parent`.
//! - **§2 `validate_header_batch` (magic / sequencing / contiguity)** —
//!   INVARIANT: every header must match the chain's network magic, connect to
//!   a known parent, increment height by exactly one, and chain
//!   `prev_hash`-to-hash contiguously within the batch.
//!   THREAT: cross-network replay or a disjoint/forked batch being accepted
//!   as a valid extension of the chain.
//!   TESTS: `rejects_non_contiguous_header_batch`,
//!   `rejects_header_without_known_parent`.
//! - **§3 `validate_header_batch` (version / timestamp / MTP)** — INVARIANT:
//!   header version never regresses below the height-activation floor or the
//!   parent's version; timestamp strictly advances past the parent and, once
//!   `MTP_WINDOW` history exists, past the median-time-past.
//!   THREAT: timestamp manipulation to bias difficulty retargeting or
//!   replay stale headers.
//!   TESTS: (gap — no dedicated unit test exercises the version/MTP branches
//!   directly; only covered incidentally via the accept/reject paths above).
//! - **§4 `validate_header_batch` (checkpoint + difficulty target)** —
//!   INVARIANT: a hardcoded checkpoint mismatch rejects the header outright;
//!   otherwise the header's `target` must equal the chain's own
//!   `expected_next_target` for that history (single-sourced, not
//!   recomputed ad hoc).
//!   THREAT: a peer claiming an easier-than-valid target once difficulty is
//!   active, or a checkpoint-violating alternate history.
//!   TESTS: `rejects_self_declared_easy_target_after_difficulty_activates`.
//! - **§5 `validate_header_batch` (proof-of-work)** — INVARIANT: `verify_pow`
//!   must succeed against the header's bound anchor/nonce/tx_root/target
//!   before a header is accepted into `hashes`. Headers the chain already
//!   holds skip the check and are left out of the result.
//!   THREAT: a structurally-valid header with forged or missing PoW being
//!   queued for sync.
//!   TESTS: `accepts_connected_header_with_valid_pow`,
//!   `headers_already_in_the_chain_are_not_returned`.
//! - **§6 `handle_get_headers`** — INVARIANT: oversized `GetHeaders` payloads
//!   are dropped and scored before parsing; the response is bounded to
//!   `MAX_HEADERS_RESPONSE` headers starting from the first locator match.
//!   THREAT: a giant or unbounded GetHeaders request driving unbounded disk
//!   reads or an oversized response.
//!   TESTS: (gap — no dedicated unit test for `handle_get_headers` in this
//!   file; only its sibling `handle_headers` inbound path is unit-tested).
//! - **§7 `handle_headers` (nonce validation)** — INVARIANT: an inbound
//!   `Headers` response is honored only for the peer it was issued to, and a
//!   nonce is consumed on first (even empty) use, never on a cross-peer or
//!   replayed attempt.
//!   THREAT: eclipse-style cross-peer nonce spoofing or nonce replay
//!   poisoning `ChainSync` state.
//!   TESTS: `handle_headers_cross_peer_nonce_is_rejected_without_consuming`,
//!   `handle_headers_valid_nonce_is_single_use`,
//!   `handle_headers_unsolicited_nonce_zero_is_ignored`.
//! - **§8 `handle_headers` (deserialization + batch-reject scoring)** —
//!   INVARIANT: malformed borsh and rejected header batches both score the
//!   peer via `record_misbehavior` with the classified offense, and a
//!   rejected batch never reaches `queue_headers_from_peer`.
//!   THREAT: unscored garbage or invalid-header spam from a misbehaving peer.
//!   TESTS: `handle_headers_borsh_garbage_scores_protocol_violation`.
//! - **§9 `handle_headers` (off-lock batch verification)** — INVARIANT: the
//!   `ChainSync` write lock is released while `validate_header_batch` runs;
//!   `begin_headers_validation` / `end_headers_validation` bracket the call so
//!   `headers_request_pending()` stays true and no second GetHeaders goes out.
//!   THREAT: holding the lock across ~2000 RandomX header checks froze the
//!   sync driver for the whole batch; the ticks it missed then fired as a
//!   burst and tripped the 60-tick no-progress watchdog, forcing a Headers
//!   re-fetch (and a full re-verification) after every ~100 blocks.
//!   TESTS: `handle_headers_rejected_batch_clears_validation_flag`,
//!   `handle_headers_valid_batch_queues_and_clears_validation_flag`.

use std::collections::{HashMap, HashSet};

use dashmap::DashMap;
use rayon::prelude::*;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, warn};

use crate::chain::SharedBlockchain;
use crate::consensus::{verify_pow, BlockHeader, DifficultyBlock};
use crate::error::Result;
use crate::network::peer::{PeerId, PeerInfo};
use crate::network::protocol::{GetHeadersMessage, Message, MAX_HEADERS_RESPONSE};
use crate::network::scoring::{MisbehaviorType, PeerScorer};
use crate::network::sync::ChainSync;
use crate::primitives::Hash;

use super::super::broadcast::send_to_peer;
use super::chain::same_pow_epoch;

fn header_history(
    chain: &SharedBlockchain,
    accepted: &HashMap<Hash, BlockHeader>,
    parent_hash: Hash,
) -> std::result::Result<Vec<DifficultyBlock>, String> {
    let difficulty_window = crate::constants::DIFFICULTY_LONG_WINDOW as usize;
    let mut history = Vec::with_capacity(difficulty_window);
    let mut cursor = parent_hash;

    for _ in 0..difficulty_window {
        let header = if let Some(header) = accepted.get(&cursor) {
            header.clone()
        } else if let Some(block) = chain.get_block(&cursor) {
            block.header
        } else {
            return Err(format!("missing ancestor {}", cursor.to_hex()));
        };

        history.push(DifficultyBlock {
            height: header.height,
            timestamp: header.timestamp,
            target: header.target,
        });

        if header.height == 0 {
            break;
        }
        cursor = header.prev_hash;
    }

    history.reverse();
    Ok(history)
}

#[derive(Debug)]
struct HeaderBatchError {
    index: usize,
    reason: String,
    offense: MisbehaviorType,
}

fn validate_header_batch(
    chain: &SharedBlockchain,
    known: &HashSet<Hash>,
    headers: &[BlockHeader],
) -> std::result::Result<Vec<Hash>, HeaderBatchError> {
    let expected_magic = chain.network().magic_bytes();
    let mut accepted = HashMap::with_capacity(headers.len());
    let mut hashes = Vec::with_capacity(headers.len());
    let mut unverified = Vec::with_capacity(headers.len());
    let mut held = Vec::with_capacity(headers.len());

    for (index, header) in headers.iter().enumerate() {
        let reject = |reason: String, offense| HeaderBatchError {
            index,
            reason,
            offense,
        };

        if header.network_magic != expected_magic {
            return Err(reject(
                "wrong network magic".into(),
                MisbehaviorType::WrongNetwork,
            ));
        }

        let parent = if index == 0 {
            chain
                .get_block(&header.prev_hash)
                .map(|block| block.header)
                .ok_or_else(|| {
                    reject(
                        "first header does not connect to a known block".into(),
                        MisbehaviorType::ProtocolViolation,
                    )
                })?
        } else {
            let previous = &headers[index - 1];
            if header.prev_hash != hashes[index - 1] {
                return Err(reject(
                    "header batch is not contiguous".into(),
                    MisbehaviorType::ProtocolViolation,
                ));
            }
            previous.clone()
        };

        let expected_height = parent.height.checked_add(1).ok_or_else(|| {
            reject(
                "parent height overflows u64".into(),
                MisbehaviorType::ProtocolViolation,
            )
        })?;
        if header.height != expected_height {
            return Err(reject(
                format!(
                    "non-sequential height: expected {}, got {}",
                    expected_height, header.height
                ),
                MisbehaviorType::ProtocolViolation,
            ));
        }
        if header.version < crate::constants::block_version_at_height(header.height)
            || header.version < parent.version
        {
            return Err(reject(
                "invalid header version".into(),
                MisbehaviorType::ProtocolViolation,
            ));
        }
        if header.timestamp <= parent.timestamp {
            return Err(reject(
                "timestamp does not advance".into(),
                MisbehaviorType::ProtocolViolation,
            ));
        }
        if header
            .checkpoint_vote
            .as_ref()
            .is_some_and(|(height, _)| *height >= header.height)
        {
            return Err(reject(
                "checkpoint vote references a future height".into(),
                MisbehaviorType::ProtocolViolation,
            ));
        }

        let checkpoint_match = match chain.network() {
            crate::config::NetworkType::Mainnet => {
                crate::mainnet::verify_checkpoint(header.height, &header.hash())
            }
            crate::config::NetworkType::Testnet | crate::config::NetworkType::Regtest => {
                crate::testnet::verify_checkpoint(header.height, &header.hash())
            }
        };
        if checkpoint_match == Some(false) {
            return Err(reject(
                "hardcoded checkpoint mismatch".into(),
                MisbehaviorType::InvalidBlockPoW,
            ));
        }

        let history = header_history(chain, &accepted, header.prev_hash)
            .map_err(|reason| reject(reason, MisbehaviorType::ProtocolViolation))?;

        if history.len() >= crate::constants::MTP_WINDOW {
            let mut timestamps: Vec<u64> = history
                .iter()
                .rev()
                .take(crate::constants::MTP_WINDOW)
                .map(|block| block.timestamp)
                .collect();
            timestamps.sort_unstable();
            let median = timestamps[timestamps.len() / 2];
            if header.timestamp <= median {
                return Err(reject(
                    "timestamp does not exceed median-time-past".into(),
                    MisbehaviorType::ProtocolViolation,
                ));
            }
        }

        if history.len() >= 2 {
            // Single-source the difficulty rule via the chain's network-aware
            // computation (identical to `calculate_difficulty` on mainnet/testnet,
            // but honors the regtest pin/ease). Calling `calculate_difficulty`
            // directly here diverged from the miner + block validator on regtest
            // and rejected every peer header, wedging regtest multi-node sync.
            let expected_target = chain.expected_next_target(&history, header.height);
            if header.target != expected_target {
                return Err(reject(
                    format!(
                        "difficulty target mismatch: expected {}, got {}",
                        expected_target.to_hex(),
                        header.target.to_hex()
                    ),
                    MisbehaviorType::InvalidBlockPoW,
                ));
            }
        }

        let hash = header.hash();
        // A hash that is already queued for download came through this same
        // validation, and a hash the chain holds was verified when the block
        // was applied. Neither needs its RandomX hash again. Every reconnect,
        // tip refresh and watchdog round re-sends the range we are already
        // downloading, and hashing 2000 headers costs 25-45 s of one core.
        let in_chain = chain.get_block_hash(header.height) == Some(hash);
        if !known.contains(&hash) && !in_chain {
            unverified.push(index);
        }
        held.push(in_chain);
        accepted.insert(hash, header.clone());
        hashes.push(hash);
    }

    // RandomX is the expensive part, 10-25 ms per header in light mode. The
    // headers are independent once the batch is linked, so hash them on all
    // cores and report the lowest failing index, as the loop above would.
    // One epoch at a time, though: the dataset cache holds a single key and
    // rebuilds on a mismatch (0.3 s in light mode, 23 s with the full
    // dataset), so a batch that straddles a 2048-block boundary with both
    // keys live on different threads rebuilt it on nearly every hash.
    for group in epoch_groups(headers, &unverified) {
        let failure = group
            .par_iter()
            .filter_map(|&index| {
                let header = &headers[index];
                verify_pow(
                    &header.prev_hash,
                    header.height,
                    header.timestamp,
                    header.nonce,
                    &header.tx_root,
                    &header.target,
                    &header.anchor,
                    header.algorithm,
                    &header.pow_binding(),
                )
                .err()
                .map(|error| (index, error.to_string()))
            })
            .min_by_key(|(index, _)| *index);
        if let Some((index, reason)) = failure {
            return Err(HeaderBatchError {
                index,
                reason,
                offense: MisbehaviorType::InvalidBlockPoW,
            });
        }
    }

    // Headers for blocks we already have are not handed back. A peer that is
    // behind us answers our locator from the first entry it knows, genesis
    // when it is far behind, and returns its whole chain; queueing those
    // downloads up to 2000 blocks we hold and processes them as duplicates,
    // on every GetHeaders that happens to land on such a peer.
    Ok(hashes
        .into_iter()
        .zip(held)
        .filter_map(|(hash, in_chain)| (!in_chain).then_some(hash))
        .collect())
}

/// Splits `indices` (ascending positions in `headers`) into runs whose
/// headers hash with the same RandomX key, in order.
fn epoch_groups(headers: &[BlockHeader], indices: &[usize]) -> Vec<Vec<usize>> {
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for &index in indices {
        let height = headers[index].height;
        match groups.last_mut() {
            Some(group) if same_pow_epoch(headers[group[0]].height, height) => group.push(index),
            _ => groups.push(vec![index]),
        }
    }
    groups
}

/// #158: resolve the GetHeaders response start height from a block locator.
///
/// Returns `(deepest common MAIN-CHAIN ancestor in the locator).height + 1`, or
/// `0` (genesis) if nothing matches. `block_height(hash)` yields the height of
/// ANY stored block (including side chains); `main_chain_hash_at(h)` yields the
/// hash of our MAIN-CHAIN block at height `h`. A locator entry only counts when
/// those agree — i.e. the entry is on our main chain — so the headers we return
/// descend from it and connect for the requester. Matching a side-chain entry
/// (as the old code did) made us send main-chain headers whose parent a forked
/// requester lacked ("does not connect"), wedging it forever. The locator always
/// ends at genesis, which is on-chain, so a match is guaranteed.
fn locator_start_height(
    locator: &[Hash],
    block_height: impl Fn(&Hash) -> Option<u64>,
    main_chain_hash_at: impl Fn(u64) -> Option<Hash>,
) -> u64 {
    for hash in locator {
        if let Some(h) = block_height(hash) {
            if main_chain_hash_at(h) == Some(*hash) {
                return h + 1;
            }
        }
    }
    0
}

pub(super) async fn handle_get_headers(
    peer_id: PeerId,
    payload: &[u8],
    magic: [u8; 4],
    peers: &DashMap<PeerId, PeerInfo>,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    chain: &SharedBlockchain,
    scorer: &RwLock<PeerScorer>,
) -> Result<()> {
    if payload.len() > crate::network::protocol::MAX_GETHEADERS_PAYLOAD {
        warn!("GetHeaders message too large from peer {:?}", &peer_id[..4]);
        if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
            scorer
                .write()
                .await
                .get_or_create(addr)
                .record_misbehavior(crate::network::scoring::MisbehaviorType::OversizedMessage);
        }
        return Ok(());
    }
    if let Ok(msg) = borsh::from_slice::<GetHeadersMessage>(payload) {
        if let Err(e) = msg.validate() {
            warn!("Invalid GetHeaders from peer {:?}: {}", &peer_id[..4], e);
            if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                scorer.write().await.get_or_create(addr).record_misbehavior(
                    crate::network::scoring::MisbehaviorType::ProtocolViolation,
                );
            }
            return Ok(());
        }

        // Database reads can stall without yielding to other async tasks.
        let headers = tokio::task::block_in_place(|| {
            // #158: start the response at the deepest COMMON MAIN-CHAIN ancestor
            // in the locator (see `locator_start_height`). Matching a side-chain
            // block here would send headers the requester can't connect, wedging
            // a forked peer in an endless EMERGENCY-TIER-3 loop.
            let start_height = locator_start_height(
                &msg.locator,
                |hash| chain.get_block(hash).map(|b| b.height()),
                |h| chain.get_block_hash(h),
            );
            let mut headers = Vec::new();
            for h in start_height..start_height + MAX_HEADERS_RESPONSE as u64 {
                if let Some(block) = chain.get_block_by_height(h) {
                    let block_hash = block.hash();
                    headers.push(block.header.clone());
                    if block_hash == msg.stop_hash {
                        break;
                    }
                } else {
                    break;
                }
            }
            headers
        });

        if let Ok(resp) = Message::headers_with_nonce(magic, headers, msg.nonce) {
            let _ = send_to_peer(senders, &peer_id, resp.to_bytes()?).await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::chain::Blockchain;
    use crate::consensus::{calculate_difficulty, compute_full_anchor, compute_pow_hash, PowAlgorithm};

    use super::*;

    #[test]
    fn locator_start_height_skips_side_chain_matches_158() {
        let g = Hash::from_bytes([0u8; 32]);
        let a1 = Hash::from_bytes([1u8; 32]);
        let a2 = Hash::from_bytes([2u8; 32]);
        let s2 = Hash::from_bytes([0x52u8; 32]); // a stored SIDE block, also at h=2

        // Our MAIN chain: g@0, a1@1, a2@2. s2 is a side block at height 2.
        let block_height = |h: &Hash| -> Option<u64> {
            if *h == g {
                Some(0)
            } else if *h == a1 {
                Some(1)
            } else if *h == a2 {
                Some(2)
            } else if *h == s2 {
                Some(2)
            } else {
                None
            }
        };
        let main_chain_hash_at = |h: u64| -> Option<Hash> {
            match h {
                0 => Some(g),
                1 => Some(a1),
                2 => Some(a2),
                _ => None,
            }
        };

        // A forked requester's locator leads with its own fork tip s2 (a side
        // block for us), then the common main-chain ancestor a1, then genesis.
        // We MUST skip s2 and start from a1+1 = 2, so the headers we send (from
        // a2, whose parent is a1) connect for the requester. Pre-fix this matched
        // s2 and started at 3, sending a3 whose parent (a2) the requester lacked.
        assert_eq!(
            locator_start_height(&[s2, a1, g], block_height, main_chain_hash_at),
            2,
            "#158: must skip the side-chain locator entry and start from the \
             common main-chain ancestor + 1"
        );
        // A locator whose tip IS on our main chain starts right after it.
        assert_eq!(
            locator_start_height(&[a2, a1, g], block_height, main_chain_hash_at),
            3
        );
        // A locator of only unknown hashes falls back to genesis.
        let unknown = Hash::from_bytes([0xFFu8; 32]);
        assert_eq!(
            locator_start_height(&[unknown], block_height, main_chain_hash_at),
            0
        );
    }

    fn mine_easy_header(mut header: BlockHeader) -> BlockHeader {
        header.algorithm = PowAlgorithm::RandomX as u8;
        // audit §1: bind the header fields into the anchor (binding excludes
        // anchor/nonce, so compute it before setting them).
        let binding = header.pow_binding();
        header.anchor =
            compute_full_anchor(&header.prev_hash, header.height, header.timestamp, &binding)
                .expect("anchor")
                .mixed_hash;

        for nonce in 0..u64::MAX {
            header.nonce = nonce;
            let pow = compute_pow_hash(
                PowAlgorithm::RandomX,
                &header.anchor,
                nonce,
                &header.tx_root,
                header.height,
            )
            .expect("RandomX available in default/testnet builds");
            if pow.meets_difficulty(&header.target) {
                return header;
            }
        }
        panic!("easy target exhausted nonce space");
    }

    fn setup() -> (SharedBlockchain, crate::consensus::Block) {
        let chain = Arc::new(Blockchain::new());
        chain.init_genesis().expect("genesis");
        let genesis = chain.get_block_by_height(0).expect("genesis block");
        (chain, genesis)
    }

    pub(super) fn first_header(genesis: &crate::consensus::Block) -> BlockHeader {
        let mut header = genesis.header.clone();
        header.height = 1;
        header.version = crate::constants::block_version_at_height(1);
        header.prev_hash = genesis.hash();
        header.timestamp = genesis.header.timestamp + crate::constants::TARGET_BLOCK_TIME;
        header.target = Hash::from_bytes([0xFE; 32]);
        mine_easy_header(header)
    }

    #[test]
    fn accepts_connected_header_with_valid_pow() {
        let (chain, genesis) = setup();
        let header = first_header(&genesis);
        let hashes =
            validate_header_batch(&chain, &HashSet::new(), &[header]).expect("valid header");
        assert_eq!(hashes.len(), 1);
    }

    #[test]
    fn rejects_self_declared_easy_target_after_difficulty_activates() {
        let (chain, genesis) = setup();
        let first = first_header(&genesis);
        let history = [
            DifficultyBlock {
                height: genesis.header.height,
                timestamp: genesis.header.timestamp,
                target: genesis.header.target,
            },
            DifficultyBlock {
                height: first.height,
                timestamp: first.timestamp,
                target: first.target,
            },
        ];
        let expected = calculate_difficulty(&history, 2);
        let claimed = if expected != Hash::from_bytes([0xFE; 32]) {
            Hash::from_bytes([0xFE; 32])
        } else {
            Hash::from_bytes([0xFD; 32])
        };

        let mut second = first.clone();
        second.height = 2;
        second.version = crate::constants::block_version_at_height(2);
        second.prev_hash = first.hash();
        second.timestamp += crate::constants::TARGET_BLOCK_TIME;
        second.target = claimed;

        let error = validate_header_batch(&chain, &HashSet::new(), &[first, second])
            .expect_err("target mismatch");
        assert_eq!(error.index, 1);
        assert!(
            error.reason.contains("difficulty target mismatch"),
            "{}",
            error.reason
        );
        assert_eq!(error.offense, MisbehaviorType::InvalidBlockPoW);
    }

    #[test]
    fn rejects_non_contiguous_header_batch() {
        let (chain, genesis) = setup();
        let first = first_header(&genesis);
        let mut second = first.clone();
        second.height = 2;
        second.prev_hash = genesis.hash();

        let error = validate_header_batch(&chain, &HashSet::new(), &[first, second])
            .expect_err("disconnected batch");
        assert_eq!(error.index, 1);
        assert!(error.reason.contains("not contiguous"), "{}", error.reason);
        assert_eq!(error.offense, MisbehaviorType::ProtocolViolation);
    }

    #[test]
    fn rejects_header_without_known_parent() {
        let (chain, genesis) = setup();
        let mut header = first_header(&genesis);
        header.prev_hash = Hash::from_bytes([0xA5; 32]);

        let error =
            validate_header_batch(&chain, &HashSet::new(), &[header]).expect_err("unknown parent");
        assert_eq!(error.index, 0);
        assert!(error.reason.contains("known block"), "{}", error.reason);
        assert_eq!(error.offense, MisbehaviorType::ProtocolViolation);
    }

    #[test]
    fn queued_header_skips_the_pow_check() {
        let (chain, genesis) = setup();
        let mut header = first_header(&genesis);
        // Nothing meets an all-zero target, so the PoW check must fail...
        header.target = Hash::zero();
        let error = validate_header_batch(&chain, &HashSet::new(), std::slice::from_ref(&header))
            .expect_err("unknown header is hashed");
        assert_eq!(error.offense, MisbehaviorType::InvalidBlockPoW);

        // ...unless the hash is one we already validated and queued.
        let known: HashSet<Hash> = [header.hash()].into_iter().collect();
        let hashes = validate_header_batch(&chain, &known, std::slice::from_ref(&header))
            .expect("queued header is trusted");
        assert_eq!(hashes, vec![header.hash()]);
    }

    #[test]
    fn headers_already_in_the_chain_are_not_returned() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Arc::new(crate::db::Database::open(dir.path()).expect("db"));
        let chain = Arc::new(Blockchain::with_database(
            db,
            crate::config::NetworkType::Testnet,
        ));
        chain.init_genesis().expect("genesis");
        chain.seed_linear_chain_for_testing(1, crate::constants::TARGET_BLOCK_TIME);
        let block = chain.get_block_by_height(1).expect("seeded block");
        assert_eq!(chain.get_block_hash(1), Some(block.hash()));
        // The peer sends a header we already have: nothing to hash, nothing
        // to queue.
        let hashes = validate_header_batch(&chain, &HashSet::new(), &[block.header])
            .expect("a header we hold is valid");
        assert!(
            hashes.is_empty(),
            "held headers must not be queued: {:?}",
            hashes
        );
    }

    #[test]
    fn header_pow_runs_one_epoch_at_a_time() {
        let (_chain, genesis) = setup();
        // The first height whose RandomX key differs from its parent's.
        let Some(boundary) = (1..10_000u64).find(|&h| !same_pow_epoch(h - 1, h)) else {
            return; // no epochs in this build
        };
        let headers: Vec<BlockHeader> = (boundary - 2..boundary + 2)
            .map(|height| {
                let mut header = first_header(&genesis);
                header.height = height;
                header
            })
            .collect();
        assert_eq!(
            epoch_groups(&headers, &[0, 1, 2, 3]),
            vec![vec![0, 1], vec![2, 3]],
            "headers on each side of the boundary are hashed as separate groups"
        );
        assert!(epoch_groups(&headers, &[]).is_empty());
    }
}

pub(super) async fn handle_headers(
    peer_id: PeerId,
    payload: &[u8],
    peers: &DashMap<PeerId, PeerInfo>,
    sync: &RwLock<ChainSync>,
    chain: &SharedBlockchain,
    scorer: &RwLock<PeerScorer>,
) -> Result<()> {
    if payload.len() > crate::network::protocol::MAX_MESSAGE_SIZE {
        warn!(
            "Headers message too large from peer {}",
            hex::encode(&peer_id[..8])
        );
        if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
            scorer
                .write()
                .await
                .get_or_create(addr)
                .record_misbehavior(crate::network::scoring::MisbehaviorType::OversizedMessage);
        }
        return Ok(());
    }
    match borsh::from_slice::<crate::network::protocol::HeadersMessage>(payload) {
        Ok(headers_msg) => {
            if let Err(e) = headers_msg.validate() {
                warn!(
                    "Invalid HeadersMessage from peer {}: {}",
                    hex::encode(&peer_id[..8]),
                    e
                );
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr).record_misbehavior(
                        crate::network::scoring::MisbehaviorType::ProtocolViolation,
                    );
                }
                return Ok(());
            }
            let mut sync_guard = sync.write().await;
            if !sync_guard.validate_header_nonce(headers_msg.nonce, &peer_id) {
                debug!(
                    "Ignoring Headers nonce={} from peer {:?}: not outstanding for this peer \
                     (cross-peer, stale generation, or already consumed)",
                    headers_msg.nonce,
                    &peer_id[..4]
                );
                return Ok(());
            }

            // A full batch is 2000 headers = 2000 RandomX hashes, tens of
            // seconds in light mode. Verify it with the lock RELEASED: the
            // sync driver takes this lock every tick, and holding it here
            // stalled the driver for the whole verification (audit map, 9). The
            // validating flag keeps `headers_request_pending()` true so the
            // driver does not issue a second GetHeaders meanwhile.
            let known = sync_guard.queued_header_hashes();
            sync_guard.begin_headers_validation();
            drop(sync_guard);

            let validated = validate_header_batch(chain, &known, &headers_msg.headers);

            let mut sync_guard = sync.write().await;
            sync_guard.end_headers_validation();
            let hashes = match validated {
                Ok(hashes) => hashes,
                Err(error) => {
                    warn!(
                        "Headers validation reject: header[{}] from peer {:?} (h={}): {}",
                        error.index,
                        &peer_id[..4],
                        headers_msg.headers[error.index].height,
                        error.reason.as_str(),
                    );
                    drop(sync_guard);
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer
                            .write()
                            .await
                            .get_or_create(addr)
                            .record_misbehavior(error.offense);
                    }
                    return Ok(());
                }
            };

            let max_header_height = headers_msg
                .headers
                .last()
                .map(|header| header.height)
                .unwrap_or(0);
            sync_guard.update_peer_height(max_header_height);
            sync_guard.update_peer_height_for(peer_id, max_header_height);
            debug!(
                "Accepted Headers nonce={} count={} max_height={} from peer {:?}",
                headers_msg.nonce,
                hashes.len(),
                max_header_height,
                &peer_id[..4]
            );
            sync_guard.queue_headers_from_peer(peer_id, hashes);
        }
        Err(e) => {
            warn!(
                "Failed to deserialize HeadersMessage from peer {}: {}",
                hex::encode(&peer_id[..8]),
                e
            );
            if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                scorer.write().await.get_or_create(addr).record_misbehavior(
                    crate::network::scoring::MisbehaviorType::ProtocolViolation,
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod handle_headers_tests {
    use super::*;
    use crate::chain::Blockchain;
    use crate::network::protocol::HeadersMessage;
    use std::net::SocketAddr;
    use std::sync::Arc;

    fn genesis_chain() -> SharedBlockchain {
        let chain: SharedBlockchain = Arc::new(Blockchain::new());
        chain.init_genesis().expect("genesis");
        chain
    }

    fn addr_for(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    #[tokio::test]
    async fn handle_headers_cross_peer_nonce_is_rejected_without_consuming() {
        // Jun #2: a nonce issued to peer A must not be honoured from peer B, and
        // rejecting B's attempt must NOT consume the nonce (A can still respond).
        let peer_a = [10u8; 32];
        let peer_b = [11u8; 32];
        let peers = DashMap::new();
        peers.insert(peer_b, PeerInfo::new(peer_b, addr_for(31001), false));
        let sync = RwLock::new(ChainSync::new(0, Hash::zero()));
        let nonce = sync
            .write()
            .await
            .begin_headers_request(peer_a, 123)
            .expect("nonce issued to A");
        let chain = genesis_chain();
        let scorer = RwLock::new(PeerScorer::new());

        let payload = borsh::to_vec(&HeadersMessage {
            headers: vec![],
            nonce,
        })
        .unwrap();
        handle_headers(peer_b, &payload, &peers, &sync, &chain, &scorer)
            .await
            .unwrap();

        assert!(
            sync.read().await.headers_request_pending(),
            "A's nonce not consumed by B's cross-peer response"
        );
    }

    #[tokio::test]
    async fn handle_headers_valid_nonce_is_single_use() {
        let peer = [12u8; 32];
        let peers = DashMap::new();
        peers.insert(peer, PeerInfo::new(peer, addr_for(31002), false));
        let sync = RwLock::new(ChainSync::new(0, Hash::zero()));
        let nonce = sync.write().await.begin_headers_request(peer, 123).unwrap();
        let chain = genesis_chain();
        let scorer = RwLock::new(PeerScorer::new());

        let payload = borsh::to_vec(&HeadersMessage {
            headers: vec![],
            nonce,
        })
        .unwrap();
        // First (empty but valid) response consumes the nonce.
        handle_headers(peer, &payload, &peers, &sync, &chain, &scorer)
            .await
            .unwrap();
        assert!(
            !sync.read().await.headers_request_pending(),
            "nonce consumed after first response"
        );

        // Replay with the same nonce: rejected (already consumed), no re-queue.
        handle_headers(peer, &payload, &peers, &sync, &chain, &scorer)
            .await
            .unwrap();
        assert!(!sync.read().await.headers_request_pending());
    }

    #[tokio::test]
    async fn handle_headers_unsolicited_nonce_zero_is_ignored() {
        // nonce 0 is never allocated → unsolicited Headers rejected (anti-eclipse).
        let peer = [13u8; 32];
        let addr = addr_for(31003);
        let peers = DashMap::new();
        peers.insert(peer, PeerInfo::new(peer, addr, false));
        let sync = RwLock::new(ChainSync::new(0, Hash::zero()));
        let chain = genesis_chain();
        let scorer = RwLock::new(PeerScorer::new());

        let payload = borsh::to_vec(&HeadersMessage {
            headers: vec![],
            nonce: 0,
        })
        .unwrap();
        handle_headers(peer, &payload, &peers, &sync, &chain, &scorer)
            .await
            .unwrap();

        assert!(scorer.read().await.get(&addr).is_none(), "no scoring");
        assert!(!sync.read().await.headers_request_pending());
    }

    #[tokio::test]
    async fn handle_headers_rejected_batch_clears_validation_flag() {
        // The batch is verified with the ChainSync lock released, bracketed by
        // the validating flag. The flag must be cleared on the reject path too,
        // or no GetHeaders could ever be issued again.
        let peer = [15u8; 32];
        let addr = addr_for(31005);
        let peers = DashMap::new();
        peers.insert(peer, PeerInfo::new(peer, addr, false));
        let sync = RwLock::new(ChainSync::new(0, Hash::zero()));
        let nonce = sync.write().await.begin_headers_request(peer, 123).unwrap();
        let chain = genesis_chain();
        let scorer = RwLock::new(PeerScorer::new());

        let genesis = chain.get_block_by_height(0).expect("genesis block");
        let mut header = genesis.header.clone();
        header.height = 1;
        header.prev_hash = Hash::from_bytes([0xA5; 32]); // unknown parent
        let payload = borsh::to_vec(&HeadersMessage {
            headers: vec![header],
            nonce,
        })
        .unwrap();
        handle_headers(peer, &payload, &peers, &sync, &chain, &scorer)
            .await
            .unwrap();

        assert!(scorer.read().await.get(&addr).is_some(), "reject is scored");
        assert!(
            !sync.read().await.headers_request_pending(),
            "validating flag cleared after a rejected batch"
        );
        let reissued = sync.write().await.begin_headers_request(peer, 124);
        assert!(reissued.is_some(), "a new GetHeaders can be issued");
    }

    #[tokio::test]
    async fn handle_headers_valid_batch_queues_and_clears_validation_flag() {
        use crate::network::sync::SyncState;

        let peer = [16u8; 32];
        let peers = DashMap::new();
        peers.insert(peer, PeerInfo::new(peer, addr_for(31006), false));
        let sync = RwLock::new(ChainSync::new(0, Hash::zero()));
        let nonce = sync.write().await.begin_headers_request(peer, 123).unwrap();
        let chain = genesis_chain();
        let scorer = RwLock::new(PeerScorer::new());

        let genesis = chain.get_block_by_height(0).expect("genesis block");
        let header = super::tests::first_header(&genesis);
        let payload = borsh::to_vec(&HeadersMessage {
            headers: vec![header],
            nonce,
        })
        .unwrap();
        handle_headers(peer, &payload, &peers, &sync, &chain, &scorer)
            .await
            .unwrap();

        let sg = sync.read().await;
        assert!(!sg.headers_request_pending(), "flag cleared after accept");
        assert_eq!(sg.pending_count(), 1, "verified header hash queued");
        assert_eq!(sg.state(), SyncState::Blocks);
    }

    #[tokio::test]
    async fn handle_headers_borsh_garbage_scores_protocol_violation() {
        let peer = [14u8; 32];
        let addr = addr_for(31004);
        let peers = DashMap::new();
        peers.insert(peer, PeerInfo::new(peer, addr, false));
        let sync = RwLock::new(ChainSync::new(0, Hash::zero()));
        let chain = genesis_chain();
        let scorer = RwLock::new(PeerScorer::new());

        let payload = vec![0u8; 2]; // too short to decode a HeadersMessage
        handle_headers(peer, &payload, &peers, &sync, &chain, &scorer)
            .await
            .unwrap();

        assert!(scorer.read().await.get(&addr).unwrap().reputation < 100);
    }
}
