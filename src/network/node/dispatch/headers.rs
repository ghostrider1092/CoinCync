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
//!   before a header is accepted into `hashes`.
//!   THREAT: a structurally-valid header with forged or missing PoW being
//!   queued for sync.
//!   TESTS: `accepts_connected_header_with_valid_pow`.
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

use std::collections::HashMap;

use dashmap::DashMap;
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
    headers: &[BlockHeader],
) -> std::result::Result<Vec<Hash>, HeaderBatchError> {
    let expected_magic = chain.network().magic_bytes();
    let mut accepted = HashMap::with_capacity(headers.len());
    let mut hashes = Vec::with_capacity(headers.len());

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
        .map_err(|error| reject(error.to_string(), MisbehaviorType::InvalidBlockPoW))?;

        let hash = header.hash();
        accepted.insert(hash, header.clone());
        hashes.push(hash);
    }

    Ok(hashes)
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
            let mut start_height = 0u64;
            for hash in &msg.locator {
                if let Some(block) = chain.get_block(hash) {
                    start_height = block.height() + 1;
                    break;
                }
            }
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

    fn first_header(genesis: &crate::consensus::Block) -> BlockHeader {
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
        let hashes = validate_header_batch(&chain, &[header]).expect("valid header");
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

        let error = validate_header_batch(&chain, &[first, second]).expect_err("target mismatch");
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

        let error =
            validate_header_batch(&chain, &[first, second]).expect_err("disconnected batch");
        assert_eq!(error.index, 1);
        assert!(error.reason.contains("not contiguous"), "{}", error.reason);
        assert_eq!(error.offense, MisbehaviorType::ProtocolViolation);
    }

    #[test]
    fn rejects_header_without_known_parent() {
        let (chain, genesis) = setup();
        let mut header = first_header(&genesis);
        header.prev_hash = Hash::from_bytes([0xA5; 32]);

        let error = validate_header_batch(&chain, &[header]).expect_err("unknown parent");
        assert_eq!(error.index, 0);
        assert!(error.reason.contains("known block"), "{}", error.reason);
        assert_eq!(error.offense, MisbehaviorType::ProtocolViolation);
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

            let hashes = match validate_header_batch(chain, &headers_msg.headers) {
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
