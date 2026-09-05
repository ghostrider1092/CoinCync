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
        header.anchor = compute_full_anchor(&header.prev_hash, header.height, header.timestamp)
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
