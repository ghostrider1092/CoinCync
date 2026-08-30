use dashmap::DashMap;
use tokio::sync::mpsc;
use tracing::warn;

use crate::chain::SharedBlockchain;
use crate::error::Result;
use crate::network::peer::PeerId;
use crate::network::protocol::{Message, MessageType};

use super::super::broadcast::send_to_peer;

use once_cell::sync::Lazy;
use parking_lot::Mutex;

/// Response byte budget for the filter/digest range queries. Item COUNT is
/// already capped (bounded_height_range); this bounds the SERIALIZED size so an
/// output-dense range can't produce an oversized response regardless of count.
/// Half of MAX_MESSAGE_SIZE (16 MiB) leaves framing/encoding headroom.
const MAX_QUERY_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Max GetKeyImageStatus payload (32 B per key image x 100 max ~= 3.2 KiB; 8 KiB
/// leaves slack for the borsh length prefix + framing). Handler-local backstop;
/// the router (dispatch/mod.rs) also gates light-query payloads.
const MAX_KI_QUERY_PAYLOAD: usize = 8 * 1024;

/// Checkpoint-response memo. The checkpoint set is a pure function of chain
/// height at 1000-block spacing, so recomputing 1000 filters on every
/// (zero-body!) request is pure waste — cache per 1000-block bucket so N
/// requests in one bucket cost ONE rebuild. (cached_bucket, checkpoints).
static CHECKPOINT_CACHE: Lazy<
    Mutex<Option<(u64, Vec<crate::network::block_filter::FilterCheckpoint>)>>,
> = Lazy::new(|| Mutex::new(None));

fn bounded_height_range(
    start: u64,
    requested_end: u64,
    chain_tip: u64,
    max_items: u64,
) -> Option<(u64, u64)> {
    if start > requested_end || start > chain_tip || max_items == 0 {
        return None;
    }

    let end = requested_end
        .min(start.saturating_add(max_items - 1))
        .min(chain_tip);
    Some((start, end))
}

pub(super) async fn handle_get_filters(
    peer_id: PeerId,
    payload: &[u8],
    magic: [u8; 4],
    chain: &SharedBlockchain,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
) -> Result<()> {
    // Network/Archive nodes serve compact block filters to personal nodes.
    // Request contains (start_height: u64, end_height: u64).
    if payload.len() >= 16 {
        let start = u64::from_le_bytes(
            payload[0..8]
                .try_into()
                .expect("filter request length was validated"),
        );
        let end = u64::from_le_bytes(
            payload[8..16]
                .try_into()
                .expect("filter request length was validated"),
        );

        // Validate range and bound to prevent DoS (max 1000 filters per request)
        if start > end {
            warn!(
                "GetFilters: start {} > end {} from peer {:?}",
                start,
                end,
                &peer_id[..4]
            );
            return Ok(());
        }
        let chain_height = chain.height();
        let range = bounded_height_range(start, end, chain_height, 1000);

        if let Some((start, end)) = range {
            tracing::debug!(
                "GetFilters from {:?}: heights {}..={}",
                &peer_id[..4],
                start,
                end
            );
        }

        // Build filters on the fly from blocks (or serve from cache/db).
        // Layer 2: per-height DB read + filter computation are both
        // synchronous and CPU-bound; the chained filter_hash means
        // the loop can't easily parallelize. Wrap in block_in_place.
        let filters = tokio::task::block_in_place(|| {
            let mut filters = Vec::new();
            let mut prev_filter_hash = crate::primitives::Hash::default();
            let mut total_bytes = 0usize;
            if let Some((start, end)) = range {
                for h in start..=end {
                    if let Some(block) = chain.get_block_by_height(h) {
                        let filter = crate::network::block_filter::BlockFilter::from_block(
                            &block,
                            prev_filter_hash,
                        );
                        prev_filter_hash = filter.filter_hash();
                        // Bound by ENCODED size, not just count, so an
                        // output-dense range can't produce an oversized response.
                        match borsh::to_vec(&filter).map(|v| v.len()) {
                            Ok(sz) if total_bytes + sz > MAX_QUERY_RESPONSE_BYTES => break,
                            Ok(sz) => total_bytes += sz,
                            Err(_) => break, // unserializable → stop, don't spin
                        }
                        filters.push(filter);
                    }
                }
            }
            filters
        });

        // Serialize and send response. Use Message::to_bytes() so
        // the per-peer write loop reads `data[4]` as the real
        // message type instead of a body byte (see 2026-05-09 IBD
        // wedge: 5 sites bypassed framing and broke the connection).
        if let Ok(encoded) = borsh::to_vec(&filters) {
            let msg = Message::new(magic, MessageType::Filters, encoded);
            if let Ok(data) = msg.to_bytes() {
                let _ = send_to_peer(senders, &peer_id, data).await;
            }
        }
    }
    Ok(())
}

pub(super) async fn handle_get_output_digests(
    peer_id: PeerId,
    payload: &[u8],
    magic: [u8; 4],
    chain: &SharedBlockchain,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
) -> Result<()> {
    // Personal nodes request compact per-block output digests so
    // their light-wallet can detect ownership without downloading
    // full blocks. Wire format mirrors GetFilters: 16-byte payload
    // (start_height, end_height) u64-LE. Range is capped to keep
    // any single response well under MAX_MESSAGE_SIZE (16 MiB).
    //
    // Privacy property: the server learns only the height range,
    // never which outputs are interesting to the wallet. Stronger
    // than BIP-157, where the address-set is leaked. See
    // docs/security/LIGHTSYNC_AUDIT.md.
    const MAX_DIGEST_BLOCKS_PER_REQ: u64 = 100;

    if payload.len() < 16 {
        warn!(
            "GetOutputDigests from {:?}: payload too short",
            &peer_id[..4]
        );
        return Ok(());
    }
    let start = u64::from_le_bytes(
        payload[0..8]
            .try_into()
            .expect("digest request length was validated"),
    );
    let end = u64::from_le_bytes(
        payload[8..16]
            .try_into()
            .expect("digest request length was validated"),
    );
    if start > end {
        warn!(
            "GetOutputDigests: start {} > end {} from peer {:?}",
            start,
            end,
            &peer_id[..4]
        );
        return Ok(());
    }
    let chain_height = chain.height();
    let range = bounded_height_range(start, end, chain_height, MAX_DIGEST_BLOCKS_PER_REQ);

    if let Some((start, end)) = range {
        tracing::debug!(
            "GetOutputDigests from {:?}: heights {}..={}",
            &peer_id[..4],
            start,
            end
        );
    }

    // Layer 2: per-height DB read + BlockDigest computation
    // wrapped in block_in_place so the worker thread is reusable
    // during the synchronous fan-out.
    let digests = tokio::task::block_in_place(|| {
        // Grow the Vec rather than pre-reserving `count`: with a byte budget the
        // final length isn't `count`, and reserving the full range up-front is an
        // over-alloc a malicious dense request could exploit.
        let mut digests = Vec::new();
        let mut total_bytes = 0usize;
        if let Some((start, end)) = range {
            for h in start..=end {
                if let Some(block) = chain.get_block_by_height(h) {
                    let digest = crate::wallet::lightsync::BlockDigest::from_block(&block);
                    match borsh::to_vec(&digest).map(|v| v.len()) {
                        Ok(sz) if total_bytes + sz > MAX_QUERY_RESPONSE_BYTES => break,
                        Ok(sz) => total_bytes += sz,
                        Err(_) => break,
                    }
                    digests.push(digest);
                }
            }
        }
        digests
    });

    if let Ok(encoded) = borsh::to_vec(&digests) {
        let msg = Message::new(magic, MessageType::OutputDigests, encoded);
        if let Ok(data) = msg.to_bytes() {
            let _ = send_to_peer(senders, &peer_id, data).await;
        }
    }
    Ok(())
}

pub(super) async fn handle_get_filter_checkpoints(
    peer_id: PeerId,
    magic: [u8; 4],
    chain: &SharedBlockchain,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
) -> Result<()> {
    // Serve filter chain checkpoints for integrity verification.
    tracing::debug!("GetFilterCheckpoints from {:?}", &peer_id[..4]);

    // Build checkpoints from chain (every 1000 blocks).
    //
    // Bounded: at most MAX_CHECKPOINTS entries per response.
    // Each iteration does a disk-backed get_block_by_height +
    // filter recomputation, so an unbounded loop lets any peer
    // amplify their request into per-request O(chain_height)
    // disk + CPU. 1000 entries = 1M blocks of coverage at
    // 1000-block spacing, which is ~30 years of mainnet at
    // 120s block time. Plenty of headroom; well past any
    // legitimate peer's needs.
    const MAX_CHECKPOINTS: usize = 1000;
    const SPACING: u64 = 1000;
    let chain_height = chain.height();
    let bucket = chain_height / SPACING;

    // Fast path: cached response for the current 1000-block bucket. N requests
    // in one bucket then cost ONE rebuild, not N x (up to 1000 disk reads +
    // filter recomputations) — closing the zero-body-request amplifier.
    let cached = {
        let guard = CHECKPOINT_CACHE.lock();
        match *guard {
            Some((b, ref cps)) if b == bucket => Some(cps.clone()),
            _ => None,
        }
    };
    let checkpoints = if let Some(cps) = cached {
        cps
    } else {
        // Slow path: rebuild once for this bucket, then cache. Layer 2: up to
        // 1000 disk-backed reads + filter recomputations; wrap in block_in_place.
        let built = tokio::task::block_in_place(|| {
            let mut checkpoints = Vec::with_capacity(MAX_CHECKPOINTS);
            let mut h = 0u64;
            while h <= chain_height && checkpoints.len() < MAX_CHECKPOINTS {
                if let Some(block) = chain.get_block_by_height(h) {
                    let filter = crate::network::block_filter::BlockFilter::from_block(
                        &block,
                        crate::primitives::Hash::default(),
                    );
                    checkpoints.push(crate::network::block_filter::FilterCheckpoint {
                        height: h,
                        block_hash: block.hash(),
                        filter_hash: filter.filter_hash(),
                    });
                }
                h = match h.checked_add(SPACING) {
                    Some(next) => next,
                    None => break,
                };
            }
            checkpoints
        });
        if built.len() == MAX_CHECKPOINTS {
            tracing::warn!(
                "GetFilterCheckpoints from {:?}: hit MAX_CHECKPOINTS={} cap (chain_height={})",
                &peer_id[..4],
                MAX_CHECKPOINTS,
                chain_height
            );
        }
        *CHECKPOINT_CACHE.lock() = Some((bucket, built.clone()));
        built
    };

    if let Ok(encoded) = borsh::to_vec(&checkpoints) {
        let msg = Message::new(magic, MessageType::FilterCheckpoints, encoded);
        if let Ok(data) = msg.to_bytes() {
            let _ = send_to_peer(senders, &peer_id, data).await;
        }
    }
    Ok(())
}

pub(super) async fn handle_get_key_image_status(
    peer_id: PeerId,
    payload: &[u8],
    magic: [u8; 4],
    chain: &SharedBlockchain,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
) -> Result<()> {
    // DHT query: is this key image spent?
    // Payload: Vec<[u8; 32]> — list of key images to check.
    // borsh::from_slice reads a length prefix and allocates BEFORE take(100)
    // runs; bound the payload so a giant declared length can't force a large
    // pre-parse alloc. (Router also gates this; handler-local backstop.)
    if payload.len() > MAX_KI_QUERY_PAYLOAD {
        warn!(
            "GetKeyImageStatus payload too large ({} bytes) from {:?}",
            payload.len(),
            &peer_id[..4]
        );
        return Ok(());
    }
    if let Ok(key_images) = borsh::from_slice::<Vec<[u8; 32]>>(payload) {
        let max_query = 100usize;
        let key_images: Vec<[u8; 32]> = key_images.into_iter().take(max_query).collect();

        tracing::debug!(
            "GetKeyImageStatus from {:?}: {} key images",
            &peer_id[..4],
            key_images.len()
        );

        // Check each key image against the chain's spent set.
        // Layer 2: up to 100 DB lookups per request; wrap in
        // block_in_place so the worker thread is reusable.
        let statuses: Vec<u8> = tokio::task::block_in_place(|| {
            let mut statuses: Vec<u8> = Vec::with_capacity(key_images.len());
            for ki_bytes in &key_images {
                let ki = crate::primitives::KeyImage::from_bytes(*ki_bytes);
                let spent = chain.is_spent(&ki);
                statuses.push(if spent { 1 } else { 0 });
            }
            statuses
        });

        if let Ok(encoded) = borsh::to_vec(&statuses) {
            let msg = Message::new(magic, MessageType::KeyImageStatus, encoded);
            if let Ok(data) = msg.to_bytes() {
                let _ = send_to_peer(senders, &peer_id, data).await;
            }
        }
    }
    Ok(())
}

pub(super) fn handle_response(msg_type: MessageType) {
    // These are responses — personal nodes process them via their sync loop.
    // Full nodes receiving these can safely ignore them.
    tracing::trace!(
        "Received response message {:?} (no-op on full node)",
        msg_type
    );
}

#[cfg(test)]
mod tests {
    use super::bounded_height_range;

    #[test]
    fn bounded_range_is_empty_past_the_chain_tip() {
        assert_eq!(bounded_height_range(11, 20, 10, 100), None);
    }

    #[test]
    fn bounded_range_applies_request_and_chain_limits() {
        assert_eq!(bounded_height_range(5, 500, 400, 100), Some((5, 104)));
        assert_eq!(bounded_height_range(5, 8, 400, 100), Some((5, 8)));
        assert_eq!(bounded_height_range(5, 500, 7, 100), Some((5, 7)));
    }

    #[test]
    fn bounded_range_rejects_reverse_or_zero_sized_requests() {
        assert_eq!(bounded_height_range(9, 8, 10, 100), None);
        assert_eq!(bounded_height_range(0, 0, 0, 0), None);
    }
}
