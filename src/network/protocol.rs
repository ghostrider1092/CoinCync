//! # Network Protocol Messages
//!
//! P2P protocol message definitions and serialization.

use crate::consensus::Block;
use crate::constants::{
    is_protocol_version_supported, MAX_SUPPORTED_PROTOCOL_VERSION, MIN_SUPPORTED_PROTOCOL_VERSION,
    PROTOCOL_VERSION,
};
use crate::error::{Error, Result};
use crate::primitives::Hash;
use crate::transaction::Transaction;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Maximum message size (16 MB)
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Maximum header locator chain length (prevents DoS via oversized locators)
/// 64 entries allows for 2^64 blocks of history with exponential backoff
pub const MAX_LOCATOR_SIZE: usize = 64;

/// Maximum number of headers in a single response
pub const MAX_HEADERS_RESPONSE: usize = 2000;

/// Maximum number of block hashes in a single request
pub const MAX_BLOCK_HASHES: usize = 500;

/// Maximum inventory items in a single message
/// SECURITY: Reduced from 50,000 to prevent hash flood DoS attacks
/// 500 hashes * 32 bytes = 16 KB max, reasonable for inventory announcements
pub const MAX_INV_SIZE: usize = 500;

/// Maximum addresses in a single addr message
pub const MAX_ADDR_SIZE: usize = 1000;

/// Maximum transactions in a single txs message
pub const MAX_TXS_PER_MESSAGE: usize = 100;

/// Maximum user agent length (prevent memory exhaustion)
pub const MAX_USER_AGENT_LENGTH: usize = 256;

/// Maximum reject message data size
pub const MAX_REJECT_DATA_SIZE: usize = 256;

/// Maximum reject message reason length
pub const MAX_REJECT_REASON_LENGTH: usize = 256;

// P5-N-CLASS-A + P5-P1 SURGICAL FIX (2026-07-03): the CANONICAL
// per-message-type size caps are `MessageType::max_size()` below
// (L240+). The framer at network/framing.rs:110-119 and :264
// enforces those caps BEFORE the payload reaches any handler, so
// handler-side size checks are defense-in-depth only. The
// constants below are ALIASES that point at the canonical
// per-type caps via `MessageType::X.max_size()` calls; use
// `MessageType::X.max_size()` directly in new code.
//
// Legacy aliases retained so existing handler-side checks in
// node.rs continue to compile; they now match `max_size()` values
// exactly, restoring single-source-of-truth semantics.
pub const MAX_GETHEADERS_PAYLOAD: usize = 2 * 1024;
pub const MAX_GETBLOCKS_PAYLOAD: usize = 16 * 1024;
pub const MAX_GETTXS_PAYLOAD: usize = 16 * 1024;
pub const MAX_GETDATA_PAYLOAD: usize = 16 * 1024;
pub const MAX_INV_PAYLOAD: usize = 64 * 1024;
pub const MAX_ADDR_PAYLOAD: usize = 256 * 1024;

/// Message header
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct MessageHeader {
    /// Network magic bytes
    pub magic: [u8; 4],
    /// Message type
    pub msg_type: u8,
    /// Payload length
    pub length: u32,
    /// Checksum (first 4 bytes of hash)
    pub checksum: [u8; 4],
}

impl MessageHeader {
    pub const SIZE: usize = 4 + 1 + 4 + 4;

    pub fn new(magic: [u8; 4], msg_type: MessageType, payload: &[u8]) -> Self {
        let checksum = compute_checksum(payload);
        MessageHeader {
            magic,
            msg_type: msg_type as u8,
            length: payload.len() as u32,
            checksum,
        }
    }

    pub fn validate(&self, expected_magic: [u8; 4]) -> Result<()> {
        if self.magic != expected_magic {
            return Err(Error::ProtocolError("invalid magic".into()));
        }
        if self.length as usize > MAX_MESSAGE_SIZE {
            return Err(Error::MessageTooLarge);
        }
        Ok(())
    }

    pub fn verify_checksum(&self, payload: &[u8]) -> bool {
        compute_checksum(payload) == self.checksum
    }
}

fn compute_checksum(data: &[u8]) -> [u8; 4] {
    let hash = blake3::hash(data);
    let mut checksum = [0u8; 4];
    checksum.copy_from_slice(&hash.as_bytes()[..4]);
    checksum
}

/// Message types
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum MessageType {
    Version = 0,
    Verack = 1,
    Ping = 2,
    Pong = 3,
    GetHeaders = 10,
    Headers = 11,
    GetBlocks = 12,
    Blocks = 13,
    GetData = 14,
    BlockData = 15,
    GetTxs = 20,
    Txs = 21,
    InvTx = 22,
    InvBlock = 23,
    /// v1.0.13 #2 — `NotFound` response to GetTxs/GetData for items
    /// we don't have. Without this, peers re-ask indefinitely (no
    /// signal that the item is genuinely absent vs in-flight), and
    /// we re-do disk/mempool lookups for every re-ask. Payload is
    /// the same shape as the request: a list of hashes the receiver
    /// can cache as "this peer doesn't have these — don't re-ask
    /// for a while".
    NotFound = 24,
    GetAddr = 30,
    Addr = 31,
    Reject = 40,
    Alert = 41,
    /// Firework: Flare capability-negotiation message.
    /// Sent immediately after VERSION, before the select! loop.
    /// Carries a u64 bitfield of supported features. Unknown bits ignored.
    Flare = 50,

    /// Firework: cumulative chain-work advertisement (Phase 2 total-
    /// difficulty sync trust). Sent only to peers that advertised
    /// `CAP_CHAINWORK` in their Flare — on handshake completion and when
    /// our tip advances. Lets a peer recognize a heavier chain even when
    /// that chain is shorter in height. Gated by the capability bit so
    /// nodes predating this message never receive it (they reject unknown
    /// message types).
    ChainWork = 51,

    // ── Personal Node (Tier 1) Protocol Messages ────────────────────
    /// Request compact block filters for a height range.
    /// Personal nodes send this to network nodes.
    GetFilters = 60,
    /// Response with compact block filters.
    /// Network nodes send this to personal nodes.
    Filters = 61,
    /// Request output digests for specific block heights.
    /// Personal nodes send this after a filter match.
    GetOutputDigests = 62,
    /// Response with output digests for requested blocks.
    OutputDigests = 63,
    /// Request filter chain checkpoints for verification.
    GetFilterCheckpoints = 64,
    /// Response with filter chain checkpoints.
    FilterCheckpoints = 65,

    // ── Network Node (Tier 2) DHT Messages ──────────────────────────
    /// Query whether a key image has been spent (DHT lookup).
    GetKeyImageStatus = 70,
    /// Response with key image spend status.
    KeyImageStatus = 71,

    // ── ChainAnchorStamp (Invention 2) ──────────────────────────────
    /// Miner asks connected peers to sign the canonical anchor payload.
    AnchorRequest = 80,
    /// Peer responds with its Ed25519 signature over the canonical payload.
    AnchorResponse = 81,

    // ── Traffic shaping (4th Amendment defense) ─────────────────────
    /// Dummy cover-traffic packet from the constant-rate padding loop.
    /// Receiver silently discards. The per-connection framer normalizes
    /// it to the same size buckets used for real traffic.
    ///
    /// Replaces the `PADDING_MAGIC` (0xDEADBEEF) hack that bypassed the
    /// framer entirely — that scheme was wired in tests but never
    /// reached production because the per-peer write loop expects
    /// framed messages and would have dropped the connection on the
    /// padding bytes.
    Padding = 99,
}

impl TryFrom<u8> for MessageType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(MessageType::Version),
            1 => Ok(MessageType::Verack),
            2 => Ok(MessageType::Ping),
            3 => Ok(MessageType::Pong),
            10 => Ok(MessageType::GetHeaders),
            11 => Ok(MessageType::Headers),
            12 => Ok(MessageType::GetBlocks),
            13 => Ok(MessageType::Blocks),
            14 => Ok(MessageType::GetData),
            15 => Ok(MessageType::BlockData),
            20 => Ok(MessageType::GetTxs),
            21 => Ok(MessageType::Txs),
            22 => Ok(MessageType::InvTx),
            23 => Ok(MessageType::InvBlock),
            24 => Ok(MessageType::NotFound),
            30 => Ok(MessageType::GetAddr),
            31 => Ok(MessageType::Addr),
            40 => Ok(MessageType::Reject),
            41 => Ok(MessageType::Alert),
            50 => Ok(MessageType::Flare),
            51 => Ok(MessageType::ChainWork),
            60 => Ok(MessageType::GetFilters),
            61 => Ok(MessageType::Filters),
            62 => Ok(MessageType::GetOutputDigests),
            63 => Ok(MessageType::OutputDigests),
            64 => Ok(MessageType::GetFilterCheckpoints),
            65 => Ok(MessageType::FilterCheckpoints),
            70 => Ok(MessageType::GetKeyImageStatus),
            71 => Ok(MessageType::KeyImageStatus),
            80 => Ok(MessageType::AnchorRequest),
            81 => Ok(MessageType::AnchorResponse),
            99 => Ok(MessageType::Padding),
            _ => Err(Error::InvalidMessage(format!("unknown type: {}", value))),
        }
    }
}

impl MessageType {
    /// SECURITY (H15-FIX): Per-command maximum message size limits.
    /// Like Monero's get_max_bytes() in connection_context.cpp, each message
    /// type has its own size limit enforced before deserialization. This prevents
    /// attackers from sending oversized payloads for small message types
    /// (e.g., a 16MB "Ping" message that wastes memory during deserialization).
    pub fn max_size(&self) -> usize {
        match self {
            // Control messages: small
            MessageType::Version => 4 * 1024, // 4 KB
            MessageType::Verack => 256,       // 256 bytes
            MessageType::Ping => 256,         // 256 bytes
            MessageType::Pong => 256,         // 256 bytes
            MessageType::Flare => 1024,       // 1 KB
            MessageType::ChainWork => 256,    // u128 + u64 + Hash (~56 B)

            // Request messages: moderate
            MessageType::GetHeaders => 2 * 1024, // 2 KB (locator hashes)
            MessageType::GetBlocks => 16 * 1024, // 16 KB (hash list)
            MessageType::GetData => 16 * 1024,   // 16 KB
            MessageType::GetTxs => 16 * 1024,    // 16 KB
            MessageType::GetAddr => 256,         // 256 bytes

            // Data messages: large
            // 1 MB headroom for MAX_HEADERS_RESPONSE=2000. CoinCync's
            // BlockHeader serializes to ~287 bytes (prev_hash + tx_root +
            // anchor + target + signature + nonce + height + timestamp +
            // version + algo + magic), so 2000 of them is ~574 KB pre-
            // framing — the prior 512 KB cap rejected every full IBD
            // Headers response and broke fresh-node sync. Sandbox node
            // hit this immediately on 2026-05-09. Receiver-side fix only;
            // existing senders happily emit 574 KB and now we accept it.
            MessageType::Headers => 1024 * 1024, // 1 MB (up to 2000 headers @ ~287B each)
            MessageType::Blocks => MAX_MESSAGE_SIZE, // 16 MB (block data)
            MessageType::BlockData => 4 * 1024 * 1024, // 4 MB (single block)
            MessageType::Txs => 4 * 1024 * 1024, // 4 MB (transaction batch)

            // Inventory: moderate
            MessageType::InvTx => 64 * 1024,    // 64 KB
            MessageType::InvBlock => 64 * 1024, // 64 KB

            // v1.0.13 #2 — NotFound mirrors a GetTxs/GetData request
            // shape (list of hashes). Cap matches GetTxs (16 KB =
            // ~500 hashes @ 32 bytes each + framing overhead).
            MessageType::NotFound => 16 * 1024, // 16 KB

            // Peer addresses: moderate
            MessageType::Addr => 256 * 1024, // 256 KB

            // Meta messages: small
            MessageType::Reject => 4 * 1024, // 4 KB
            MessageType::Alert => 64 * 1024, // 64 KB

            // Personal node (Tier 1) messages
            MessageType::GetFilters => 1024, // 1 KB (height range request)
            MessageType::Filters => 2 * 1024 * 1024, // 2 MB (batch of GCS filters)
            MessageType::GetOutputDigests => 16 * 1024, // 16 KB (height list)
            MessageType::OutputDigests => 4 * 1024 * 1024, // 4 MB (output digests)
            MessageType::GetFilterCheckpoints => 1024, // 1 KB
            MessageType::FilterCheckpoints => 256 * 1024, // 256 KB

            // Network node (Tier 2) DHT messages
            MessageType::GetKeyImageStatus => 4 * 1024, // 4 KB (key image query)
            MessageType::KeyImageStatus => 4 * 1024,    // 4 KB (spend status)

            // ChainAnchorStamp (Invention 2) — small, bounded payloads
            MessageType::AnchorRequest => 1024,  // 1 KB
            MessageType::AnchorResponse => 1024, // 1 KB

            // Traffic-shaping cover packet: logical payload before framing.
            MessageType::Padding => 8 * 1024,
        }
    }
}

/// Version message
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct VersionMessage {
    pub version: u32,
    pub services: u64,
    pub timestamp: u64,
    pub nonce: u64,
    pub user_agent: String,
    pub start_height: u64,
    pub best_hash: Hash,
}

/// Firework capability advertisement.
///
/// Sent immediately after the Version/Verack handshake. `capabilities` is a
/// bitfield of supported optional features; unknown bits MUST be ignored by
/// the receiver so the field stays forward-compatible. See
/// [`crate::network::firework`] for the bit definitions and the
/// backward-compatibility contract (a peer that never sends a Flare has
/// capabilities `0` and every feature falls back gracefully).
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct FlareMessage {
    pub capabilities: u64,
}

/// Cumulative chain-work advertisement (Firework `CAP_CHAINWORK`).
///
/// `total_difficulty` is our tip's cumulative PoW work; `height`/`best_hash`
/// identify the tip it refers to. The receiver feeds `total_difficulty` into
/// its peer-work table so it can detect and sync to a heavier chain even when
/// that chain is shorter in height (closing the higher-block/lower-work
/// private-fork trap).
///
/// SECURITY: the advertised work is a CLAIM, not proof. It only gates whether
/// we *request* a peer's headers; adoption still requires downloading those
/// headers and recomputing their summed PoW (fork choice already does this).
/// Never let an unverified claim mutate our tip. See the failure-modes
/// section of docs/architecture/sync-total-difficulty-trust-design.md.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ChainWorkMessage {
    pub total_difficulty: u128,
    pub height: u64,
    pub best_hash: Hash,
}

impl VersionMessage {
    pub fn new(height: u64, best_hash: Hash) -> Self {
        use rand::RngCore;
        let mut nonce = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        Self::with_nonce(height, best_hash, u64::from_le_bytes(nonce))
    }

    /// Create with a specific nonce (for self-connection detection - NET-001)
    pub fn with_nonce(height: u64, best_hash: Hash, nonce: u64) -> Self {
        VersionMessage {
            version: PROTOCOL_VERSION,
            services: 1,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            nonce,
            user_agent: format!("CoinCync/{}", crate::VERSION),
            start_height: height,
            best_hash,
        }
    }

    /// Validate the message to prevent DoS attacks and check protocol compatibility
    pub fn validate(&self) -> Result<()> {
        // Check user agent length to prevent memory exhaustion
        if self.user_agent.len() > MAX_USER_AGENT_LENGTH {
            return Err(Error::ProtocolError(format!(
                "user agent too long: {} > {}",
                self.user_agent.len(),
                MAX_USER_AGENT_LENGTH
            )));
        }

        // Check protocol version compatibility
        if !is_protocol_version_supported(self.version) {
            return Err(Error::UnsupportedProtocolVersion {
                peer_version: self.version,
                min_supported: MIN_SUPPORTED_PROTOCOL_VERSION,
                max_supported: MAX_SUPPORTED_PROTOCOL_VERSION,
            });
        }

        Ok(())
    }

    /// Check if this peer's version is compatible with ours
    pub fn is_compatible(&self) -> bool {
        is_protocol_version_supported(self.version)
    }

    /// Get a human-readable compatibility status
    pub fn compatibility_status(&self) -> &'static str {
        if self.version < MIN_SUPPORTED_PROTOCOL_VERSION {
            "outdated (upgrade required)"
        } else if self.version > MAX_SUPPORTED_PROTOCOL_VERSION {
            "too new (our node needs upgrade)"
        } else if self.version < PROTOCOL_VERSION {
            "compatible (older version)"
        } else if self.version > PROTOCOL_VERSION {
            "compatible (newer version)"
        } else {
            "compatible (same version)"
        }
    }
}

/// Get headers request
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct GetHeadersMessage {
    pub locator: Vec<Hash>,
    pub stop_hash: Hash,
    /// Request nonce — echoed back in Headers response for correlation.
    /// Prevents crossed responses when both sides send GetHeaders simultaneously.
    #[serde(default)]
    pub nonce: u64,
}

impl GetHeadersMessage {
    /// Validate the message to prevent DoS attacks
    pub fn validate(&self) -> Result<()> {
        if self.locator.len() > MAX_LOCATOR_SIZE {
            return Err(Error::ProtocolError(format!(
                "locator chain too long: {} > {}",
                self.locator.len(),
                MAX_LOCATOR_SIZE
            )));
        }
        Ok(())
    }
}

/// Headers response
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct HeadersMessage {
    pub headers: Vec<crate::consensus::BlockHeader>,
    /// Echoed nonce from the GetHeaders request for correlation.
    #[serde(default)]
    pub nonce: u64,
}

impl HeadersMessage {
    /// Validate the message to prevent DoS attacks
    pub fn validate(&self) -> Result<()> {
        if self.headers.len() > MAX_HEADERS_RESPONSE {
            return Err(Error::ProtocolError(format!(
                "too many headers: {} > {}",
                self.headers.len(),
                MAX_HEADERS_RESPONSE
            )));
        }
        Ok(())
    }
}

/// Get blocks request
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct GetBlocksMessage {
    pub hashes: Vec<Hash>,
}

impl GetBlocksMessage {
    /// Validate the message to prevent DoS attacks
    pub fn validate(&self) -> Result<()> {
        if self.hashes.len() > MAX_BLOCK_HASHES {
            return Err(Error::ProtocolError(format!(
                "too many block hashes: {} > {}",
                self.hashes.len(),
                MAX_BLOCK_HASHES
            )));
        }
        Ok(())
    }
}

/// v1.0.13 #2 — `NotFound` reply to GetTxs/GetData for items the
/// receiver doesn't have. Mirrors the request shape exactly so the
/// requester can mark each absent hash in its absence cache.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct NotFoundMessage {
    pub hashes: Vec<Hash>,
}

impl NotFoundMessage {
    pub fn validate(&self) -> Result<()> {
        // Bounded at MAX_BLOCK_HASHES (500) — same cap as the GetData/
        // GetTxs requests it answers.
        if self.hashes.len() > MAX_BLOCK_HASHES {
            return Err(Error::ProtocolError(format!(
                "NotFound has too many hashes: {} > {}",
                self.hashes.len(),
                MAX_BLOCK_HASHES,
            )));
        }
        Ok(())
    }
}

/// Blocks response
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BlocksMessage {
    pub blocks: Vec<Block>,
}

impl BlocksMessage {
    /// SECURITY (BUG-15): Validate block count to prevent DoS via unbounded allocations.
    /// Must be called after deserialization to reject oversized messages.
    pub fn validate(&self) -> Result<()> {
        if self.blocks.len() > MAX_BLOCK_HASHES {
            return Err(Error::InvalidState(format!(
                "BlocksMessage contains {} blocks (max {})",
                self.blocks.len(),
                MAX_BLOCK_HASHES
            )));
        }
        Ok(())
    }
}

/// Inventory vector
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct InvVector {
    pub inv_type: u8,
    pub hash: Hash,
}

/// Inventory message
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct InvMessage {
    pub inventory: Vec<InvVector>,
}

impl InvMessage {
    /// Validate the message to prevent DoS attacks.
    ///
    /// In addition to the size cap, reject duplicate hashes. Pre-fix
    /// a peer could send MAX_INV_SIZE invs all referencing the same
    /// hash; the InvTx/InvBlock handlers would push the duplicate
    /// into `needed` MAX_INV_SIZE times and emit a GetTxs/GetBlocks
    /// asking for the same item that many times in one message.
    /// Wasted bandwidth was bounded but real across many peers, and
    /// the receiver may double-process the same payload.
    ///
    /// Prior art: Bitcoin Core's `ProcessMessage` Inv handler caps
    /// at MAX_INV_SZ (50,000) AND rejects duplicates via the
    /// `m_recent_rejects` filter; we apply the dup check at the
    /// validate-message layer so the rejection signals a malformed
    /// envelope rather than per-item state.
    pub fn validate(&self) -> Result<()> {
        if self.inventory.len() > MAX_INV_SIZE {
            return Err(Error::ProtocolError(format!(
                "too many inventory items: {} > {}",
                self.inventory.len(),
                MAX_INV_SIZE
            )));
        }
        let mut seen = std::collections::HashSet::with_capacity(self.inventory.len());
        for inv in &self.inventory {
            if !seen.insert(inv.hash) {
                return Err(Error::ProtocolError("duplicate inventory hash".to_string()));
            }
        }
        Ok(())
    }
}

/// Transactions message
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct TxsMessage {
    pub transactions: Vec<Transaction>,
}

impl TxsMessage {
    /// Validate the message to prevent DoS attacks
    pub fn validate(&self) -> Result<()> {
        if self.transactions.len() > MAX_TXS_PER_MESSAGE {
            return Err(Error::ProtocolError(format!(
                "too many transactions: {} > {}",
                self.transactions.len(),
                MAX_TXS_PER_MESSAGE
            )));
        }
        Ok(())
    }
}

/// Address message
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct AddrMessage {
    pub addresses: Vec<NetAddr>,
}

impl AddrMessage {
    /// Validate the message to prevent DoS attacks
    pub fn validate(&self) -> Result<()> {
        if self.addresses.len() > MAX_ADDR_SIZE {
            return Err(Error::ProtocolError(format!(
                "too many addresses: {} > {}",
                self.addresses.len(),
                MAX_ADDR_SIZE
            )));
        }
        Ok(())
    }
}

/// Network address
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct NetAddr {
    pub services: u64,
    pub ip: [u8; 16],
    pub port: u16,
    pub timestamp: u64,
}

/// Reject message
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct RejectMessage {
    pub message: String,
    pub code: u8,
    pub reason: String,
    pub data: Vec<u8>,
}

impl RejectMessage {
    /// Validate the message to prevent DoS attacks.
    ///
    /// Audit fix: previously only `reason` and `data` were length-checked,
    /// leaving `message` unbounded. A malicious peer could send a Reject
    /// with a 16 MB `message` field; borsh would happily allocate the
    /// full Vec for the String length prefix before `validate()` ever
    /// ran, OOM-bombing the node. The fix caps `message.len()` at
    /// `MAX_REJECT_REASON_LENGTH` before any borsh allocation can
    /// occur.
    pub fn validate(&self) -> Result<()> {
        if self.message.len() > MAX_REJECT_REASON_LENGTH {
            return Err(Error::ProtocolError(format!(
                "reject message too long: {} > {}",
                self.message.len(),
                MAX_REJECT_REASON_LENGTH
            )));
        }
        if self.reason.len() > MAX_REJECT_REASON_LENGTH {
            return Err(Error::ProtocolError(format!(
                "reject reason too long: {} > {}",
                self.reason.len(),
                MAX_REJECT_REASON_LENGTH
            )));
        }
        if self.data.len() > MAX_REJECT_DATA_SIZE {
            return Err(Error::ProtocolError(format!(
                "reject data too large: {} > {}",
                self.data.len(),
                MAX_REJECT_DATA_SIZE
            )));
        }
        Ok(())
    }
}

/// Ping/Pong message
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct PingPongMessage {
    pub nonce: u64,
}

/// Network message
#[derive(Clone, Debug)]
pub struct Message {
    pub header: MessageHeader,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn new(magic: [u8; 4], msg_type: MessageType, payload: Vec<u8>) -> Self {
        let header = MessageHeader::new(magic, msg_type, &payload);
        Message { header, payload }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let header_bytes =
            borsh::to_vec(&self.header).map_err(|e| Error::SerializationError(e.to_string()))?;
        let mut bytes = header_bytes;
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    pub fn msg_type(&self) -> Result<MessageType> {
        MessageType::try_from(self.header.msg_type)
    }

    pub fn version(magic: [u8; 4], height: u64, best_hash: Hash) -> Result<Self> {
        let msg = VersionMessage::new(height, best_hash);
        let payload = borsh::to_vec(&msg).map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(Self::new(magic, MessageType::Version, payload))
    }

    /// Create version message with a specific nonce (for self-connection detection)
    pub fn version_with_nonce(
        magic: [u8; 4],
        height: u64,
        best_hash: Hash,
        nonce: u64,
    ) -> Result<Self> {
        let msg = VersionMessage::with_nonce(height, best_hash, nonce);
        let payload = borsh::to_vec(&msg).map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(Self::new(magic, MessageType::Version, payload))
    }

    pub fn verack(magic: [u8; 4]) -> Self {
        Self::new(magic, MessageType::Verack, vec![])
    }

    /// Firework capability advertisement, sent right after Verack. Carries
    /// the u64 capability bitfield from [`crate::network::firework::local_capabilities`].
    pub fn flare(magic: [u8; 4], capabilities: u64) -> Result<Self> {
        let msg = FlareMessage { capabilities };
        let payload = borsh::to_vec(&msg).map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(Self::new(magic, MessageType::Flare, payload))
    }

    /// Cumulative chain-work advertisement (Firework `CAP_CHAINWORK`). Only
    /// sent to peers that advertised the capability in their Flare.
    pub fn chain_work(
        magic: [u8; 4],
        total_difficulty: u128,
        height: u64,
        best_hash: Hash,
    ) -> Result<Self> {
        let msg = ChainWorkMessage {
            total_difficulty,
            height,
            best_hash,
        };
        let payload = borsh::to_vec(&msg).map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(Self::new(magic, MessageType::ChainWork, payload))
    }

    pub fn ping(magic: [u8; 4]) -> Self {
        use rand::RngCore;
        let mut nonce = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let msg = PingPongMessage {
            nonce: u64::from_le_bytes(nonce),
        };
        // INVARIANT: PingPongMessage is a single u64 wrapper — borsh writes 8
        // bytes with no I/O and no fallible step. Changing the type's layout
        // (e.g., adding a Vec field) would break this invariant and re-introduce
        // a panic-in-network-hot-path. If the type grows, switch to a fallible
        // helper that returns Result<Self> and update node.rs:1511 + 2578.
        let payload = borsh::to_vec(&msg).expect("PingPongMessage borsh: single u64, infallible");
        Self::new(magic, MessageType::Ping, payload)
    }

    pub fn pong(magic: [u8; 4], nonce: u64) -> Self {
        let msg = PingPongMessage { nonce };
        // INVARIANT: see ping() above — borsh of a single u64 is infallible.
        let payload = borsh::to_vec(&msg).expect("PingPongMessage borsh: single u64, infallible");
        Self::new(magic, MessageType::Pong, payload)
    }

    pub fn get_headers(magic: [u8; 4], locator: Vec<Hash>, stop_hash: Hash) -> Result<Self> {
        Self::get_headers_with_nonce(magic, locator, stop_hash, 0)
    }

    pub fn get_headers_with_nonce(
        magic: [u8; 4],
        locator: Vec<Hash>,
        stop_hash: Hash,
        nonce: u64,
    ) -> Result<Self> {
        let msg = GetHeadersMessage {
            locator,
            stop_hash,
            nonce,
        };
        let payload = borsh::to_vec(&msg).map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(Self::new(magic, MessageType::GetHeaders, payload))
    }

    pub fn headers(magic: [u8; 4], headers: Vec<crate::consensus::BlockHeader>) -> Result<Self> {
        Self::headers_with_nonce(magic, headers, 0)
    }

    pub fn headers_with_nonce(
        magic: [u8; 4],
        headers: Vec<crate::consensus::BlockHeader>,
        nonce: u64,
    ) -> Result<Self> {
        let msg = HeadersMessage { headers, nonce };
        let payload = borsh::to_vec(&msg).map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(Self::new(magic, MessageType::Headers, payload))
    }

    pub fn inv_block(magic: [u8; 4], hash: Hash) -> Result<Self> {
        let msg = InvMessage {
            inventory: vec![InvVector { inv_type: 2, hash }],
        };
        let payload = borsh::to_vec(&msg).map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(Self::new(magic, MessageType::InvBlock, payload))
    }

    pub fn inv_tx(magic: [u8; 4], hash: Hash) -> Result<Self> {
        let msg = InvMessage {
            inventory: vec![InvVector { inv_type: 1, hash }],
        };
        let payload = borsh::to_vec(&msg).map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(Self::new(magic, MessageType::InvTx, payload))
    }

    /// v1.0.13 #2 — build a NotFound reply for a list of absent hashes.
    pub fn not_found(magic: [u8; 4], hashes: Vec<Hash>) -> Result<Self> {
        let msg = NotFoundMessage { hashes };
        let payload = borsh::to_vec(&msg).map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(Self::new(magic, MessageType::NotFound, payload))
    }

    pub fn blocks(magic: [u8; 4], blocks: Vec<Block>) -> Result<Self> {
        let msg = BlocksMessage { blocks };
        let payload = borsh::to_vec(&msg).map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(Self::new(magic, MessageType::Blocks, payload))
    }

    pub fn txs(magic: [u8; 4], transactions: Vec<Transaction>) -> Result<Self> {
        let msg = TxsMessage { transactions };
        let payload = borsh::to_vec(&msg).map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(Self::new(magic, MessageType::Txs, payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MAINNET_MAGIC;

    #[test]
    fn test_message_creation() {
        let msg = Message::ping(MAINNET_MAGIC);
        assert_eq!(msg.header.magic, MAINNET_MAGIC);
        assert_eq!(msg.header.msg_type, MessageType::Ping as u8);
    }

    #[test]
    fn test_version_message() {
        let msg = Message::version(MAINNET_MAGIC, 100, Hash::zero()).unwrap();
        assert_eq!(msg.msg_type().unwrap(), MessageType::Version);
    }

    #[test]
    fn flare_message_round_trips() {
        let caps = crate::network::firework::CAP_CHAINWORK | (1 << 40);
        let msg = Message::flare(MAINNET_MAGIC, caps).unwrap();
        assert_eq!(msg.msg_type().unwrap(), MessageType::Flare);
        let decoded: FlareMessage = borsh::from_slice(&msg.payload).unwrap();
        assert_eq!(decoded.capabilities, caps);
    }

    #[test]
    fn chain_work_message_round_trips() {
        let td: u128 = 123_456_789_012_345_678_901;
        let h = Hash::from_bytes([9u8; 32]);
        let msg = Message::chain_work(MAINNET_MAGIC, td, 10_042, h).unwrap();
        assert_eq!(msg.msg_type().unwrap(), MessageType::ChainWork);
        // Within the per-type size cap.
        assert!(msg.payload.len() <= MessageType::ChainWork.max_size());
        let decoded: ChainWorkMessage = borsh::from_slice(&msg.payload).unwrap();
        assert_eq!(decoded.total_difficulty, td);
        assert_eq!(decoded.height, 10_042);
        assert_eq!(decoded.best_hash, h);
    }

    #[test]
    fn chain_work_type_byte_is_51_and_decodes() {
        // Guards the wire discriminant: a peer that predates ChainWork must
        // see byte 51, and TryFrom must map it back.
        assert_eq!(MessageType::ChainWork as u8, 51);
        assert_eq!(MessageType::try_from(51u8).unwrap(), MessageType::ChainWork);
    }

    /// InvMessage::validate rejects duplicates. Pre-fix the only check
    /// was the size cap; a peer could ship MAX_INV_SIZE invs all
    /// referencing the same hash and the receiver's GetTxs/GetBlocks
    /// would re-request the same item that many times in one message.
    #[test]
    fn inv_validate_rejects_duplicate_hashes() {
        let h = Hash::from_bytes([7u8; 32]);
        let msg = InvMessage {
            inventory: vec![
                InvVector {
                    inv_type: 1,
                    hash: h,
                },
                InvVector {
                    inv_type: 1,
                    hash: h,
                }, // dup
            ],
        };
        let err = msg.validate().unwrap_err();
        let s = format!("{:?}", err).to_lowercase();
        assert!(s.contains("duplicate"), "must cite duplicate, got: {}", s);
    }

    /// A well-formed InvMessage with all-distinct hashes still passes.
    #[test]
    fn inv_validate_accepts_distinct_hashes() {
        let msg = InvMessage {
            inventory: vec![
                InvVector {
                    inv_type: 1,
                    hash: Hash::from_bytes([1u8; 32]),
                },
                InvVector {
                    inv_type: 1,
                    hash: Hash::from_bytes([2u8; 32]),
                },
                InvVector {
                    inv_type: 1,
                    hash: Hash::from_bytes([3u8; 32]),
                },
            ],
        };
        assert!(msg.validate().is_ok());
    }

    /// Distinct hashes carrying the same `inv_type` are not duplicates —
    /// the dedup check operates on hash only, matching the semantic
    /// "same target item." Different hashes = different items even when
    /// of the same type.
    #[test]
    fn inv_validate_distinct_hashes_same_type_pass() {
        let msg = InvMessage {
            inventory: vec![
                InvVector {
                    inv_type: 2,
                    hash: Hash::from_bytes([10u8; 32]),
                },
                InvVector {
                    inv_type: 2,
                    hash: Hash::from_bytes([11u8; 32]),
                },
            ],
        };
        assert!(msg.validate().is_ok());
    }

    // ── Test helpers (audit test-plan additions) ────────────────────────
    use crate::consensus::BlockHeader;
    use crate::primitives::{Amount, PublicKey};
    use crate::transaction::TxType;

    /// The full set of wire discriminants `TryFrom<u8>` accepts. This is the
    /// authoritative list mirrored from the `TryFrom` impl; any drift between
    /// this and the impl is a wire-compatibility break the sweep tests catch.
    const VALID_DISCRIMINANTS: &[u8] = &[
        0, 1, 2, 3, 10, 11, 12, 13, 14, 15, 20, 21, 22, 23, 24, 30, 31, 40, 41, 50, 51, 60, 61, 62,
        63, 64, 65, 70, 71, 80, 81, 99,
    ];

    /// n distinct hashes (varying the first two bytes so counts up to ~65k
    /// stay unique — matters only where dedup is enforced, but cheap to keep).
    fn distinct_hashes(n: usize) -> Vec<Hash> {
        (0..n)
            .map(|i| {
                let mut b = [0u8; 32];
                b[0] = (i & 0xff) as u8;
                b[1] = ((i >> 8) & 0xff) as u8;
                Hash::from_bytes(b)
            })
            .collect()
    }

    fn version_msg(version: u32, user_agent: String) -> VersionMessage {
        VersionMessage {
            version,
            services: 1,
            timestamp: 0,
            nonce: 0,
            user_agent,
            start_height: 0,
            best_hash: Hash::zero(),
        }
    }

    fn tiny_header() -> BlockHeader {
        BlockHeader {
            network_magic: MAINNET_MAGIC,
            version: 0,
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
        }
    }

    fn tiny_tx() -> Transaction {
        Transaction {
            version: 0,
            tx_type: TxType::Transfer,
            inputs: vec![],
            outputs: vec![],
            fee: Amount::from_atomic(0),
            range_proof: vec![],
            extra: vec![],
        }
    }

    fn tiny_block() -> Block {
        Block {
            header: tiny_header(),
            transactions: vec![],
        }
    }

    fn tiny_addr() -> NetAddr {
        NetAddr {
            services: 0,
            ip: [0u8; 16],
            port: 0,
            timestamp: 0,
        }
    }

    // ── MessageType discriminant + max_size properties ──────────────────

    /// Every defined discriminant maps to a variant and round-trips back to
    /// the same byte (`try_from(x as u8) as u8 == x`), guarding discriminant
    /// stability for the whole enum, not just ChainWork==51.
    #[test]
    fn message_type_try_from_accepts_and_round_trips_all_defined_discriminants() {
        for &b in VALID_DISCRIMINANTS {
            let variant = MessageType::try_from(b)
                .unwrap_or_else(|_| panic!("discriminant {} must be accepted", b));
            assert_eq!(variant as u8, b, "discriminant {} must round-trip", b);
        }
        assert_eq!(
            VALID_DISCRIMINANTS.len(),
            32,
            "expected 32 defined message types"
        );
    }

    /// Every byte NOT in the defined set is rejected — full 0..=255 sweep,
    /// covering all gaps (4-9, 16-19, 25-29, 32-39, 42-49, 52-59, 66-69,
    /// 72-79, 82-98, 100-255).
    #[test]
    fn message_type_try_from_rejects_all_undefined_bytes() {
        for b in 0u8..=255 {
            let expected_ok = VALID_DISCRIMINANTS.contains(&b);
            assert_eq!(
                MessageType::try_from(b).is_ok(),
                expected_ok,
                "byte {} acceptance mismatch",
                b
            );
        }
    }

    /// Every message type's per-command cap is positive and never exceeds the
    /// global MAX_MESSAGE_SIZE (the framer relies on this ordering).
    #[test]
    fn every_max_size_is_positive_and_within_global_cap() {
        for &b in VALID_DISCRIMINANTS {
            let variant = MessageType::try_from(b).unwrap();
            let cap = variant.max_size();
            assert!(cap > 0, "{:?} max_size must be > 0", variant);
            assert!(
                cap <= MAX_MESSAGE_SIZE,
                "{:?} max_size {} exceeds MAX_MESSAGE_SIZE {}",
                variant,
                cap,
                MAX_MESSAGE_SIZE
            );
        }
    }

    // ── MessageHeader validate / verify_checksum / round-trip ───────────

    #[test]
    fn message_header_validate_rejects_wrong_magic() {
        let header = MessageHeader::new(MAINNET_MAGIC, MessageType::Ping, &[1, 2, 3]);
        let wrong_magic = [0xAA, 0xBB, 0xCC, 0xDD];
        assert!(header.validate(wrong_magic).is_err());
    }

    #[test]
    fn message_header_validate_rejects_length_over_max() {
        let mut header = MessageHeader::new(MAINNET_MAGIC, MessageType::Blocks, &[]);
        header.length = (MAX_MESSAGE_SIZE + 1) as u32;
        assert!(matches!(
            header.validate(MAINNET_MAGIC),
            Err(Error::MessageTooLarge)
        ));
    }

    #[test]
    fn message_header_validate_accepts_good_magic_and_length() {
        let header = MessageHeader::new(MAINNET_MAGIC, MessageType::Ping, &[1, 2, 3]);
        assert!(header.validate(MAINNET_MAGIC).is_ok());
    }

    /// verify_checksum must fail on any single-bit flip in the payload AND on
    /// any single-bit flip in the stored checksum.
    #[test]
    fn verify_checksum_fails_on_single_bit_flip() {
        let payload: Vec<u8> = (0u8..64).collect();
        let header = MessageHeader::new(MAINNET_MAGIC, MessageType::Blocks, &payload);
        assert!(header.verify_checksum(&payload));

        for bit in 0..(payload.len() * 8) {
            let mut flipped = payload.clone();
            flipped[bit / 8] ^= 1 << (bit % 8);
            assert!(
                !header.verify_checksum(&flipped),
                "flip at bit {} must fail checksum",
                bit
            );
        }

        // Flipping the stored checksum also fails against the true payload.
        for i in 0..4 {
            let mut bad = header.clone();
            bad.checksum[i] ^= 0x01;
            assert!(!bad.verify_checksum(&payload));
        }
    }

    /// `to_bytes` then re-parse of the leading header yields identical
    /// magic/type/length/checksum.
    #[test]
    fn to_bytes_then_reparse_header_is_identical() {
        let payload = vec![0xABu8; 200];
        let msg = Message::new(MAINNET_MAGIC, MessageType::Blocks, payload.clone());
        let bytes = msg.to_bytes().unwrap();
        let parsed: MessageHeader =
            borsh::from_slice(&bytes[..MessageHeader::SIZE]).expect("header must reparse");
        assert_eq!(parsed.magic, msg.header.magic);
        assert_eq!(parsed.msg_type, msg.header.msg_type);
        assert_eq!(parsed.length, msg.header.length);
        assert_eq!(parsed.length as usize, payload.len());
        assert_eq!(parsed.checksum, msg.header.checksum);
    }

    // ── VersionMessage::validate ────────────────────────────────────────

    /// user_agent boundary: exactly MAX_USER_AGENT_LENGTH (256) passes, 257
    /// is rejected.
    #[test]
    fn version_validate_user_agent_boundary_256_ok_257_err() {
        let ok = version_msg(PROTOCOL_VERSION, "a".repeat(MAX_USER_AGENT_LENGTH));
        assert!(ok.validate().is_ok());

        let too_long = version_msg(PROTOCOL_VERSION, "a".repeat(MAX_USER_AGENT_LENGTH + 1));
        assert!(matches!(
            too_long.validate(),
            Err(Error::ProtocolError(_))
        ));
    }

    /// Protocol versions below MIN and above MAX are rejected; MIN and MAX
    /// themselves are accepted.
    #[test]
    fn version_validate_rejects_unsupported_protocol_versions() {
        let below = version_msg(MIN_SUPPORTED_PROTOCOL_VERSION - 1, "x".into());
        assert!(matches!(
            below.validate(),
            Err(Error::UnsupportedProtocolVersion { .. })
        ));

        let above = version_msg(MAX_SUPPORTED_PROTOCOL_VERSION + 1, "x".into());
        assert!(matches!(
            above.validate(),
            Err(Error::UnsupportedProtocolVersion { .. })
        ));

        assert!(version_msg(MIN_SUPPORTED_PROTOCOL_VERSION, "x".into())
            .validate()
            .is_ok());
        assert!(version_msg(MAX_SUPPORTED_PROTOCOL_VERSION, "x".into())
            .validate()
            .is_ok());
    }

    // ── Per-message count / length caps ─────────────────────────────────

    #[test]
    fn get_headers_validate_locator_boundary_64_ok_65_err() {
        let ok = GetHeadersMessage {
            locator: distinct_hashes(MAX_LOCATOR_SIZE),
            stop_hash: Hash::zero(),
            nonce: 0,
        };
        assert!(ok.validate().is_ok());

        let too_many = GetHeadersMessage {
            locator: distinct_hashes(MAX_LOCATOR_SIZE + 1),
            stop_hash: Hash::zero(),
            nonce: 0,
        };
        assert!(too_many.validate().is_err());
    }

    #[test]
    fn headers_validate_boundary_2000_ok_2001_err() {
        let ok = HeadersMessage {
            headers: vec![tiny_header(); MAX_HEADERS_RESPONSE],
            nonce: 0,
        };
        assert!(ok.validate().is_ok());

        let too_many = HeadersMessage {
            headers: vec![tiny_header(); MAX_HEADERS_RESPONSE + 1],
            nonce: 0,
        };
        assert!(too_many.validate().is_err());
    }

    #[test]
    fn get_blocks_validate_boundary_500_ok_501_err() {
        let ok = GetBlocksMessage {
            hashes: distinct_hashes(MAX_BLOCK_HASHES),
        };
        assert!(ok.validate().is_ok());

        let too_many = GetBlocksMessage {
            hashes: distinct_hashes(MAX_BLOCK_HASHES + 1),
        };
        assert!(too_many.validate().is_err());
    }

    #[test]
    fn blocks_validate_boundary_500_ok_501_err() {
        let ok = BlocksMessage {
            blocks: vec![tiny_block(); MAX_BLOCK_HASHES],
        };
        assert!(ok.validate().is_ok());

        let too_many = BlocksMessage {
            blocks: vec![tiny_block(); MAX_BLOCK_HASHES + 1],
        };
        assert!(matches!(
            too_many.validate(),
            Err(Error::InvalidState(_))
        ));
    }

    #[test]
    fn not_found_validate_boundary_500_ok_501_err() {
        let ok = NotFoundMessage {
            hashes: distinct_hashes(MAX_BLOCK_HASHES),
        };
        assert!(ok.validate().is_ok());

        let too_many = NotFoundMessage {
            hashes: distinct_hashes(MAX_BLOCK_HASHES + 1),
        };
        assert!(too_many.validate().is_err());
    }

    #[test]
    fn txs_validate_boundary_100_ok_101_err() {
        let ok = TxsMessage {
            transactions: vec![tiny_tx(); MAX_TXS_PER_MESSAGE],
        };
        assert!(ok.validate().is_ok());

        let too_many = TxsMessage {
            transactions: vec![tiny_tx(); MAX_TXS_PER_MESSAGE + 1],
        };
        assert!(too_many.validate().is_err());
    }

    #[test]
    fn addr_validate_boundary_1000_ok_1001_err() {
        let ok = AddrMessage {
            addresses: vec![tiny_addr(); MAX_ADDR_SIZE],
        };
        assert!(ok.validate().is_ok());

        let too_many = AddrMessage {
            addresses: vec![tiny_addr(); MAX_ADDR_SIZE + 1],
        };
        assert!(too_many.validate().is_err());
    }

    /// InvMessage: exactly MAX_INV_SIZE distinct hashes passes; one more fails
    /// on the size cap (distinct hashes so the dup check is not what trips).
    #[test]
    fn inv_validate_exactly_max_size_passes_plus_one_fails() {
        let ok = InvMessage {
            inventory: distinct_hashes(MAX_INV_SIZE)
                .into_iter()
                .map(|hash| InvVector { inv_type: 1, hash })
                .collect(),
        };
        assert!(ok.validate().is_ok());

        let too_many = InvMessage {
            inventory: distinct_hashes(MAX_INV_SIZE + 1)
                .into_iter()
                .map(|hash| InvVector { inv_type: 1, hash })
                .collect(),
        };
        assert!(too_many.validate().is_err());
    }

    /// RejectMessage caps all three variable fields, including the
    /// historically-unbounded `message`.
    #[test]
    fn reject_validate_rejects_oversized_message_reason_and_data() {
        let base = || RejectMessage {
            message: "ok".into(),
            code: 1,
            reason: "ok".into(),
            data: vec![],
        };
        // Well-formed at the caps passes.
        let at_cap = RejectMessage {
            message: "a".repeat(MAX_REJECT_REASON_LENGTH),
            code: 1,
            reason: "b".repeat(MAX_REJECT_REASON_LENGTH),
            data: vec![0u8; MAX_REJECT_DATA_SIZE],
        };
        assert!(at_cap.validate().is_ok());

        let mut long_message = base();
        long_message.message = "a".repeat(MAX_REJECT_REASON_LENGTH + 1);
        assert!(long_message.validate().is_err());

        let mut long_reason = base();
        long_reason.reason = "a".repeat(MAX_REJECT_REASON_LENGTH + 1);
        assert!(long_reason.validate().is_err());

        let mut long_data = base();
        long_data.data = vec![0u8; MAX_REJECT_DATA_SIZE + 1];
        assert!(long_data.validate().is_err());
    }

    /// Borsh decode of each Vec/String-bearing message given an absurd length
    /// prefix (u32::MAX) with no following bytes must return Err promptly
    /// rather than pre-allocating gigabytes. A hang/OOM here is the bug this
    /// guards against; a fast `Err` return is the pass condition.
    #[test]
    fn borsh_decode_with_absurd_length_prefix_errs_without_preallocating() {
        let absurd = u32::MAX.to_le_bytes();

        // Types whose FIRST field is the Vec/String — the absurd prefix sits
        // at offset 0.
        assert!(borsh::from_slice::<InvMessage>(&absurd).is_err());
        assert!(borsh::from_slice::<AddrMessage>(&absurd).is_err());
        assert!(borsh::from_slice::<TxsMessage>(&absurd).is_err());
        assert!(borsh::from_slice::<HeadersMessage>(&absurd).is_err());
        assert!(borsh::from_slice::<GetBlocksMessage>(&absurd).is_err());
        assert!(borsh::from_slice::<NotFoundMessage>(&absurd).is_err());
        assert!(borsh::from_slice::<GetHeadersMessage>(&absurd).is_err());
        assert!(borsh::from_slice::<BlocksMessage>(&absurd).is_err());
        // RejectMessage.message is a String (length-prefixed) at offset 0.
        assert!(borsh::from_slice::<RejectMessage>(&absurd).is_err());

        // VersionMessage: fixed fields (u32 + 3×u64 = 28 bytes) precede the
        // user_agent String length prefix.
        let mut version_bytes = vec![0u8; 4 + 8 + 8 + 8];
        version_bytes.extend_from_slice(&absurd);
        assert!(borsh::from_slice::<VersionMessage>(&version_bytes).is_err());
    }
}
