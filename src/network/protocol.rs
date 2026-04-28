//! # Network Protocol Messages
//!
//! P2P protocol message definitions and serialization.

use crate::primitives::Hash;
use crate::consensus::Block;
use crate::transaction::Transaction;
use serde::{Serialize, Deserialize};
use borsh::{BorshSerialize, BorshDeserialize};
use crate::error::{Error, Result};
use crate::constants::{
    PROTOCOL_VERSION,
    MIN_SUPPORTED_PROTOCOL_VERSION,
    MAX_SUPPORTED_PROTOCOL_VERSION,
    is_protocol_version_supported,
};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
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
    GetAddr = 30,
    Addr = 31,
    Reject = 40,
    Alert = 41,
    /// Firework: Flare capability-negotiation message.
    /// Sent immediately after VERSION, before the select! loop.
    /// Carries a u64 bitfield of supported features. Unknown bits ignored.
    Flare = 50,

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
            30 => Ok(MessageType::GetAddr),
            31 => Ok(MessageType::Addr),
            40 => Ok(MessageType::Reject),
            41 => Ok(MessageType::Alert),
            50 => Ok(MessageType::Flare),
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
            MessageType::Version => 4 * 1024,       // 4 KB
            MessageType::Verack => 256,              // 256 bytes
            MessageType::Ping => 256,                // 256 bytes
            MessageType::Pong => 256,                // 256 bytes
            MessageType::Flare => 1024,              // 1 KB

            // Request messages: moderate
            MessageType::GetHeaders => 2 * 1024,     // 2 KB (locator hashes)
            MessageType::GetBlocks => 16 * 1024,     // 16 KB (hash list)
            MessageType::GetData => 16 * 1024,       // 16 KB
            MessageType::GetTxs => 16 * 1024,        // 16 KB
            MessageType::GetAddr => 256,             // 256 bytes

            // Data messages: large
            MessageType::Headers => 512 * 1024,      // 512 KB (up to 2000 headers)
            MessageType::Blocks => MAX_MESSAGE_SIZE,  // 16 MB (block data)
            MessageType::BlockData => 4 * 1024 * 1024, // 4 MB (single block)
            MessageType::Txs => 4 * 1024 * 1024,    // 4 MB (transaction batch)

            // Inventory: moderate
            MessageType::InvTx => 64 * 1024,         // 64 KB
            MessageType::InvBlock => 64 * 1024,      // 64 KB

            // Peer addresses: moderate
            MessageType::Addr => 256 * 1024,         // 256 KB

            // Meta messages: small
            MessageType::Reject => 4 * 1024,         // 4 KB
            MessageType::Alert => 64 * 1024,         // 64 KB

            // Personal node (Tier 1) messages
            MessageType::GetFilters => 1024,          // 1 KB (height range request)
            MessageType::Filters => 2 * 1024 * 1024,  // 2 MB (batch of GCS filters)
            MessageType::GetOutputDigests => 16 * 1024, // 16 KB (height list)
            MessageType::OutputDigests => 4 * 1024 * 1024, // 4 MB (output digests)
            MessageType::GetFilterCheckpoints => 1024,  // 1 KB
            MessageType::FilterCheckpoints => 256 * 1024, // 256 KB

            // Network node (Tier 2) DHT messages
            MessageType::GetKeyImageStatus => 4 * 1024, // 4 KB (key image query)
            MessageType::KeyImageStatus => 4 * 1024,    // 4 KB (spend status)

            // ChainAnchorStamp (Invention 2) — small, bounded payloads
            MessageType::AnchorRequest  => 1024,        // 1 KB
            MessageType::AnchorResponse => 1024,        // 1 KB
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
    /// Validate the message to prevent DoS attacks
    pub fn validate(&self) -> Result<()> {
        if self.inventory.len() > MAX_INV_SIZE {
            return Err(Error::ProtocolError(format!(
                "too many inventory items: {} > {}",
                self.inventory.len(),
                MAX_INV_SIZE
            )));
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
    /// Validate the message to prevent DoS attacks
    pub fn validate(&self) -> Result<()> {
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
        let header_bytes = borsh::to_vec(&self.header)
            .map_err(|e| Error::SerializationError(e.to_string()))?;
        let mut bytes = header_bytes;
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    pub fn msg_type(&self) -> Result<MessageType> {
        MessageType::try_from(self.header.msg_type)
    }

    pub fn version(magic: [u8; 4], height: u64, best_hash: Hash) -> Result<Self> {
        let msg = VersionMessage::new(height, best_hash);
        let payload = borsh::to_vec(&msg)
            .map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(Self::new(magic, MessageType::Version, payload))
    }

    /// Create version message with a specific nonce (for self-connection detection)
    pub fn version_with_nonce(magic: [u8; 4], height: u64, best_hash: Hash, nonce: u64) -> Result<Self> {
        let msg = VersionMessage::with_nonce(height, best_hash, nonce);
        let payload = borsh::to_vec(&msg)
            .map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(Self::new(magic, MessageType::Version, payload))
    }

    pub fn verack(magic: [u8; 4]) -> Self {
        Self::new(magic, MessageType::Verack, vec![])
    }

    pub fn ping(magic: [u8; 4]) -> Self {
        use rand::RngCore;
        let mut nonce = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let msg = PingPongMessage { nonce: u64::from_le_bytes(nonce) };
        // SECURITY: PingPongMessage is a simple struct that should always serialize
        let payload = borsh::to_vec(&msg).expect("PingPongMessage serialization should never fail");
        Self::new(magic, MessageType::Ping, payload)
    }

    pub fn pong(magic: [u8; 4], nonce: u64) -> Self {
        let msg = PingPongMessage { nonce };
        // SECURITY: PingPongMessage is a simple struct that should always serialize
        let payload = borsh::to_vec(&msg).expect("PingPongMessage serialization should never fail");
        Self::new(magic, MessageType::Pong, payload)
    }

    pub fn get_headers(magic: [u8; 4], locator: Vec<Hash>, stop_hash: Hash) -> Result<Self> {
        Self::get_headers_with_nonce(magic, locator, stop_hash, 0)
    }

    pub fn get_headers_with_nonce(magic: [u8; 4], locator: Vec<Hash>, stop_hash: Hash, nonce: u64) -> Result<Self> {
        let msg = GetHeadersMessage { locator, stop_hash, nonce };
        let payload = borsh::to_vec(&msg)
            .map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(Self::new(magic, MessageType::GetHeaders, payload))
    }

    pub fn headers(magic: [u8; 4], headers: Vec<crate::consensus::BlockHeader>) -> Result<Self> {
        Self::headers_with_nonce(magic, headers, 0)
    }

    pub fn headers_with_nonce(magic: [u8; 4], headers: Vec<crate::consensus::BlockHeader>, nonce: u64) -> Result<Self> {
        let msg = HeadersMessage { headers, nonce };
        let payload = borsh::to_vec(&msg)
            .map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(Self::new(magic, MessageType::Headers, payload))
    }

    pub fn inv_block(magic: [u8; 4], hash: Hash) -> Result<Self> {
        let msg = InvMessage {
            inventory: vec![InvVector { inv_type: 2, hash }],
        };
        let payload = borsh::to_vec(&msg)
            .map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(Self::new(magic, MessageType::InvBlock, payload))
    }

    pub fn inv_tx(magic: [u8; 4], hash: Hash) -> Result<Self> {
        let msg = InvMessage {
            inventory: vec![InvVector { inv_type: 1, hash }],
        };
        let payload = borsh::to_vec(&msg)
            .map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(Self::new(magic, MessageType::InvTx, payload))
    }

    pub fn blocks(magic: [u8; 4], blocks: Vec<Block>) -> Result<Self> {
        let msg = BlocksMessage { blocks };
        let payload = borsh::to_vec(&msg)
            .map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(Self::new(magic, MessageType::Blocks, payload))
    }

    pub fn txs(magic: [u8; 4], transactions: Vec<Transaction>) -> Result<Self> {
        let msg = TxsMessage { transactions };
        let payload = borsh::to_vec(&msg)
            .map_err(|e| Error::SerializationError(e.to_string()))?;
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
}
