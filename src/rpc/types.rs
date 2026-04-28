//! # RPC Types
//!
//! Request and response types for JSON-RPC API.

use serde::{Serialize, Deserialize};

/// Block information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInfo {
    pub hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub prev_hash: String,
    pub merkle_root: String,
    pub difficulty: String,
    pub nonce: u64,
    pub tx_count: usize,
    pub size: usize,
    pub reward: String,
}

/// Transaction information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInfo {
    pub hash: String,
    pub block_hash: Option<String>,
    pub block_height: Option<u64>,
    pub timestamp: u64,
    pub fee: String,
    pub input_count: usize,
    pub output_count: usize,
    pub ring_size: usize,
    pub confirmations: u64,
}

/// UTXO information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoInfo {
    pub tx_hash: String,
    pub output_index: u32,
    pub amount: String,
    pub height: u64,
    pub unlocked: bool,
    pub key_image: Option<String>,
}

/// Balance information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceInfo {
    pub balance: String,
    pub unlocked_balance: String,
    pub locked_balance: String,
    pub pending_in: String,
    pub pending_out: String,
}

/// Address information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressInfo {
    pub address: String,
    pub label: String,
    pub address_index: u32,
    pub used: bool,
    pub balance: String,
}

/// Transfer destination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferDestination {
    pub address: String,
    pub amount: String,
}

/// Transfer request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRequest {
    pub destinations: Vec<TransferDestination>,
    pub priority: Option<u32>,
    pub mixin: Option<u32>,
    pub unlock_time: Option<u64>,
    pub payment_id: Option<String>,
}

/// Transfer response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferResponse {
    pub tx_hash: String,
    pub tx_key: String,
    pub fee: String,
    pub amount: String,
}

/// Asset send request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetSendRequest {
    /// Hex-encoded 32-byte asset ID
    pub asset_id: String,
    /// Recipient address
    pub address: String,
    /// Amount in atomic units (as string to avoid precision loss)
    pub amount: String,
}

/// Asset issuance request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetIssueRequest {
    /// Short name (≤32 ASCII bytes, e.g. "TUSDC")
    pub name: String,
    /// Decimal precision (e.g. 6)
    pub precision: u8,
    /// Initial supply in atomic units
    pub initial_supply: u64,
    /// Whether more can be minted later
    pub can_mint_more: bool,
}

/// Response common to both asset_send and asset_issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetTxResponse {
    pub tx_hash: String,
    pub asset_id: String,
    pub fee: String,
}

/// A single decrypted audit record for an output carrying a specific asset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetAuditRecord {
    /// Transaction hash containing the audited output.
    pub tx_hash: String,
    /// Output index within the transaction.
    pub output_index: u32,
    /// Block height the transaction was confirmed at (0 = unconfirmed).
    pub block_height: u64,
    /// Decrypted asset ID (hex).
    pub asset_id: String,
    /// Decrypted amount in atomic units.
    pub amount: String,
}

/// Request to audit all outputs of an asset using the issuer audit key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetAuditRequest {
    /// Hex-encoded 32-byte asset ID to audit.
    pub asset_id: String,
    /// Hex-encoded 32-byte audit secret key.
    pub audit_secret_key: String,
    /// Optional starting block height (default 0).
    pub from_height: Option<u64>,
}

/// Node sync status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    pub synced: bool,
    pub height: u64,
    pub target_height: u64,
    pub progress: f64,
    pub peers: u32,
}

/// Peer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: String,
    pub address: String,
    pub height: u64,
    pub latency_ms: u64,
    pub inbound: bool,
    pub state: String,
}

/// Mining status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningStatus {
    pub active: bool,
    pub threads: u32,
    pub hashrate: f64,
    pub difficulty: String,
    pub address: Option<String>,
}

/// Block template for mining
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTemplate {
    pub blob: String,
    pub difficulty: String,
    pub height: u64,
    pub prev_hash: String,
    pub expected_reward: String,
    pub reserved_offset: u32,
    pub seed_hash: String,
}

/// Submit block result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitBlockResult {
    pub accepted: bool,
    pub reason: Option<String>,
}

/// Network info.
///
/// `connections` is the total live peer count and is always known. The
/// per-direction (`incoming` / `outgoing`) and per-bucket (`white_peers` /
/// `grey_peers`) breakdowns are `Option<u32>` so a monitoring consumer can
/// distinguish "this stat is currently unavailable" (serialized as JSON
/// `null`) from "this stat is genuinely zero". Returning `0` for "unknown"
/// is exactly the kind of silent-stub bug that masks an eclipse attack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub network: String,
    pub version: String,
    pub protocol_version: u32,
    pub connections: u32,
    pub incoming: Option<u32>,
    pub outgoing: Option<u32>,
    pub white_peers: Option<u32>,
    pub grey_peers: Option<u32>,
}

/// Transaction pool stats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxPoolStats {
    pub count: usize,
    pub size: usize,
    pub fees: String,
    pub oldest_timestamp: u64,
}

/// Wallet info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInfo {
    pub address: String,
    pub view_key: String,
    pub height: u64,
    pub balance: String,
    pub unlocked_balance: String,
}

/// Key image
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyImageInfo {
    pub key_image: String,
    pub spent: bool,
    pub tx_hash: Option<String>,
}

/// Output info for wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputInfo {
    pub amount: String,
    pub index: u64,
    pub global_index: u64,
    pub tx_hash: String,
    pub tx_public_key: String,
    pub spent: bool,
    pub frozen: bool,
}

/// RPC error codes
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_info_serde_roundtrip() {
        let info = BlockInfo {
            hash: "abc123".to_string(),
            height: 42,
            timestamp: 1700000000,
            prev_hash: "def456".to_string(),
            merkle_root: "aaa".to_string(),
            difficulty: "1000".to_string(),
            nonce: 99,
            tx_count: 5,
            size: 2048,
            reward: "50000000000000".to_string(),
        };
        let json = serde_json::to_string(&info).unwrap();
        let deser: BlockInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.height, 42);
        assert_eq!(deser.hash, "abc123");
    }

    #[test]
    fn test_balance_info_serde_roundtrip() {
        let info = BalanceInfo {
            balance: "1000".to_string(),
            unlocked_balance: "900".to_string(),
            locked_balance: "100".to_string(),
            pending_in: "0".to_string(),
            pending_out: "50".to_string(),
        };
        let json = serde_json::to_string(&info).unwrap();
        let deser: BalanceInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.balance, "1000");
        assert_eq!(deser.locked_balance, "100");
    }
}

pub mod error_codes {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;

    // Custom error codes
    pub const WALLET_NOT_LOADED: i32 = -1;
    pub const INSUFFICIENT_FUNDS: i32 = -2;
    pub const INVALID_ADDRESS: i32 = -3;
    pub const TX_NOT_FOUND: i32 = -4;
    pub const BLOCK_NOT_FOUND: i32 = -5;
    pub const ALREADY_EXISTS: i32 = -6;
    pub const NOT_SYNCED: i32 = -7;
    pub const WALLET_LOCKED: i32 = -8;
}
