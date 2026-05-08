//! # RPC Method Discovery
//!
//! JSON-RPC service discovery following the `rpc.discover` convention.
//! Returns a catalog of all available methods, their parameters, and return types.

use serde_json::json;

/// Generate RPC method discovery document
pub fn rpc_methods_doc() -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "info": {
            "title": "CoinCync 1.0 JSON-RPC API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Privacy-focused cryptocurrency node and wallet RPC interface"
        },
        "methods": [
            {
                "name": "get_info",
                "description": "Get node status and chain info",
                "params": [],
                "result": {
                    "type": "object",
                    "fields": {
                        "version": "string - software version",
                        "network": "string - network name (testnet/mainnet)",
                        "height": "number - current block height",
                        "target_height": "number - sync target height",
                        "top_hash": "string - tip block hash (hex)",
                        "difficulty": "string - current difficulty",
                        "tx_pool_size": "number - mempool transaction count",
                        "synced": "boolean - whether node is synced"
                    }
                },
                "auth": false
            },
            {
                "name": "get_block_count",
                "description": "Get current block height",
                "params": [],
                "result": { "type": "number", "description": "Current block height" },
                "auth": false
            },
            {
                "name": "get_peers",
                "description": "Get connected peer list",
                "params": [],
                "result": {
                    "type": "object",
                    "fields": {
                        "peers": "array of peer objects with id, addr, height, outbound, state"
                    }
                },
                "auth": false
            },
            {
                "name": "get_block_hash",
                "description": "Get block hash by height",
                "params": [
                    { "name": "height", "type": "number", "required": true }
                ],
                "result": { "type": "string", "description": "Block hash (hex)" },
                "auth": false
            },
            {
                "name": "get_block",
                "description": "Get block details by hash",
                "params": [
                    { "name": "hash", "type": "string", "required": true, "description": "Block hash (hex)" }
                ],
                "result": {
                    "type": "object",
                    "fields": {
                        "height": "number",
                        "hash": "string",
                        "prev_hash": "string",
                        "timestamp": "number",
                        "tx_count": "number",
                        "difficulty": "string",
                        "nonce": "number"
                    }
                },
                "auth": false
            },
            {
                "name": "get_block_by_height",
                "description": "Get block data by height (hex-encoded)",
                "params": [
                    { "name": "height", "type": "number", "required": true }
                ],
                "result": { "type": "string", "description": "Block data (hex)" },
                "auth": false
            },
            {
                "name": "get_block_template",
                "description": "Get block template for mining",
                "params": [
                    { "name": "miner_address", "type": "string", "required": true }
                ],
                "result": {
                    "type": "object",
                    "fields": {
                        "height": "number - next block height",
                        "prev_hash": "string - tip hash",
                        "difficulty": "string",
                        "timestamp": "number",
                        "tx_count": "number"
                    }
                },
                "auth": false
            },
            {
                "name": "get_tx_pool",
                "description": "Get mempool transaction list",
                "params": [],
                "result": {
                    "type": "object",
                    "fields": {
                        "count": "number",
                        "size": "number",
                        "transactions": "array of tx hashes"
                    }
                },
                "auth": false
            },
            {
                "name": "submit_block",
                "description": "Submit a mined block",
                "params": [
                    { "name": "block_hex", "type": "string", "required": true },
                    { "name": "api_key", "type": "string", "required": false }
                ],
                "result": { "type": "string", "description": "Block hash if accepted" },
                "auth": true
            },
            {
                "name": "submit_transaction",
                "description": "Submit a signed transaction",
                "params": [
                    { "name": "tx_hex", "type": "string", "required": true },
                    { "name": "api_key", "type": "string", "required": false }
                ],
                "result": { "type": "string", "description": "Transaction hash" },
                "auth": true
            },
            {
                "name": "get_balance",
                "description": "Get wallet balance",
                "params": [
                    { "name": "api_key", "type": "string", "required": false }
                ],
                "result": {
                    "type": "object",
                    "fields": {
                        "balance": "string - total balance (atomic units)",
                        "unlocked": "string - spendable balance",
                        "locked": "string - locked balance"
                    }
                },
                "auth": "optional"
            },
            {
                "name": "get_address",
                "description": "Get primary wallet address",
                "params": [
                    { "name": "api_key", "type": "string", "required": false }
                ],
                "result": {
                    "type": "object",
                    "fields": { "address": "string" }
                },
                "auth": "optional"
            },
            {
                "name": "create_subaddress",
                "description": "Generate a new subaddress for receiving",
                "params": [
                    { "name": "account", "type": "number", "required": false, "description": "Account index (default: 0)" },
                    { "name": "label", "type": "string", "required": false, "description": "Optional label" },
                    { "name": "api_key", "type": "string", "required": false }
                ],
                "result": {
                    "type": "object",
                    "fields": {
                        "address": "string - new subaddress",
                        "account": "number",
                        "index": "number",
                        "label": "string"
                    }
                },
                "auth": true
            },
            {
                "name": "get_subaddresses",
                "description": "List subaddresses for an account",
                "params": [
                    { "name": "account", "type": "number", "required": false, "description": "Account index (default: all)" },
                    { "name": "api_key", "type": "string", "required": false }
                ],
                "result": {
                    "type": "object",
                    "fields": {
                        "addresses": "array of {address, account, index, label, used}"
                    }
                },
                "auth": true
            },
            {
                "name": "label_subaddress",
                "description": "Set label on a subaddress",
                "params": [
                    { "name": "account", "type": "number", "required": true },
                    { "name": "index", "type": "number", "required": true },
                    { "name": "label", "type": "string", "required": true },
                    { "name": "api_key", "type": "string", "required": false }
                ],
                "result": {
                    "type": "object",
                    "fields": { "success": "boolean" }
                },
                "auth": true
            },
            {
                "name": "transfer",
                "description": "Create and sign a transaction",
                "params": [
                    { "name": "address", "type": "string", "required": true, "description": "Destination address" },
                    { "name": "amount", "type": "string", "required": true, "description": "Amount in atomic units" },
                    { "name": "api_key", "type": "string", "required": false }
                ],
                "result": {
                    "type": "object",
                    "fields": {
                        "tx_hash": "string",
                        "fee": "string",
                        "amount": "string"
                    }
                },
                "auth": true
            },
            {
                "name": "rpc.discover",
                "description": "Returns this service discovery document",
                "params": [],
                "result": { "type": "object", "description": "This document" },
                "auth": false
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_doc_is_valid_json() {
        let doc = rpc_methods_doc();
        // Verify it's a valid JSON object with expected top-level keys
        assert!(doc.get("jsonrpc").is_some());
        assert!(doc.get("info").is_some());
        assert!(doc.get("methods").is_some());
        // Verify methods is a non-empty array
        let methods = doc["methods"].as_array().unwrap();
        assert!(!methods.is_empty());
        // Verify get_info method exists
        let has_get_info = methods.iter().any(|m| m["name"] == "get_info");
        assert!(has_get_info, "discovery doc should include get_info method");
    }
}
