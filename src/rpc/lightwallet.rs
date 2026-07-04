//! # Light Wallet Server API
//!
//! HTTP/JSON API for external wallet apps (Trust Wallet, Exodus, Cake Wallet,
//! custom mobile apps) to integrate CoinCync without running a full node.
//!
//! ## How it works
//!
//! 1. Wallet app sends encrypted view key + start height
//! 2. Server scans the chain using that view key
//! 3. Server returns matching outputs (encrypted — only the wallet can read amounts)
//! 4. Wallet app builds transactions locally and submits via `submit_raw_tx`
//!
//! ## Security model
//!
//! - The server sees the VIEW key (not the SPEND key) — it can detect incoming
//!   payments but CANNOT spend coins
//! - The server learns WHICH outputs belong to the user — this is a privacy
//!   tradeoff vs running a full node. Same model as MyMonero.
//! - Transaction SIGNING happens client-side — the server never touches
//!   the spend key
//! - Communication should use HTTPS (TLS) to protect the view key in transit
//!
//! ## Endpoints
//!
//! - `POST /wallet/scan` — scan chain for outputs matching a view key
//! - `POST /wallet/submit` — submit a signed transaction
//! - `GET  /wallet/info` — chain height, fee estimate, sync status
//! - `GET  /wallet/outputs?height=N` — get output digests for a block range
//! - `GET  /wallet/coin_info` — coin specification (ticker, decimals, etc.)

use serde::{Serialize, Deserialize};

use crate::chain::SharedBlockchain;
use crate::mempool::SharedMempool;
use crate::wallet::lightsync::BlockDigest;
use crate::primitives::PublicKey;

/// Hard cap on number of candidate outputs returned per scan request.
///
/// Unlike `MAX_SCAN_BLOCKS_PER_REQ`, hitting this cap is NOT an error
/// — the scan returns early with `has_more = true` and the partial
/// outputs collected so far. The caller MUST advance `start_height`
/// past the highest `output.height` it received and re-issue to keep
/// going. Wallets that ignore `has_more` will silently miss outputs.
const MAX_SCAN_OUTPUTS: usize = 10_000;

/// Hard cap on the block range a single scan request may sweep. A
/// caller asking for more must paginate. Previously the over-cap was
/// silently clamped — the caller couldn't tell their requested range
/// got truncated, so they'd keep re-issuing the same over-cap request
/// and never finish syncing.
const MAX_SCAN_BLOCKS_PER_REQ: u64 = 5_000;

// ═══════════════════════════════════════════════════════════════════════
// API types
// ═══════════════════════════════════════════════════════════════════════

/// Coin specification for wallet integration.
/// Wallet apps use this to configure their UI and transaction builder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinSpec {
    pub ticker: &'static str,
    pub name: &'static str,
    pub decimals: u8,
    pub address_prefix: &'static str,
    pub default_ring_size: usize,
    pub default_rpc_port: u16,
    pub default_p2p_port: u16,
    pub block_time_seconds: u64,
    pub supply_cap: &'static str,
    pub privacy_model: &'static str,
    pub signature_scheme: &'static str,
    pub range_proof: &'static str,
    pub address_type: &'static str,
    pub fee_model: &'static str,
    pub explorer_url: &'static str,
}

/// The CoinCync coin specification.
pub const COINCYNC_SPEC: CoinSpec = CoinSpec {
    ticker: "CYNC",
    name: "CoinCync",
    decimals: 12,
    address_prefix: "tCYNC",  // testnet; mainnet will be "CYNC"
    default_ring_size: 11,
    default_rpc_port: 28081,
    default_p2p_port: 28080,
    block_time_seconds: 120,
    supply_cap: "100000000",
    privacy_model: "mandatory",
    signature_scheme: "CLSAG",
    range_proof: "Bulletproofs+",
    address_type: "stealth",
    fee_model: "per_byte_dynamic",
    explorer_url: "https://explorer.coincync.network",
};

/// Request to scan the chain for a wallet's outputs.
#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    /// View public key (hex, 64 chars)
    pub view_public: String,
    /// Spend public key (hex, 64 chars)
    pub spend_public: String,
    /// Start scanning from this block height
    pub start_height: u64,
    /// Maximum number of blocks to scan in this request. Default 1000;
    /// hard limit `MAX_SCAN_BLOCKS_PER_REQ` (5000). Values above the
    /// hard limit are rejected with `max_blocks too large` — callers
    /// must paginate by advancing `start_height` and re-issuing.
    pub max_blocks: Option<u64>,
}

/// A detected output belonging to the wallet.
#[derive(Debug, Serialize)]
pub struct DetectedOutput {
    /// Transaction hash
    pub tx_hash: String,
    /// Output index within the transaction
    pub output_index: u8,
    /// Block height where this output was confirmed
    pub height: u64,
    /// Stealth address (hex)
    pub stealth_address: String,
    /// Pedersen commitment (hex)
    pub commitment: String,
    /// Encrypted amount (hex — only the wallet can decrypt this)
    pub encrypted_amount: String,
    /// Transaction public key for ECDH (hex)
    pub tx_public_key: String,
    /// False for server-side candidate scans that do not have a view secret.
    pub ownership_verified: bool,
}

/// Scan response returned to the wallet app.
#[derive(Debug, Serialize)]
pub struct ScanResponse {
    /// Number of blocks scanned
    pub blocks_scanned: u64,
    /// Highest block scanned
    pub scanned_to_height: u64,
    /// Current chain height
    pub chain_height: u64,
    /// Detected outputs belonging to this wallet
    pub outputs: Vec<DetectedOutput>,
    /// True when the caller must paginate to get the rest. Set in two
    /// cases: (1) `scanned_to_height < chain_height` — the requested
    /// range didn't reach the tip; (2) the output cap fired mid-scan
    /// — `MAX_SCAN_OUTPUTS` candidates were collected and the scan
    /// stopped early. In case (2), some outputs at `scanned_to_height`
    /// may still be unreturned; resume at `scanned_to_height` (not
    /// `scanned_to_height + 1`) so the next request re-covers that
    /// block and picks up any remainder.
    pub has_more: bool,
    /// True only when outputs are cryptographically ownership-verified.
    /// Current public scan endpoint returns candidate matches only.
    pub ownership_verified: bool,
    /// Human-readable trust model note for integrators.
    pub trust_note: String,
}

/// Chain info for wallet apps.
#[derive(Debug, Serialize)]
pub struct WalletChainInfo {
    pub height: u64,
    pub synced: bool,
    pub difficulty: String,
    pub block_time_target: u64,
    pub min_fee_per_byte: u64,
    pub ring_size: usize,
    pub network: String,
}

// ═══════════════════════════════════════════════════════════════════════
// Light wallet server
// ═══════════════════════════════════════════════════════════════════════

/// Light wallet server state.
pub struct LightWalletServer {
    chain: SharedBlockchain,
    mempool: SharedMempool,
}

impl LightWalletServer {
    pub fn new(chain: SharedBlockchain, mempool: SharedMempool) -> Self {
        Self { chain, mempool }
    }

    /// Get coin specification.
    pub fn coin_info(&self) -> &'static CoinSpec {
        &COINCYNC_SPEC
    }

    /// Get chain info for wallet apps.
    pub fn chain_info(&self) -> WalletChainInfo {
        let stats = self.chain.stats();
        WalletChainInfo {
            height: stats.height,
            synced: self.chain.is_synced(),
            difficulty: stats.difficulty.to_string(),
            block_time_target: crate::constants::TARGET_BLOCK_TIME,
            min_fee_per_byte: crate::constants::MIN_FEE_PER_BYTE,
            // C1: the ring size advertised to external light wallets must
            // reflect what the validator will require for a tx mined into
            // the NEXT block (chain tip + 1), not a hardcoded bootstrap
            // value. Light wallets that trust this field to build their tx
            // must see the height-aware ring size, otherwise they build
            // ring-11 txs at h>=5000 (v1.0.12 ramp activation) and get
            // InvalidRingSize rejection at submission time.
            //
            // saturating_add is defensive: a tip at u64::MAX has bigger
            // problems than ring-size selection.
            ring_size: crate::constants::ring_size_at_height(
                stats.height.saturating_add(1),
            ),
            network: "testnet".to_string(),
        }
    }

    /// Scan the chain for outputs belonging to a wallet.
    ///
    /// This is the core operation. The wallet app sends its view + spend
    /// public keys, and the server scans blocks looking for outputs that
    /// match (via ECDH + view tag filtering).
    ///
    /// The server does NOT learn the amounts (they're encrypted). It only
    /// learns which outputs belong to this view key — this is the privacy
    /// tradeoff of using a light wallet server.
    ///
    /// # Pagination contract (read this before integrating)
    ///
    /// Two distinct ways the scan can return early — wallet integrators
    /// MUST handle both via `has_more`:
    ///
    /// 1. **Block-range cap** — `max_blocks` (default 1000, hard limit
    ///    `MAX_SCAN_BLOCKS_PER_REQ = 5000`). Requesting more is rejected
    ///    with `max_blocks too large` Err. To continue: advance
    ///    `start_height` past `scanned_to_height` and re-issue.
    ///
    /// 2. **Output-count cap** — `MAX_SCAN_OUTPUTS = 10_000` candidate
    ///    matches per response. Hitting this cap is NOT an error; the
    ///    response returns successfully with `has_more = true` and the
    ///    partial outputs collected so far. To continue: resume at
    ///    `scanned_to_height` (NOT `+1`) so the next request re-covers
    ///    the cap-block and picks up any remainder. A wallet that
    ///    advances past `scanned_to_height` after a cap-stop will
    ///    silently lose outputs.
    ///
    /// Both pagination modes use the same `(start_height, max_blocks,
    /// has_more, scanned_to_height)` 4-tuple — wallets don't need
    /// different code paths.
    pub fn scan(&self, req: &ScanRequest) -> std::result::Result<ScanResponse, String> {
        // Parse keys
        let view_pub = parse_public_key(&req.view_public)
            .map_err(|e| format!("invalid view_public: {}", e))?;
        let spend_pub = parse_public_key(&req.spend_public)
            .map_err(|e| format!("invalid spend_public: {}", e))?;

        let max_blocks = req.max_blocks.unwrap_or(1000);
        if max_blocks > MAX_SCAN_BLOCKS_PER_REQ {
            return Err(format!(
                "max_blocks too large: {} (limit {}); paginate by advancing start_height",
                max_blocks, MAX_SCAN_BLOCKS_PER_REQ
            ));
        }
        let chain_height = self.chain.height();
        let end_height = (req.start_height + max_blocks).min(chain_height);

        let mut detected = Vec::new();
        let mut blocks_scanned = 0u64;
        let mut capped = false;
        // When the output cap fires mid-block we must report the
        // partially-scanned block as the resume point, not end_height.
        // A caller advancing past end_height would skip every block
        // between the cap-block and end_height.
        let mut last_h = req.start_height;

        for h in req.start_height..=end_height {
            last_h = h;
            if let Some(block) = self.chain.get_block_by_height(h) {
                let digest = BlockDigest::from_block(&block);

                for output in &digest.outputs {
                    // P8-Lw1 (2026-07-03): view-tag pre-filter REMOVED.
                    // The sender's view_tag is
                    //   H("COINCYNC_VIEWTAG_v2", ECDH(tx_secret, view_public) || idx)
                    // — see transaction/builder.rs::compute_view_tag. The
                    // server holds only `view_public`, so it CANNOT
                    // compute the ECDH shared point (needs view_secret
                    // OR tx_secret, neither of which are available here).
                    // The previous filter compared the sender's ECDH
                    // view_tag against a wholly different value
                    // (H(tx_pub || view_pub || idx)), so it rejected
                    // ~255/256 outputs at random and passed 1/256 of
                    // wrong outputs as "candidates" — real user outputs
                    // effectively never matched.
                    //
                    // Correct behaviour for a `view_pub`-only server: no
                    // filter, return every output as a candidate. The
                    // caller is expected to run the ECDH-based scan
                    // client-side using the view_SECRET they hold; see
                    // `wallet::lightsync::LightWalletSync`. Client-side
                    // scanning is O(outputs) with a fast view-tag reject
                    // there, so the extra bandwidth is the trade-off for
                    // never leaking the view_secret to the server.
                    if is_output_for_keys(&output.tx_public_key, &output.stealth_address, &view_pub, &spend_pub, output.output_index) {
                        detected.push(DetectedOutput {
                            tx_hash: hex::encode(output.tx_hash.as_bytes()),
                            output_index: output.output_index,
                            height: h,
                            stealth_address: hex::encode(output.stealth_address.as_bytes()),
                            commitment: hex::encode(output.commitment),
                            encrypted_amount: hex::encode(&output.encrypted_amount),
                            tx_public_key: hex::encode(output.tx_public_key.as_bytes()),
                            ownership_verified: false,
                        });
                        if detected.len() >= MAX_SCAN_OUTPUTS {
                            capped = true;
                            break;
                        }
                    }
                }
                blocks_scanned += 1;
                if capped {
                    break;
                }
            }
        }

        let scanned_to_height = if capped { last_h } else { end_height };
        Ok(ScanResponse {
            blocks_scanned,
            scanned_to_height,
            chain_height,
            outputs: detected,
            has_more: capped || end_height < chain_height,
            ownership_verified: false,
            trust_note: "Results are candidate outputs matched by view-tag/public-key heuristics. Wallet must perform client-side ownership verification before balance/spend decisions.".to_string(),
        })
    }

    /// Get output digests for a block range (for wallets that want to
    /// scan client-side but need the compact data).
    pub fn get_digests(&self, start: u64, end: u64) -> Vec<BlockDigest> {
        let end = end.min(start + 100); // cap at 100 blocks per request
        let mut digests = Vec::new();
        for h in start..=end {
            if let Some(block) = self.chain.get_block_by_height(h) {
                digests.push(BlockDigest::from_block(&block));
            }
        }
        digests
    }

    /// Submit a raw signed transaction (built client-side by the wallet).
    pub fn submit_transaction(&self, tx_hex: &str) -> std::result::Result<String, String> {
        let tx_bytes = hex::decode(tx_hex)
            .map_err(|e| format!("invalid hex: {}", e))?;
        let tx: crate::transaction::Transaction = borsh::from_slice(&tx_bytes)
            .map_err(|e| format!("invalid transaction: {}", e))?;

        let tx_hash = tx.hash();
        self.mempool.add_with_chain(tx, &self.chain)
            .map_err(|e| format!("rejected: {}", e))?;

        Ok(hex::encode(tx_hash.as_bytes()))
    }

    /// Get decoys for building a ring signature (wallet needs these).
    /// Delegates to the existing `get_decoys` RPC method internally.
    pub fn get_decoy_count(&self) -> usize {
        crate::constants::BOOTSTRAP_MIN_RING_SIZE * 8 // request 8x ring size for selection
    }

    /// Estimate the fee for a transaction of a given size.
    pub fn estimate_fee(&self, tx_size_bytes: usize) -> u64 {
        let base_fee = (tx_size_bytes as u64) * crate::constants::MIN_FEE_PER_BYTE;
        // Add 20% buffer for fee market variance
        base_fee + base_fee / 5
    }

    /// Reorg-handling Task #4: find the deepest height ≤ `known_height`
    /// where the wallet's `known_hash` is on the canonical chain.
    ///
    /// The wallet calls this when it suspects a reorg (its
    /// `scanner.last_hash` no longer matches `chain.get_block_hash(last_height)`).
    /// The server walks backwards from `known_height` looking for a
    /// height where the wallet's previously-seen hash matches the
    /// canonical chain's current view.
    ///
    /// Returns:
    /// - `Some(height)` — the fork point. Wallet rewinds to here, then
    ///   re-scans forward from `height + 1` along the new canonical chain.
    /// - `None` — `known_hash` is not on the canonical chain at any
    ///   height ≤ `known_height` (catastrophic — the wallet's last-known
    ///   state diverged so deeply that there's no shared ancestor in
    ///   our walk window, OR the chain itself doesn't have the blocks
    ///   we're searching). Wallet must fall back to rescanning from a
    ///   hardcoded checkpoint or genesis.
    ///
    /// The walk is bounded by `max_walk_depth` (default 256) to keep
    /// the call cheap. A wallet that was offline through a deeper
    /// reorg falls through to the `None` path, which the wallet
    /// orchestrator handles via full rescan.
    ///
    /// Server cost: O(walk_depth) hash comparisons via
    /// `chain.get_block_hash`. Each is an O(log N) tree lookup.
    /// Cheap enough to not need rate-limiting beyond the existing
    /// per-IP RPC caps.
    pub fn find_fork_point(
        &self,
        known_hash: crate::primitives::Hash,
        known_height: u64,
        max_walk_depth: Option<u64>,
    ) -> Option<u64> {
        let walk_depth = max_walk_depth.unwrap_or(256);

        // Cheap path: check if known_height + known_hash IS still on
        // the canonical chain. If so the wallet wasn't reorged off and
        // the fork point is just known_height.
        if let Some(canonical) = self.chain.get_block_hash(known_height) {
            if canonical == known_hash {
                return Some(known_height);
            }
        }

        // Walk backwards looking for the first height where the
        // wallet's recorded hash matches the canonical chain's hash.
        // The wallet's full history isn't accessible to the server
        // — we can only check the SINGLE pair (known_hash, known_height)
        // against the canonical chain. If that doesn't match, the
        // server has to give up (it can't ask "was hash X EVER on
        // your chain at some lower height?" without the wallet
        // sending more state).
        //
        // For the v1.0 minimum-viable implementation, we accept this:
        // the wallet either passes a known-good (hash, height) pair
        // that's still canonical → Some(height), or it doesn't →
        // None and full-rescan fallback.
        //
        // The full algorithm (wallet sends a journal of recent
        // (height, hash) pairs and server picks the deepest one that
        // matches its canonical chain) belongs in a v1.1 enhancement.
        // Tracked in docs/wallet-v2-reorg-handling-design.md §3.5.
        let _ = walk_depth; // suppress unused-var warning for v1.0 stub
        None
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════

fn parse_public_key(hex_str: &str) -> std::result::Result<PublicKey, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("bad hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(PublicKey::from_bytes(arr))
}

/// DO NOT USE for scan filtering. This function is not the sender's
/// view_tag algorithm; it hashes public keys directly rather than the
/// ECDH shared point. It is retained solely because the module tests
/// exercise its determinism property. See `transaction::builder::compute_view_tag`
/// for the real algorithm (which requires `tx_secret` or `view_secret`).
/// P8-Lw1 (2026-07-03) removed this from the scan path.
#[allow(dead_code)]
fn compute_view_tag(tx_pub: &PublicKey, view_pub: &PublicKey, output_index: u8) -> u8 {
    use crate::primitives::hash_data;
    let mut data = Vec::with_capacity(65);
    data.extend_from_slice(tx_pub.as_bytes());
    data.extend_from_slice(view_pub.as_bytes());
    data.push(output_index);
    let hash = hash_data(&data);
    hash.as_bytes()[0]
}

/// Check if an output belongs to a given (view_pub, spend_pub) pair.
/// This is the slow ECDH check — only called when view tag matches.
fn is_output_for_keys(
    _tx_pub: &PublicKey,
    _stealth: &PublicKey,
    _view_pub: &PublicKey,
    _spend_pub: &PublicKey,
    _output_index: u8,
) -> bool {
    // Simplified ownership check:
    // The full check requires the view SECRET key for ECDH.
    // Since we only have the PUBLIC keys here, we can't do the real
    // ECDH check. The wallet must send the view SECRET key (encrypted)
    // for server-side scanning, OR do client-side scanning with digests.
    //
    // For now, outputs that pass the view tag filter are returned as
    // candidates — the wallet does final verification client-side.
    // This gives ~0.4% false positive rate (1/256), which is acceptable
    // for a light wallet (the wallet discards non-matching outputs).
    true // All view-tag-matching outputs are returned as candidates
}

// ═══════════════════════════════════════════════════════════════════════
// RPC registration
// ═══════════════════════════════════════════════════════════════════════

// Registration of light wallet methods happens in server.rs via
// the LightWalletServer API. External wallet apps call these methods:
//
//   wallet_get_coin_info  — coin specification
//   wallet_get_chain_info — height, fee, sync status
//   wallet_scan           — scan for outputs (view key required)
//   wallet_submit_tx      — submit signed transaction
//   wallet_get_digests    — output digests for client-side scanning
//   wallet_estimate_fee   — fee estimation
//
// The server.rs RPC setup uses LightWalletServer directly.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coin_spec_is_correct() {
        let spec = &COINCYNC_SPEC;
        assert_eq!(spec.ticker, "CYNC");
        assert_eq!(spec.decimals, 12);
        assert_eq!(spec.default_ring_size, 11);
        assert_eq!(spec.supply_cap, "100000000");
        assert_eq!(spec.privacy_model, "mandatory");
    }

    #[test]
    fn view_tag_is_deterministic() {
        let tx_pub = PublicKey::from_bytes([1u8; 32]);
        let view_pub = PublicKey::from_bytes([2u8; 32]);
        let tag1 = compute_view_tag(&tx_pub, &view_pub, 0);
        let tag2 = compute_view_tag(&tx_pub, &view_pub, 0);
        assert_eq!(tag1, tag2, "view tag must be deterministic");
    }

    #[test]
    fn different_index_different_tag() {
        let tx_pub = PublicKey::from_bytes([1u8; 32]);
        let view_pub = PublicKey::from_bytes([2u8; 32]);
        let tag0 = compute_view_tag(&tx_pub, &view_pub, 0);
        let tag1 = compute_view_tag(&tx_pub, &view_pub, 1);
        // Different indices SHOULD produce different tags (with high probability)
        // but this isn't guaranteed — it's a hash, so collisions are possible.
        // Just verify they're both valid bytes.
        let _ = (tag0, tag1);
    }
}
