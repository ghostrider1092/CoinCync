//! Chain queries, block serialization, supply, and synchronization RPCs.

use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::RpcModule;
use serde_json::{json, Value};

use crate::error::{Error, Result};

use super::{supply_atomic_decimal, RpcState};

/// Serialize a block into the rich JSON shape the embedded explorer
/// (and external clients) expect. Single source of truth so
/// `get_block_by_height` and `get_block` cannot drift apart in their
/// payload shape — the kind of bug that bit `Transaction::signing_hash`
/// in an earlier audit.
///
/// Fields:
/// - `height`, `hash`, `prev_hash`, `tx_root`, `timestamp`
/// - `nonce`, `algorithm` (numeric), `algorithm_name` (string),
///   `difficulty`, `target`
/// - `tx_count`, `size` (serialized byte count)
/// - `reward` (atomic units, computed from the emission curve at
///   this height — what a coinbase at this height earns)
/// - `transactions` — array of `{hash, kind}` per tx, lightweight
///   but enough to render a tx list
/// - `bytes` — full borsh-serialized block, hex-encoded, for clients
///   that want to deserialize the block themselves
fn serialize_block(block: &crate::consensus::Block, height: u64) -> Value {
    let block_bytes = borsh::to_vec(block).unwrap_or_default();
    let size = block_bytes.len();

    let txs_json: Vec<Value> = block
        .transactions
        .iter()
        .map(|tx| {
            let kind = match tx.tx_type {
                crate::transaction::TxType::Coinbase => "coinbase",
                crate::transaction::TxType::Transfer => "transfer",
                crate::transaction::TxType::Churn => "churn",
            };
            json!({
                "hash":     hex::encode(tx.hash().as_bytes()),
                "kind":     kind,
                "inputs":   tx.input_count(),
                "outputs":  tx.output_count(),
                "fee":      tx.fee.as_atomic(),
            })
        })
        .collect();

    json!({
        "height":         height,
        "hash":           hex::encode(block.hash().as_bytes()),
        "prev_hash":      hex::encode(block.header.prev_hash.as_bytes()),
        "tx_root":        hex::encode(block.header.tx_root.as_bytes()),
        "timestamp":      block.header.timestamp,
        "nonce":          block.header.nonce,
        // CoinCync 1.0 is RandomX-only — see `consensus::pow::PowAlgorithm`.
        "algorithm":      block.header.algorithm,
        "algorithm_name": "RandomX",
        "difficulty":     block.header.target.to_difficulty().to_string(),
        "target":         hex::encode(block.header.target.as_bytes()),
        "tx_count":       block.transactions.len(),
        "size":           size,
        "reward":         crate::emission::calculate_block_reward(height).as_atomic(),
        "transactions":   txs_json,
        "bytes":          hex::encode(&block_bytes),
    })
}

pub(super) fn register(module: &mut RpcModule<RpcState>) -> Result<()> {
    // ── get_supply_info ───────────────────────────────────────
    module
        .register_method("get_supply_info", |_params, state, _ext| {
            let stats = state.chain.stats();
            let height = stats.height;
            let reward = crate::emission::calculate_block_reward(height);
            let phase = crate::emission::emission_phase(height);
            Ok::<_, ErrorObjectOwned>(json!({
                "height":             height,
                "current_reward":     reward.as_atomic(),
                "total_emitted":      supply_atomic_decimal(stats.total_supply),
                // `total_emitted`/`total_supply` is GROSS emission (the summed
                // deterministic schedule). `total_burned` is the cumulative fees
                // provably burned by the fee-market split, and `circulating_supply`
                // is the net in circulation = total_supply − total_burned.
                "total_supply":       supply_atomic_decimal(stats.total_supply),
                "total_burned":       supply_atomic_decimal(stats.total_burned),
                "circulating_supply": supply_atomic_decimal(
                    stats.total_supply.saturating_sub(stats.total_burned),
                ),
                "supply_note":        "total_supply/total_emitted is gross emission; circulating_supply is net of burned fees (total_supply − total_burned).",
                "emission_phase":     phase.name(),
                // Public emission parameters so anyone can independently
                // recompute the schedule and confirm `total_emitted`. Emission
                // is a deterministic function of height — no hidden and no
                // discretionary issuance.
                "emission_formula":   "reward(h) = max(tail_emission, (supply_target*coin - emitted) / emission_divisor)",
                "supply_target_cync": crate::constants::TOTAL_SUPPLY_TARGET,
                "emission_divisor":   crate::constants::EMISSION_DIVISOR,
                "tail_emission_atomic": crate::constants::TAIL_EMISSION,
                "coin":               crate::constants::COIN,
                "supply_model":       "asymptotic issuance toward supply_target plus a perpetual fixed tail — not a hard cap; total supply exceeds supply_target long-term",
                "verification_note":  "No hidden inflation: coinbase outputs are transparent (zero blinding) and consensus-checked to equal the scheduled reward exactly on every block; every transaction is cryptographically proven to balance (inputs = outputs + fee) and every ring member references a real prior on-chain output. total_emitted therefore provably equals the summed deterministic schedule — recompute it from the parameters above (or via /api/v1/emission) and compare against this value.",
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_block_by_height ───────────────────────────────────
    //
    // Rich block payload: every field the embedded explorer's
    // block-detail panel reads, plus the raw `bytes` for clients
    // that want to deserialize the block themselves. The
    // `transactions` array carries lightweight per-tx records
    // (hash, timestamp, kind) rather than the full encoded txs —
    // the explorer only displays a list of txids and their kind,
    // and full tx bodies require a tx-index that doesn't exist
    // yet (see `get_transaction` below).
    module
        .register_method("get_block_by_height", |params, state, _ext| {
            let (h,): (u64,) = params.parse().map_err(|e: ErrorObjectOwned| {
                ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
            })?;
            // Layer 2: DB lookup + serialize under block_in_place so a slow
            // RocksDB read doesn't freeze the worker mid-handler.
            let block_opt = tokio::task::block_in_place(|| state.chain.get_block_by_height(h));
            match block_opt {
                Some(block) => Ok::<_, ErrorObjectOwned>(serialize_block(&block, h)),
                None => Err(ErrorObjectOwned::owned(
                    // -5 = not-found; the REST proxy maps it to HTTP 404 (not 500).
                    -5,
                    format!("block at height {} not found", h),
                    None::<()>,
                )),
            }
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── find_fork_point (light-wallet reorg recovery, v1.1) ────
    //
    // The wallet sends its recent (height, hex_hash) journal; we return the
    // deepest height still on the canonical chain (the last common ancestor)
    // so the wallet rewinds there instead of full-rescanning. See
    // src/rpc/lightwallet.rs::fork_point_in_journal and
    // docs/wallet-v2-reorg-handling-design.md §3.5.
    module
        .register_method("find_fork_point", |params, state, _ext| {
            let (journal_hex,): (Vec<(u64, String)>,) =
                params.parse().map_err(|e: ErrorObjectOwned| {
                    ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
                })?;
            // DoS guard: reject an oversized journal before any hex decode or
            // chain lookups. A real wallet journal is a few thousand entries at
            // most (see wallet::scanner::JOURNAL_MAX_DEFAULT).
            const MAX_JOURNAL: usize = 4096;
            if journal_hex.len() > MAX_JOURNAL {
                return Err(ErrorObjectOwned::owned(
                    -32602,
                    format!(
                        "find_fork_point: journal too large ({} > {})",
                        journal_hex.len(),
                        MAX_JOURNAL
                    ),
                    None::<()>,
                ));
            }
            let journal =
                crate::rpc::lightwallet::parse_journal_hex(&journal_hex).map_err(|e| {
                    ErrorObjectOwned::owned(-32602, format!("find_fork_point: {}", e), None::<()>)
                })?;
            // Layer 2: canonical-hash lookups under block_in_place — same
            // rationale as get_block_by_height above.
            let fork = tokio::task::block_in_place(|| {
                crate::rpc::lightwallet::fork_point_in_journal(&journal, |h| {
                    state.chain.get_block_hash(h)
                })
            });
            Ok::<_, ErrorObjectOwned>(serde_json::json!({ "fork_point": fork }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_block (by hash) ───────────────────────────────────
    //
    // Hash-based block lookup. The embedded explorer's search
    // bar in `src/explorer/app/11-router.js` calls this
    // with a 64-char hex string; we accept that and fall back to
    // a 32-byte raw form if the input isn't hex.
    module
        .register_method("get_block", |params, state, _ext| {
            let (hash_hex,): (String,) = params.parse().map_err(|e: ErrorObjectOwned| {
                ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
            })?;
            let mut bytes = [0u8; 32];
            if hex::decode_to_slice(hash_hex.trim_start_matches("0x"), &mut bytes).is_err() {
                return Err(ErrorObjectOwned::owned(
                    -32602,
                    format!("get_block: expected 64-char hex hash, got {:?}", hash_hex),
                    None::<()>,
                ));
            }
            let hash = crate::primitives::Hash::from_bytes(bytes);
            // Layer 2: DB lookup under block_in_place — same rationale as
            // get_block_by_height above.
            let block_opt = tokio::task::block_in_place(|| state.chain.get_block(&hash));
            match block_opt {
                Some(block) => {
                    let height = block.header.height;
                    Ok::<_, ErrorObjectOwned>(serialize_block(&block, height))
                }
                None => Err(ErrorObjectOwned::owned(
                    // -5 = not-found; the REST proxy maps it to HTTP 404 (not 500).
                    -5,
                    format!("block with hash {} not found", hex::encode(bytes)),
                    None::<()>,
                )),
            }
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_burn_stats ────────────────────────────────────────
    //
    // Returns fee burn statistics for the explorer burn page.
    module
        .register_method("get_burn_stats", |_params, state, _ext| {
            let stats = state.chain.stats();
            let height = stats.height;
            let is_active = height >= state.chain.network().fee_distribution_height();

            let burn_pct = crate::constants::FEE_BURN_NORMAL_PERCENT;
            let miner_pct = crate::constants::FEE_MINER_NORMAL_PERCENT;

            let supply = supply_atomic_decimal(stats.total_supply);
            let max_supply = crate::constants::MAX_SUPPLY;
            let reward = crate::emission::calculate_block_reward(height).as_atomic();
            // Fees per block needed to make chain deflationary:
            // burn needs to exceed block reward → fee * burn_pct/100 > reward
            // → fee > reward * 100 / burn_pct
            let deflation_threshold = if burn_pct > 0 {
                reward as f64 * 100.0 / burn_pct as f64
            } else {
                0.0
            };

            Ok::<_, ErrorObjectOwned>(json!({
                "active": is_active,
                "activation_height": state.chain.network().fee_distribution_height(),
                "current_height": height,
                "miner_pct_normal": miner_pct,
                "burn_pct_normal": burn_pct,
                "miner_pct_congested": crate::constants::FEE_MINER_CONGESTED_PERCENT,
                "burn_pct_congested": crate::constants::FEE_BURN_CONGESTED_PERCENT,
                "protocol_pct": 0,
                "block_reward": reward,
                "circulating_supply": supply,
                "max_supply": supply_atomic_decimal(max_supply),
                "deflation_threshold_fee_per_block": deflation_threshold as u64,
                "congestion_threshold_pct": crate::constants::CONGESTION_THRESHOLD,
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_finality_info ────────────────────────────────────
    //
    // Returns checkpoint finality status for the explorer.
    module.register_method("get_finality_info", |_params, state, _ext| {
        let stats = state.chain.stats();
        let height = stats.height;
        let last_checkpoint = height - (height % 5); // every 5 blocks
        let next_checkpoint = last_checkpoint + 5;
        let blocks_until_next = next_checkpoint.saturating_sub(height);
        let seconds_until_next = blocks_until_next * crate::constants::TARGET_BLOCK_TIME;

        Ok::<_, ErrorObjectOwned>(json!({
            "current_height": height,
            "last_checkpoint": last_checkpoint,
            "next_checkpoint": next_checkpoint,
            "blocks_until_checkpoint": blocks_until_next,
            "seconds_until_checkpoint": seconds_until_next,
            "checkpoint_interval": 5,
            "finality_type": "PoW + Checkpoint",
            // F31 SEV-A fix (2026-07-05): use the runtime-network variant
            // rather than the deprecated compile-time `max_reorg_depth()`.
            // A binary built without --features testnet was previously
            // returning 100 here even when configured to run on testnet at
            // runtime, misleading the explorer about hard-finality behavior.
            "max_reorg_depth": state.chain.max_reorg_depth(),
            "checkpoint_finality": "absolute",
            "description": "Blocks below the last checkpoint cannot be reverted by any amount of hashpower",
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_chain_events ──────────────────────────────────────
    //
    // Recent chain convergence events (reorgs, forks, rejects,
    // checkpoints) for the explorer timeline. `limit` is
    // clamped server-side to 500.
    module
        .register_method("get_chain_events", |params, state, _ext| {
            // Accept either [] (defaults) or [limit].
            let limit: usize = match params.parse::<Vec<usize>>() {
                Ok(v) => v.into_iter().next().unwrap_or(100),
                Err(_) => 100,
            };
            let capped = limit.min(500);
            let events = state.chain.get_events(capped);
            let height = state.chain.height();
            let tip = state.chain.tip();
            Ok::<_, ErrorObjectOwned>(json!({
                "events":         events,
                "count":          events.len(),
                "current_height": height,
                "current_tip":    hex::encode(tip.hash.as_bytes()),
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_block_range ───────────────────────────────────────
    //
    // Wallet-side chain scan: fetch a range of blocks by height.
    // Each block in the response uses the SAME shape as
    // `get_block_by_height` and `get_block`, via the shared
    // `serialize_block` helper — single source of truth for the
    // block payload prevents the kind of payload-shape drift
    // that bit `Transaction::signing_hash` in an earlier audit.
    // The server caps the range to MAX_RANGE blocks per call to
    // prevent huge responses.
    module
        .register_method("get_block_range", |params, state, _ext| {
            let (start, end): (u64, u64) = params.parse().map_err(|e: ErrorObjectOwned| {
                ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
            })?;
            const MAX_RANGE: u64 = 100;
            if end < start {
                return Err(ErrorObjectOwned::owned(
                    -32602,
                    "end must be >= start".to_string(),
                    None::<()>,
                ));
            }
            // Saturating arithmetic on caller-controlled u64 height bounds.
            // Pre-fix `end - start + 1` overflowed when start=0/end=u64::MAX,
            // and `start + capped` overflowed near MAX. In debug builds the
            // bare addition panics; in release it wraps to give an empty
            // range — both wrong. With saturating math we degrade cleanly
            // to a small or empty range at the u64::MAX boundary, which is
            // the right semantics (no blocks exist that high anyway).
            let span = end.saturating_sub(start).saturating_add(1);
            let capped = span.min(MAX_RANGE);
            let mut blocks = Vec::with_capacity(capped as usize);
            let loop_end = start.saturating_add(capped);
            for h in start..loop_end {
                if let Some(block) = state.chain.get_block_by_height(h) {
                    blocks.push(serialize_block(&block, h));
                }
            }
            let response_end = start.saturating_add(capped).saturating_sub(1);
            Ok::<_, ErrorObjectOwned>(json!({
                "start": start,
                "end": response_end,
                "count": blocks.len(),
                "blocks": blocks,
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_output_digests ───────────────────────────────────
    //
    // Light-wallet SPV path: returns compact per-block output
    // summaries (~138 B / output vs ~1-5 KB / full tx) for client-
    // side scanning. The server learns only the height range; it
    // never sees which outputs the wallet cares about. Privacy
    // posture is strictly stronger than BIP-157 (which leaks the
    // wallet's address set to the filter server). See
    // `docs/security/LIGHTSYNC_AUDIT.md`.
    //
    // Params: [start_height: u64, end_height: u64].
    // Range capped to 100 blocks per request to bound response
    // size; the same bound applies at the network layer
    // (`MessageType::GetOutputDigests`).
    module
        .register_method("get_output_digests", |params, state, _ext| {
            let (start, end): (u64, u64) = params.parse().map_err(|e: ErrorObjectOwned| {
                ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
            })?;
            if end < start {
                return Err(ErrorObjectOwned::owned(
                    -32602,
                    "end must be >= start".to_string(),
                    None::<()>,
                ));
            }
            const MAX_DIGEST_BLOCKS: u64 = 100;
            let chain_height = state.chain.height();
            let end = end
                .min(start.saturating_add(MAX_DIGEST_BLOCKS - 1))
                .min(chain_height);
            // `end` was just clamped to `min(chain_height)`, which can drop it
            // below `start` when `start > chain_height` (the earlier guard saw
            // the pre-clamp `end`). Use saturating math — matching the sibling
            // range handlers — so the capacity calc can't underflow. The
            // `start..=end` loop below is simply empty in that case.
            let mut digests = Vec::with_capacity(
                (end.saturating_sub(start).saturating_add(1) as usize)
                    .min(MAX_DIGEST_BLOCKS as usize),
            );
            for h in start..=end {
                if let Some(block) = state.chain.get_block_by_height(h) {
                    digests.push(crate::wallet::lightsync::BlockDigest::from_block(&block));
                }
            }
            let count = digests.len();
            Ok::<_, ErrorObjectOwned>(json!({
                "start": start,
                "end": end,
                "count": count,
                "digests": digests,
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_sync_checkpoints ─────────────────────────────────
    //
    // Periodic trust anchors so a fresh light wallet can skip
    // ancient history and start scanning from a recent height.
    //
    // SECURITY NOTE: Authentication of these checkpoints is
    // currently a checksum, not a signature (Gap 2 in
    // LIGHTSYNC_AUDIT.md). For v1.0 the wallet MUST cross-check
    // returned checkpoints against the hardcoded consensus
    // checkpoint table in `src/constants.rs::CONSENSUS_CHECKPOINTS`
    // before trusting them. Miner-signed checkpoints arrive in
    // v1.0.1 (CIP-009.D activation track).
    //
    // Params: optional [stride: u64] — emit one checkpoint every
    // `stride` blocks. Default 10000 (~14 days at 120s).
    module.register_method("get_sync_checkpoints", |params, state, _ext| {
        let requested: u64 = params.parse::<(u64,)>().map(|(s,)| s).unwrap_or(10_000);
        let chain_height = state.chain.height();
        // SECURITY (DoS): bound the work regardless of the requested stride.
        // This method is in the REST allowlist (reachable UNAUTHENTICATED via
        // POST /rpc), so a `stride=1` request must not force O(chain_height) DB
        // reads + a chain_height-sized Vec — that scales attacker damage with
        // chain height. Floor the stride so the loop yields at most
        // MAX_CHECKPOINTS entries; the actual stride used is returned to the
        // caller. Also run the synchronous DB scan under block_in_place so it
        // can't monopolize a tokio worker (matches the other DB-scan handlers).
        const MAX_CHECKPOINTS: u64 = 512;
        let min_stride = chain_height.div_ceil(MAX_CHECKPOINTS).max(1);
        let stride = requested.max(min_stride).min(50_000);
        let checkpoints = tokio::task::block_in_place(|| {
            let mut checkpoints = Vec::new();
            let mut h = stride;
            while h <= chain_height {
                if let Some(block) = state.chain.get_block_by_height(h) {
                    let block_hash = block.hash();
                    let cp = crate::wallet::lightsync::SyncCheckpoint::new(
                        h,
                        block_hash,
                        0, // total_outputs not tracked at this layer
                        crate::primitives::Hash::default(), // utxo_hash deferred to Gap 2
                    );
                    checkpoints.push(cp);
                }
                h = match h.checked_add(stride) {
                    Some(next) => next,
                    None => break,
                };
            }
            checkpoints
        });
        Ok::<_, ErrorObjectOwned>(json!({
            "stride": stride,
            "chain_height": chain_height,
            "count": checkpoints.len(),
            "checkpoints": checkpoints,
            "auth_note": "Cross-check against CONSENSUS_CHECKPOINTS in src/constants.rs. Miner-signed authentication queued for v1.0.1 (CIP-009.D).",
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_state_snapshot ─────────────────────────────────────
    // Returns a compact chain state summary for fast sync verification.
    // New nodes can compare their state against this to detect divergence.
    module
        .register_method("get_state_snapshot", |_params, state, _ext| {
            let stats = state.chain.stats();
            let tip = state.chain.tip_hash();

            Ok::<_, ErrorObjectOwned>(json!({
                "height": stats.height,
                "tip_hash": tip.to_hex(),
                "total_difficulty": stats.total_difficulty.to_string(),
                "total_supply": supply_atomic_decimal(stats.total_supply),
                "total_transactions": stats.total_transactions,
                "checkpoints": crate::testnet::testnet_checkpoints().iter()
                    .map(|cp| json!({"height": cp.height, "hash": cp.hash.to_hex()}))
                    .collect::<Vec<_>>(),
                "version": "1.0.0",
                "network": "testnet",
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_blocks_batch ─────────────────────────────────────
    // Returns up to 100 serialized blocks in a single RPC call for fast sync.
    // Clients request a height range and get back hex-encoded blocks.
    module
        .register_method("get_blocks_batch", |params, state, _ext| {
            let (from_height, count): (u64, u64) =
                params.parse().map_err(|e: ErrorObjectOwned| {
                    ErrorObjectOwned::owned(
                        -32602,
                        format!("params: [from_height, count]: {}", e),
                        None::<()>,
                    )
                })?;
            let count = count.min(100); // Cap at 100 blocks per request
            let mut blocks = Vec::new();
            // Saturating arithmetic so from_height near u64::MAX doesn't
            // overflow. In debug builds the bare addition panics; in
            // release it wraps to an empty range. With saturating_add the
            // loop is simply empty at the saturation point, which is the
            // correct semantics (no blocks exist at u64::MAX anyway).
            let end = from_height.saturating_add(count);
            for h in from_height..end {
                if let Some(block) = state.chain.get_block_by_height(h) {
                    let block_hex = hex::encode(borsh::to_vec(&block).unwrap_or_default());
                    blocks.push(json!({
                        "height": h,
                        "hash": block.hash().to_hex(),
                        "hex": block_hex,
                    }));
                } else {
                    break; // No more blocks at this height
                }
            }
            Ok::<_, ErrorObjectOwned>(json!({
                "blocks": blocks,
                "count": blocks.len(),
                "from": from_height,
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    Ok(())
}
