//! Privacy-store and wallet decoy snapshot RPCs.

use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::RpcModule;
use serde_json::{json, Value};

use crate::decoy::OutputLocator;
use crate::error::{Error, Result};
use crate::primitives::Hash;

use super::RpcState;

/// Collect + sort a spent-tag set into canonical page order. This is the
/// expensive part (O(N log N)); the handler caches its result per chain height
/// so paging the whole set re-sorts it once per block, not once per page.
#[cfg(feature = "sketch-gk-proof")]
fn sort_spent_tags(set: std::collections::HashSet<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut all: Vec<Vec<u8>> = set.into_iter().collect();
    // Sorted order makes successive [offset, limit) pages tile the set.
    all.sort_unstable();
    all
}

/// Slice a pre-sorted tag vec to `[offset, offset + limit)`, hex-encoded, and
/// return `(total, page)`. Cheap (O(limit)); safe to call per page.
#[cfg(feature = "sketch-gk-proof")]
fn page_spent_tags(sorted: &[Vec<u8>], offset: usize, limit: usize) -> (usize, Vec<String>) {
    let page = sorted
        .iter()
        .skip(offset)
        .take(limit)
        .map(|t| hex::encode(t))
        .collect();
    (sorted.len(), page)
}

/// Per-response cap on a spent-tag page: bounds the serialized response size
/// (a DoS guard). A larger request is clamped and the wallet pages the rest.
#[cfg(feature = "sketch-gk-proof")]
const MAX_SPENT_TAGS_PAGE: usize = 50_000;

/// Clamp a caller-supplied `limit` to `[1, MAX_SPENT_TAGS_PAGE]`; `None` → the
/// cap. The upper bound caps the serialized response; the lower bound of 1
/// guarantees a paging client always makes progress — a `limit` of 0 would
/// otherwise return `count=0` with `total>0` forever, spinning the client.
#[cfg(feature = "sketch-gk-proof")]
fn clamp_spent_tags_limit(requested: Option<u64>) -> usize {
    match requested {
        Some(l) => (l as usize).clamp(1, MAX_SPENT_TAGS_PAGE),
        None => MAX_SPENT_TAGS_PAGE,
    }
}

/// Page the spent-tag set as `chain_sorted` (the per-height cached, sorted
/// on-chain set) overlaid with `mempool_tags` (snapshotted LIVE on this call).
///
/// F1: the on-chain set is immutable within a chain height, so it is sorted
/// once per block and cached. The mempool is NOT cached — a spend admitted
/// after the cache was built must still be visible, or a wallet that just sent
/// and then refreshes its balance would see the note as unspent and could
/// re-select it. So the live mempool tags are unioned in on EVERY call. Returns
/// `(total, page)` with the page hex-encoded in global sorted order over
/// `[offset, offset + limit)`.
#[cfg(feature = "sketch-gk-proof")]
fn spent_tags_overlay_page(
    chain_sorted: &[Vec<u8>],
    mempool_tags: &[Vec<u8>],
    offset: usize,
    limit: usize,
) -> (usize, Vec<String>) {
    // The pending tags the per-height chain cache cannot see: mempool tags not
    // already on chain. `chain_sorted` is sorted, so membership is a binary
    // search; the mempool is small, so this overlay is cheap.
    let mut extra: Vec<Vec<u8>> = mempool_tags
        .iter()
        .filter(|&t| chain_sorted.binary_search(t).is_err())
        .cloned()
        .collect();
    if extra.is_empty() {
        // Common case (no pending shielded spends not yet mined): page straight
        // from the cached, already-sorted chain set — no per-call O(N) merge.
        return page_spent_tags(chain_sorted, offset, limit);
    }
    extra.sort_unstable();
    extra.dedup();
    let total = chain_sorted.len() + extra.len();
    // Merge the two disjoint sorted sequences, emitting only the requested
    // window — linear in the window, not a re-sort of the whole set.
    let mut i = 0usize;
    let mut j = 0usize;
    let mut skipped = 0usize;
    let mut page: Vec<String> = Vec::new();
    while (i < chain_sorted.len() || j < extra.len()) && page.len() < limit {
        let take_chain = match (i < chain_sorted.len(), j < extra.len()) {
            (true, true) => chain_sorted[i] <= extra[j],
            (true, false) => true,
            (false, true) => false,
            (false, false) => break,
        };
        let next = if take_chain {
            let x = &chain_sorted[i];
            i += 1;
            x
        } else {
            let x = &extra[j];
            j += 1;
            x
        };
        if skipped < offset {
            skipped += 1;
            continue;
        }
        page.push(hex::encode(next));
    }
    (total, page)
}

/// Sort + slice in one shot: returns `(total, page)` where `page` is the
/// hex-encoded tags in sorted order sliced to `[offset, offset + limit)`. Kept
/// so the paging invariant (pages tile the whole set with no gap or overlap) is
/// unit-testable without constructing an `RpcState`; the handler itself caches
/// `sort_spent_tags` across pages and calls `page_spent_tags` directly, so this
/// composed form is only referenced from the test below.
#[cfg(all(test, feature = "sketch-gk-proof"))]
fn paginate_spent_tags(
    set: std::collections::HashSet<Vec<u8>>,
    offset: usize,
    limit: usize,
) -> (usize, Vec<String>) {
    page_spent_tags(&sort_spent_tags(set), offset, limit)
}

pub(super) fn register(module: &mut RpcModule<RpcState>) -> Result<()> {
    // ── get_privacy_stats ─────────────────────────────────────
    // Aggregate view of the Phase 2 privacy stores.
    module.register_method("get_privacy_stats", |_params, state, _ext| {
        let cut_through = state.chain.cut_through_stats();
        Ok::<_, ErrorObjectOwned>(json!({
            "shielded_root":      hex::encode(state.chain.shielded_root()),
            "shielded_tree_size": state.chain.shielded_store.as_ref().map(|s| s.tree_size()).unwrap_or(0),
            "spark_root":         hex::encode(state.chain.spark_root()),
            "spark_accumulator_size": state.chain.spark_store.as_ref().map(|s| s.size()).unwrap_or(0),
            "mw_kernel_root":     hex::encode(state.chain.mw_kernel_root()),
            "mw_kernels_kept":    cut_through.kernels_kept,
            "mw_pending_candidates": cut_through.pending_candidates,
            "mw_bytes_saved":     cut_through.bytes_saved,
            "mw_compression":     cut_through.compression_ratio,
            "mandatory_confidential": crate::constants::MANDATORY_CONFIDENTIAL,
            "mandatory_stealth":      crate::constants::MANDATORY_STEALTH,
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_shielded_anchor ───────────────────────────────────
    // Light wallets query this to get the current Merkle root they
    // should anchor their spend proofs against.
    module.register_method("get_shielded_anchor", |_params, state, _ext| {
        Ok::<_, ErrorObjectOwned>(json!({
            "anchor": hex::encode(state.chain.shielded_root()),
            "tree_size": state.chain.shielded_store.as_ref().map(|s| s.tree_size()).unwrap_or(0),
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_spark_anchor ──────────────────────────────────────
    module
        .register_method("get_spark_anchor", |_params, state, _ext| {
            Ok::<_, ErrorObjectOwned>(json!({
                "root": hex::encode(state.chain.spark_root()),
                "size": state.chain.spark_store.as_ref().map(|s| s.size()).unwrap_or(0),
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_shielded_cover_set ────────────────────────────────
    // A wallet fetches the anchored Spark cover set to build a shielded
    // spend: the ordered coins {C_i} the Grootle one-of-many proof hides
    // the real coin among, each with its serial context (needed to
    // identify + spend an owned coin) and outpoint. The array position is
    // the coin's spend index for a proof anchored at
    // (cover_set_id, anchor_height) — the same set + order the verifier
    // resolves. Params: [cover_set_id, anchor_height]. Read-only.
    //
    // Gated: the pool store exists only in a `sketch-gk-proof` build, and
    // shielded is activation-gated OFF until the audit, so on a live node
    // this set is empty. This is the wallet-facing counterpart to
    // get_decoy_distribution (transparent ring members) for the shielded
    // pool.
    #[cfg(feature = "sketch-gk-proof")]
    module
        .register_method("get_shielded_cover_set", |params, state, _ext| {
            let (cover_set_id, anchor_height): (u64, u64) =
                params.parse().map_err(|e: ErrorObjectOwned| {
                    ErrorObjectOwned::owned(
                        -32602,
                        format!("bad params (expected [cover_set_id, anchor_height]): {e}"),
                        None::<()>,
                    )
                })?;
            let entries = state.chain.spark_pool_cover_entries(cover_set_id, anchor_height);
            // Defensive cap: never serialize an unbounded response. The pool is
            // naturally bounded by the Grootle set size; pagination is a
            // follow-up if a group ever exceeds this.
            const MAX_COVER_COINS: usize = 100_000;
            if entries.len() > MAX_COVER_COINS {
                return Err(ErrorObjectOwned::owned(
                    -32000,
                    format!(
                        "cover set too large ({} coins > {MAX_COVER_COINS}); pagination unimplemented",
                        entries.len()
                    ),
                    None::<()>,
                ));
            }
            let coins: Vec<Value> = entries
                .into_iter()
                .enumerate()
                .map(|(index, (outpoint, coin, ctx, height))| {
                    json!({
                        "index": index,
                        "outpoint": hex::encode(outpoint),
                        "coin": hex::encode(coin),
                        "serial_context": hex::encode(ctx),
                        "height": height,
                    })
                })
                .collect();
            Ok::<_, ErrorObjectOwned>(json!({
                "cover_set_id": cover_set_id,
                "anchor_height": anchor_height,
                "count": coins.len(),
                "coins": coins,
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── is_nullifier_spent ────────────────────────────────────
    // Wallet calls before building a shielded spend to make sure it
    // won't be rejected as a double-spend.
    module.register_method("is_nullifier_spent", |params, state, _ext| {
        let (hex_nf,): (String,) = params.parse().map_err(|e: ErrorObjectOwned| {
            ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
        })?;
        // Pre-decode length cap: a 32-byte nullifier is 64 hex chars.
        // Reject inputs that are obviously oversized BEFORE allocating a
        // potentially huge Vec inside hex::decode. Prevents 1 GB hex →
        // 500 MB Vec alloc DoS. Audit-fix.
        if hex_nf.len() > 128 {
            return Err(ErrorObjectOwned::owned(
                -32602, "nullifier hex too long (max 128 chars)".to_string(), None::<()>,
            ));
        }
        let bytes = hex::decode(&hex_nf).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("bad hex: {}", e), None::<()>)
        })?;
        if bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602, "nullifier must be 32 bytes".to_string(), None::<()>,
            ));
        }
        let mut nf = [0u8; 32];
        nf.copy_from_slice(&bytes);
        Ok::<_, ErrorObjectOwned>(json!({
            "nullifier": hex::encode(nf),
            "spent": state.chain.shielded_store.as_ref().map(|s| s.is_nullifier_spent(&nf)).unwrap_or(false),
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── is_spark_pool_tag_spent ───────────────────────────────
    // v2 (libspark) shielded linking tag. A wallet calls this per owned pool
    // coin (tag derived via coin_ltag) to exclude ALREADY-SPENT notes from its
    // shielded balance and spend selection: a spent coin's bytes remain in the
    // cover set, so view-key identification alone over-counts. The tag (Spark
    // `T`) serializes to 34 bytes (68 hex).
    module.register_method("is_spark_pool_tag_spent", |params, state, _ext| {
        let (hex_t,): (String,) = params.parse().map_err(|e: ErrorObjectOwned| {
            ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
        })?;
        // Pre-decode length cap (DoS), as in is_nullifier_spent.
        if hex_t.len() > 128 {
            return Err(ErrorObjectOwned::owned(
                -32602, "tag hex too long (max 128 chars)".to_string(), None::<()>,
            ));
        }
        let bytes = hex::decode(&hex_t).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("bad hex: {}", e), None::<()>)
        })?;
        // Exact-length guard, like is_spark_serial_spent / is_nullifier_spent: the
        // Spark linking tag `T` serializes to exactly 34 bytes. Without it a
        // wrong-length tag silently misses the spent-set lookup and returns
        // spent=false, so a wallet told "available" re-selects an already-spent
        // note and then builds a spend the node rejects as a duplicate linking tag.
        if bytes.len() != 34 {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "tag must be 34 bytes".to_string(),
                None::<()>,
            ));
        }
        // "spent" means UNAVAILABLE to spend: already spent on-chain OR already
        // on a PENDING mempool spend. The latter matters because a note whose
        // spend is in the mempool but not yet mined is not in the on-chain spent
        // set — without it the wallet re-picks the note and the node rejects the
        // double-spend ("duplicate shielded linking tag in mempool").
        #[cfg(feature = "sketch-gk-proof")]
        let spent =
            state.chain.spark_pool_tag_spent(&bytes) || state.mempool.contains_linking_tag(&bytes);
        #[cfg(not(feature = "sketch-gk-proof"))]
        let spent = {
            let _ = (&bytes, &state);
            false
        };
        Ok::<_, ErrorObjectOwned>(json!({
            "tag": hex::encode(&bytes),
            "spent": spent,
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_spark_spent_tags ──────────────────────────────────
    // The wallet-facing counterpart to is_spark_pool_tag_spent: instead of
    // asking the node whether each owned pool coin's tag is spent (which reveals
    // the linking tags of a wallet's STILL-UNSPENT notes — #378), a wallet
    // fetches the whole "unavailable" tag set and tests its notes locally. The
    // set is public chain + mempool data, so downloading it reveals nothing
    // about which coins the wallet owns. "Unavailable" = spent on-chain OR on a
    // pending mempool spend, matching is_spark_pool_tag_spent's semantics (so a
    // note whose spend is pending is excluded too). Read-only.
    //
    // PAGINATED: params `[offset, limit]`, both optional (default offset 0,
    // limit `MAX_SPENT_TAGS_PAGE`). `limit` is clamped to that cap, which bounds a single
    // response (the DoS guard) WITHOUT a whole-set error: the response carries
    // `total` and the wallet pages until it has all of it. An earlier version
    // returned an error past a 100k whole-set cap and bricked balance/send —
    // wrong, because the pool is split into `SPARK_COVER_SET_GROUP`-sized cover
    // groups but this spent set is GLOBAL, so it is NOT bounded by the single
    // cover-set group the wallet fetches, and there was no per-tag fallback.
    // Tags are returned SORTED so pages tile the set deterministically within a
    // call; a spend mined between pages shifts the set by one tag, which the
    // wallet's next scan reconciles.
    // F1: cache the sorted ON-CHAIN spent set per chain height (it is immutable
    // within a height, so it is sorted once per block, not once per page). The
    // MEMPOOL is deliberately NOT cached — it is snapshotted live on every call
    // and unioned in (see `spent_tags_overlay_page`), so a spend admitted to the
    // mempool after the cache was built is never invisible to a paging wallet.
    #[cfg(feature = "sketch-gk-proof")]
    let spent_tags_cache: std::sync::Arc<
        std::sync::RwLock<Option<(u64, std::sync::Arc<Vec<Vec<u8>>>)>>,
    > = std::sync::Arc::new(std::sync::RwLock::new(None));
    #[cfg(feature = "sketch-gk-proof")]
    module
        .register_method("get_spark_spent_tags", move |params, state, _ext| {
            use std::collections::HashSet;
            // Optional positional params [offset, limit]; tolerate none/partial.
            let args: Vec<u64> = params.parse().unwrap_or_default();
            let offset = args.first().copied().unwrap_or(0) as usize;
            // Per-response cap bounds the serialized size; a larger request is
            // clamped and the wallet pages through the remainder.
            let limit = clamp_spent_tags_limit(args.get(1).copied());
            // Snapshot the MEMPOOL FIRST (live, every call), THEN read the chain.
            // Block connect adds a tag to the chain spent set BEFORE removing it
            // from the mempool, so mempool-first guarantees a spend being mined
            // concurrently is in at least one of the two views; the reverse order
            // has a window where a just-mined spend is in NEITHER.
            let mempool_tags = state.mempool.linking_tags_snapshot();
            // The on-chain set is immutable within a height, so sort it once and
            // cache it under the height; a new block (height change) rebuilds it.
            // If a block lands between the height read and the snapshot, the new
            // set is merely labelled with the old height — harmless: the next
            // call at the new height rebuilds, and the mempool overlay is live.
            let height = state.chain.height();
            let chain_sorted: std::sync::Arc<Vec<Vec<u8>>> = {
                let hit = spent_tags_cache.read().ok().and_then(|g| match &*g {
                    Some((h, v)) if *h == height => Some(v.clone()),
                    _ => None,
                });
                match hit {
                    Some(v) => v,
                    None => {
                        let set: HashSet<Vec<u8>> =
                            state.chain.spark_pool_spent_tags().into_iter().collect();
                        let v = std::sync::Arc::new(sort_spent_tags(set));
                        if let Ok(mut g) = spent_tags_cache.write() {
                            *g = Some((height, v.clone()));
                        }
                        v
                    }
                }
            };
            // Overlay the LIVE mempool tags on the cached chain set (F1).
            let (total, tags) =
                spent_tags_overlay_page(&chain_sorted, &mempool_tags, offset, limit);
            Ok::<_, ErrorObjectOwned>(json!({
                "total": total,
                "offset": offset,
                "count": tags.len(),
                "tags": tags,
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── is_spark_serial_spent ─────────────────────────────────
    module.register_method("is_spark_serial_spent", |params, state, _ext| {
        let (hex_s,): (String,) = params.parse().map_err(|e: ErrorObjectOwned| {
            ErrorObjectOwned::owned(-32602, format!("bad params: {}", e), None::<()>)
        })?;
        // Same pre-decode length cap as is_nullifier_spent — see comment there.
        if hex_s.len() > 128 {
            return Err(ErrorObjectOwned::owned(
                -32602, "serial hex too long (max 128 chars)".to_string(), None::<()>,
            ));
        }
        let bytes = hex::decode(&hex_s).map_err(|e| {
            ErrorObjectOwned::owned(-32602, format!("bad hex: {}", e), None::<()>)
        })?;
        if bytes.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                -32602, "serial must be 32 bytes".to_string(), None::<()>,
            ));
        }
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes);
        Ok::<_, ErrorObjectOwned>(json!({
            "serial": hex::encode(s),
            "spent": state.chain.spark_store.as_ref().map(|store| store.is_serial_spent(&s)).unwrap_or(false),
        }))
    }).map_err(|e| Error::RpcError(e.to_string()))?;

    // Deprecated node-selected decoy surface. Wallets construct covered,
    // snapshot-bound locator requests through the replacement methods below.
    module
        .register_method("get_decoys", |_params, _state, _ext| {
            Err::<Value, _>(ErrorObjectOwned::owned(
                -32004,
                "get_decoys is deprecated; use get_decoy_distribution and get_outputs_by_locators",
                None::<()>,
            ))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    module
        .register_blocking_method("get_decoy_distribution", |_params, state, _ext| {
            Ok::<_, ErrorObjectOwned>(state.chain.decoy_distribution_snapshot())
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    module
        .register_blocking_method("get_outputs_by_locators", |params, state, _ext| {
            let (snapshot_height, snapshot_hash, policy_version, locators): (
                u64,
                Hash,
                u16,
                Vec<OutputLocator>,
            ) = params.parse().map_err(|e: ErrorObjectOwned| {
                ErrorObjectOwned::owned(-32602, format!("bad params: {e}"), None::<()>)
            })?;
            state
                .chain
                .resolve_decoy_snapshot(snapshot_height, snapshot_hash, policy_version, &locators)
                .map_err(|e| ErrorObjectOwned::owned(-32000, e.to_string(), None::<()>))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_anonymity_set ─────────────────────────────────────
    //
    // The single most important privacy metric: every unspent
    // output is a potential decoy, so the size of this set is
    // the size of every future spend's anonymity set.
    module
        .register_method("get_anonymity_set", |_params, state, _ext| {
            let count = state.chain.available_output_count();
            let height = state.chain.height();
            let outputs_per_block = if height > 0 {
                count / usize::try_from(height).unwrap_or(usize::MAX)
            } else {
                0
            };
            Ok::<_, ErrorObjectOwned>(json!({
                "anonymity_set":    count,
                "height":           height,
                "outputs_per_block": outputs_per_block,
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    // ── get_privacy_features ──────────────────────────────────
    // Full, HONEST status of every privacy feature: which are live, which are
    // gated-inert pending external audit, and which are disabled — the single
    // source of truth the community can query so nothing is over-claimed.
    // Backed by the privacy connector's read-only registry (#49). Re-landed
    // here after main moved RPC registration into per-domain register fns.
    module
        .register_method("get_privacy_features", |_params, state, _ext| {
            use crate::crypto::privacy_connector::{
                privacy_feature_registry, ConnectorGate, FeatureStatus, CONNECTOR_AUDITED,
            };
            let height = state.chain.stats().height;
            // `None` activation height => gated consensus schemes report as
            // inert, the truthful state until they are audited + scheduled.
            let gate = ConnectorGate::new(state.chain.network(), height, None);
            let features: Vec<_> = privacy_feature_registry(&gate)
                .into_iter()
                .map(|f| {
                    let status = match f.status {
                        FeatureStatus::Active => "active",
                        FeatureStatus::GatedInert => "gated-inert",
                        FeatureStatus::Disabled => "disabled",
                    };
                    json!({ "name": f.name, "status": status, "note": f.note })
                })
                .collect();
            Ok::<_, ErrorObjectOwned>(json!({
                "connector_audited": CONNECTOR_AUDITED,
                "network": format!("{:?}", state.chain.network()),
                "height": height,
                "features": features,
            }))
        })
        .map_err(|e| Error::RpcError(e.to_string()))?;

    Ok(())
}

#[cfg(all(test, feature = "sketch-gk-proof"))]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn paginate_spent_tags_tiles_whole_set_without_gaps_or_dups() {
        // The #378 wallet pages this RPC until it has `total` tags; the pages
        // must cover the whole set exactly once (no tag dropped, none repeated),
        // or a wallet would miscount a spent note as available (or vice versa).
        let mut set: HashSet<Vec<u8>> = HashSet::new();
        for i in 0u8..10 {
            set.insert(vec![i; 34]);
        }
        let mut seen: HashSet<String> = HashSet::new();
        let mut offset = 0usize;
        let total = loop {
            let (total, page) = paginate_spent_tags(set.clone(), offset, 3);
            let got = page.len();
            for t in page {
                assert!(seen.insert(t), "a tag must not appear on two pages");
            }
            offset += got;
            // Mirror the wallet's loop guard: stop at the end or an empty page.
            if offset >= total || got == 0 {
                break total;
            }
        };
        assert_eq!(total, 10, "total reported independent of paging");
        assert_eq!(seen.len(), 10, "every tag fetched exactly once across pages");

        // An offset past the end yields an empty page but still reports `total`,
        // so the wallet's `offset >= total` guard terminates cleanly.
        let (total, page) = paginate_spent_tags(set, 100, 3);
        assert_eq!(total, 10);
        assert!(page.is_empty());
    }

    #[test]
    fn clamp_spent_tags_limit_bounds_the_page() {
        // None → the cap; 0 → 1 (so a paging client always makes progress);
        // a request over the cap is clamped down to it.
        assert_eq!(clamp_spent_tags_limit(None), MAX_SPENT_TAGS_PAGE);
        assert_eq!(clamp_spent_tags_limit(Some(0)), 1);
        assert_eq!(clamp_spent_tags_limit(Some(10)), 10);
        assert_eq!(
            clamp_spent_tags_limit(Some(MAX_SPENT_TAGS_PAGE as u64 + 1)),
            MAX_SPENT_TAGS_PAGE
        );
    }

    #[test]
    fn mempool_overlay_makes_a_pending_spend_visible() {
        // F1 regression: a spend sitting in the mempool (not yet on chain) MUST
        // appear in the result on every call — not only when the cache was built.
        // If it were invisible, a wallet that just sent and then refreshed its
        // balance would treat the note as unspent and could re-select it.
        let chain_sorted = vec![vec![1u8; 34], vec![3u8; 34]];
        let pending = vec![2u8; 34]; // in the mempool, not yet on chain
        let (total, page) = spent_tags_overlay_page(&chain_sorted, &[pending], 0, 10);
        assert_eq!(total, 3, "pending mempool tag counts toward the total");
        assert_eq!(
            page,
            vec![
                hex::encode([1u8; 34]),
                hex::encode([2u8; 34]),
                hex::encode([3u8; 34])
            ],
            "pending tag appears in global sorted position"
        );

        // A mempool tag already mined onto the chain is deduped, not counted twice.
        let (total, page) = spent_tags_overlay_page(&chain_sorted, &[vec![1u8; 34]], 0, 10);
        assert_eq!(total, 2, "a mempool tag already on chain is deduped");
        assert_eq!(
            page,
            vec![hex::encode([1u8; 34]), hex::encode([3u8; 34])]
        );
    }

    #[test]
    fn overlay_pages_tile_the_union_of_chain_and_mempool() {
        // Chain {0,2,4,6,8} overlaid with mempool {1,3,5} (none on chain) → a
        // union of 8 tags that paging must cover exactly once, pending included.
        let chain_sorted: Vec<Vec<u8>> = (0u8..5).map(|i| vec![i * 2; 34]).collect();
        let mempool: Vec<Vec<u8>> = [1u8, 3, 5].iter().map(|&i| vec![i; 34]).collect();
        let mut seen: HashSet<String> = HashSet::new();
        let mut offset = 0usize;
        let total = loop {
            let (total, page) = spent_tags_overlay_page(&chain_sorted, &mempool, offset, 3);
            let got = page.len();
            for t in page {
                assert!(seen.insert(t), "a tag must not appear on two pages");
            }
            offset += got;
            if offset >= total || got == 0 {
                break total;
            }
        };
        assert_eq!(total, 8, "union total independent of paging");
        assert_eq!(seen.len(), 8, "every chain+mempool tag fetched exactly once");
    }
}
