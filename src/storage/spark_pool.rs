//! # Spark Pool Store — the libspark-FFI-aligned canonical shielded store
//!
//! This is the store the **audited libspark spend path** actually needs, and
//! the one `SparkBackend::verify_solvency` checks tags against. It holds, for
//! the chosen "one audited Spark pool" ([[coincync-strategy-narrow-shielded]]):
//!
//! 1. **Coins by outpoint.** Each minted Spark coin is stored as its full
//!    libspark serialization ([`spark_connector::CoinBytes`], which carries the
//!    on-wire `S, K, C`), keyed by its outpoint (`tx_hash ‖ vout`), together
//!    with the **deterministic serial context** derived from that outpoint
//!    (`spark_connector::ffi::serial_context`). Storing the context makes a
//!    coin recoverable/spendable later from its chain position alone.
//! 2. **Ordered cover set.** Coins are appended in a dense `cover_index` order,
//!    so [`cover_set`](SparkPoolStore::cover_set) yields the exact `&[CoinBytes]`
//!    a spender passes to `build_spend_over_set`.
//! 3. **Spent VRF-tag set.** The double-spend / unspent nullifier set, keyed on
//!    the **34-byte VRF linking tag** `T = (U−D)·s⁻¹` the spend proof reveals
//!    (not the 32-byte serial of the earlier native sketch).
//!    [`spent_tags`](SparkPoolStore::spent_tags) feeds `verify_solvency`, whose
//!    `T ∉ spent-set` check is what makes "I own an in-range coin" mean "…that
//!    is still unspent."
//!
//! ## Relationship to the other stores (honest note)
//! The tree accumulated three partial shielded designs: the Halo2/Orchard
//! [`shielded`](crate::storage::shielded) tree (BLAKE3 leaves; ZK spend never
//! implemented) and the native [`spark`](crate::storage::spark) `SparkStore`
//! (32-byte commitments + 32-byte serials, pre-FFI sketch). Neither matches the
//! libspark FFI's data shapes (variable-length `CoinBytes`, 34-byte VRF tags).
//! This store is the FFI-aligned one; retiring the other two under the one-pool
//! consolidation is follow-up migration, not done here.
//!
//! ## Status
//! Gated `sketch-gk-proof` (+ `libspark-ffi` for the real backend). **Wired into
//! the GATED consensus path:** `chain.rs::verify_block_spark_v2` /
//! `apply_spark_v2_txs` verify against and feed this store, and
//! `checkpoint_phase2_stores` / `rewind_phase2_stores` drive its reorg API
//! ([`checkpoint_at_height`](SparkPoolStore::checkpoint_at_height) /
//! [`rewind`](SparkPoolStore::rewind)) in lock-step with the sibling Phase-2
//! stores. RocksDB persistence is implemented
//! ([`open_with_db`](SparkPoolStore::open_with_db)); [`new`](SparkPoolStore::new)
//! is the in-memory form for tests. Shielded stays **activation-gated OFF**
//! (activation height `u64::MAX` on testnet/mainnet), so this store is never on
//! the LIVE consensus path until the external audit clears — but it IS exercised
//! end-to-end in gated regtest and the 24h in-block soak.

use std::collections::HashMap;

use borsh::{BorshDeserialize, BorshSerialize};
use parking_lot::RwLock;
use spark_connector::{CoinBytes, Nullifier};

use crate::db::shim;
use crate::db::Database;
use crate::error::{Error, Result};

/// Bound on the reorg checkpoint stack — matches the sibling Phase-2 stores
/// (`ShieldedStore` / `SparkStore` use 1000, covering testnet max_reorg_depth).
const MAX_CHECKPOINTS: usize = 1000;

/// Maximum coins in a single Spark cover-set group (= N, the libspark
/// `get_coincync` Grootle capacity n^m = 8^3 = 512, CoinCync's RATIFIED
/// production anon-set). libspark rejects a cover set larger than N on both
/// prove and verify, so [`SparkPoolStore::cover_set_at`] buckets the pool into
/// fixed groups of at most this many coins (#259). MUST stay in lock-step with
/// `cc_params()`/`spark_ffi_cover_set_size` in the shim.
pub const SPARK_COVER_SET_GROUP: usize = 512;

/// Borsh-serializable form of a [`SparkPoolCoin`] for RocksDB. `CoinBytes` /
/// `Nullifier` are the connector's plain byte wrappers (not Borsh), so the
/// persisted row uses plain `Vec<u8>` fields and converts at the boundary.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
struct PersistedCoin {
    outpoint: Vec<u8>,
    coin: Vec<u8>,
    serial_context: Vec<u8>,
    height: u64,
    cover_index: u64,
}

/// Optional RocksDB-backed persistence: coins keyed by `cover_index` (BE), and
/// spent VRF tags keyed by the tag bytes.
struct SparkPoolPersistence {
    coins: shim::Tree,
    tags: shim::Tree,
    /// Small metadata CF: the running pool value survives restart (key
    /// `POOL_VALUE_KEY`, an i128 in little-endian).
    meta: shim::Tree,
}

/// Persistence key for the running pool value in the meta CF.
const POOL_VALUE_KEY: &[u8] = b"pool_value";

/// One coin in the pool: its libspark serialization plus the metadata needed to
/// re-derive its spend witness (the deterministic serial context) and to place
/// it in the cover set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparkPoolCoin {
    /// The coin's outpoint identity (`tx_hash ‖ vout`) — also the seed the
    /// deterministic serial context is derived from.
    pub outpoint: Vec<u8>,
    /// The full libspark-serialized `Coin` (carries `S, K, C`).
    pub coin: CoinBytes,
    /// The deterministic serial context bound into this coin (from the
    /// outpoint). Kept so a spender need not re-derive it.
    pub serial_context: Vec<u8>,
    /// Block height the coin was minted at.
    pub height: u64,
    /// Dense position in the ordered cover set.
    pub cover_index: u64,
}

/// One reorg checkpoint boundary — taken BEFORE a block applies. `coins_len` is
/// the cover-set length at the boundary (coins at index `>= coins_len` belong to
/// the block being guarded); `height` is that block (tags spent at or above it
/// are dropped on rewind).
#[derive(Clone, Copy, Debug)]
struct PoolCheckpoint {
    height: u64,
    coins_len: usize,
    /// Pool value (`Σ value_balance`) at the boundary, so a reorg restores the
    /// exact pre-block total.
    pool_value: i128,
}

/// One staged persistence op for the pool's RocksDB trees. When a block's apply
/// is staging (`begin_staging`), the pool's write methods buffer these instead
/// of writing immediately, so the chain can flush them into the SAME atomic
/// `WriteBatch` as the transparent block commit — pool state then lands together
/// with the committed tip (all-or-nothing) and can never be left one block ahead
/// of (or behind) the chain. The variant selects which tree the op targets.
#[derive(Clone, Debug)]
pub enum StagedPoolOp {
    /// `coins` tree: `cover_index` (BE) → serialized `PersistedCoin`.
    CoinInsert { cover_index: u64, value: Vec<u8> },
    /// `coins` tree: delete `cover_index` (BE) — a reorg rewind.
    CoinRemove { cover_index: u64 },
    /// `tags` tree: tag bytes → spend height (LE).
    TagInsert { tag: Vec<u8>, height: u64 },
    /// `tags` tree: delete a tag — a reorg rewind.
    TagRemove { tag: Vec<u8> },
    /// `meta` tree: a fixed key → value (today only the running pool value).
    MetaInsert { key: Vec<u8>, value: Vec<u8> },
}

/// The libspark-aligned Spark pool store. RocksDB-backed when opened via
/// [`SparkPoolStore::open_with_db`] (coins, spent tags, pool value, and the
/// reorg checkpoint stack all persist + replay); a plain `new()` is in-memory
/// (tests). See module docs for the gated/inert status.
pub struct SparkPoolStore {
    /// Ordered cover set — coins in `cover_index` order.
    coins: RwLock<Vec<SparkPoolCoin>>,
    /// `outpoint -> cover_index`, so a coin is locatable by its chain identity.
    by_outpoint: RwLock<HashMap<Vec<u8>, u64>>,
    /// `blake3(coin bytes) -> cover_index` content index, maintained for EVERY
    /// pooled coin (mint feed and spend outputs alike). A mint coin is keyed in
    /// `by_outpoint` by its tx-derived outpoint, so the SAME mint bundle replayed
    /// under different tx inputs yields fresh outpoints and would re-enter the
    /// pool, inflating `pool_value` with coins no one can spend (#380). This index
    /// lets the block gate reject a coin whose libspark bytes are already pooled.
    /// A libspark coin commits to a random serial, so identical bytes mean a
    /// replay, never two honest coins — it is a presence check, exact in the
    /// absence of content duplicates (which the gate now forbids going forward).
    by_coin: RwLock<HashMap<[u8; 32], u64>>,
    /// Spent VRF-tag set: tag bytes -> spend height.
    spent_tags: RwLock<HashMap<Vec<u8>, u64>>,
    /// Reorg checkpoint stack (in lock-step with the block-apply path), capped
    /// at `MAX_CHECKPOINTS`. In-memory: the pool is rebuilt deterministically
    /// from the committed chain on restart (`Blockchain::rebuild_phase2_stores`),
    /// which re-checkpoints this stack to the committed depth — so a reorg past a
    /// restart rewinds correctly without persisting the stack here.
    checkpoints: RwLock<Vec<PoolCheckpoint>>,
    /// Maintained max coin/tag heights so the security guard is O(1) on the hot
    /// path (a per-block O(n) scan would itself be a DoS as the pool grows).
    /// Updated on add/mark; recomputed on the (rare) rewind.
    max_coin_height: RwLock<Option<u64>>,
    max_spent_tag_height: RwLock<Option<u64>>,
    /// The running shielded pool value: `Σ value_balance` applied, where a
    /// shield-in (`value_balance < 0`) grows it and an unshield-out shrinks it.
    /// The "no inflation across the veil" invariant is `pool_value >= 0` — you
    /// cannot unshield more than was ever shielded in. Persisted + reorg-aware.
    pool_value: RwLock<i128>,
    /// RocksDB-backed persistence. `None` for in-memory tests.
    persistence: Option<SparkPoolPersistence>,
    /// Block-apply staging buffer. `None` = persist immediately (the default,
    /// and what tests / `rebuild_phase2_stores` use). `Some(buf)` = defer every
    /// persist op into `buf` for the chain to flush into the block's atomic
    /// commit batch (see `begin_staging` / `take_staged_ops` and `StagedPoolOp`).
    /// In-memory mutations still happen eagerly; only durability is deferred.
    staging: RwLock<Option<Vec<StagedPoolOp>>>,
}

impl SparkPoolStore {
    /// A fresh, empty in-memory pool store.
    pub fn new() -> Self {
        Self {
            coins: RwLock::new(Vec::new()),
            by_outpoint: RwLock::new(HashMap::new()),
            by_coin: RwLock::new(HashMap::new()),
            spent_tags: RwLock::new(HashMap::new()),
            checkpoints: RwLock::new(Vec::new()),
            max_coin_height: RwLock::new(None),
            max_spent_tag_height: RwLock::new(None),
            pool_value: RwLock::new(0),
            persistence: None,
            staging: RwLock::new(None),
        }
    }

    /// Open a persistent pool store. Replays coins by `cover_index`, loads spent
    /// VRF tags, the running pool value, AND the reorg checkpoint stack — so a
    /// reorg deeper than a node restart can still rewind the pool (restart-durable
    /// Phase-2 rewind) instead of stranding a disconnected block's state.
    pub fn open_with_db(database: &Database) -> Result<Self> {
        let coins_tree = database.open_tree("spark_pool_coins")?;
        let tags_tree = database.open_tree("spark_pool_tags")?;
        let meta_tree = database.open_tree("spark_pool_meta")?;

        // Collect + sort coins by cover_index (the BE-encoded key).
        let mut loaded: Vec<(u64, PersistedCoin)> = Vec::new();
        for item in coins_tree.iter() {
            let (key, value) =
                item.map_err(|e| Error::DatabaseError(format!("spark_pool coins iter: {}", e)))?;
            let key_bytes: [u8; 8] = key.as_ref().try_into().map_err(|_| {
                Error::DatabaseError("spark_pool_coins key must be 8 bytes".into())
            })?;
            let entry: PersistedCoin = borsh::from_slice(value.as_ref())
                .map_err(|e| Error::SerializationError(format!("spark_pool coin: {}", e)))?;
            loaded.push((u64::from_be_bytes(key_bytes), entry));
        }
        loaded.sort_by_key(|(id, _)| *id);

        let mut coins = Vec::with_capacity(loaded.len());
        let mut by_outpoint = HashMap::with_capacity(loaded.len());
        let mut by_coin: HashMap<[u8; 32], u64> = HashMap::with_capacity(loaded.len());
        for (cover_index, p) in loaded {
            by_outpoint.insert(p.outpoint.clone(), cover_index);
            by_coin.insert(*blake3::hash(&p.coin).as_bytes(), cover_index);
            coins.push(SparkPoolCoin {
                outpoint: p.outpoint,
                coin: CoinBytes(p.coin),
                serial_context: p.serial_context,
                height: p.height,
                cover_index,
            });
        }

        let mut spent_tags = HashMap::new();
        for item in tags_tree.iter() {
            let (key, value) =
                item.map_err(|e| Error::DatabaseError(format!("spark_pool tags iter: {}", e)))?;
            let h_bytes: [u8; 8] = value.as_ref().try_into().map_err(|_| {
                Error::DatabaseError("spark_pool_tags value must be 8 bytes".into())
            })?;
            spent_tags.insert(key.as_ref().to_vec(), u64::from_le_bytes(h_bytes));
        }

        let max_coin_height = coins.iter().map(|c| c.height).max();
        let max_spent_tag_height = spent_tags.values().copied().max();

        // Restore the running pool value (i128 LE); default 0 if unset.
        let pool_value = meta_tree
            .get(POOL_VALUE_KEY)
            .ok()
            .flatten()
            .and_then(|v| <[u8; 16]>::try_from(v.as_ref()).ok())
            .map(i128::from_le_bytes)
            .unwrap_or(0);

        // The reorg checkpoint stack is NOT restored at the store level: unlike
        // its three sibling Phase-2 stores (whose coins/notes are committed
        // atomically with the block, so restoring their persisted stack is exact),
        // this pool persists its coins/tags/pool_value via IMMEDIATE writes OUTSIDE
        // the block's atomic commit, so after an ill-timed crash it can be one
        // block AHEAD of the committed tip — and its checkpoint stack one deeper.
        // So the pool is REBUILT deterministically from the committed chain on
        // restart (`Blockchain::rebuild_phase2_stores`), which clears this store and
        // replays committed blocks, re-checkpointing the stack to exactly the
        // committed depth — matching the siblings and making a reorg past the
        // restart rewind correctly (#369/#373). Start empty here; the rebuild
        // repopulates it.
        let checkpoints: Vec<PoolCheckpoint> = Vec::new();

        Ok(Self {
            coins: RwLock::new(coins),
            by_outpoint: RwLock::new(by_outpoint),
            by_coin: RwLock::new(by_coin),
            spent_tags: RwLock::new(spent_tags),
            checkpoints: RwLock::new(checkpoints),
            max_coin_height: RwLock::new(max_coin_height),
            max_spent_tag_height: RwLock::new(max_spent_tag_height),
            pool_value: RwLock::new(pool_value),
            persistence: Some(SparkPoolPersistence {
                coins: coins_tree,
                tags: tags_tree,
                meta: meta_tree,
            }),
            staging: RwLock::new(None),
        })
    }

    /// Begin staging this block's persistence into a buffer instead of writing
    /// it immediately, so the chain can flush it into the block's atomic commit
    /// batch (`commit_block_atomic`). Call BEFORE the block's apply; pair with
    /// [`take_staged_ops`](Self::take_staged_ops) after the commit. In-memory
    /// mutations still happen eagerly (they compute the staged key/values); only
    /// durability is deferred, so a crash before the batch commits leaves the
    /// pool exactly in sync with the (also-uncommitted) tip. A no-op on an
    /// in-memory store (nothing to persist). Re-entrancy: block apply is
    /// serialized by the chain's apply lock, so at most one block stages at once.
    pub fn begin_staging(&self) {
        *self.staging.write() = Some(Vec::new());
    }

    /// Stop staging and drain the ops accumulated since [`begin_staging`]. The
    /// chain flushes these into the block's `WriteBatch`; on a commit failure it
    /// discards them and rewinds the in-memory apply. Empty if staging was not
    /// active. Always call this once per `begin_staging`, even on the error path,
    /// so staging never leaks into the next block.
    pub fn take_staged_ops(&self) -> Vec<StagedPoolOp> {
        self.staging.write().take().unwrap_or_default()
    }

    /// The pool's three persistence column families in the fixed order
    /// `[coins, tags, meta]`, for joining into the block's atomic commit batch via
    /// `Database::commit_block_atomic_with_phase2`. `None` for an in-memory store
    /// (nothing to persist).
    pub(crate) fn staging_trees(&self) -> Option<[&shim::Tree; 3]> {
        self.persistence.as_ref().map(|p| [&p.coins, &p.tags, &p.meta])
    }

    /// Translate staged ops into `(tree_index, key, value-or-delete)` tuples keyed
    /// to [`staging_trees`](Self::staging_trees)'s order — `0 = coins`, `1 = tags`,
    /// `2 = meta` — ready to pass as the `extra_ops` of
    /// `commit_block_atomic_with_phase2` / `apply_reorg_atomic_with_phase2`. A
    /// `None` value is a delete (a reorg rewind), `Some(v)` a put.
    pub(crate) fn staged_ops_to_writes(
        ops: &[StagedPoolOp],
    ) -> Vec<(usize, Vec<u8>, Option<Vec<u8>>)> {
        ops.iter()
            .map(|op| match op {
                StagedPoolOp::CoinInsert { cover_index, value } => {
                    (0usize, cover_index.to_be_bytes().to_vec(), Some(value.clone()))
                }
                StagedPoolOp::CoinRemove { cover_index } => {
                    (0usize, cover_index.to_be_bytes().to_vec(), None)
                }
                StagedPoolOp::TagInsert { tag, height } => {
                    (1usize, tag.clone(), Some(height.to_le_bytes().to_vec()))
                }
                StagedPoolOp::TagRemove { tag } => (1usize, tag.clone(), None),
                StagedPoolOp::MetaInsert { key, value } => {
                    (2usize, key.clone(), Some(value.clone()))
                }
            })
            .collect()
    }

    /// Route a persist op: buffer it when a block is staging, otherwise write it
    /// to RocksDB immediately (the pre-atomic-commit behavior, kept for tests,
    /// `rebuild_phase2_stores`, and any non-block-apply mutation). The immediate
    /// path is R-61 CLASS — a persistence failure on consensus pool state halts,
    /// never continues in-memory-only, since that would diverge the replayed
    /// store after a restart.
    fn apply_pool_write(&self, op: StagedPoolOp) {
        if let Some(buf) = self.staging.write().as_mut() {
            buf.push(op);
            return;
        }
        let p = match &self.persistence {
            Some(p) => p,
            None => return,
        };
        match op {
            StagedPoolOp::CoinInsert { cover_index, value } => {
                if let Err(e) = p.coins.insert(cover_index.to_be_bytes(), value) {
                    panic!("R-61: spark_pool_coins write failed at cover_index {cover_index}: {e}");
                }
            }
            StagedPoolOp::CoinRemove { cover_index } => {
                if let Err(e) = p.coins.remove(cover_index.to_be_bytes()) {
                    panic!(
                        "R-61: spark_pool coin rewind-remove failed at cover_index {cover_index}: {e}"
                    );
                }
            }
            StagedPoolOp::TagInsert { tag, height } => {
                if let Err(e) = p.tags.insert(&tag, height.to_le_bytes()) {
                    panic!("R-61: spark_pool_tags write failed at height {height}: {e}");
                }
            }
            StagedPoolOp::TagRemove { tag } => {
                if let Err(e) = p.tags.remove(tag.as_slice()) {
                    panic!("R-61: spark_pool tag rewind-remove failed: {e}");
                }
            }
            StagedPoolOp::MetaInsert { key, value } => {
                if let Err(e) = p.meta.insert(&key, value) {
                    panic!("R-61: spark_pool meta write failed: {e}");
                }
            }
        }
    }

    /// Append a minted coin at `outpoint` (with its libspark bytes, its
    /// deterministic serial context, and mint height). Returns the assigned
    /// dense `cover_index`, or `None` if `outpoint` is already present (a coin's
    /// outpoint is unique, so a duplicate is a caller bug / replay).
    pub fn add_coin(
        &self,
        outpoint: Vec<u8>,
        coin: CoinBytes,
        serial_context: Vec<u8>,
        height: u64,
    ) -> Option<u64> {
        let mut by_op = self.by_outpoint.write();
        if by_op.contains_key(&outpoint) {
            return None;
        }
        let mut coins = self.coins.write();
        let cover_index = coins.len() as u64;
        let entry = SparkPoolCoin {
            outpoint: outpoint.clone(),
            coin,
            serial_context,
            height,
            cover_index,
        };
        // Persist (immediately) or stage (for the block's atomic batch) the coin.
        // Only serialize when a write will actually be used — an in-memory-only
        // store (tests) has no persistence and never stages, so it skips this.
        if self.persistence.is_some() {
            let persisted = PersistedCoin {
                outpoint: entry.outpoint.clone(),
                coin: entry.coin.0.clone(),
                serial_context: entry.serial_context.clone(),
                height: entry.height,
                cover_index,
            };
            let value = borsh::to_vec(&persisted).unwrap_or_else(|e| {
                panic!("R-61: SparkPoolCoin borsh serialize failed at cover_index {cover_index}: {e}")
            });
            self.apply_pool_write(StagedPoolOp::CoinInsert { cover_index, value });
        }
        // Content index (#380): key this coin by its libspark bytes so the block
        // gate can reject a replayed mint bundle whose coins are already pooled.
        self.by_coin
            .write()
            .insert(*blake3::hash(&entry.coin.0).as_bytes(), cover_index);
        by_op.insert(outpoint, cover_index);
        coins.push(entry);
        // O(1) guard maintenance.
        let mut m = self.max_coin_height.write();
        *m = Some(m.map_or(height, |cur| cur.max(height)));
        Some(cover_index)
    }

    /// The ordered cover set as `CoinBytes` — exactly what a spender hands to
    /// `spark_connector::ffi::build_spend_over_set`.
    pub fn cover_set(&self) -> Vec<CoinBytes> {
        self.coins.read().iter().map(|c| c.coin.clone()).collect()
    }

    /// The cover set anchored at a pool snapshot: the `cover_set_id` group's
    /// coins with `height <= anchor_height`, in `cover_index` order (canonical,
    /// so every node resolves the identical `{C_i}` a Grootle proof was built
    /// against).
    ///
    /// #259: the pool is split into FIXED groups of at most
    /// [`SPARK_COVER_SET_GROUP`] (= N, the libspark `get_coincync` Grootle
    /// capacity) coins, indexed by `cover_set_id`: group `g` is the coins whose
    /// insertion position lies in `[g*N, (g+1)*N)`. A coin's group is stable (its
    /// insertion index never changes), so it is always spendable in exactly one
    /// group, and the returned set never exceeds N — which libspark requires
    /// (it rejects an oversized cover set on both prove and verify). Group 0 is
    /// the whole pool until it first exceeds N.
    pub fn cover_set_at(&self, cover_set_id: u64, anchor_height: u64) -> Vec<CoinBytes> {
        let start = (cover_set_id as usize).saturating_mul(SPARK_COVER_SET_GROUP);
        let end = start.saturating_add(SPARK_COVER_SET_GROUP);
        self.coins
            .read()
            .iter()
            .enumerate()
            .filter(|(idx, c)| *idx >= start && *idx < end && c.height <= anchor_height)
            .map(|(_, c)| c.coin.clone())
            .collect()
    }

    /// Number of coins in the cover set.
    pub fn coin_count(&self) -> usize {
        self.coins.read().len()
    }

    /// The anchored cover set as `(outpoint, coin bytes, serial_context,
    /// height)` in canonical cover-index order — coins with `height <=
    /// anchor_height`. This is exactly the set [`cover_set_at`](Self::cover_set_at)
    /// resolves (same filter + order), enriched with each coin's serial context
    /// and outpoint so a REMOTE wallet (which lacks the store) can identify its
    /// owned coin and build a spend against the identical set the verifier will
    /// resolve. The position in this `Vec` is the coin's spend index for a proof
    /// anchored at `(cover_set_id, anchor_height)`. Resolves the SAME fixed
    /// `cover_set_id` group as [`cover_set_at`](Self::cover_set_at) (#259), so a
    /// remote wallet and the verifier agree on the set and the spend index.
    pub fn cover_entries_at(
        &self,
        cover_set_id: u64,
        anchor_height: u64,
    ) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>, u64)> {
        let start = (cover_set_id as usize).saturating_mul(SPARK_COVER_SET_GROUP);
        let end = start.saturating_add(SPARK_COVER_SET_GROUP);
        self.coins
            .read()
            .iter()
            .enumerate()
            .filter(|(idx, c)| *idx >= start && *idx < end && c.height <= anchor_height)
            .map(|(_, c)| {
                (
                    c.outpoint.clone(),
                    c.coin.0.clone(),
                    c.serial_context.clone(),
                    c.height,
                )
            })
            .collect()
    }

    /// Every pool coin as `(outpoint, coin bytes, serial_context, height)` in
    /// cover-set order — what a wallet scan needs to test ownership (via
    /// `SparkBackend::identify` on the coin bytes) and, for owned coins, key the
    /// note by its outpoint + recover its serial context for a later spend.
    pub fn coin_entries(&self) -> Vec<(Vec<u8>, CoinBytes, Vec<u8>, u64)> {
        self.coins
            .read()
            .iter()
            .map(|c| (c.outpoint.clone(), c.coin.clone(), c.serial_context.clone(), c.height))
            .collect()
    }

    /// The cover-set index of the coin at `outpoint`, if present.
    pub fn index_of(&self, outpoint: &[u8]) -> Option<u64> {
        self.by_outpoint.read().get(outpoint).copied()
    }

    /// Whether a coin with these exact libspark bytes is already pooled (#380).
    /// `content` is `blake3(coin bytes)`. Used by the block gate to reject a mint
    /// bundle replayed under fresh tx inputs: the replay's coins carry identical
    /// bytes, so this returns `true` and the gate rejects before the dead copies
    /// can re-enter the pool and inflate `pool_value`.
    pub fn coin_content_present(&self, content: &[u8; 32]) -> bool {
        self.by_coin.read().contains_key(content)
    }

    /// The coin at a cover-set index, if present.
    pub fn coin_at(&self, cover_index: u64) -> Option<SparkPoolCoin> {
        self.coins.read().get(cover_index as usize).cloned()
    }

    /// The deterministic serial context stored for the coin at `outpoint`.
    pub fn context_for(&self, outpoint: &[u8]) -> Option<Vec<u8>> {
        let idx = *self.by_outpoint.read().get(outpoint)?;
        self.coins
            .read()
            .get(idx as usize)
            .map(|c| c.serial_context.clone())
    }

    /// Mark a VRF linking tag spent at `height`. Returns `false` if the tag was
    /// already spent (double-spend / not-unspent).
    pub fn mark_tag_spent(&self, tag: &Nullifier, height: u64) -> bool {
        let mut tags = self.spent_tags.write();
        if tags.contains_key(&tag.0) {
            return false;
        }
        // Persist immediately or stage for the block's atomic batch.
        if self.persistence.is_some() {
            self.apply_pool_write(StagedPoolOp::TagInsert { tag: tag.0.clone(), height });
        }
        tags.insert(tag.0.clone(), height);
        // O(1) guard maintenance.
        let mut m = self.max_spent_tag_height.write();
        *m = Some(m.map_or(height, |cur| cur.max(height)));
        true
    }

    /// Whether a VRF linking tag has been spent.
    pub fn is_tag_spent(&self, tag: &Nullifier) -> bool {
        self.spent_tags.read().contains_key(&tag.0)
    }

    /// The height a tag was spent at, if spent. (Read-only; used by the pool
    /// security service for forensic investigation.)
    pub fn spent_tag_height(&self, tag: &Nullifier) -> Option<u64> {
        self.spent_tags.read().get(&tag.0).copied()
    }

    /// Number of spent tags.
    pub fn spent_tag_count(&self) -> usize {
        self.spent_tags.read().len()
    }

    /// The highest block height any coin was minted at (`None` if empty). O(1):
    /// a maintained field, so the security guard never scans the pool.
    pub fn max_coin_height(&self) -> Option<u64> {
        *self.max_coin_height.read()
    }

    /// Wipe the pool to empty — in-memory AND persisted — so recovery can rebuild
    /// it deterministically from the committed chain.
    ///
    /// The pool persists its coins / spent tags / pool value via IMMEDIATE writes
    /// DURING block apply (`add_coin` / `mark_tag_spent` / `apply_value_balance`),
    /// which happen OUTSIDE the block's atomic `commit_block_atomic`. A crash in
    /// that window can therefore leave the persisted pool one block AHEAD of the
    /// committed chain tip; on restart the node re-syncs the uncommitted block and
    /// `verify_block_spark_v2` rejects it ("mint coin outpoint already in the
    /// pool"), wedging the node. Recovery clears the pool and replays block apply
    /// up to the committed tip (see `Blockchain::rebuild_phase2_stores`, mirroring
    /// `rebuild_utxo_set`), making the pool a deterministic function of the chain
    /// and eliminating the divergence for any crash window.
    pub fn clear(&self) -> Result<()> {
        self.coins.write().clear();
        self.by_outpoint.write().clear();
        self.by_coin.write().clear();
        self.spent_tags.write().clear();
        self.checkpoints.write().clear();
        *self.max_coin_height.write() = None;
        *self.max_spent_tag_height.write() = None;
        *self.pool_value.write() = 0;
        if let Some(ref p) = self.persistence {
            p.coins
                .clear()
                .map_err(|e| Error::DatabaseError(format!("spark_pool coins clear: {e}")))?;
            p.tags
                .clear()
                .map_err(|e| Error::DatabaseError(format!("spark_pool tags clear: {e}")))?;
            p.meta
                .clear()
                .map_err(|e| Error::DatabaseError(format!("spark_pool meta clear: {e}")))?;
        }
        Ok(())
    }

    /// The highest block height any tag was spent at (`None` if none spent).
    /// O(1) maintained field.
    pub fn max_spent_tag_height(&self) -> Option<u64> {
        *self.max_spent_tag_height.read()
    }

    /// How many coins were minted at `height` or later — a velocity signal for
    /// the surveillance scan.
    pub fn coins_at_or_after(&self, height: u64) -> usize {
        self.coins.read().iter().filter(|c| c.height >= height).count()
    }

    /// Apply one shielded tx's `value_balance` to the running pool total: a
    /// shield-in (`value_balance < 0`) grows it, an unshield-out (`> 0`) shrinks
    /// it. Returns `Err` (and leaves the total unchanged) if it would drive the
    /// pool NEGATIVE — an attempt to unshield more than was ever shielded in
    /// ("no inflation across the veil"). Persists the new total. Reorg-safe: a
    /// checkpoint snapshots the pre-block total and `rewind` restores it.
    pub fn apply_value_balance(&self, value_balance: i64) -> Result<()> {
        let mut pv = self.pool_value.write();
        // total_after = total − value_balance (value_balance > 0 removes value).
        let after = *pv - value_balance as i128;
        if after < 0 {
            return Err(Error::InvalidTransaction(format!(
                "shielded pool underflow: pool {} − value_balance {} = {} < 0 \
                 (cannot unshield more than the pool holds)",
                *pv, value_balance, after
            )));
        }
        *pv = after;
        // The pool value is a consensus quantity (the "no inflation across the
        // veil" gate); persist it immediately or stage it for the block's atomic
        // batch, together with the coins/tags of the same block.
        if self.persistence.is_some() {
            self.apply_pool_write(StagedPoolOp::MetaInsert {
                key: POOL_VALUE_KEY.to_vec(),
                value: after.to_le_bytes().to_vec(),
            });
        }
        Ok(())
    }

    /// The current shielded pool value (`Σ value_balance`). The invariant is
    /// `>= 0`; the security detail guards it.
    pub fn pool_value(&self) -> i128 {
        *self.pool_value.read()
    }

    /// A snapshot of the spent VRF-tag set — passed straight to
    /// `SparkBackend::verify_solvency` as the `spent_tags` the proof's revealed
    /// tag must NOT be in.
    pub fn spent_tags(&self) -> Vec<Nullifier> {
        self.spent_tags
            .read()
            .keys()
            .cloned()
            .map(Nullifier)
            .collect()
    }

    /// Mark a reorg checkpoint for the block at `height`, taken BEFORE its coins
    /// and tags are applied. Capped at `MAX_CHECKPOINTS` (oldest dropped past
    /// the cap), matching the sibling stores.
    pub fn checkpoint_at_height(&self, height: u64) {
        let coins_len = self.coins.read().len();
        let pool_value = *self.pool_value.read();
        // In-memory stack. The pool is a deterministic rebuild of the committed
        // chain on restart (`Blockchain::rebuild_phase2_stores` clears + replays +
        // re-checkpoints), so this stack is not persisted at the store level —
        // the rebuild repopulates it to the committed depth, matching the siblings.
        let mut cps = self.checkpoints.write();
        cps.push(PoolCheckpoint { height, coins_len, pool_value });
        if cps.len() > MAX_CHECKPOINTS {
            cps.remove(0);
        }
    }

    /// Number of reorg checkpoints currently held.
    pub fn checkpoint_count(&self) -> usize {
        self.checkpoints.read().len()
    }

    /// A blake3 accumulator root over the ordered coin serializations. This is a
    /// diagnostic / lock-step quantity for the [`Phase2Store`] seam — the store
    /// is not (yet) a consensus commitment, so this root is not anchored into
    /// block headers.
    pub fn current_root(&self) -> [u8; 32] {
        let coins = self.coins.read();
        let mut h = blake3::Hasher::new();
        h.update(b"COINCYNC_SPARK_POOL_ROOT_v1");
        for c in coins.iter() {
            h.update(&(c.coin.0.len() as u64).to_le_bytes());
            h.update(&c.coin.0);
        }
        *h.finalize().as_bytes()
    }

    /// Rewind one checkpoint — disconnect the most recently applied block:
    /// truncate the cover set to the checkpoint's `coins_len` (dropping the
    /// disconnected block's coins and their `by_outpoint` + `by_coin` index
    /// entries) and drop every tag spent at `height >= restore.height`. Returns
    /// `false` if the checkpoint stack was empty.
    pub fn rewind(&self) -> bool {
        let restore = match self.checkpoints.write().pop() {
            Some(cp) => cp,
            None => return false,
        };

        // Drop coins at or past the boundary, and their index entries.
        let removed_indices: Vec<u64> = {
            let mut coins = self.coins.write();
            let mut by_op = self.by_outpoint.write();
            let mut by_coin = self.by_coin.write();
            let removed: Vec<u64> = (restore.coins_len as u64..coins.len() as u64).collect();
            for c in coins.iter().skip(restore.coins_len) {
                by_op.remove(&c.outpoint);
                // Only drop the content key if it still points at the coin being
                // removed: the gate forbids content duplicates going forward, so
                // this is exact; guarding by index keeps a pre-fix duplicate from
                // erasing a surviving lower-index coin's entry.
                let content = *blake3::hash(&c.coin.0).as_bytes();
                if by_coin.get(&content) == Some(&c.cover_index) {
                    by_coin.remove(&content);
                }
            }
            coins.truncate(restore.coins_len);
            removed
        };

        // Drop tags spent at or after the disconnected block's height.
        let removed_tags: Vec<Vec<u8>> = {
            let mut tags = self.spent_tags.write();
            let drop: Vec<Vec<u8>> = tags
                .iter()
                .filter(|(_, &h)| h >= restore.height)
                .map(|(t, _)| t.clone())
                .collect();
            for t in &drop {
                tags.remove(t);
            }
            drop
        };

        // Clean persistence so a future `open_with_db` replay reconstructs the
        // rewound state instead of resurrecting the disconnected block. Routed
        // through `apply_pool_write`, so during a staged reorg these removes land
        // in the same atomic batch as the reorg's transparent commit.
        if self.persistence.is_some() {
            for idx in &removed_indices {
                self.apply_pool_write(StagedPoolOp::CoinRemove { cover_index: *idx });
            }
            for t in &removed_tags {
                self.apply_pool_write(StagedPoolOp::TagRemove { tag: t.clone() });
            }
        }

        // Recompute the O(1) guard maxes from the surviving state (rewind is
        // rare, so an O(n) recompute here is fine; the hot path stays O(1)).
        *self.max_coin_height.write() = self.coins.read().iter().map(|c| c.height).max();
        *self.max_spent_tag_height.write() = self.spent_tags.read().values().copied().max();

        // Restore the pool value to the disconnected block's pre-apply boundary
        // and mirror it to disk, so a reorg (and a later replay) is exact.
        *self.pool_value.write() = restore.pool_value;
        if self.persistence.is_some() {
            self.apply_pool_write(StagedPoolOp::MetaInsert {
                key: POOL_VALUE_KEY.to_vec(),
                value: restore.pool_value.to_le_bytes().to_vec(),
            });
        }
        // The checkpoint stack is in-memory (the pool is rebuilt from the
        // committed chain on restart; see `checkpoint_at_height` / `clear`). The
        // pop above shortened it, and coins/tags/pool_value were persisted above,
        // so the restored tip is exact.
        true
    }
}

impl Default for SparkPoolStore {
    fn default() -> Self {
        Self::new()
    }
}

/// The libspark-aligned pool store is a first-class Phase-2 store: it takes a
/// reorg checkpoint before each block and rewinds one block at a time, in
/// lock-step with `ShieldedStore` / `SparkStore` / `KernelStore` through the
/// unified [`Phase2Store`](crate::storage::phase2::Phase2Store) seam. (Inherent
/// methods win resolution, so the forwards below call the store's own methods,
/// never these trait methods.)
impl crate::storage::phase2::Phase2Store for SparkPoolStore {
    fn store_label(&self) -> &'static str {
        "spark_pool"
    }
    fn checkpoint_at_height(&self, height: u64) {
        self.checkpoint_at_height(height)
    }
    fn checkpoint_count(&self) -> usize {
        self.checkpoint_count()
    }
    fn rewind(&self) -> bool {
        self.rewind()
    }
    fn element_count(&self) -> usize {
        self.coin_count()
    }
    fn current_root(&self) -> [u8; 32] {
        self.current_root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coin(tag: u8) -> CoinBytes {
        CoinBytes(vec![tag; 40])
    }
    fn nf(tag: u8) -> Nullifier {
        Nullifier(vec![tag; 34])
    }

    #[test]
    fn add_coins_dense_cover_set_and_lookup_round_trip() {
        let s = SparkPoolStore::new();
        let i0 = s.add_coin(b"tx1:0".to_vec(), coin(1), b"ctx1".to_vec(), 10).unwrap();
        let i1 = s.add_coin(b"tx1:1".to_vec(), coin(2), b"ctx2".to_vec(), 10).unwrap();
        assert_eq!((i0, i1), (0, 1));
        assert_eq!(s.coin_count(), 2);
        assert_eq!(s.cover_set(), vec![coin(1), coin(2)]);
        assert_eq!(s.index_of(b"tx1:1"), Some(1));
        assert_eq!(s.context_for(b"tx1:1").as_deref(), Some(&b"ctx2"[..]));
        assert_eq!(s.coin_at(0).unwrap().outpoint, b"tx1:0");
        assert!(s.index_of(b"nope").is_none());
    }

    #[test]
    fn coin_content_index_tracks_adds_and_rewind() {
        // #380 — the content index reports a coin's libspark bytes as pooled
        // regardless of its outpoint key, and a rewind that truncates a coin drops
        // its content entry (so an honest re-mint is not later falsely rejected)
        // while a surviving coin keeps its entry.
        let s = SparkPoolStore::new();
        let h = |c: &CoinBytes| *blake3::hash(&c.0).as_bytes();

        s.add_coin(b"op:0".to_vec(), coin(1), b"ctx".to_vec(), 5).unwrap();
        // Boundary taken BEFORE the block that mints coin(2), mirroring apply.
        s.checkpoint_at_height(6);
        s.add_coin(b"op:1".to_vec(), coin(2), b"ctx".to_vec(), 6).unwrap();

        assert!(s.coin_content_present(&h(&coin(1))), "coin(1) present by content");
        assert!(s.coin_content_present(&h(&coin(2))), "coin(2) present by content");
        assert!(!s.coin_content_present(&h(&coin(9))), "unpooled content absent");

        // Reorg out the block that minted coin(2): its content key is dropped, the
        // surviving coin(1) keeps its entry.
        assert!(s.rewind());
        assert_eq!(s.coin_count(), 1);
        assert!(s.coin_content_present(&h(&coin(1))), "coin(1) survives rewind");
        assert!(!s.coin_content_present(&h(&coin(2))), "coin(2) content gone after rewind");
    }

    #[test]
    fn cover_entries_at_filters_by_height_and_preserves_cover_order() {
        let s = SparkPoolStore::new();
        s.add_coin(b"op:0".to_vec(), coin(1), b"ctx-a".to_vec(), 5).unwrap();
        s.add_coin(b"op:1".to_vec(), coin(2), b"ctx-b".to_vec(), 10).unwrap();
        s.add_coin(b"op:2".to_vec(), coin(3), b"ctx-c".to_vec(), 15).unwrap();

        // Anchor at height 10 → only the first two coins, in cover order.
        let e = s.cover_entries_at(0, 10);
        assert_eq!(e.len(), 2, "coin at height 15 is excluded");
        assert_eq!(e[0].0, b"op:0");
        assert_eq!(e[0].1, coin(1).0, "coin bytes");
        assert_eq!(e[0].2, b"ctx-a", "serial context");
        assert_eq!(e[0].3, 5, "height");
        assert_eq!(e[1].0, b"op:1");
        // The same set + order cover_set_at resolves (what the verifier uses).
        let cs = s.cover_set_at(0, 10);
        assert_eq!(cs, vec![coin(1), coin(2)]);
        assert_eq!(e.iter().map(|x| x.1.clone()).collect::<Vec<_>>(), vec![coin(1).0, coin(2).0]);

        // Anchor above every coin → the full set.
        assert_eq!(s.cover_entries_at(0, 100).len(), 3);
        // Anchor below every coin → empty.
        assert!(s.cover_entries_at(0, 1).is_empty());
    }

    #[test]
    fn duplicate_outpoint_is_rejected() {
        let s = SparkPoolStore::new();
        assert_eq!(s.add_coin(b"tx:0".to_vec(), coin(1), b"c".to_vec(), 1), Some(0));
        assert!(
            s.add_coin(b"tx:0".to_vec(), coin(9), b"c".to_vec(), 1).is_none(),
            "same outpoint must not be added twice"
        );
        assert_eq!(s.coin_count(), 1);
    }

    #[test]
    fn tag_spent_set_and_double_spend() {
        let s = SparkPoolStore::new();
        assert!(!s.is_tag_spent(&nf(7)));
        assert!(s.mark_tag_spent(&nf(7), 5));
        assert!(s.is_tag_spent(&nf(7)));
        assert!(!s.mark_tag_spent(&nf(7), 6), "second spend of a tag is a double-spend");
        assert_eq!(s.spent_tags(), vec![nf(7)]);
    }

    #[test]
    fn checkpoint_and_rewind_disconnects_a_block() {
        let s = SparkPoolStore::new();
        // Block 1: one coin + one spent tag.
        s.checkpoint_at_height(1);
        s.add_coin(b"b1:0".to_vec(), coin(1), b"c1".to_vec(), 1);
        s.mark_tag_spent(&nf(0x11), 1);

        // Block 2: two coins + one spent tag.
        s.checkpoint_at_height(2);
        s.add_coin(b"b2:0".to_vec(), coin(2), b"c2".to_vec(), 2);
        s.add_coin(b"b2:1".to_vec(), coin(3), b"c3".to_vec(), 2);
        s.mark_tag_spent(&nf(0x22), 2);
        assert_eq!(s.coin_count(), 3);

        // Disconnect block 2.
        assert!(s.rewind());
        assert_eq!(s.coin_count(), 1, "block-2 coins dropped");
        assert!(s.index_of(b"b2:0").is_none(), "block-2 outpoint index dropped");
        assert!(s.index_of(b"b1:0").is_some(), "block-1 coin kept");
        assert!(!s.is_tag_spent(&nf(0x22)), "block-2 tag dropped");
        assert!(s.is_tag_spent(&nf(0x11)), "block-1 tag kept");

        // Disconnect block 1 → empty; stack exhausted.
        assert!(s.rewind());
        assert_eq!(s.coin_count(), 0);
        assert!(!s.is_tag_spent(&nf(0x11)));
        assert!(!s.rewind(), "empty checkpoint stack → false");
    }

    #[test]
    fn spent_tags_feeds_verify_solvency_shape() {
        // The store's spent_tags() is exactly the `&[Nullifier]` type
        // SparkBackend::verify_solvency takes — this is the wiring contract.
        let s = SparkPoolStore::new();
        s.mark_tag_spent(&nf(0xAB), 3);
        let tags: Vec<Nullifier> = s.spent_tags();
        // A tag in the set is "already spent"; one not in it is unspent.
        assert!(tags.contains(&nf(0xAB)));
        assert!(!tags.contains(&nf(0xCD)));
    }

    #[test]
    fn pool_value_shield_unshield_and_underflow() {
        let s = SparkPoolStore::new();
        assert_eq!(s.pool_value(), 0);
        // Shield 100 in (value_balance = -100) → pool 100.
        s.apply_value_balance(-100).unwrap();
        assert_eq!(s.pool_value(), 100);
        // Unshield 40 out → pool 60.
        s.apply_value_balance(40).unwrap();
        assert_eq!(s.pool_value(), 60);
        // Unshield 100 (more than held) → rejected, pool unchanged.
        assert!(s.apply_value_balance(100).is_err(), "cannot unshield more than the pool holds");
        assert_eq!(s.pool_value(), 60, "rejected apply leaves the total unchanged");
    }

    #[test]
    fn pool_value_rewinds_with_reorg() {
        let s = SparkPoolStore::new();
        s.checkpoint_at_height(1);
        s.apply_value_balance(-100).unwrap(); // block 1 shields 100 → pool 100
        s.checkpoint_at_height(2);
        s.apply_value_balance(-50).unwrap(); // block 2 shields 50 → pool 150
        assert_eq!(s.pool_value(), 150);
        // Disconnect block 2 → pool back to its pre-block-2 boundary (100).
        assert!(s.rewind());
        assert_eq!(s.pool_value(), 100);
        // Disconnect block 1 → back to 0.
        assert!(s.rewind());
        assert_eq!(s.pool_value(), 0);
    }

    #[test]
    fn pool_value_persists_across_reopen() {
        use crate::db::Database;
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(Database::open(dir.path()).unwrap());
        {
            let s = SparkPoolStore::open_with_db(&db).unwrap();
            s.apply_value_balance(-250).unwrap(); // shield 250 in
            assert_eq!(s.pool_value(), 250);
        }
        // Reopen: the pool value replays from the meta CF.
        let re = SparkPoolStore::open_with_db(&db).unwrap();
        assert_eq!(re.pool_value(), 250, "pool value survives restart");
    }

    #[test]
    fn checkpoint_stack_is_store_local_and_coins_persist_across_restart() {
        // STORE-LEVEL contract: the reorg checkpoint stack is in-memory, so a bare
        // `open_with_db` reopen starts it empty, while coins/tags/pool_value DO
        // persist and reflect the applied tip. Unlike the three sibling Phase-2
        // stores (whose contents commit atomically with the block, so restoring
        // their persisted checkpoint stack is exact), this pool writes its coins
        // OUTSIDE the block's atomic commit, so after a crash it can be one block
        // ahead. The chain therefore REBUILDS it deterministically on restart via
        // `Blockchain::rebuild_phase2_stores` (clear + replay + re-checkpoint to the
        // committed depth), which is what restores four-way Phase-2 lock-step and
        // makes a reorg past a restart rewind — verified end-to-end by the
        // ApexParasite Phase-2 acceptance harness. This test pins the store-level
        // half (persist coins, not the stack); the chain rebuild is the other half.
        use crate::db::Database;
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(Database::open(dir.path()).unwrap());

        // Session 1: apply two checkpointed blocks (coin + shield-in each).
        {
            let s = SparkPoolStore::open_with_db(&db).unwrap();
            s.checkpoint_at_height(1);
            s.add_coin(b"b1:0".to_vec(), coin(1), b"c".to_vec(), 1);
            s.apply_value_balance(-100).unwrap(); // pool 100
            s.checkpoint_at_height(2);
            s.add_coin(b"b2:0".to_vec(), coin(2), b"c".to_vec(), 2);
            s.apply_value_balance(-50).unwrap(); // pool 150
            assert_eq!((s.coin_count(), s.pool_value(), s.checkpoint_count()), (2, 150, 2));
        }

        // Session 2 (bare reopen, NO chain rebuild): the in-memory checkpoint stack
        // starts empty; coins/tags/pool_value are restored from disk. In the full
        // node the chain's `rebuild_phase2_stores` re-checkpoints this stack back to
        // the committed depth (2), matching the sibling stores.
        let re = SparkPoolStore::open_with_db(&db).unwrap();
        assert_eq!(re.checkpoint_count(), 0, "store-level stack is in-memory; the chain rebuild repopulates it");
        assert_eq!((re.coin_count(), re.pool_value()), (2, 150), "coin/pool state persisted across restart");
        // A bare store without the chain rebuild cannot rewind past the restart.
        assert!(!re.rewind(), "no in-memory checkpoint → store-level rewind refuses (chain rebuild provides it)");
    }

    #[test]
    fn persist_and_replay_roundtrips() {
        use crate::db::Database;
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(Database::open(dir.path()).unwrap());

        // Session 1: two coins, one spent tag.
        {
            let s = SparkPoolStore::open_with_db(&db).unwrap();
            s.add_coin(b"op:0".to_vec(), coin(1), b"ctx0".to_vec(), 1);
            s.add_coin(b"op:1".to_vec(), coin(2), b"ctx1".to_vec(), 1);
            assert!(s.mark_tag_spent(&nf(0x55), 2));
        }

        // Session 2: reopen — coins (order + context) and the tag replay.
        let s2 = SparkPoolStore::open_with_db(&db).unwrap();
        assert_eq!(s2.coin_count(), 2);
        assert_eq!(s2.cover_set(), vec![coin(1), coin(2)]);
        assert_eq!(s2.index_of(b"op:1"), Some(1));
        assert_eq!(s2.context_for(b"op:1").as_deref(), Some(&b"ctx1"[..]));
        assert!(s2.is_tag_spent(&nf(0x55)));
        // A fresh append continues the dense index.
        assert_eq!(s2.add_coin(b"op:2".to_vec(), coin(3), b"ctx2".to_vec(), 3), Some(2));
        // #380 — the content index is rebuilt from the persisted coins on reopen.
        let h = |c: &CoinBytes| *blake3::hash(&c.0).as_bytes();
        assert!(s2.coin_content_present(&h(&coin(1))), "coin(1) content rebuilt on open");
        assert!(s2.coin_content_present(&h(&coin(2))), "coin(2) content rebuilt on open");
        assert!(!s2.coin_content_present(&h(&coin(8))), "unpooled content absent after open");
    }

    #[test]
    fn staging_defers_persistence_and_collects_ops() {
        // Atomic Phase-2 commit (A): under `begin_staging`, a block's pool writes
        // mutate in-memory immediately but their DURABILITY is deferred into a
        // buffer the chain flushes into the block's atomic WriteBatch. So mid-block
        // (before the chain commits) NOTHING is on disk — the pool can't be left
        // ahead of the tip. The staged ops carry exactly the writes to flush.
        use crate::db::Database;
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(Database::open(dir.path()).unwrap());

        let ops = {
            let s = SparkPoolStore::open_with_db(&db).unwrap();
            s.begin_staging();
            s.add_coin(b"op:0".to_vec(), coin(1), b"ctx0".to_vec(), 1).unwrap();
            s.add_coin(b"op:1".to_vec(), coin(2), b"ctx1".to_vec(), 1).unwrap();
            assert!(s.mark_tag_spent(&nf(0x55), 1));
            s.apply_value_balance(-100).unwrap(); // pool 0 → 100

            // In-memory reflects the writes immediately...
            assert_eq!(s.coin_count(), 2);
            assert_eq!(s.pool_value(), 100);
            assert!(s.is_tag_spent(&nf(0x55)));

            // ...but nothing is persisted yet — staging deferred every write.
            s.take_staged_ops()
        };
        // Reopen WITHOUT the chain having flushed the staged ops: disk is empty,
        // proving staging truly deferred all durability (no ahead-of-commit write).
        let reopened = SparkPoolStore::open_with_db(&db).unwrap();
        assert_eq!(reopened.coin_count(), 0, "staged coins were not persisted");
        assert_eq!(reopened.pool_value(), 0, "staged pool value not persisted");
        assert!(!reopened.is_tag_spent(&nf(0x55)), "staged tag not persisted");

        // The staged ops are exactly the writes the chain flushes into the block's
        // atomic batch: 2 coin inserts, 1 tag insert, 1 pool-value meta.
        let coins = ops.iter().filter(|o| matches!(o, StagedPoolOp::CoinInsert { .. })).count();
        let tags = ops.iter().filter(|o| matches!(o, StagedPoolOp::TagInsert { .. })).count();
        let metas = ops.iter().filter(|o| matches!(o, StagedPoolOp::MetaInsert { .. })).count();
        assert_eq!((ops.len(), coins, tags, metas), (4, 2, 1, 1));
    }

    #[test]
    fn immediate_persist_unchanged_when_not_staging() {
        // Without `begin_staging`, writes persist immediately — the pre-A default
        // path, unchanged, so tests / rebuild / any non-block mutation still work.
        use crate::db::Database;
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(Database::open(dir.path()).unwrap());
        {
            let s = SparkPoolStore::open_with_db(&db).unwrap();
            s.add_coin(b"op:0".to_vec(), coin(1), b"ctx0".to_vec(), 1).unwrap();
            s.apply_value_balance(-50).unwrap();
            assert!(s.take_staged_ops().is_empty(), "no staging active → nothing buffered");
        }
        let reopened = SparkPoolStore::open_with_db(&db).unwrap();
        assert_eq!(reopened.coin_count(), 1, "immediate-mode write persisted");
        assert_eq!(reopened.pool_value(), 50);
    }

    #[test]
    fn rewind_cleans_persistence_so_replay_matches() {
        use crate::db::Database;
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(Database::open(dir.path()).unwrap());

        let (count_after_1, tags_after_1) = {
            let s = SparkPoolStore::open_with_db(&db).unwrap();
            s.checkpoint_at_height(1);
            s.add_coin(b"b1:0".to_vec(), coin(1), b"c".to_vec(), 1);
            s.mark_tag_spent(&nf(0x11), 1);
            let snap = (s.coin_count(), s.spent_tags().len());

            // Block 2, then reorged out.
            s.checkpoint_at_height(2);
            s.add_coin(b"b2:0".to_vec(), coin(2), b"c".to_vec(), 2);
            s.mark_tag_spent(&nf(0x22), 2);
            assert!(s.rewind());
            assert_eq!(s.coin_count(), snap.0);
            assert!(!s.is_tag_spent(&nf(0x22)));
            snap
        };

        // Reopen: replay must NOT resurrect block 2's coin or tag.
        let re = SparkPoolStore::open_with_db(&db).unwrap();
        assert_eq!(re.coin_count(), count_after_1);
        assert_eq!(re.spent_tags().len(), tags_after_1);
        assert!(re.is_tag_spent(&nf(0x11)), "block-1 tag survives");
        assert!(!re.is_tag_spent(&nf(0x22)), "reorged block-2 tag not resurrected");
        assert!(re.index_of(b"b2:0").is_none(), "reorged coin not resurrected");
    }

    #[test]
    fn satisfies_phase2_seam_and_rewinds_in_lockstep() {
        // SparkPoolStore, driven ONLY through the Phase2Store seam + shared
        // drivers, must checkpoint/rewind together with the three existing
        // Phase-2 stores — the reorg lock-step contract a fourth store must
        // satisfy before it can be wired into chain.rs.
        use crate::storage::phase2::{checkpoint_all, rewind_all, Phase2Store, RewindOutcome};
        use crate::storage::{KernelStore, ShieldedStore, SparkStore};

        let shielded = ShieldedStore::new();
        let spark = SparkStore::new();
        let kernel = KernelStore::new();
        let pool = SparkPoolStore::new();
        let stores: [&dyn Phase2Store; 4] = [&shielded, &spark, &kernel, &pool];

        for h in 1..=5u64 {
            assert_eq!(checkpoint_all(&stores, h).unwrap(), h as usize, "lock-step at {h}");
        }
        for _ in 0..5 {
            for (label, outcome) in rewind_all(&stores) {
                assert!(
                    matches!(outcome, RewindOutcome::RolledBack | RewindOutcome::EmptyNoop),
                    "{label} failed to roll back cleanly"
                );
            }
        }
        assert_eq!(pool.checkpoint_count(), 0, "pool drained in lock-step");
    }

    // End-to-end over the REAL libspark backend: mint coins into the store,
    // build a spend over the store's cover set, and run the unspent-solvency
    // check against the store's spent-tag set — the full Route-B loop. Needs the
    // C++ FFI, so it only compiles/runs with `libspark-ffi` on.
    #[cfg(feature = "libspark-ffi")]
    #[test]
    fn end_to_end_store_drives_spend_and_unspent_check() {
        use spark_connector::ffi::{
            build_spend_over_set, mint_to_seed, serial_context, LibsparkBackend,
        };
        use spark_connector::SparkBackend;

        let store = SparkPoolStore::new();
        let seed = b"treasury-e2e-seed";
        let n = 8usize; // #259: small cover set for the fixture (Grootle pads; real N=512)

        // Mint N coins into the store, each keyed by a synthetic outpoint whose
        // deterministic serial context we store alongside the coin.
        for i in 0..n {
            let outpoint = format!("e2e:tx:{i}").into_bytes();
            let ctx = serial_context(&outpoint).expect("ctx");
            let coin = mint_to_seed(seed, 10_000 + i as u64, &ctx).expect("mint");
            store.add_coin(outpoint, coin, ctx, 1).expect("store coin");
        }
        assert_eq!(store.coin_count(), n);

        // Build a spend over the STORE's cover set, spending the coin at index 3.
        let spend_index = 3usize;
        let owned_outpoint = format!("e2e:tx:{spend_index}").into_bytes();
        let ctx = store.context_for(&owned_outpoint).expect("stored ctx");
        let cover = store.cover_set();
        let spend = build_spend_over_set(seed, &cover, spend_index, &ctx, 4_000)
            .expect("build spend over store cover set");

        let backend = LibsparkBackend;
        // Unspent: the store's (empty) spent-tag set → solvency holds. Verify over
        // the REAL store cover set (verify_solvency now refuses an empty set — it
        // would take the permissive stateless path instead of a node-resolved one).
        let tags = backend
            .verify_solvency(&cover, &spend, 0, 0, &store.spent_tags())
            .expect("unspent coin proves solvency");
        assert_eq!(tags.len(), 1);

        // Record the tag as spent in the store; the SAME proof is now rejected —
        // by the spent-tag check (membership still holds over the real cover set).
        assert!(store.mark_tag_spent(&tags[0], 5));
        assert!(
            backend
                .verify_solvency(&cover, &spend, 0, 0, &store.spent_tags())
                .is_err(),
            "once the store marks the tag spent, the coin is no longer unspent"
        );
    }
}
