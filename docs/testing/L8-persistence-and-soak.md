# L8 — Sync-from-Genesis Persistence & Soak (foundation)

**Status:** DB-reopen reproducibility test DONE + shipped; reorg-reopen variant and
the soak binary remain.

## Done this session
- **`db_reopen_reconstructs_identical_state`** (`tests/reorg_double_spend_e2e.rs`,
  `#[ignore]` real-PoW): build+persist a 6-block chain to a temp RocksDB, drop the
  node + `Database`, re-open a fresh `Blockchain::with_database` from the same dir,
  assert `load_from_database_with_outcome()==Loaded` and a full state fingerprint
  (height, tip, total_supply, total_difficulty, total_burned, total_transactions,
  total_blocks, `available_output_count`) is byte-identical to the persisted chain.
- **Bug found + fixed** by this test: the DB load path did NOT reconstruct
  `total_blocks`/`total_transactions` (not in `ChainStateData`), so they reset to 0
  after every restart and undercount forever. Fixed in `rebuild_utxo_set`
  (`src/chain.rs`) — accumulate both during the block replay. Same class as the
  earlier `difficulty=0`-on-restart fix.

## Key facts (for the remaining work)
- **Two constructors:** `Blockchain::new()` (in-memory, `db:None`, chain.rs:448/471) vs
  `Blockchain::with_database(Arc<Database>, net)` (RocksDB, :491). Integration tests
  use `tempfile::tempdir()` + `Database::open(dir.path())` (db/mod.rs:702);
  `open_temp()` is `#[cfg(test)]` in-crate only.
- **Persistence is automatic** on the DB path: `init_genesis` writes state
  (chain.rs:756-772); every main-chain `add_block` persists block + `ChainStateData`
  (chain.rs:2103/2311-2331). No explicit flush needed in the test.
- **Base-1 total_difficulty trap:** `init_genesis` persists `total_difficulty=1` but
  the in-memory extend path accumulates from 0; the reload self-heal recomputes
  `1+Σ dft` (chain.rs:897-909). The builder chain MUST call
  `restore_state(0, genesis.hash(), 1)` so live==reloaded (off-by-one otherwise).
- **RocksDB close-before-reopen (Windows):** drop BOTH the `Blockchain` and its
  `Arc<Database>` before re-opening the dir, or the second open contends for the lock.
- **No consensus UTXO state-root:** the fingerprint is `ChainStats` +
  `available_output_count()` (chain.rs:1215). `last_checkpoint` is NOT part of it
  (post-2026-08-18 the finality floor is a pure function of tip height).

## Remaining: Test B — reorg-then-reopen (path-independence)
Reach the tip via a REORG before persisting, reopen, assert reloaded == a linear DB
build of the same canonical chain. Sound in principle (self-heal makes total_difficulty
path-independent). **Deterministic-reorg caveat:** equal-work MIN_DIFFICULTY ties break
on mined block hash (varies run-to-run, `reorg_double_spend_e2e.rs:754-764`). Make it
robust with a *strictly heavier* fork + re-mine the fork tip until its hash wins any tie
(`:480-495`), OR defer this assertion to the soak (which checks `reload==recompute`, a
path-independent invariant, not `reload==a second fixed build`).

## Remaining: soak binary
`src/bin/soak.rs` + `[[bin]] name="coincync-soak" required-features=["testnet"]`. Gate on
`COINCYNC_SOAK=1` (+ `COINCYNC_SOAK_SECS`/`_REORG_EVERY`/`_SEED`); no env → print usage,
exit 0 (never runs in CI). Loop: mine/validate/reorg under load; every K blocks assert
supply==Σ emission, height advanced (no stall), total_difficulty==`1+Σ dft` (reorg history
doesn't leak), and every N minutes drop+reopen and assert reload==pre-drop fingerprint;
sample RSS and assert a memory ceiling (guards the ~200-block cache window chain.rs:1000
+ event ring `MAX_CHAIN_EVENTS=500`). Structured periodic log + non-zero exit on any
breach. Run nightly/manually only: `COINCYNC_SOAK=1 cargo run --release --features testnet --bin coincync-soak`.

## Effort & risks
Test B ≈ 0.5-1 day (deterministic heavier fork); soak ≈ 1-2 days. Risks: base-1 trap,
RocksDB close-before-reopen, real-PoW cost (keep N small, light mode), reorg determinism
(force strictly heavier or defer).
