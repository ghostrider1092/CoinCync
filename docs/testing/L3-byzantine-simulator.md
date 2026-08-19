# L3 — Byzantine Discrete-Event Consensus Simulator (foundation)

**Status:** minimal deliverable BUILT + PASSING (`tests/sim_l3_consensus.rs`
`honest_single_miner_safety_and_liveness`, real-PoW `#[ignore]`, ~84s) — seeded
`StdRng`, `(time,seq)` `BinaryHeap` event queue, virtual clock, per-link
delay + 10% duplication, deterministic per-node keys; SAFETY checked after every
accepted block + LIVENESS asserted (3 nodes converge to the miner's tip at
height 8). Uses `tests/common/mining.rs`. **Remaining:** the Byzantine behaviors
(equivocation/withholding/invalid-spam/demon-timing) + a second miner — the
`Behavior` enum and `broadcast()` seam are already stubbed for them.
Highest-value / largest-effort layer.
**Goal:** seeded, deterministic, replayable safety+liveness fuzzing of the
consensus/fork-choice logic under Byzantine peers (equivocation, withholding,
invalid-block spam, adversarial timing).

## Architectural decision
- **Build on `Blockchain` (`src/chain.rs`), one instance per node.** Do NOT use
  `src/tick_adapter/` (it is an RPC-over-HTTP sidecar, `mod.rs:17-27`, cannot hold
  `Arc<Blockchain>`), and do NOT use the real P2P stack (`src/network/node.rs:36`
  is TCP/Noise only — no in-process transport). The clean deterministic in-process
  API is `add_block` + `stats()`/`tip_hash()`/`height()`.
- **One entropy source:** a seed → `rand_chacha::ChaCha20Rng`. `SystemTime`/`OsRng`
  are forbidden in the driver. The only wall-clock input is validation's
  `now + 600s` future-timestamp bound — neutralized by keeping every virtual
  block timestamp in the past (genesis is April 2026).
- **Cheap valid blocks:** real RandomX in **light mode**
  (`COINCYNC_RANDOMX_LIGHT_MODE=1` + `bind_randomx_genesis_for_network(Testnet)`)
  mined at the `MIN_DIFFICULTY=500` floor (space blocks ≥ 3600s so ASERT clamps to
  the floor). ~500 light hashes/block; verify = 1 hash. A 3-node × 8-round run
  ≈ 8 mined blocks ≈ 10-20s. Optional turbo for scale campaigns: build
  `--features "testnet insecure-fast-sync"` + DB-backed nodes with `last_checkpoint`
  seeded above the run height → `add_block` skips PoW/crypto (`validation.rs:196-245`;
  inert on in-memory nodes, `chain.rs:1941/471`). Never use turbo for crypto-safety
  assertions.

## Core (proposed `tests/sim/mod.rs` + `tests/sim_l3_consensus.rs`)
- **Message queue:** `BinaryHeap<Reverse<Event>>` ordered by `(time, seq)`; `seq` is a
  monotonic tiebreak → total reproducible order. Per-link latency/drop/dup drawn from
  the seeded RNG at broadcast.
- **Node:** wraps a `Blockchain` + deterministic keys + `Behavior`.
- `EventKind`: `MineTick{miner}`, `DeliverBlock{to, Arc<Block>}`, `ReleaseWithheld{miner}`.
- **Mandatory per-node init:** `init_genesis()` then `restore_state(0, genesis.hash(), 1)`
  (base-1 cumulative-work seed; without it equal-work forks reorg spuriously —
  `reorg_double_spend_e2e.rs:360-369`).

## Invariants (checked after every accepted block)
- **SAFETY:** for every honest pair `(a,b)` and every height
  `h ≤ min(tip_a,tip_b).height − finality_depth`,
  `a.get_block_by_height(h).hash() == b...hash()`. Violation ⇒ chain split.
- **LIVENESS:** with honest majority + bounded delay, `max_honest_height()` strictly
  advances by ≥ K over the run, and every honest tip is within `finality_depth` of max.

## Byzantine behaviors (most-valuable-first, injection points)
1. **Equivocation** — mine twin blocks (bump timestamp until `hash(B)≠hash(A)`,
   `reorg_double_spend_e2e.rs:480-495`), send A to half the peers, B to the other half.
2. **Withholding (selfish)** — mine but don't broadcast; `ReleaseWithheld` dumps the
   private chain later to race the honest tip.
3. **Invalid-block spam** — bad nonce / corrupted tx_root / inflated coinbase; assert
   every honest `add_block` returns `Invalid(_)` and `stats()` is byte-unchanged
   (reuse the atomicity assertion).
4. **Adversarial timing** — a "demon scheduler" delay policy that picks worst-case
   delivery times instead of random latency.

## Minimal first deliverable (green, deterministic foundation)
`tests/sim_l3_consensus.rs` with `#[path="sim/mod.rs"] mod sim;` — one `#[ignore]`
test `honest_single_miner_safety_and_liveness`: 3 nodes, miner=[0], all Honest,
`dup_prob=0.10` (exercises `AlreadyKnown`), `block_spacing=3600`, 8 rounds. One miner
⇒ single canonical chain ⇒ safety+liveness trivially hold ⇒ stable green baseline that
still exercises the queue, per-link delay, duplication, and multi-node `add_block`.
Next session flips behaviors + adds a second miner (no harness change beyond the
`broadcast()` branch per `Behavior`).

## Integration points
`Blockchain::new` chain.rs:448 · `with_database` :491 · `init_genesis` :708 ·
`restore_state` :1554 · `add_block` :1848 · `next_target` :1306 · `stats`/`tip_hash`/
`height` :1379/:1210/:1195 · `get_block_by_height` :1453 · `BlockStatus` :211 ·
`max_reorg_depth_for` :35-40 (1000 testnet/100 mainnet) · mining helpers
`reorg_double_spend_e2e.rs` `mine_block`:279 `build_coinbase`:86 · light mode
`pow.rs:486` · `MIN_DIFFICULTY` `difficulty.rs:54`.

## Effort & risks
~2-2.5 days first deliverable; +2-3 days for behaviors + demon scheduler. Risks:
real-PoW speed (mitigated: mine-once-deliver-clones + floor difficulty + turbo);
process-global RandomX env (run in own binary, `--test-threads=1`); determinism leaks
(first deliverable is coinbase-only — `build_double_spend` uses `OsRng`); the mandatory
`restore_state` seed.
