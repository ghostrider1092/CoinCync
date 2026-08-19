# L3 — Byzantine Discrete-Event Consensus Simulator (foundation)

**Status:** minimal deliverable BUILT + PASSING (`tests/sim_l3_consensus.rs`
`honest_single_miner_safety_and_liveness`, real-PoW `#[ignore]`, ~84s) — seeded
`StdRng`, `(time,seq)` `BinaryHeap` event queue, virtual clock, per-link
delay + 10% duplication, deterministic per-node keys; SAFETY checked after every
accepted block + LIVENESS asserted (3 nodes converge to the miner's tip at
height 8). **EQUIVOCATION now BUILT + PASSING** (`equivocating_miner_does_not_
split_honest_nodes`): a double-signing miner sends different twins to different
honest nodes; they converge deterministically to one chain (this also drove the
fork-choice fix in the RESOLVED finding below). Uses `tests/common/mining.rs`.
**Remaining:** withholding / invalid-spam / demon-timing behaviors + a second
miner — the `Behavior` enum and `broadcast_to()` seam are stubbed for them.
Highest-value / largest-effort layer.

## FINDING — RESOLVED 2026-08-18 (option a: deterministic hash-tiebreak)

The inconsistency below was fixed by making `evaluate_reorg_acceptability`'s
Tier-1 + bootstrap branches accept EQUAL work (`>=`), honoring the deliberate
network-deterministic hash-lex tiebreak in `take_fork` (chain.rs:2455-2471). Deep
equal-work reorgs stay rejected by the MESS tier. Three tests updated to the
intended semantics (chain.rs shallow + bootstrap, tier14 `tier1_...`); the full
reorg suite + total_difficulty guard re-verified green. The
`equivocating_miner_does_not_split_honest_nodes` sim test now PASSES — an
equivocating miner cannot split honest nodes; they converge deterministically to
the same tie-winning chain. Original finding for the record:

## FINDING (surfaced building the equivocation behavior) — equal-work fork returned Err(ReorgTooDeep)

Building the equivocation test (a miner double-signs twin blocks at the same
height) surfaced a **consensus-design inconsistency the codebase's own tests and
comments disagree on**:

- `evaluate_reorg_acceptability` unit tests (chain.rs:4551, 4615) assert an
  equal-work reorg (`fork_work == honest_work`) → **Err** (Tier-1 and bootstrap
  branches require strictly `fork_work > honest_work`).
- The reorg E2E `restore_state(0, gh, 1)` rationale (reorg_double_spend_e2e.rs
  :358-369) says an equal-work fork is "a true tie **broken by the hash rule**".
- The live `take_fork` fork-choice (chain.rs ~2488) sets `take_fork=true` for an
  equal-work fork whose tip hash is smaller (`fork_tip < current_tip`), enters
  the reorg path, and `evaluate_reorg_acceptability` then rejects it →
  `add_block` returns **`Err(ReorgTooDeep{depth:1,max:1000})`** for a VALID
  equal-work fork block.

**Severity: consensus-SAFE, error-classification wart.** The fork block IS
persisted (`inner.blocks.insert` + `db.blocks.insert` run BEFORE the reorg eval),
so it can still be extended and adopted later if its branch becomes strictly
heavier — no fund/inflation/permanent-partition risk. But half of all equal-work
forks (the smaller-hash ones) return `Err` instead of `Ok(AcceptedFork)`, which
a caller reads as "bad block" → possible peer-scoring penalty for relaying a
valid fork, and the block is not relayed onward via the normal accepted path.

**Owner decision required (do NOT change consensus fork-choice unilaterally):**
which is the intended equal-work semantics —
(a) hash-rule tiebreak *reorg* (adopt smaller-hash equal-work tip; then
    `evaluate_reorg_acceptability` Tier-1/bootstrap must allow `>=`), or
(b) first-seen wins, equal-work never reorgs (Bitcoin-style; then `take_fork`
    must NOT set true for equal work, and the equal-work fork returns
    `Ok(AcceptedFork)`)?
Either resolution makes equal-work forks return `AcceptedFork` not `Err`; the
unit tests at 4551/4615 and the reorg-test comment must be reconciled to match.
The equivocation sim test is the reproducer, deferred until this is decided.
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
