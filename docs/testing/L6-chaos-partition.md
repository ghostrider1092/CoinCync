# L6 — Chaos / Partition Harness (foundation)

**Status:** minimal deliverable BUILT + PASSING (`tests/chaos_partition_l6.rs`
`two_node_partition_heals_to_heavier_chain`, real-PoW `#[ignore]`, ~60s) —
2 nodes diverge under partition (heights 5 vs 6) then heal and converge
three-way (tip+height+total_difficulty) on the heavier chain via a real reorg.
Shared mining helpers live in `tests/common/mining.rs` (reusable by L3).
Remaining: scenarios (b) asymmetric, (c) crash-consistency, (d) slow node; and
scaling to N>2 nodes.
**Goal:** multi-node partition → heal → verify convergence to ONE chain;
asymmetric partitions; a slow node; and crash-consistency (kill mid-write, reload
from RocksDB).

## Architectural decision
- **No in-process transport exists at the node layer** (`src/network/node.rs:36,779`
  is TCP/Noise only; `tick_adapter/` is an RPC sidecar). So the harness operates at
  the **`Blockchain::add_block` layer** — fully in-process, synchronous,
  deterministic. This deliberately scopes L6 to *chain-convergence* partitioning
  (which is where the real bugs live: total_difficulty divergence, reorg tip
  re-validation, Phase-2 rewind) rather than socket-level partitioning.
- **Model:** a node = a `Blockchain` + an **outbox** `Vec<Block>` of every block it
  ever accepted (needed because `get_block_by_height` only returns *main-chain*
  blocks — fork tips would be invisible). A "message" = a `Block`. The "bus" = a
  boolean adjacency matrix `link[a][b]`. "Deliver" = replay `src.known` into
  `dst.add_block` in height order, skipping `AlreadyKnown`; loop to a fixpoint so
  `Orphan` (missing parent) resolves once the parent arrives. "Partition" = set
  `link[a][b]=false` for the cut; "heal" = restore + deliver to fixpoint.
- Pattern to copy: `tests/dandelion_multi_node.rs:52-107` (Vec of nodes + index
  adjacency + tick-based direct-call delivery), but payload = `Block`/`Blockchain`
  instead of tx/`DandelionRouter`.

## Convergence assertion (three-way — rules out the known false-convergence class)
After `deliver_to_fixpoint`, for all honest nodes: equal `tip_hash` AND equal `height`
AND equal `stats().total_difficulty`, height > fork point, and tip == the heavier side.
(Tip-only agreement is insufficient — see `project_total_difficulty_divergence`:
identical tip, divergent work.)

## Scenarios (most-valuable-first)
- **(a) Symmetric partition → heal → converge** [PRIMARY]: shared prefix; partition
  {0,1}|{2,3}; mine 3 on side A / 5 on side B; heal; assert all 4 land on side B's
  heavier chain (nodes 0,1 return `AcceptedReorg`).
- **(b) Asymmetric** (A hears B, B silent to A): assert A converges to B if heavier,
  B unaffected.
- **(c) Crash-consistency** [greenfield]: DB-backed node, `db.flush()` after block K to
  set a durable checkpoint, mine K+1..N unflushed, drop `Blockchain`+`Database`
  without a final flush, reopen, assert `load_from_database_with_outcome()==Loaded`
  and tip is a consistent durable state (the load-path invariants at chain.rs:820-848
  are the property under test). Stronger variant: write block data but not
  `ChainStateData` → assert load returns the `Err` at chain.rs:822 (no silent re-init).
- **(d) Slow node** (10× delay): per-link `delay` in rounds; assert the laggard still
  converges by fixpoint, never wedges on an orphan.

## Minimal first deliverable
`tests/chaos_partition_l6.rs`, single `#[ignore]` test, 2 nodes: shared 3-block prefix →
partition → mine 2 on node0 / 3 on node1 → assert tips differ and `work(1)>work(0)` →
heal + deliver-to-fixpoint → assert three-way convergence to node1's tip. Copy
`build_coinbase`/`mine_block` from `reorg_double_spend_e2e.rs` (or a `tests/common/`
module). Light mode + `bind_randomx_genesis_for_network(Testnet)` once; floor difficulty.

## Bus API sketch
`Bus{ nodes: Vec<Node>, link: Vec<Vec<bool>> }` with `new_in_memory(n)` /
`new_db_backed(n,dirs)`, `fully_connect`/`partition(a,b)`/`asymmetric(hearer,silent)`/
`heal`, `mine_on(node,txs)->BlockStatus`, `deliver_round()->usize` /
`deliver_to_fixpoint(max_rounds)`, `tip/height/work(node)`. Delivery is
`dst.chain.add_block(src.known[i].clone())`; partition = simply not calling it; all
synchronous ⇒ bit-for-bit deterministic.

## Integration points
`add_block` chain.rs:1848 · `BlockStatus{Accepted,AcceptedFork,AcceptedReorg,AlreadyKnown,Orphan,Invalid}` :211 ·
`with_database` :491 · `load_from_database_with_outcome` :815 · `Database::open`/`flush`
db/mod.rs:702/:989 · bus pattern dandelion_multi_node.rs:52-107 · mining helpers
reorg_double_spend_e2e.rs:86/279 · light mode pow.rs:486.

## Effort & risks
~0.5 day minimal; ~2-3 days full suite (crash-consistency is the largest, greenfield —
no prior `with_database` test besides the new L8 one). Risks: real-PoW speed (floor +
light mode, keep block counts single-digit per side); process-global RandomX (Testnet
epoch 0 only, own binary); orphan ordering (height-ordered delivery + fixpoint, cap
rounds to fail loud). Touches only `tests/` — no hash-locked file.
