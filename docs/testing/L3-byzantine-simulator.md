# L3 Byzantine deterministic-simulation (DST) harness

A seeded, deterministic, **replayable** discrete-event simulator for consensus +
P2P. It is the project's highest-leverage correctness tool: it runs a whole
multi-node network — mining, gossip, latency, drops, duplication, partitions and
Byzantine behaviors — under a single deterministic schedule, so **any failure
reproduces bit-for-bit from its seed**.

Harness: [`tests/common/sim/`](../../tests/common/sim/mod.rs).
First consumer / scenarios: [`tests/sim_l3_consensus.rs`](../../tests/sim_l3_consensus.rs).

Run the (slow, real-PoW) scenarios:

```bash
cargo test --features testnet --test sim_l3_consensus -- --ignored
```

## Determinism model

- Each node is an in-process `Blockchain`.
- A single seeded `StdRng` (ChaCha) is the **only** entropy source — per-link
  latency, drops, duplication, and keypairs all derive from `SimConfig::seed`.
- No `SystemTime` / `OsRng` in the driver. Block timestamps are kept in the past
  (`base_ts + height * block_spacing_secs`) so validation's future-timestamp
  bound is never accidentally load-bearing; a scenario that *wants* to exercise
  it makes that explicit.
- Messages flow through a `BinaryHeap` event queue ordered by `(time, seq)` — a
  total, reproducible delivery order. `seq` is a monotonic tiebreak so same-time
  events never depend on heap internals.

Because the only inputs are `SimConfig` + `seed`, a failing run is reproduced by
re-running the same config; the seed is printed in safety-violation reports.

## Configuring a scenario (`SimConfig`)

| Field | Meaning |
|---|---|
| `seed` | the single entropy source; also the replay key |
| `n_nodes`, `miners` | node count and which nodes mine |
| `behaviors` | per-node `Behavior` (see below) |
| `min_delay` / `max_delay` | per-link latency range (virtual ms), drawn from the seed |
| `drop_prob` / `dup_prob` | per-message drop / duplication probability |
| `block_spacing_secs` | timestamp spacing between heights |
| `finality_depth` | depth below the min honest height that SAFETY is checked at |
| `rounds` | number of mine-tick rounds (ticks at `t = r * 1000`) |
| `partitions` | network partitions over virtual time (empty = fully connected) |

## Behaviors

- `Honest` — mines a valid block and broadcasts it.
- `Equivocate` — double-signs: two valid twin blocks at one height, sent to
  different halves of its peers. Under the deterministic hash-lex fork-choice the
  honest nodes still converge on one chain.
- `Withhold` — mines a valid block and adopts it locally but **never broadcasts**
  it (selfish mining). Still relays other nodes' blocks it receives.

Planned: `InvalidSpam`, and clock-skew / demon-timing nodes that drive
`net_time` and the future-block cap (the #59 clock-poisoning exercise).

## Network faults

- **Latency / reordering** — seeded per-link delay; with random delays, deliveries
  arrive out of order through the queue.
- **Drops / duplication** — `drop_prob` / `dup_prob` per message.
- **Partitions** — a `Partition { start, end, groups }` blocks messages between
  nodes in different `groups` over `[start, end)`. A node in no group is always
  reachable, so a subset can be eclipsed while the rest stay connected. Partition
  **recovery** (heal + block backfill) needs a pull-sync model and is a later
  increment — the push-only gossip here cannot fill a gap.

## Invariants checked

After every accepted block the harness checks:

- **SAFETY** — no two honest nodes hold different blocks at or below the finality
  floor (`min honest height − finality_depth`). A violation returns the coded
  `CYNC-CONS-003` report (via `consensus::invariants::check`), including the
  reproduce-from-seed hint — the **same** registry the validator and runtime
  guards use, not a bespoke string.
- **LIVENESS** — the canonical honest height advances over the run (asserted per
  scenario).

As the consensus-invariant registry (`src/consensus/invariants.rs`) grows
executable checks, the harness runs the whole set after every event.

## Adding a scenario

1. Build a `SimConfig` (pick a memorable `seed`).
2. `let mut sim = Sim::new(cfg); sim.run()?;`
3. Assert the scenario-specific properties on `sim.nodes[i].chain`, and call
   `sim.check_safety()` for the global safety property.
4. Mark it `#[ignore]` (real-PoW mining is slow) and run with `-- --ignored`.

## Roadmap (Stage 3)

- **A** — extract the harness into `tests/common/sim/` ✓
- **B** — network partitions / drops / reordering ✓
- **C** — more Byzantine behaviors (`Withhold` ✓; `InvalidSpam`, clock-skew next)
- **D** — wire the `consensus::invariants` registry as the after-event check ✓
- **E** — targeted scenarios for the live-net bug classes: clock-poisoning (#59),
  post-restart partition-stall, reorg-stranded pool state.
