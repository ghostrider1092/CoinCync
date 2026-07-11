# CIP-019 — Near-Tip Block Propagation (the chronic-lag / single-miner-stall fix)

**Status:** Draft (root-caused; implementation pending, test-gated)
**Type:** Standards Track (networking / sync — non-consensus wire behavior)
**Created:** 2026-07-11

## Abstract

A node that falls even slightly behind the tip (`is_synced() == false`) stops
using the fast InvBlock block-fetch path and falls back to slow, poll-based
header catch-up. On a live-producing chain that catch-up cannot keep pace, so
the node stays **chronically a few blocks behind**, which keeps `is_synced`
false, which keeps it on the slow path — a self-reinforcing trap. For a mining
node this is fatal: the rig's sync gate (`is_synced`) never clears, so a healthy
near-tip miner **never mines**, and its hashrate is lost. This CIP fixes the
gate to distinguish *near-tip* (fetch promptly, catch to the exact tip) from
*deep IBD* (keep the orphan-avoidance skip).

## Symptom (observed live, 2026-07-11)

- `randomx2` node followed the tip but sat **exactly ~3 blocks behind** (11,675
  vs tip 11,678), indefinitely. No orphan cascade, no `EMERGENCY-TIER-3` — it
  was *following*, just permanently trailing.
- Its rig was `active` but logged `refusing to mine … is_synced=false` on every
  poll. A node restart did **not** help — it returned to ~3 behind within
  seconds.
- Consequence: only one effective miner on the network. Difficulty spiked
  (77k → 83k) against a single ~630 H/s CPU, block times ballooned, and the
  chain appeared to **stall**. The single-miner SPOF and the chronic-lag bug are
  the *same* root cause.

## Root cause

In `src/network/node.rs`, the `MessageType::InvBlock` handler:

```rust
if !sync.read().await.is_synced() {
    // send a GetHeaders to refresh peer.height, then:
    return Ok(());            // <-- skips the fast block-fetch entirely
}
// ... below: compute `needed` from the announced inventory and, if the gap is
//     small, directly GetBlocks them (the fast path). Only reached when synced.
```

The early return was added to avoid orphan pileup during **deep** IBD, where an
announced new-tip hash won't chain off the node's far-behind position. But the
condition is `!is_synced()` alone, which is *also* true for a node only 2–3
blocks behind. Such a node:

1. receives the new-tip InvBlock,
2. takes the `!is_synced()` branch → sends GetHeaders → **returns without
   fetching the gap**,
3. waits for the header round-trip + the sync layer's *polled* GetBlocks to fill
   the gap — a cycle slower than block production,
4. so it never closes the last few blocks → `is_synced` never clears → step 2
   repeats forever.

`is_synced()` itself (`chain.rs`) tolerates ≤2 blocks behind with a fresh tip;
the node sits at 3, one outside the window, and the InvBlock gate keeps it there.

## Specification

Split the InvBlock gate into two regimes by **gap size**:

```rust
let gap = best_known_height.saturating_sub(chain.height());

if !is_synced() && gap > NEAR_TIP_INV_WINDOW {
    // DEEP IBD: announced tip won't chain; send GetHeaders, return.
    // (existing behavior — orphan avoidance)
    return Ok(());
}
// NEAR-TIP or SYNCED: fall through and promptly fetch the missing range so we
// reach the exact tip instead of trailing it.
```

Two design points the implementation must get right:

1. **Fetch the *range*, not just the announced hash.** A node 3 behind that is
   sent the tip InvBlock (`11,679`) is missing `11,676–11,678` too; fetching only
   `11,679` would orphan. Near-tip fetch must request the contiguous gap
   (`local_tip+1 … announced`), which requires the heights the GetHeaders
   response provides — so near-tip should trigger a **prompt** (non-polled)
   GetBlocks for the gap once heights are known, rather than waiting on the
   periodic sync tick.
2. **Window sizing.** `NEAR_TIP_INV_WINDOW` must be small enough that the gap
   genuinely chains soon (e.g. on the order of a handful to a few dozen blocks —
   aligned with the reorg/backfill window), and large enough to cover the normal
   propagation trailing distance. Start conservative (e.g. 16) and tune.

Non-consensus: this changes *when/what a node fetches*, not block validity. It
cannot fork the chain; a bad value only affects catch-up latency. But it runs on
every node's hot sync path, so it is test-gated (below).

## Test plan (gates deployment)

- **Unit:** the gate returns "fetch" for `gap ≤ WINDOW && !is_synced`, and "skip"
  for `gap > WINDOW`.
- **Integration (off-fleet):** start a node N blocks behind a *live-producing*
  chain; assert it reaches the exact tip within a bounded time and then holds
  `is_synced == true` across several new blocks — i.e. it does **not** settle
  into a chronic trailing distance. Run at N = 1, 3, 16, 200.
- **Miner-gate:** with the fixed node near tip, assert the rig's `is_synced`
  gate clears and it mines a canonical (non-orphan) block.

## Rollout

1. Implement + pass the tests above on a throwaway node.
2. Deploy to **one** non-critical fleet node (a relay), observe it holds the tip.
3. Then randomx2 (un-gates the second miner), then the rest — deliberately, one
   at a time, per the deploy runbook. Never a simultaneous fleet-wide push of a
   sync-path change.

## Immediate mitigations (until this ships)

- Difficulty (ASERT) self-corrects the single-miner stall over subsequent blocks.
- Recruiting external CPU miners removes the single-miner SPOF and stabilizes
  difficulty — the fastest real-world mitigation, independent of this code fix.

## References

- `src/network/node.rs` — `MessageType::InvBlock` handler (the gate)
- `src/chain.rs::is_synced` — the ≤2-block tolerance the gate interacts with
- 2026-06-27 gossip-bug history (PR #123/#125) — prior propagation fixes in the
  same handler; this is the residual near-tip case they didn't cover.
