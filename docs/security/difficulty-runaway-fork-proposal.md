# Proposal: difficulty-drop clamp to prevent isolated-miner runaway forks

**Status:** PROPOSAL — not implemented. Touches consensus-critical
`src/consensus/difficulty.rs` (hash-locked in `critical_files.lock`) and
therefore requires a coordinated hard fork. Do **not** fast-code this.

**Origin:** 2026-07-08 testnet fleet incident. Companion to the already-shipped
miner-side mitigation (fork-divergence mine-gate in `coincync-rig`).

---

## Problem

When a miner becomes isolated from the network — even briefly, e.g. during
a node restart — it keeps mining alone. With only its own hashrate on the
chain, the difficulty-adjustment algorithm drives difficulty **down** toward
what that single miner can solve at the target block time. On 2026-07-08,
randomx2 (~450 H/s) restarted, briefly lost mesh sync, and its local
difficulty collapsed from **159 655** to roughly **1 600** (~100×). It then
produced blocks every ~2 seconds and raced hundreds of blocks ahead
(10042 → 10544) on a **private fork** that the rest of the fleet correctly
rejected as lower cumulative work.

Two independent failures combined:

1. **Miner side** — the sync gate keyed on `is_synced`, which is *height*-based
   (`local_height >= peer_target_height`). A node "ahead" of every peer on a
   higher-block/lower-work fork still reports synced, so the miner kept going.
   *Fixed* by the fork-divergence mine-gate (refuse to mine when local height
   runs > `FORK_DIVERGENCE_MARGIN` blocks ahead of the best peer).

2. **Consensus side** — nothing bounds how fast difficulty may *fall*, so an
   isolated miner can crater it far enough to spew a long low-work fork. This
   proposal addresses #2: even if a miner *does* mine while isolated, a
   difficulty floor / drop-clamp keeps that fork from becoming cheap enough to
   grow explosively, shrinking blast radius and making eventual reconciliation
   trivial.

The two layers are complementary: #1 stops an honest miner from *building* the
fork; #2 caps the damage from any miner (honest or malicious) that mines while
partitioned, and blunts a low-difficulty time-warp style attack.

## Proposed consensus rule

Clamp the **per-retarget downward** movement of difficulty:

```
next_difficulty >= prev_difficulty / MAX_DROP_FACTOR
```

with a starting `MAX_DROP_FACTOR` on the order of **2–4** per retarget window
(exact value TBD by simulation). Upward movement is left unclamped (recovering
from a genuine hashrate influx should stay responsive). Optionally pair with an
absolute network `MIN_DIFFICULTY` floor for testnet.

### Why a factor, not a fixed floor alone

A fixed floor mis-serves a network whose honest difficulty legitimately spans
orders of magnitude over its lifetime. A *relative* per-step clamp adapts to
whatever the current honest difficulty is, while still making a 100× overnight
collapse impossible — it would take many retarget windows to fall that far, by
which point the isolated miner has produced only a handful of blocks, not
hundreds.

## Interactions / risks to model before shipping

- **Legitimate hashrate loss.** If half the real miners genuinely leave, the
  clamp slows the difficulty's descent, lengthening block times during the
  transition. Must confirm the network still recovers within an acceptable
  window (simulate a 50–90% hashrate drop).
- **Retarget-window coupling.** The right `MAX_DROP_FACTOR` depends on the
  existing window length and damping in `difficulty.rs`. Derive them together.
- **Genesis / early-chain edge cases.** Ensure the clamp is inert for the first
  N blocks where `prev_difficulty` is still the seed value.
- **Fork coordination.** Any change here is consensus-breaking. Requires: an
  activation height, `critical_files.lock` refresh via
  `COINCYNC_REGEN_LOCK=1 cargo run --locked --bin update-critical-hashes` (elevation on Windows), a testnet
  dry run, and fleet-wide upgrade before activation.

## Recommendation

Ship the miner-side fork-divergence gate first (done — non-consensus, immediate
protection). Treat this difficulty clamp as a scheduled consensus change:
prototype in a branch, simulate hashrate-drop scenarios, pick `MAX_DROP_FACTOR`
from data, then fork it in with the normal locked-file review. Do not merge
under incident pressure.
