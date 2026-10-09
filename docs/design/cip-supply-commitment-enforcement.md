# CIP: enforce `BlockHeader.supply_commitment`

**Status:** DESIGN — implementation-ready. Code + tests land post-soak (a
consensus rule must be built + full-suite-tested before commit; a wrong rule =
chain-wide self-reject, so it is NOT written blind while the 24h shielded soak
owns the build lane).

## What exists today
- `BlockHeader.supply_commitment: [u8;32]` (`consensus/header.rs`) — **PoW-bound**
  (fed into `hash()`/`pow_binding()`), but **every producer writes `[0u8;32]`**
  (`mining/block_builder.rs:347`) and **no validation rule reads it**. It is
  RESERVED / NOT-YET-ENFORCED (audit note 2026-09-07).
- `emission::supply::calculate_supply_commitment(&SupplyStats) -> [u8;32]`
  (`emission/supply.rs:295`) — hashes `total_emitted ‖ total_burned ‖
  circulating ‖ emission_remaining`. Called by nobody in the live path.
- `SupplyStats { total_emitted, total_burned, circulating, emission_remaining,
  in_tail }`.

## The definition (the part that MUST be pinned)
`supply_commitment` binds the cumulative supply **as the block leaves it**
(post-apply): the `SupplyStats` after this block's coinbase emission and any
burns are applied. Rationale: it ties each header to the supply state it
*produces*, so a block that lies about its own emission is caught. Producer and
validator MUST compute the identical stats for the identical block, else honest
blocks self-reject — this is the whole risk surface.

**Fork blocks:** the stats are a pure function of (parent cumulative supply +
this block's coinbase/burns), so a fork block commits to *its own* resulting
supply, computed the same way regardless of whether its parent is the active
tip. The validator must therefore recompute from the block's PARENT stats, not
the current tip's — see plumbing.

## Plumbing gap to close
`chain.stats()` returns `ChainStats`, not `SupplyStats`. Need one accessor that,
given a block's parent, yields the parent's cumulative `SupplyStats`, then apply
this block's delta. Options (pick at implementation, with a test):
1. Add `Blockchain::supply_stats_at(&self, parent_hash) -> SupplyStats` deriving
   from stored per-height cumulative emission/burn (preferred — works for forks).
2. If only tip-relative stats exist, restrict enforcement to main-chain-extend
   blocks initially and file fork-block enforcement as a follow-up (weaker).

## Producer (`mining/block_builder.rs:347`)
Replace `supply_commitment: [0u8;32]` with the resulting stats commitment:
```
let parent_supply = chain.supply_stats_at(&prev_hash);      // (plumbing #1)
let resulting = parent_supply.apply_block_delta(reward, burned); // emitted+=reward, burned+=burns, ...
supply_commitment: if height >= net.supply_commitment_enforce_height() {
    calculate_supply_commitment(&resulting)
} else { [0u8;32] },
```

## Validator (chain level — `chain.rs::add_block`, NOT stateless `validate_block_ctx`)
`validate_block_ctx` lacks cumulative supply. In `add_block`, once the block's
parent + coinbase are known:
```
if block.header.height >= self.network.supply_commitment_enforce_height() {
    let parent_supply = self.supply_stats_at(&block.header.prev_hash)?;
    let resulting = parent_supply.apply_block_delta(reward, burned);
    let expected = calculate_supply_commitment(&resulting);
    if block.header.supply_commitment != expected {
        return Ok(BlockStatus::Invalid("supply_commitment mismatch".into()));
    }
}
```

## Activation (retro-compat)
New network-aware `supply_commitment_enforce_height(&self)` in `config.rs`
(mirroring `fee_distribution_height` etc.): **mainnet = `u64::MAX`** (until a
governance-agreed height), **testnet = a finite fork height**, **regtest/beta =
low**. Before the height, the field stays `[0u8;32]` and is not checked, so
pre-fork chains are unaffected. This is a hard fork; coordinate the testnet
height. (`constants.rs` gets the const + the drift-guard mirror.)

## Test plan (all must pass before commit)
- Producer populates a non-zero commitment at/after the enforce height.
- Validator ACCEPTS a block whose commitment matches the recomputed stats.
- Validator REJECTS a block with a tampered commitment (the anti-lie guarantee).
- Below the enforce height, a `[0u8;32]` commitment is still accepted (retro-compat).
- Fork block: a competing block commits to its own resulting supply and validates.
- Full lib suite green; regen `critical_files.lock` (constants/header/validation touched).

## Why not now
Untestable for ~15h (soak owns the lane). A consensus rule with a
producer/validator stats-consistency requirement is exactly the kind of change
that must be validated before it exists in committed form. This note makes the
post-soak implementation a fast, low-risk drop-in.

---

## Implementation refinements (2026-09-29) — DONE + resolved plumbing

Two findings from reading the real seams; the first two items below are already
CODED on this branch (staged, validate post-soak).

### 1. u64 overflow → use a `u128` consensus commitment (CODED)
`calculate_supply_commitment(&SupplyStats)` hashes `Amount` (u64) fields.
Cumulative emitted supply reaches MAX_SUPPLY = 100M × 10^12 = 10^20 atomic,
which **overflows u64 (~1.84e19) at ~18.4M CYNC** (height ~408k) — the exact
reason `ChainStats::{total_supply,total_burned}` are `u128`. The u64 helper is
therefore fine for RPC display today but **wrong as a consensus commitment**.

→ Added `emission::supply::supply_commitment_consensus(total_emitted: u128,
total_burned: u128, emission_remaining: u128) -> [u8;32]` — hashes the u128
values, domain-separated by `COINCYNC_SUPPLY_COMMITMENT_CONSENSUS_V1` (distinct
tag so it can never collide with the u64 audit digest). Tests cover determinism,
per-field sensitivity, saturation, domain separation, and **exactness above
u64::MAX** (the whole point). Producer + validator MUST use THIS function.

### 2. Activation gate (CODED)
`NetworkType::supply_commitment_enforce_height(&self)` added to `config.rs`,
**`u64::MAX` on every network** (gated OFF). Below it the field stays `[0u8;32]`
and is unchecked → no live chain changes. A finite height is a coordinated hard
fork and needs audit-gate clearance. Post-soak: add the
`constants::SUPPLY_COMMITMENT_ENFORCE_HEIGHT` mirror + drift-guard.

### 3. Plumbing gap RESOLVED — validate at the apply site (post-soak wiring)
The chain has **no per-height stored `SupplyStats`** — only a single running
accumulator (`inner.stats.{total_supply,total_burned}`, u128) that moves with
the tip and unwinds on reorg. So `supply_stats_at(arbitrary parent)` is not
cheaply available. BUT: at **every apply site**, `inner.stats` already equals
the **parent's** cumulative supply, because blocks are applied in parent→child
order onto the active chain — including during reorg. So validate at apply-time,
right where the delta is added, using the POST-apply totals:

```
// after inner.stats.total_supply += reward and inner.stats.total_burned += burns:
let expected = supply_commitment_consensus(
    inner.stats.total_supply,
    inner.stats.total_burned,
    MAX_SUPPLY_ATOMIC - inner.stats.total_supply,   // emission_remaining
);
if block.header.height >= net.supply_commitment_enforce_height()
    && block.header.supply_commitment != expected {
    // reject / roll back this connect
}
```

This needs **no new storage** and **covers fork blocks for free** — a fork block
is checked when the reorg applies it (at which point `inner.stats` is its
parent's cumulative). This supersedes the earlier "restrict to tip-extend
blocks" option 2.

**Apply sites to wire (chain.rs)** — the sites where `total_supply`/
`total_burned` are `+=`'d on connect (NOT the disconnect `-=` sites):
- normal block connect (~1495: `inner.stats.total_burned += …`)
- reorg fork-block connect (~2255)
- reorg tip apply (~2683)
Factor a single `check_supply_commitment(height, header_commitment, &stats)` helper
and call it at each `+=` site to avoid drift between the three paths.

**Producer** (`mining/block_builder.rs`): compute the same post-apply totals for
the block being built (parent cumulative + this block's reward/burns) and write
`supply_commitment_consensus(...)` when `height >= enforce_height`, else `[0;32]`.

### Remaining post-soak steps
1. `check_supply_commitment` helper + calls at the 3 connect sites.
2. Producer in `block_builder.rs`.
3. `constants::SUPPLY_COMMITMENT_ENFORCE_HEIGHT` mirror + drift-guard.
4. Tests: producer non-zero at/after height; validator accept-match / reject-tamper;
   below-height `[0;32]` accepted; fork-block competing commit validates; full lib
   suite; regen `critical_files.lock` (constants/header/validation/config touched).
