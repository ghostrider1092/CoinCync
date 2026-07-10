# CIP-017 — Ring-Size Increase Above 16

**Status:** Draft
**Type:** Standards Track (consensus)
**Created:** 2026-07-10
**Activation:** Mode B (signal-then-activate) per [CIP-007](CIP-007-hard-fork-activation-policy.md)

## Abstract

Raise the mandatory CLSAG ring size for mature-chain transactions above the
current value of **16**, in coordinated hard-fork steps, to enlarge the sender
anonymity set. The proposed path is **16 → 24 → 32** (32 is the current
`MAX_RING_SIZE` ceiling), with each step a separate Mode-B activation gated on
measured verification cost.

## Motivation

Ring size is the size of the decoy set that hides the true spender. A larger
ring is strictly more private. CoinCync has enforced ring size 16 network-wide
since block 10,000 (`ring_size_at_height`), matching Monero's current mainnet
value. Pushing beyond 16 puts CoinCync ahead of that baseline.

This is explicitly sanctioned by the Constitution — **Article III**: *"Privacy
may be strengthened through technical advancement. It may never be weakened."*
The number 16 is a `constants.rs` value, not a constitutional constant, so no
amendment is required — only a consensus hard fork and a re-lock of the
critical-files hash for `constants.rs`.

### Relationship to the queued bootstrap-floor bump

CIP-007 already queues `BOOTSTRAP_MIN_RING_SIZE_V2` (raise the *bootstrap floor*
**11 → 13**). That knob only affects a chain's first 10,000 blocks (or a testnet
reset), when the UTXO set is too small to form a full ring. It is orthogonal to
this CIP, which raises the *post-bootstrap target* on a mature chain. The two
can ship independently.

## Cost analysis (why the target is measured, not chosen)

CLSAG is **O(N)** in ring size — both signature bytes and verification time
scale linearly. Benchmark (dev box, release, single-signature verify):

| Ring size | Signature bytes | Verify (µs) | vs. 16 |
|-----------|-----------------|-------------|--------|
| 11 (bootstrap floor) | 452 | 2,791 | — |
| **16 (current)** | **612** | **4,593** | baseline |
| 24 | 868 | 8,415 | +42% size, +83% verify |
| 32 (MAX) | 1,124 | 13,164 | +84% size, **+187% verify (~2.9×)** |

**Caveats before finalizing a target:**

1. These are **single-signature** verifies on a **dev box**. The fleet's 1–4
   vCPU nodes are slower — treat as lower bounds. A block with 20 inputs at
   ring 32 ≈ 260 ms of CLSAG verify per block; block-verify throughput is
   exactly what the 2026-07 sync-wedge incidents were about.
2. Production block validation should use the **batch verifier**
   (`src/crypto/batch_verify.rs`), which amortizes cost well below these
   standalone figures. The real per-block cost must be measured with batching,
   on fleet-class hardware, before a target is locked in.

## Specification

### Enforcement is already data-driven

`consensus/validation.rs::check_tx_ring_size_and_unique_members` reads
`constants::effective_ring_size(height, available_outputs)`, which delegates to
`ring_size_at_height(height)`. **The locked validator needs no logic change** —
only the constant function it calls. This keeps the locked-file blast radius to
`constants.rs` alone.

### `ring_size_at_height` gains tiers (constants.rs — LOCKED, re-lock after)

```rust
pub fn ring_size_at_height(height: u64) -> usize {
    if height >= RING_SIZE_32_HEIGHT { 32 }
    else if height >= RING_SIZE_24_HEIGHT { 24 }
    else if height >= 10_000 { 16 }   // existing post-bootstrap target
    else { BOOTSTRAP_MIN_RING_SIZE }  // 11 (or 13 if CIP-007 V2 lands)
}
```

New activation-height constants mirror `HARD_FORK_V1_0_12_HEIGHT`:

```rust
pub const RING_SIZE_24_HEIGHT: u64 = /* TBD — set with lead time */;
pub const RING_SIZE_32_HEIGHT: u64 = u64::MAX; // disabled until step 2 scheduled
```

### Fork-signal bit (fork_signal.rs — NOT locked)

Add a readiness bit alongside the existing `RING_SIZE_16` (CIP-002 bit):

```rust
/// CIP-017: ring-size increase (24, then 32).
pub const RING_SIZE_24: u32 = 1 << /* next free bit */;
pub const RING_SIZE_32: u32 = 1 << /* next free bit */;
```

Miners signal readiness; the height gate is the hard activation (Mode B).

### Wallet (wallet ring builder — NOT locked)

The wallet's decoy selection must produce the new ring size for transactions
built at/after the activation height. Decoy supply is not a concern on the
mature chain; `effective_ring_size` already adapts if outputs are ever sparse.

## Phased rollout

1. **Step 1 — 16 → 24.** Moderate cost bump (+83% verify, +42% size).
   Set `RING_SIZE_24_HEIGHT` with lead time; signal; activate.
2. **Step 2 — 24 → 32.** Gated on (a) confirming batch-verify covers block
   validation, and (b) the IBD-throughput work (per-peer best-known-header /
   pindexBestKnownBlock redesign) landing, so the ~3× verify cost of 32 does
   not re-introduce the sync-throughput fragility.

A single 16 → 32 fork is possible **only if** the batch-verify + fleet-hardware
benchmark shows 32 is comfortably within the nodes' block-verify budget.

## Backward compatibility

This is a hard fork. Before each activation height, nodes on the old binary
enforce the old ring size and will **reject** transactions using the new size.
All nodes and wallets must upgrade before the activation height — coordinated
exactly like the v1.0.12 fork (`HARD_FORK_V1_0_12_HEIGHT = 13,000`).

## Implementation checklist

Prep (safe, now):
- [ ] Benchmark the **batch verifier** at 16/24/32 on fleet-class hardware.
- [ ] Add `RING_SIZE_24` / `RING_SIZE_32` fork-signal bits (unlocked).

At fork time (per step):
- [ ] Set the `RING_SIZE_<n>_HEIGHT` constant with lead time.
- [ ] Add the tier to `ring_size_at_height`.
- [ ] Re-lock `constants.rs` (`update-critical-hashes`; needs elevation on Windows).
- [ ] Ship wallet + node upgrade; announce activation height.
- [ ] Miners signal; monitor signal threshold; activate at height.

## References

- [CIP-002 bit] `RING_SIZE_16` fork-signal (the 11→16 precedent)
- [CIP-007](CIP-007-hard-fork-activation-policy.md) — activation policy (Mode A/B), queued `BOOTSTRAP_MIN_RING_SIZE_V2` (11→13)
- Constitution Article III — mandatory privacy; strengthening permitted
- Benchmark harness: `crypto::clsag` (temporary `bench_ring_size_cost`, run + reverted 2026-07-10)
