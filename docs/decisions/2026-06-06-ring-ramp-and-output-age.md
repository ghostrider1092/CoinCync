# v1.0.12 — Ring-size ramp + MIN_OUTPUT_AGE activation

**Date:** 2026-06-06
**Status:** Implemented on branch `v1.0.12-consensus-refresh` (not yet shipped)
**Authors:** maintainer (operator-directed)

## Context

v1.0.11 ships the canonical-CLSAG consensus break in isolation, as its
own focused release. v1.0.12 batches the next two queued consensus
parameter changes into a single follow-on release so we coordinate one
fleet wipe → Crucible cycle → publish per consensus event rather than
two.

The two parameter changes:

1. **Ring-size ramp.** Replace the single hard cutover at h=10,000
   (ring 11 → ring 16) with a graduated ramp 11 → 13 → 16 at h=5,000
   and h=10,000 respectively.
2. **MIN_OUTPUT_AGE activation.** Set
   `MIN_OUTPUT_AGE_HARDFORK_HEIGHT` to 5,000 on testnet (was
   `u64::MAX` placeholder), activating the previously-coded 10 → 100
   maturity-floor hard fork.

## Decision

Implement both with activation at **h=5,000 and h=10,000** post-fresh-
genesis-wipe. `MIN_OUTPUT_AGE` aligns with the ring 11 → 13 step so
operators see "h=5,000: ring +2, maturity floor +90" as a single
mental event at one height.

## Rationale

### Ring ramp (11 → 13 → 16)

The pre-v1.0.12 code kept ring size at 11 for the entire 0..10,000
window, then jumped to 16 in a single step. This had three issues:

1. **Available-output cliff at activation.** A healthy chain produces
   ~30 blocks/hour at 120s target. At h=10,000 with 2 outputs/block
   coinbase-only, the chain has ~20,000 mature spendable outputs.
   Ring 16 requires 15 decoys per input. The math works on paper —
   but real-world testnets have transient periods where output growth
   lags (mining stalls, churn), and a hard cutover from 11 to 16 at a
   single height can leave the network briefly underprovisioned.

2. **Anonymity-set ripening time.** The privacy guarantee from a ring
   of size N requires that the decoys be distributionally
   indistinguishable from the real signer. Ring 16 on a thin
   anonymity set (e.g. 50 mature outputs) gives weaker indistinguish-
   ability than ring 11 on the same set. A graduated ramp lets the
   anonymity-set grow proportionally to each ring-size step.

3. **Operational testing.** A single 11 → 16 transition makes it hard
   to catch ring-size-specific bugs at the intermediate point. Three
   stages give one more data point.

The graduated 11 → 13 → 16 path with steps every ~7 days
(@ 120s blocks) reaches full ring 16 at the same h=10,000 as before,
just with a midpoint stop. Cost: ~5,000 blocks worth of slightly-
smaller-ring transactions before maturity. Benefit: smoother growth
curve, no cliff, additional test surface.

### Why 5,000 / 10,000

Several alternatives considered:

- **1,000 / 2,000** (~1.4 / 2.8 days). Faster ramp, testing-friendlier.
  Rejected: doesn't give the anonymity set enough time to grow between
  steps.
- **5,000 / 10,000** (~7 / 14 days). **Selected.** Same final
  activation as the pre-v1.0.12 code, with one intermediate stop
  exactly halfway through.
- **10,000 / 20,000** (~14 / 28 days). More conservative. Rejected:
  pushes full ring 16 four weeks past genesis, which is unacceptable
  pre-mainnet given the 2026-10-01 launch window.

### MIN_OUTPUT_AGE 10 → 100 alignment

`MIN_OUTPUT_AGE_HARDFORK_HEIGHT` was queued since v1.0.10 with a
`u64::MAX` testnet placeholder ("never activate"). The 100-block
maturity floor closes a deep-reorg double-spend window — at 10-block
maturity, an attacker with >50% hashrate for ~20 minutes can mount the
attack; at 100 blocks it's ~3.3 hours.

Aligning the activation with the ring-size mid-step (both at h=5,000)
means:

- One coordinated upgrade window for testnet operators
- One "what changed at h=5,000" entry in CIP / release notes
- Lower cognitive load on Crucible Recruits verifying the upgrade

## Mainnet posture

Mainnet activation heights are not affected by this PR — mainnet
`MIN_OUTPUT_AGE_HARDFORK_HEIGHT` stays at 0 (fork-active-from-genesis)
and the ring-ramp heights are the same as on testnet, applied from
genesis at the 2026-10-01 launch. New mainnet wallets see ring 11 for
the first week, ring 13 for week 2, ring 16 thereafter, and the
100-block maturity floor from block 1.

## Compatibility / migration

This is a **consensus break against the live v1.0.11 testnet chain**
the same way v1.0.11 was a break against v1.0.10. v1.0.12 deploys via
a coordinated fleet wipe (post barns confirmation on v1.0.11; we let
v1.0.11 bake for some period first, then ship v1.0.12).

Activation heights at 5,000 / 10,000 are chosen from the post-v1.0.11-
wipe genesis. Pre-mainnet testnet operators upgrading from v1.0.11 → 
v1.0.12 see no behaviour change at heights below 5,000 (everything is
still ring 11, maturity 10). The first behaviour change is exactly at
h=5,000.

## Implementation

- `src/constants.rs` — added `MID_RING_SIZE`,
  `RING_SIZE_RAMP_TO_MID_HEIGHT`, `RING_SIZE_RAMP_TO_FULL_HEIGHT`
- `src/constants.rs::ring_size_at_height` — rewritten as three-bracket
- `src/constants.rs::effective_ring_size` — updated to use named
  constant instead of hardcoded `10_000`
- `src/constants.rs::MIN_OUTPUT_AGE_HARDFORK_HEIGHT` (testnet) —
  changed from `u64::MAX` to `5_000`
- Updated tests at `test_ring_size_at_height` to cover all three
  brackets + boundary transitions
- `critical_files.lock` — bumped for the new `constants.rs` hash
- `Cargo.toml` — version bumped 1.0.11 → 1.0.12

`cargo test --release --lib`: 624 passed, 0 failed.

## Followup

- v1.0.12 binary build, Crucible Cycle 02 bundle for barns
- Coordinate fleet wipe + redeploy + landing publish + explorer
  redeploy in one window (same coordination as v1.0.11)
- Update the `BOOTSTRAP_MIN_RING_SIZE >= 11` constitutional-floor
  comment to also note the ramp endpoints (deferred — does not
  affect consensus, just doc accuracy)

## References

- Pre-v1.0.12 single-step: `src/constants.rs::ring_size_at_height`
  before this commit (still in git history at v1.0.11-canonical-clsag
  tag)
- CIP-007 ring-size queue mention at `src/constants.rs:750`
- MIN_OUTPUT_AGE rationale: `src/constants.rs:370-405`
- 2026-06-04 testnet wipe + cascade recovery:
  `docs/operations/stress-tests/2026-06-04-testnet-cascade-recovery.md`
