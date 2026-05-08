<!-- markdownlint-disable MD036 -->
# CIP-010 — Testnet hard-fork rehearsal

**Status:** Draft
**Type:** Process / Standards Track (consensus rule activation)
**Created:** 2026-05-08
**Layer:** Consensus + operations
**Depends on:** CIP-007 (activation policy)
**Activation target:** testnet height ~10000 (estimated 2026-06-15)

---

## Purpose

CIP-007 (hard-fork activation policy) is currently theoretical. It
specifies Mode A (static-height) and Mode B (BIP8-style version-bit
signaling), but neither has fired in production. Mainnet is the wrong
place to discover the activation pipeline has a bug.

This CIP plans a deliberate testnet hard-fork to exercise the full
activation chain end-to-end:

1. The static-height activation logic in `validate_block`
2. The coordinated client release process
3. The operator-coordination channel (Discord, status page, runbook)
4. The miner / wallet upgrade flow
5. The recovery procedure if the activation fails or splits the network

The rehearsal uses the **Bump #1** change already on the
`KNOWN_ISSUES.md` open list:
`BOOTSTRAP_MIN_RING_SIZE` rises from 11 to 13 at a planned testnet
height. This change is small, well-understood, and has a clear privacy
benefit — exactly the kind of change a real activation will look
like, without the risk of a complex new feature breaking mid-fork.

The rehearsal is **not** a mainnet rule change. It exists for
mainnet only as a process artifact: "we did this once on testnet,
the playbook works."

---

## What the change does

`BOOTSTRAP_MIN_RING_SIZE` is the minimum ring-signature decoy count
required during the bootstrap phase (chain height < 10 000 blocks).
Today: 11 (≈ 1/11 = 9% per-input traceability).

After activation: 13 (≈ 1/13 = 7.7% per-input traceability), if the
chain has accumulated enough unique outputs to make ring=13 viable.

The chain has had >100 unique outputs since block ~30, so ring=13
is comfortable from then on.

This is consensus rule. Pre-activation transactions with ring=11
remain valid forever; post-activation, blocks containing
ring<13 inputs are rejected.

---

## Activation parameters

| Parameter | Value |
|---|---|
| Activation mode | CIP-007 Mode A (static height) |
| Target height | 10 000 (estimated 2026-06-15 at 120s blocks from height 4275 on 2026-05-08) |
| Pre-activation rule | `ring_members.len() >= BOOTSTRAP_MIN_RING_SIZE_V1` (= 11) |
| Post-activation rule | `ring_members.len() >= BOOTSTRAP_MIN_RING_SIZE_V2` (= 13) at `height >= ACTIVATION_HEIGHT` |
| Lock-in window | None (Mode A is unconditional at the height) |
| Grace period | None (a tx with ring=11 in a block at `height >= ACTIVATION_HEIGHT` is invalid; wallets should refuse to build them at and after the height) |

The activation height is set far enough in the future to give every
testnet node operator time to upgrade. ~6 weeks at 120s blocks.

---

## Code changes

### 1. New constants in `src/constants.rs`

```rust
/// Pre-activation bootstrap minimum ring size. Validates ring count
/// for blocks at height < RING_BUMP_ACTIVATION_HEIGHT. Frozen at 11
/// for testnet rehearsal compatibility.
pub const BOOTSTRAP_MIN_RING_SIZE_V1: usize = 11;

/// Post-activation bootstrap minimum ring size. Validates ring count
/// for blocks at height >= RING_BUMP_ACTIVATION_HEIGHT.
pub const BOOTSTRAP_MIN_RING_SIZE_V2: usize = 13;

/// Testnet activation height for the ring-size bump (CIP-010).
/// Mainnet has no equivalent at this height — the rule is testnet-
/// only for the rehearsal window. Mainnet activation is decided
/// post-launch.
#[cfg(feature = "testnet")]
pub const RING_BUMP_ACTIVATION_HEIGHT: u64 = 10_000;

/// Helper: returns the active bootstrap-min-ring-size for a given
/// block height. Single source of truth so validate_block and the
/// wallet builder agree.
pub fn bootstrap_min_ring_size_at_height(height: u64) -> usize {
    #[cfg(feature = "testnet")]
    {
        if height >= RING_BUMP_ACTIVATION_HEIGHT {
            return BOOTSTRAP_MIN_RING_SIZE_V2;
        }
    }
    BOOTSTRAP_MIN_RING_SIZE_V1
}
```

The existing constant `BOOTSTRAP_MIN_RING_SIZE` is kept as an alias
for `BOOTSTRAP_MIN_RING_SIZE_V1` for backward compatibility with
existing call sites; new code uses the height-aware function.

### 2. Validator in `src/consensus/validation.rs`

Replace the existing check:

```rust
if input.ring_members.len() < crate::constants::BOOTSTRAP_MIN_RING_SIZE {
    return Err(...);
}
```

with:

```rust
let min_ring = crate::constants::bootstrap_min_ring_size_at_height(block_height);
if input.ring_members.len() < min_ring {
    return Err(...);
}
```

### 3. Wallet builder in `src/wallet/send.rs`

Same replacement: the wallet that's building a tx for inclusion at
height `H` must use `bootstrap_min_ring_size_at_height(H)` to choose
ring members.

### 4. CLI / wallet status

Add a `next_consensus_change` field to `get_info` RPC output:

```json
{
  "next_consensus_change": {
    "name": "ring-bump-v2",
    "height": 10000,
    "blocks_remaining": 5723,
    "description": "BOOTSTRAP_MIN_RING_SIZE 11 -> 13"
  }
}
```

This gives operators a clear "you have N blocks to upgrade" signal in
their status checks.

### 5. Tests

Three new test cases:

1. `test_ring_bump_pre_activation_accepts_ring_11`: a block at
   height `ACTIVATION_HEIGHT - 1` with a ring-11 tx is accepted.
2. `test_ring_bump_at_activation_rejects_ring_11`: a block at
   height `ACTIVATION_HEIGHT` with a ring-11 tx is REJECTED.
3. `test_ring_bump_at_activation_accepts_ring_13`: a block at
   height `ACTIVATION_HEIGHT` with a ring-13 tx is accepted.

These tests exist as regression guards forever; they're cheap and
they're how we know the activation logic survives later refactors.

---

## Operational rehearsal — the actual playbook

The following is the procedure the rehearsal is testing. Each step
will be timestamped and recorded so the mainnet version is
data-driven, not best-effort.

### T-6 weeks (2026-05-08, today): announce

- Publish this CIP.
- Post in the Discord `#announcements` channel: "Ring-size bump at
  testnet height 10 000, ETA 2026-06-15. Upgrade your node by then."
- Update the website's status page: "Upcoming consensus change:
  ring-bump v2 at height 10 000."
- Announcement template: `docs/launch/HARDFORK_ANNOUNCEMENT.md`
  (to be authored as part of this rehearsal — Step T-5 weeks).

### T-5 weeks: ship the code

- PR with the constants, validator, wallet, and tests.
- Code review (single maintainer is enough for testnet; mainnet
  will require two-of-N).
- Merge to `main`.
- Tag `v1.1.0-testnet` release.
- Build signed binaries for Linux/Windows/macOS and publish to
  Forgejo releases.

### T-4 weeks: roll the fleet

- Apply the new release to all 5 fleet boxes.
- Verify `get_info.next_consensus_change` shows the activation
  parameters.
- Verify `coincync-rig` (the miner) refuses to build ring=11 txs
  for blocks at and after activation height (it should error early,
  not produce an invalid block).

### T-2 weeks: send a reminder

- Discord reminder: "2 weeks to ring bump. Last call to upgrade."
- Status page: countdown banner.

### T-1 day: pre-flight check

- All 5 fleet boxes confirm they're on `v1.1.0-testnet` or later.
- Spot-check 3 random testnet wallets in the wild (best effort —
  this is a public testnet, not all participants are reachable).
- Verify `get_info.next_consensus_change.blocks_remaining` is
  consistent with chain height across the fleet.

### T-0: activation

- Block at height 10 000 is mined.
- Every node validates the block under the V2 rule.
- Watchers note: any node still on `v1.0.x` will reject the block
  (because the V2 logic is gated by `feature = "testnet"` and the
  V1-only binary doesn't have the activation logic — but its V1
  rule still passes, so it'll accept ring=11 *and* ring=13 blocks
  and stay in sync as long as it doesn't try to validate the
  height-gate strictness).
- Critically: a node still on `v1.0.x` cannot mine a valid block
  at this height (because if it picks a ring=11 tx, post-fork
  nodes reject the block).
- Status page updates: "Activation complete. Network on V2 rules."

### T+1 hour: verify

- All fleet boxes still synced.
- No fork events in the chain log.
- No mempool backlog (no rejected ring-11 txs piled up).
- Discord post: "Ring-bump activation complete. No issues observed."

### T+1 week: write up

- Operator-facing doc: `docs/launch/POST_HARDFORK_REPORT.md`
  describing what happened, what timing was, what surprised us,
  what to change for the mainnet version.
- Update CIP-007 with any observed issues; promote any process
  improvements into the activation policy.

---

## Recovery scenarios

What if something goes wrong? Each scenario has a defined response.

### Scenario A: chain forks at activation height

Some nodes accept the block, others don't (e.g., a binary mismatch
across the fleet). Symptom: two competing tips at height ≥ 10 000.

**Response:**
- Confirm the divergence: `get_blockchain_info` on each fleet box
  shows different `tip_hash`.
- Identify which fleet box is on which side.
- Restart all fleet boxes onto the post-fork binary.
- Most-work chain wins; the loser side reorgs naturally.
- Document: which boxes were on which side, why, recovery time.

### Scenario B: activation block is invalid for a different reason

E.g., the V2 rule has a bug and rejects all blocks at the activation
height even when ring=13. Symptom: chain stalls at height 9 999.

**Response:**
- Identify the bug in the V2 validator.
- Hotfix branch + emergency release.
- Rollback the activation height in a new build (push it 1 000
  blocks further to give time for the fix), OR remove the V2 rule
  entirely from the build and revert testnet to V1.
- Either case: every fleet box upgrades.
- This scenario IS a test of the recovery process; if it happens,
  the rehearsal succeeded at finding the problem.

### Scenario C: fleet upgrades, community wallets don't

A user with a stale wallet builds a ring=11 tx, broadcasts it after
height 10 000, the fleet rejects it. Symptom: user complaints.

**Response:**
- Not a fault of the fork; a user-facing UX issue.
- Wallet should be hard-coded with the activation height and
  refuse to build ring=11 txs at height ≥ 10 000 — verify this
  works in T-1 day pre-flight.
- If a stale wallet is detected, user gets a clear "your wallet is
  out of date; download v1.1+" error, not a generic "tx rejected."

### Scenario D: activation block is mined by a node that hasn't
upgraded

The fleet's miner is on V2; some other miner on the public testnet
is on V1 and mines block 10 000 with ring=11. Symptom: the V1 miner's
block is rejected by every V2 node, but accepted by every other V1
node.

**Response:**
- Most-hashpower side wins. If the fleet has the majority hashpower
  (true today), the V2 chain wins.
- If the fleet does NOT have majority hashpower, this is the FIRST
  signal that the project has lost effective control of testnet
  consensus — that's IMPORTANT INFORMATION about how mainnet
  decentralization will work, not a failure.
- Either way: document.

---

## What this CIP teaches us about mainnet

The whole point. Things we learn from doing this on testnet that
make mainnet safer:

1. **Activation height calculation accuracy.** How close was our
   estimated date to the real one? Block-time variance accumulates.
2. **Fleet upgrade time.** Was 6 weeks enough? Was it too much?
3. **Communication channel reach.** Did everyone who needed to
   upgrade actually hear about it?
4. **Pre-flight check coverage.** Did we miss anything in T-1 day?
5. **Recovery scenario likelihood.** Which scenarios fired, which
   didn't? Calibrate mainnet expectations.
6. **Stale-wallet failure mode.** How loud was the complaint
   volume? What can the wallet do better next time?
7. **Status page utility.** Did people actually read it?
8. **Discord reminder cadence.** Was T-6w + T-2w + T-1d enough?

These answers all become part of the mainnet activation playbook.

---

## Out of scope

- **Mainnet ring bump.** Mainnet may or may not adopt the V2
  rule. That's a separate decision post-mainnet.
- **CIP-009.D rehearsal.** Soft-finality is its own activation,
  needs its own rehearsal CIP, and is much more complex (requires
  miner-set bootstrapping, see CIP-009.D § Genesis-bootstrap).
- **Wallet UX for fork awareness.** A "this version expires at
  height N, please upgrade" wallet UX is a separate work item;
  this CIP only requires that the wallet correctly refuse to build
  invalid txs.
- **Mining-pool coordination.** No mining pool exists on testnet.
  Mainnet's version of this rehearsal will have to add the
  pool-coordination layer.

---

## Decision (for the user)

Three options:

- ☐ **Approve.** Open the implementation PR; post the T-6 week
  announcement; aim for activation 2026-06-15.
- ☐ **Defer.** Stay on V1; mainnet will be the first activation.
  Higher risk, lower coordination cost.
- ☐ **Modify.** Different rule (e.g., a different activation
  height, a different rule change, both V1 and V2 simultaneously
  to test BIP8-style signaling instead of static height).

If approved, implementation is ~2 days of code work plus the 6
weeks of calendar lead time.

---

## Related work

- `docs/cip/CIP-007-hard-fork-activation-policy.md` — defines
  the activation modes
- `docs/launch/KNOWN_ISSUES.md` — Bump #1 (the rule we're
  activating)
- `src/constants.rs` — `BOOTSTRAP_MIN_RING_SIZE` constant
- `src/consensus/validation.rs` — current ring-size validator
