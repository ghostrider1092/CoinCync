<!-- markdownlint-disable MD036 -->
# CIP-011 — Rolling soft-finality activation rehearsal

**Status:** Draft (post-launch activation candidate)
**Type:** Process / Standards Track (consensus rule activation)
**Created:** 2026-05-08
**Layer:** Consensus + operations
**Depends on:** CIP-007 (activation policy), CIP-009 (Path B shipped), CIP-009.D (the protocol spec)
**Implements:** CIP-009.D phase 3 — `validate_block` integration

---

## Purpose

CIP-009.D specifies the rule. CIP-011 is the deployment plan: how
the rule actually goes live on testnet, how mainnet inherits the
process, what we measure, and what to do when something goes
wrong.

This CIP exists for the same reason CIP-010 exists for the ring-
bump: a real activation has many moving parts (binary roll, miner
upgrade, attestation-volume bootstrap, observation window, recovery
playbook). Writing them down ahead of activation turns "we'll
figure it out when we get there" into a procedure that survives
the maintainer being on a plane.

---

## Two-phase activation

CIP-009.D requires a **TWO-phase** activation, not the single-
height pattern that CIP-010 uses for the ring-bump. Reason: the
soft-finality rule depends on having an active miner set with
≥ MIN_QUORUM (= 5) distinct miners over the past WINDOW (= 10 000
blocks). On a brand-new chain that's never run the protocol, the
active miner set is empty until enough blocks have been mined
post-activation. If we turn on the *enforcement* rule before the
active set is populated, every reorg query returns "no soft-final
tip" — which is correct but useless.

The two phases:

### Phase 1 — ENABLE (collect attestations, no enforcement)

At `H_enable`:
- Blocks may include `finality_*` fields in coinbase extra. Blocks
  without them are accepted (backward-compatible).
- Validators decode and record attestations into the
  `FinalityTracker`.
- The reorg rule does NOT fire. `would_reorg_violate_finality`
  always returns `false` regardless of the tracker state.
- Operators observe: how many miners are submitting? How fast does
  the active set grow? Does it stabilize ≥ MIN_QUORUM?

This phase runs for at least `WINDOW` blocks (~14 days) so the
active miner set is fully populated.

### Phase 2 — ENFORCE (reorg rule fires)

At `H_enforce`:
- All blocks at `height >= H_enforce` MUST include a valid
  `finality_*` payload (the magic-prefix decode succeeds + the
  ed25519 signature verifies).
- The reorg rule begins firing: any reorg whose fork-point is at
  or below `soft_final_height()` is rejected.
- Operators observe: any false-positive reorg rejections? Any
  blocks rejected for missing or invalid attestations?

Between `H_enable` and `H_enforce` there's a wide observation
window. CIP-009.D §"Failure modes and mitigations" calls out four
scenarios; the observation phase exercises each one before the
rule has any consensus weight.

---

## Activation parameters

Subject to user approval; values below are the recommended defaults.

| Parameter | Recommended value |
|---|---|
| `H_enable` (testnet) | testnet height ~50 000 (≈ 6 months post-launch) |
| `H_enforce` (testnet) | testnet height ~75 000 (`H_enable` + 25 000 blocks ≈ 35 days observation) |
| `H_enable` (mainnet) | mainnet height ~25 000 (≈ 60 days post-mainnet, after testnet rehearsal completes) |
| `H_enforce` (mainnet) | mainnet height ~50 000 (`H_enable` + 25 000 blocks ≈ 35 days observation) |
| `WINDOW` | 10 000 blocks (~14 days at 120s) |
| `LAG` | 100 blocks (matches `MIN_OUTPUT_AGE`) |
| `MIN_QUORUM` | 5 active miners |
| `THRESHOLD` | ⌈2/3 × \|active set\|⌉ |
| Attestation wire version | 1 (CIP-009.D phase 2 codec) |

The ENABLE-to-ENFORCE gap of 25 000 blocks (≈ 35 days) is
deliberately wider than `WINDOW`. It lets the active set fully
populate AND gives operators a comfortable window to spot bugs
before the rule has bite.

---

## Code changes

The bulk of the code is already in `crates/coincync-rolling-
finality/` (phase 1 + phase 2, shipped at commits `05c4c74` and
`7292682`). Phase 3 (this CIP) wires it into the main crate. The
diff is concentrated:

### 1. New constants in `src/constants.rs`

```rust
/// Activation height: blocks at or after this height MAY carry
/// finality attestations in coinbase extra. Validators record
/// them; the reorg rule does NOT fire yet.
#[cfg(feature = "testnet")]
pub const ROLLING_FINALITY_ENABLE_HEIGHT: u64 = 50_000;
#[cfg(feature = "mainnet")]
pub const ROLLING_FINALITY_ENABLE_HEIGHT: u64 = 25_000;

/// Enforcement height: blocks at or after this height MUST carry
/// a valid finality attestation, AND the reorg rule fires.
#[cfg(feature = "testnet")]
pub const ROLLING_FINALITY_ENFORCE_HEIGHT: u64 = 75_000;
#[cfg(feature = "mainnet")]
pub const ROLLING_FINALITY_ENFORCE_HEIGHT: u64 = 50_000;

/// CIP-007 activation registry entry — wired into
/// `is_activated("rolling-finality-enforce", height)`.
```

Both constants live in `critical_files.lock` (constants.rs is
locked). Updating them is a deliberate consensus-rule change with
the lockfile refresh.

### 2. New module in main crate: `src/consensus/rolling_finality.rs`

A thin adapter that:
- Holds a singleton `FinalityTracker` instance per node (tip,
  active miner set, accumulated attestations).
- On every accepted block: extracts the attestation from coinbase
  extra (using the `wire-codec` feature), feeds it into
  `FinalityTracker::apply_attestation` with the production
  `Ed25519Verifier` (using the `ed25519` feature).
- Exposes `would_reorg_violate_finality(fork_height) -> bool` for
  the validator.
- Exposes `current_soft_final_height() -> Option<u64>` for the
  RPC + status page + metrics.
- Persists nothing on its own. On node restart, the tracker is
  rebuilt from chain replay (every block from
  `chain_tip - WINDOW` forward is re-fed).

### 3. Validator hook in `src/consensus/validation.rs`

After the existing checkpoint check, before the PoW score
comparison:

```rust
if is_activated("rolling-finality-enforce", block_height) {
    if state.rolling_finality
        .would_reorg_violate_finality(fork_point_height)
    {
        return Err(ValidationError::ReorgPastSoftFinality {
            fork_point_height,
            soft_final_height,
        });
    }
}
```

`validation.rs` is locked; this change rolls the lockfile.

### 4. Block-template enforcement in `src/mining/template.rs`

Post-`H_enforce`, the miner's template builder MUST include a
finality attestation in coinbase. The template builder gains a
`current_finality_target` callback that returns
`(height - LAG, hash_at_that_height)` from the local chain and a
signing key from the miner's `coincync-rig` config.

If the template builder cannot produce an attestation
(unconfigured signing key, chain too short, miner's signing key
isn't in the active set yet), it FAILS LOUDLY rather than
producing an invalid block. Block-template failure is a config
error, not a chain stall — the operator gets a clear error
message + a runbook reference.

### 5. RPC exposure

New JSON-RPC methods, gated behind the `ed25519`+`wire-codec`
features:

- `get_finality_status` → `FinalityStats` snapshot
- `get_finality_history` → list of (height, hash, signers) for
  recent finalized heights, useful for explorer + audits

These are read-only, low-cardinality, safe for the public REST
proxy.

### 6. Config + miner integration

`coincync-rig` (the miner) gains:

- `finality_signing_key`: path to an ed25519 private key file
  (mode 0600). If absent, the miner refuses to start
  post-`H_enforce`.
- `finality_pubkey_first_seen`: height at which the miner first
  registered (lazily populated when the miner first mines).

CIP-009.D §6 (key rotation) is **NOT** wired in this CIP. Phase 3
ships without rotation; rotation is its own focused commit
post-mainnet because rotation touches the active-set identity-
mapping in subtle ways and deserves dedicated attention.

---

## Operational rehearsal — the playbook

Same structure as CIP-010's ring-bump playbook. Each step is
timestamped and recorded so the mainnet version is data-driven.

### Pre-`H_enable` window

#### T-12 weeks (testnet 2026-09-20, mainnet 2026-12-01): announce

- Publish this CIP.
- Discord `#announcements`: "Rolling finality enables at testnet
  height 50 000, ETA 2026-11-15."
- Status page: "Upcoming consensus change: rolling-finality
  enable at H = 50 000."
- Update `docs/launch/HARDFORK_ANNOUNCEMENT.md`.

#### T-10 weeks: ship the code

- PR with the constants + the validator hook + miner integration.
- Code review (two-of-N maintainers required for consensus
  changes).
- Merge to `main`.
- Tag `v1.2.0` release.
- Build signed reproducible binaries.

#### T-8 weeks: roll the fleet to v1.2.0

- Apply v1.2.0 to all 5 fleet boxes.
- Verify each fleet miner has a `finality_signing_key` configured
  (generate fresh, mode 0600).
- Verify `get_info.next_consensus_change` shows correct
  `H_enable` / `H_enforce`.

#### T-2 weeks: reminder

- Discord reminder: "Rolling finality enables in 2 weeks. Last
  call to upgrade your miner."
- Status page: countdown banner.

### `H_enable` window

#### T-0 (block height = `H_enable`): enable

- Block at `H_enable` mined.
- Validators begin recording attestations from coinbase extra.
- The reorg rule still does NOT fire — backward-compatible.
- Status page: "Rolling finality ENABLED. Observation window
  begins."

#### T+1 hour: smoke test

- Confirm the fleet's miner is including attestations (check
  coinbase decode on the explorer).
- Confirm validators are recording them
  (`get_finality_status.total_attestations_recorded` is
  increasing).

#### T+1 day: active-set check

- Verify `get_finality_status.active_miner_count` matches the
  number of distinct miners in the last 24 hours.
- For the fleet alone: 1 active miner (one rig). Won't reach
  MIN_QUORUM until external miners join.

#### T+7 days: bootstrap-quorum review

- If `active_miner_count >= MIN_QUORUM`: on track.
- If `active_miner_count < MIN_QUORUM`: outreach to the community
  is needed. Soft-finality won't fire until quorum is met. This
  is the LARGEST risk in the rehearsal — see "Bootstrap
  scenarios" below.

#### T+30 days: pre-`H_enforce` go/no-go

- Has the active set been ≥ MIN_QUORUM for at least the last
  WINDOW blocks?
- Has `soft_final_height` been advancing in the recorded data?
- Have any tracker bugs surfaced?
- Any false-positive `would_reorg_violate_finality` returns?

If all four are green: continue to `H_enforce`. If any are red:
push `H_enforce` further out.

### `H_enforce` window

#### T-0 (block height = `H_enforce`): enforce

- Block at `H_enforce` mined.
- Every block must now carry a valid attestation; missing or
  invalid attestation rejects the block.
- The reorg rule fires.
- Status page: "Rolling finality ENFORCED."

#### T+1 hour: verify

- Chain still advancing (no validators stuck rejecting blocks).
- No mempool backlog.
- `get_finality_status.soft_final_height` is advancing.

#### T+1 week: write up

- Document timing, surprises, what to change for mainnet.
- File followups for any tracker bugs that surfaced.

---

## Bootstrap scenarios

### Scenario A — quorum never reached during ENABLE window

The ENABLE window expires with `active_miner_count < MIN_QUORUM`.
Soft-finality literally cannot fire even once.

**Response:**
- Push `H_enforce` out.
- Diagnose: are external miners joining? Are they configuring
  `finality_signing_key`? Is the documentation clear?
- Two paths: (1) wait longer, (2) lower MIN_QUORUM via a
  consensus-rule change. Path (1) is preferred. Path (2) is
  cheaper but encodes a "we settled for less safety because we
  couldn't bootstrap" decision into the consensus rules forever.

### Scenario B — quorum reached but unstable

Active set hovers around MIN_QUORUM, dipping below intermittently
during the ENABLE window. Soft-finality fires sporadically.

**Response:**
- Inspect what's causing miner churn. Could be rig failures,
  network issues, or just normal small-set turnover.
- Probably acceptable for testnet (we're proving the protocol);
  mainnet wants more headroom.

### Scenario C — chain forks at `H_enable`

Some fleet box hasn't upgraded; its block-template builder still
emits no-attestation blocks. After `H_enable` such blocks are
still valid (ENABLE phase is permissive), so this isn't actually
fatal — but the box's miner is also missing from the active set
because the wallet hasn't registered a finality key.

**Response:**
- Roll the box to v1.2.0.
- Active set re-populates as the box mines new blocks.

### Scenario D — chain forks at `H_enforce`

A fleet box hasn't upgraded; emits invalid blocks at
`height >= H_enforce` that other boxes reject.

**Response:**
- Same as the equivalent scenario in CIP-010: most-hashpower side
  wins. If the unrolled box is a minority, no harm; if majority,
  emergency rollback (push `H_enforce` further out via a hotfix).

### Scenario E — soft-finality blocks a legitimate reorg

A legitimate organic reorg at depth ≤ `soft_final_height` is
rejected. This shouldn't happen if soft-finality is working
correctly (the 2/3 threshold should match the chain that's
actually being followed), but if MIN_QUORUM is too low or the
miner set is concentrated, it could.

**Response:**
- This is the worst-case correctness bug. Investigate
  immediately.
- If confirmed: emergency hotfix that disables the reorg rule
  pending review. Effectively a rollback to the ENABLE phase.

---

## Mainnet inheritance

Mainnet's activation reuses the same procedure with two
differences:

1. **The testnet rehearsal must complete cleanly** (≥ 30 days post
   `H_enforce`, no false positives, no chain-fork events,
   no operator interventions beyond the planned schedule).
   Without that, mainnet activation is deferred to the next
   release window.

2. **Heights are adjusted** for mainnet's actual block-time
   target and observed chain-state-at-launch. If mainnet launches
   October 2026 at height 0, post-launch `H_enable` ~25 000 puts
   the activation roughly 60 days after launch.

The mainnet activation CIP will be `CIP-014` or whichever number
is current; this CIP doesn't pre-commit to specific mainnet
heights because they depend on observed mainnet block-time and
miner-bootstrap rate.

---

## What this CIP teaches us about mainnet

Same shape as CIP-010 §"What this CIP teaches us":

1. **Active-set bootstrap rate.** How long does it take for
   ≥ MIN_QUORUM distinct miners to register? On a brand-new
   chain this is the bottleneck.
2. **Attestation cost in practice.** ~145 bytes per block of
   coinbase-extra overhead. Does this affect fee dynamics?
3. **False-positive rate of the reorg rule.** Any organic
   reorgs blocked? Any soft-final advances that should have
   stalled?
4. **Observation-window length.** Was 25 000 blocks enough? Too
   much?
5. **Tracker memory footprint.** With a busy active set, how
   much memory does the tracker hold?

These calibrate the mainnet equivalent.

---

## Out of scope

- **Key rotation.** CIP-009.D §6 specifies it; this CIP defers
  rotation to post-mainnet.
- **Slashing.** CIP-009.D explicitly excludes slashing from the
  protocol. Re-confirming here so it doesn't sneak back in.
- **Light-client finality proofs.** SNARK-compressed proofs are
  CIP-016+ (potential post-launch work).
- **Cross-chain finality.** This is intra-CoinCync only.

---

## Decision (for the user)

- ☐ **Approve.** Open the implementation PR for phase 3 (the
  validator-hook + main-crate adapter). Schedule the testnet
  rehearsal for `H_enable` = testnet 50 000 (≈ 2026-11-15
  given current block-time projections).
- ☐ **Approve with modified parameters.** Same as above with
  different `H_enable` / `H_enforce` heights.
- ☐ **Defer.** Stay on Path B (consensus checkpoints) only.
  Revisit if a mainnet incident shows live-tip defense is
  needed.
- ☐ **Reject.** Mainnet ships with Path B + PoW only. Cancel
  CIP-009.D.

If approved: implementation begins on a feature branch, lands
behind an off-by-default Cargo feature, and gets rehearsed on
testnet for the full 6+ month window before mainnet activation.

---

## Related work

- `docs/cip/CIP-007-hard-fork-activation-policy.md` — defines
  the activation modes
- `docs/cip/CIP-009-reorg-defense-decision.md` — original
  reorg-defense decision (Path B shipped, MESS rejected)
- `docs/cip/CIP-009-D-miner-signed-rolling-checkpoints.md` —
  the protocol spec
- `docs/cip/CIP-010-testnet-hardfork-rehearsal.md` — the
  ring-bump rehearsal (smaller scope; this CIP follows its
  shape)
- `crates/coincync-rolling-finality/` — phase 1 (state
  machine) + phase 2 (ed25519 + wire codec), already shipped
- `src/constants.rs` — where `ROLLING_FINALITY_*` constants
  will live (consensus-locked)
- `src/consensus/validation.rs` — where the reorg-rule hook
  lands (consensus-locked)
