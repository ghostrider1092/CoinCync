# Runbook: CIP-009.D rolling soft-finality activation (Fort-Knox Item 7)

**Scope**: the maintainer's checklist for turning on **CIP-011** (miner-signed rolling soft-finality) in production. This runbook does NOT change any code — it lists the ordered decisions, verifications, and consensus-locked-file edits required, so the activation is deliberate rather than accidental.

**Zero scope creep**: no consensus code is touched by this document. Two consensus-locked files (`src/constants.rs`, `src/consensus/validation.rs`) will be edited as part of the activation PR that this runbook GATES; that PR is separate work.

## Current implementation state (as of 2026-07-04)

Reading `docs/operations/runbook-rolling-finality-activation.md` first tells the operator what's already shipped and what remains:

| Layer | State | File |
|---|---|---|
| Phase 1: state machine (`FinalityTracker`, `ActiveMinerSet`) | ✅ SHIPPED | `crates/coincync-rolling-finality/src/finality.rs`, `active_set.rs` (671 + 237 lines) |
| Phase 2a: real ed25519 verifier | ✅ SHIPPED (feature `ed25519`) | `crates/coincync-rolling-finality/src/verifier_ed25519.rs` (253 lines) |
| Phase 2b: wire codec | ✅ SHIPPED (feature `wire-codec`) | `crates/coincync-rolling-finality/src/codec.rs` (283 lines) |
| Phase 3: consensus adapter (`RollingFinality::on_accepted_block`, `would_reorg_violate_finality`) | ✅ SHIPPED (feature `rolling-finality`) | `src/consensus/rolling_finality.rs` (447 lines) |
| **Phase 4: `validate_block` reorg-rule integration** | ⏳ **PENDING — requires this runbook** | `src/consensus/validation.rs` (consensus-locked) |
| **Phase 5: activation height constants** | ⏳ **PENDING — requires this runbook** | `src/constants.rs` (consensus-locked) |
| Phase 6: key rotation handler | ⏳ POST-ACTIVATION | `crates/coincync-rolling-finality/` (extend) |

Every phase before phase 4 is compile-in-optional — the `rolling-finality` Cargo feature is OFF by default, so builds without it are byte-identical to a build with no rolling-finality code at all. This is by design (see `src/consensus/rolling_finality.rs` header).

## What activation actually enables

Once phase 4+5 land, the consensus layer:

1. **Reads** every miner's attestation from coinbase `extra` on every accepted block (Phase 3 already does this)
2. **Accumulates** attestations toward a soft-final height (Phase 1 already does this)
3. **Rejects** any proposed reorg whose fork-point is at or below the current soft-final height (Phase 4 is what turns this switch on)

The rule takes effect at `ROLLING_FINALITY_ACTIVATION_HEIGHT` and NOT before. Below that height the network runs on the existing 6-layer defense (see `src/consensus/finality.rs` header for the layer list — the shipped defense is comprehensive without CIP-011).

## Prerequisites for activation

### 1. Miner coordination

Miner-signed finality is only useful if enough miners are actually signing. Below `MIN_QUORUM = 5` distinct active miners, the tracker cannot finalize anything.

**Verify**: as of 2026-07-04, testnet has `randomx` + `randomx2` mining. That's 2 miners — below the default `MIN_QUORUM = 5`. Testnet activation is NOT unblocked until either:

- More community miners are attesting (recommended path: outreach + tooling for community miners to opt-in), OR
- The activation PR sets `MIN_QUORUM` to a testnet-appropriate value (2-3) explicitly — the `RollingFinality::with_params` constructor accepts this

**Verify**: mainnet activation must have `MIN_QUORUM = 5` (the default). See CIP-009.D §"Parameters" for the reasoning.

### 2. Testnet rehearsal window

Per the CIP-009.D commit message and the finality.rs doc: *"Activation behind a CIP-007 Mode A height gate after a 6-month testnet rehearsal window."*

Before mainnet activation:

1. Land Phase 4+5 on testnet at a testnet activation height
2. Observe soft-finality operation for **≥6 months** — at least one full election cycle for the community miner set
3. Verify no regressions in reorg handling, tip-tracking, block-download latency, mempool behavior
4. Public post-mortem of the testnet run before locking in mainnet activation

If any of these gates fail, activation is aborted, code is amended, testnet cycle restarts.

### 3. Audit review

CIP-009.D was designed pre-audit. Before mainnet activation:

- The full `coincync-rolling-finality` crate (1746 lines) and the consensus adapter (447 lines) must be in the audit scope of at least one external review
- Any audit findings blocking activation must be resolved with tests + fix + re-review
- Audit sign-off recorded in `docs/audit/` alongside the activation PR

### 4. Key ceremony for the maintainer set

Every miner producing blocks after activation needs an ed25519 finality keypair. This is separate from their wallet / payout keys (see CIP-009.D §"Keys"). Before activation:

- Publish the ed25519 keygen procedure (a variant of the peer-snapshot key ceremony in `runbook-bootstrap-ceremony.md`)
- Fleet miners generate their keys, back them up, and register the public keys on-chain via the coinbase-attestation format
- Community miners follow the same procedure documented publicly
- The `ROLLING_FINALITY_ACTIVATION_HEIGHT` is chosen far enough in the future that miners have time to complete this ceremony

## The activation PR (when all prerequisites clear)

### Step 1 — Constants

Add to `src/constants.rs`:

```rust
/// Height at which CIP-011 rolling soft-finality activates.
/// After this height, `validate_block` refuses reorgs whose
/// fork-point is at or below the current soft-final height.
///
/// Below this height, the shipped 6-layer reorg defense runs
/// unchanged. See src/consensus/finality.rs for the layer list.
pub const ROLLING_FINALITY_ACTIVATION_HEIGHT: u64 = <chosen height>;

/// Attestation lag: miners attest to (chain_tip - LAG), so soft-final
/// height trails the chain tip by at least LAG blocks. Matches
/// MIN_OUTPUT_AGE for symmetry with existing consensus rules.
pub const ROLLING_FINALITY_LAG: u64 = 100;

/// Active-miner sliding window: a miner counts as "active" if they
/// mined at least one block in the last WINDOW blocks.
pub const ROLLING_FINALITY_WINDOW: u64 = 10_000;

/// Minimum distinct active miners before ANY finalization can fire.
/// Below this, the tracker's quorum gate refuses to advance the
/// soft-final tip regardless of vote count.
pub const ROLLING_FINALITY_MIN_QUORUM: usize = 5; // mainnet; testnet may lower
```

`src/constants.rs` is consensus-locked. Changing it triggers `critical-lock.yml` in CI, which requires the change to be signed off (see `.github/workflows/critical-lock.yml`).

### Step 2 — Validation hook

Add to `src/consensus/validation.rs::validate_block` (or the reorg-check path — depends on where forks are evaluated in the current control flow):

```rust
#[cfg(feature = "rolling-finality")]
{
    // CIP-011 gate: at heights >= ROLLING_FINALITY_ACTIVATION_HEIGHT,
    // reject any reorg whose fork-point is at or below the current
    // soft-final height. Below the activation height this branch is a
    // no-op regardless of the feature flag — the height check dominates.
    let current_height = chain.height();
    if current_height >= crate::constants::ROLLING_FINALITY_ACTIVATION_HEIGHT {
        let rf = &chain.rolling_finality;
        if rf.would_reorg_violate_finality(fork_point_height) {
            return Err(Error::ReorgViolatesFinality {
                fork_point: fork_point_height,
                soft_final: rf.current_soft_final_height().unwrap_or(0),
            });
        }
    }
}
```

`src/consensus/validation.rs` is consensus-locked. Same CI gate.

The `chain.rolling_finality` field also needs to be added to `SharedBlockchain` — this is a `RollingFinality` instance that persists across the process, replayed from `chain_tip - WINDOW` on startup per the Phase 3 adapter doc.

### Step 3 — Enable the feature in workspace default

Add `rolling-finality` to the default features in `Cargo.toml`:

```toml
[features]
default = ["randomx", "rolling-finality"]
```

Or ship it as opt-in for a partial testnet-only rollout — governance decision.

### Step 4 — Update `finality.rs` module doc

Update the doc in `src/consensus/finality.rs` to reflect that layer 6 (miner-signed rolling finality) is now consensus-gating. The current doc says "not consensus-gating today" — that becomes false at activation.

## Verification after activation

Once the activation PR is merged and deployed:

1. **First-24h monitoring**:
   - `soft_final_height` should be `None` for the first ~LAG (100) blocks after activation — the tracker needs the initial window
   - After ~1000 blocks post-activation, `soft_final_height = current_height - LAG` should be steady-state
   - No spurious `ReorgViolatesFinality` errors in fleet logs

2. **First-week monitoring**:
   - Any legitimate reorg (chain organic depth < 10) proceeds normally — Nakamoto tier-1 still fires first
   - Any adversarial deep reorg (< soft-final) is rejected — new behavior
   - Miner participation rate stays above `MIN_QUORUM` — otherwise the tracker falls back to "no finalization" gracefully

3. **First-month post-mortem**:
   - Post to Discord / GitHub Discussions: soft-final tip statistics, any observed reorgs, miner participation graph

## Rollback path

If a critical bug is discovered post-activation:

1. **Emergency**: coordinate with fleet miners to freeze block production until a patch ships
2. Set `default = ["randomx"]` (remove `rolling-finality`) in `Cargo.toml`
3. Deploy the patch fleet-wide
4. Community miners follow via the standard release process
5. Publish a coordinated post-mortem

The rollback removes the CIP-011 gate but preserves all attestations already accumulated — a subsequent activation PR could reintroduce the gate at a new height without losing existing miner-key state.

## Cross-references

- CIP: `docs/cip/CIP-009-D-miner-signed-rolling-checkpoints.md` (spec)
- Existing implementation:
  - `crates/coincync-rolling-finality/src/finality.rs` (Phase 1 state machine)
  - `crates/coincync-rolling-finality/src/verifier_ed25519.rs` (Phase 2a verifier)
  - `crates/coincync-rolling-finality/src/codec.rs` (Phase 2b wire format)
  - `src/consensus/rolling_finality.rs` (Phase 3 adapter)
- Existing reorg-defense doc: `src/consensus/finality.rs` (comprehensive layer inventory)
- Related runbooks:
  - `runbook-bootstrap-ceremony.md` (analogous ed25519 key ceremony for peer-snapshot maintainers)
  - `INCIDENT_RUNBOOKS.md` (reorg incident response)
