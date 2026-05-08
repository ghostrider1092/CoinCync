<!-- markdownlint-disable MD036 -->
# CIP-007 — Hard-Fork Activation Policy

**Status:** Sketch (pre-Draft)
**Type:** Standards Track (consensus governance)
**Created:** 2026-05-08
**Layer:** Consensus governance / coordination protocol
**Depends on:** None

---

## Abstract

Specify the procedure CoinCync uses to activate consensus-breaking
changes. Other CIPs (CIP-001 atomic swaps, CIP-003 cut-through, CIP-004
kernel offsets, CIP-005 Spark, plus the pending `BOOTSTRAP_MIN_RING_SIZE`
bump from 11 to 13) all imply consensus changes that need coordinated
activation. Without a written policy, each one becomes an ad-hoc
negotiation about *when* and *how*. This CIP fixes the mechanism so
future CIPs only have to specify the *what*.

Two activation modes are defined:

1. **Static-height activation** — the simple case. A future block height
   is hardcoded into a release; nodes either upgrade by that height or
   fall behind. Used when network coordination is high (single-operator
   testnet, single-team mainnet pre-public).
2. **Signal-then-activate** — BIP8-style version-bit signaling with a
   "must signal" deadline. Used post-mainnet when the network is broad
   enough that asking miners to coordinate is meaningful.

---

## Motivation

The 2026-05-07 senior review surfaced a concrete blocker:
`BOOTSTRAP_MIN_RING_SIZE = 11` is enforced by the validator
(`src/consensus/validation.rs`). Raising it to 13 is a real privacy win
(1/13 vs 1/11 per-input traceability) but the constant change today
forks the testnet at the next block. There's no written rule for "how
do we ship a constant change like this?" — every chain needs one before
it has its first contentious upgrade.

CoinCync's constitutional structure already encodes most of the answer
informally: the supply cap is immutable (Article I), other params can
move via constitutional amendment. This CIP turns "amend by some
process" into a specific procedure.

---

## Static-height activation (Mode A)

Used when the upgrade is uncontentious or operator-coordinated. Mainnet
pre-launch upgrades, scheduled testnet bumps, and parameter changes
that ALL nodes are expected to track go through this mode.

### Procedure

1. **Source change.** A future-dated activation height is added to
   `src/constants.rs` as a named constant, e.g.:

   ```rust
   /// Activation height for BOOTSTRAP_MIN_RING_SIZE V2 (raise 11 → 13).
   /// CIP-007-A1.
   #[cfg(feature = "testnet")]
   pub const RING_BUMP_V2_ACTIVATION_HEIGHT: u64 = 12_000;
   #[cfg(not(feature = "testnet"))]
   pub const RING_BUMP_V2_ACTIVATION_HEIGHT: u64 = 175_000;
   ```

2. **Validator gate.** The consensus rule reads the activation height
   and applies the new rule at and after that height; older rule
   before. Both rules MUST be runnable from a single binary so a node
   can validate the entire chain history without re-binary swaps.

   ```rust
   let min_ring = if height >= RING_BUMP_V2_ACTIVATION_HEIGHT {
       BOOTSTRAP_MIN_RING_SIZE_V2  // 13
   } else {
       BOOTSTRAP_MIN_RING_SIZE     // 11 (legacy)
   };
   if input.ring_members.len() < min_ring { return Err(...) }
   ```

3. **Wallet gate.** Wallets building txs at height H consult the same
   helper to know what ring size to construct. Existing wallet helper
   `effective_ring_size(height, available_outputs)` already encodes
   the height-dependent rule and just needs the new minimum value
   wired in.

4. **Release lead time.** The activation height MUST be at least
   **2,016 blocks** (~2.8 days at 120s blocks) past the release date,
   to give every node operator time to upgrade. Mainnet hard forks
   should target 30+ days lead time. Operators who don't upgrade by
   activation height fall onto the old chain and self-isolate — the
   network rule is the protection.

5. **Documentation requirement.** Every static-height activation MUST
   appear in:
   - `docs/cip/CIP-NNN-<name>.md` (the change itself)
   - `CHANGELOG.md` (release notes for the binary that introduces it)
   - `src/constants.rs` (the activation-height constant, with the
     CIP number in the doc-comment)

### Suitability

Use Mode A when:

- The change is operator-driven (testnet during bring-up).
- The change is editorial (parameter tightening — ring size, fee
  floors, output-age rules).
- There is no plausible "vote" to be had — the change is either
  obviously correct or it isn't.

Don't use Mode A for:

- Changes that introduce or remove privacy features (those affect
  user trust and warrant signaling — see Mode B).
- Changes where reasonable operators might decline to upgrade
  (contentious forks).

---

## Signal-then-activate (Mode B)

Used when the network is broad enough that miner readiness is a real
signal worth observing. Post-mainnet, post-listing, anything where
"the operator just decided" isn't sufficient legitimacy.

### Procedure

CoinCync uses a simplified BIP8 model:

1. **Version-bit allocation.** Each Mode B activation gets a bit in
   the block header's `version` field (currently `u32`). Bit 0 is
   reserved for the "always-set" indicator; bits 1-31 are
   per-activation. CIP authors propose a bit number; if free, that
   bit is theirs for the duration of the signaling window.

2. **Signaling window.** A `start_height` and `timeout_height` are
   set, separated by at least 8,064 blocks (~11 days at 120s).

3. **Signaling counter.** During the window, the validator counts how
   many blocks in each rolling 2,016-block period set the proposed
   bit.

   - **Locked-in:** as soon as ≥1,613 of any rolling 2,016-block
     window (80%) signal, the activation is "locked in" — guaranteed
     to occur at `lockin_height + 2,016` blocks.
   - **Mandatory activation:** if `timeout_height` is reached
     without lock-in, the rule activates anyway at the next block.
     This is the BIP8 "must-signal" semantic — preserves the chain
     from indefinite limbo.

4. **Activation.** From `activation_height` onward, the new rule is
   enforced as if it were a Mode A static activation. The `version`
   bit is freed and may be reused after a 2,016-block cool-off.

### Suitability

Use Mode B when:

- The change adds a new privacy feature (CIP-004 kernel offsets,
  CIP-005 Spark) — operators should have time to review before
  shipping.
- The change is contentious (a vocal minority opposes it).
- Auditing depends on miner participation (e.g., a new opcode that
  only miners can produce).

---

## Anti-modes (what we don't do)

CoinCync deliberately does NOT support:

- **On-chain governance voting by token holders.** Stake-weighted
  governance privileges large holders and creates a market for
  rule-changes-as-a-service. Any vote is off-chain.
- **Optional rules.** Either every honest node enforces a rule or
  no honest node does. The `--testnet` / `--mainnet` split is the
  only acceptable bimodal.
- **Soft-forks that aren't preceded by a CIP.** Even an "obvious
  bugfix" goes through CIP review. Post-incident hotfixes that
  bypass this MUST be documented in `KNOWN_ISSUES.md` with a
  retroactive CIP within 7 days.

---

## Implementation

This CIP is not itself a consensus change. The validator code
described in the Mode A `validator gate` example above lands as part
of the FIRST Mode A activation (probably the BOOTSTRAP_MIN_RING_SIZE
bump). Until then this document is a sketch.

The Mode B counter implementation is also deferred until the first
contentious change that warrants it. Mainnet launch (October 2026)
ships with Mode A only; Mode B follows when the network meets the
"broad enough that operator coordination is meaningful" threshold,
roughly: third-party wallets exist that aren't run by the project,
miners exist who have never met the project team, exchanges have
listings whose policies depend on the consensus rules being stable.

Reference activation skeletons (under `pub fn is_activated(name: &str,
height: u64) -> bool`) live alongside the constants in `src/constants.rs`
once the first activation lands.

---

## Pending Mode A activations (queued)

These CIPs / changes are waiting for the first Mode A release window:

- **`BOOTSTRAP_MIN_RING_SIZE_V2`** — bump 11 → 13. Privacy
  improvement noted in 2026-05-07 senior review (Item 2). Activation
  height: testnet 12,000 / mainnet 175,000 (~tentative; see release
  CIP-008 when scheduled).
- **CIP-001 atomic swap** — the testnet activation already exists at
  block 0 (compile-time activation); mainnet will be Mode A static at
  the launch height per Constitution Article XIV.
- **CIP-003 cut-through and block-level aggregation** — Mode B target
  post-mainnet.
- **CIP-004 kernel offsets** — Mode B, depends on CIP-003.
- **CIP-005 Lelantus Spark** — Mode B, post-mainnet.

---

## Rationale

This is the simplest mechanism that accommodates both "operator
coordination" (today) and "network coordination" (tomorrow). Bitcoin's
BIP8 has been battle-tested and we copy the parts that work
(version-bit signaling with mandatory activation deadline) while
omitting the parts we don't need yet (UASF tooling, signaling client
visualizations).

Static-height activation is what most networks actually use for the
first ~2 years. Premature investment in BIP9-style signaling
infrastructure is overhead for a chain whose mainnet hasn't launched
yet. We ship it when it's needed, not before.

---

## Future work

- Implement the activation-height table + `is_activated(name, height)`
  helper as part of the first Mode A activation.
- Implement the version-bit counter when the first Mode B activation
  is queued.
- Add a `coincync-node activation-status` CLI command that reads the
  chain and reports which activations are locked in, signaling, etc.
- Cross-reference activations from the Constitution. The Constitution
  is the contract; CIPs are the procedure for amending it.
