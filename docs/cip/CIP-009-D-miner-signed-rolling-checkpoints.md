<!-- markdownlint-disable MD036 -->
# CIP-009.D — Miner-signed rolling checkpoints

**Status:** Draft (post-launch activation candidate)
**Type:** Standards Track (consensus rule)
**Created:** 2026-05-08
**Layer:** Consensus
**Depends on:** CIP-007 (activation policy), CIP-009 (Path B already shipped)
**Replaces:** CIP-009.A (MESS), rejected as too risky

---

## Problem

Path B (consensus checkpoints, shipped at commit `45e621d`) gives
us *structural* immutability past hardcoded heights, but it has
two operational weaknesses:

1. **Operator dependency.** Every checkpoint must be cut by the
   project's release process. If a release stalls — sick
   maintainer, holiday, supply-chain incident — the checkpoint
   horizon stops moving forward and the live tip is unprotected.
2. **Trust pipeline.** A determined attacker who compromises the
   release-signing pipeline can poison the checkpoint table.
   Multi-sig release signing helps but doesn't eliminate this.

MESS (Path A) was the canonical answer to "how do you defend the
live tip without an operator." But MESS is:

- **Subjective** — the score depends on local clock readings,
  which are vulnerable to time-warp attacks.
- **Tuneable in a fatal direction** — the decay constant is a
  knob. Wrong knob = wrong defense.
- **Opaque** — a node refuses a reorg because of a continuous
  function nobody can directly read off the chain. Hard to
  explain, hard to audit, hard to debug after a contentious fork.

This CIP specifies a third path: **rolling soft-finality enforced
by signatures from the same miners who produced the chain**. It
sits between B (operator-cut checkpoints) and pure PoW (Path C),
and inherits the upsides of both:

- **Auto-rolling, no operator action.** Soft-final checkpoints
  emerge as miners produce blocks. The protection horizon
  advances at the speed of the chain.
- **Discrete and explicit.** A height is finalized iff a
  threshold-of-miners signature is on-chain. You can read it.
  You can prove it. You can audit it.
- **No tuning knobs that determine security.** The threshold `K`
  and window `W` are parameters, but their wrong-direction
  failure mode is "soft-finality stalls" — i.e., we degrade to
  pure PoW for a window. Compare MESS, where wrong tuning means
  "an attacker beats the rule with a cheaper reorg."

---

## Mechanism

### 1. Miner identity

Each miner generates a long-term ed25519 keypair (the
**finality key**) and commits the pubkey to the chain by
including it in a coinbase tx extra field the first time they
mine a block. Subsequent blocks from the same miner reference
the already-committed key; they do not re-attest it.

```
coinbase.extra: {
    finality_pubkey: [u8; 32],   // first time only
    finality_sig:    Signature,  // every block, post-activation
    sig_target_height: u64,      // height being attested to
    sig_target_hash:   [u8; 32], // hash being attested to
}
```

The finality key is **not** the miner's wallet key, payout key,
or stealth-address key. It exists solely to attest to chain
state. Miners can rotate it (see §6).

### 2. Active miner set

The **active miner set** at height `H` is the set of distinct
finality pubkeys that have produced at least one block within
the window `[H - W, H)`, where `W = 10 000` blocks (~14 days at
120s).

Why the window: a miner who has been offline for >2 weeks should
not get a vote on what the live chain is. Their block count is
stale.

Why blocks-not-time as the window unit: the chain's notion of
time is the chain itself. Wall-clock-based windowing reintroduces
MESS's clock-skew vulnerabilities.

### 3. Per-block attestation

Every block produced post-activation carries a signature over
`(sig_target_height, sig_target_hash)` from the producing
miner's finality key. The signed target is a fixed offset
behind the producing block:

```
sig_target_height = block_height - LAG
LAG = 100 blocks (matches MIN_OUTPUT_AGE)
```

Why LAG=100: it's the same horizon CoinCync already enforces
for output-spendability. Reusing it means soft-finality and
output-finality move together — no second mental model.

`sig_target_hash` MUST be the hash of the block at
`sig_target_height` on the chain the miner is extending.
Miners on different forks at sig_target_height naturally sign
different hashes, which is exactly the mechanism that makes
this work.

### 4. Soft-finality threshold

A height `H` becomes **soft-final** when:

```
distinct_signers(H) >= K
where K = ceil(2/3 * |active_miner_set(H)|)
      and |active_miner_set(H)| >= MIN_QUORUM
      MIN_QUORUM = 5
```

`distinct_signers(H)` counts unique finality pubkeys that have
signed `(H, hash)` for the canonical chain's `hash` at H, where
the signatures appear in ANY block at heights `(H, H + LAG + W]`.

Why 2/3: it's the standard Byzantine threshold. A 1/3 attacker
cannot finalize an attack chain; a 2/3 honest majority can
finalize the canonical chain. Below 2/3 we don't finalize,
which means we degrade to pure PoW + Path B for that height.

Why MIN_QUORUM=5: with fewer than 5 active miners, finality is
meaningless — a single mining pool's collusion can fake it. We
intentionally do not soft-finalize when the miner set is too
sparse. This matters at network bootstrap.

### 5. Reorg rule

A node MUST reject any reorg whose proposed alt-chain diverges
from the canonical chain at any soft-final height. Compare the
existing Path B rule (reject reorgs past hardcoded checkpoints);
this is the same idea, with the checkpoint table dynamically
populated by §4.

In code (sketch):

```rust
fn validate_reorg(canonical: &Chain, alt: &Chain) -> Result<()> {
    let fork_height = canonical.fork_point(alt);
    if let Some(soft_final_height) = canonical.soft_final_tip() {
        if fork_height <= soft_final_height {
            return Err(Reorg::PastSoftFinality {
                fork_height,
                soft_final_height,
            });
        }
    }
    // existing rules: PoW score, Path B checkpoint table, ...
    Ok(())
}
```

Soft-final heights stack: the validator's `soft_final_tip()`
just returns the largest height that meets §4. Older soft-final
heights are implicitly enforced by the >= comparison.

### 6. Key rotation

Miners can rotate finality keys by including a special coinbase
field:

```
finality_pubkey_rotation: {
    old_pubkey: [u8; 32],
    new_pubkey: [u8; 32],
    sig_by_old: Signature,    // proves possession of old
    sig_by_new: Signature,    // proves possession of new
}
```

After rotation:
- The new key replaces the old in the active-set lookup as of
  the rotation block's height.
- Outstanding signatures by the old key remain valid for
  finality calculations (so a rotation doesn't retroactively
  invalidate past attestations).
- The old key is **dead** for new attestations — any post-
  rotation block signed by the old key is rejected.

This is the standard ed25519-with-rotation pattern. Same model
as SSH host-key rotation.

### 7. Loss / inactivity handling

A miner who stops producing blocks for `>W` falls out of the
active-set. They do not need to do anything to "rejoin" — the
next block they mine puts them back in. There is no slashing or
penalty; missing finality contribution is its own cost (their
share of block reward going forward — they still mine
normally).

A miner who *intentionally* refuses to sign post-activation
makes their blocks invalid. This is structurally how the rule
forces participation: you cannot mine post-activation without
contributing to soft-finality.

---

## Activation

CIP-007 Mode A, scheduled at a future height `H_activate` with
at least 6 months of testnet exposure. Pre-activation:

- Blocks may but need not include `finality_*` fields.
- Soft-finality computation is disabled.
- Path B (hardcoded checkpoints) is the only finality rule.

At `H_activate`:

- Blocks at `height >= H_activate` MUST include valid
  `finality_*` fields. Validators reject blocks missing them.
- Soft-finality computation begins. The first soft-final height
  is the first `H` past `H_activate + LAG` for which §4 holds.
- Path B continues to apply. Both rules layered: a reorg must
  beat Path B AND soft-finality.

A "grace period" alternative was considered (allow a few thousand
blocks where finality_* is optional) and rejected: the grace
window is exactly when an attacker would try to game the
new rule, and an optional field is not a rule.

---

## Failure modes and mitigations

### Concentrated mining

If three pools control 80% of hashpower, they also control 80% of
the active miner set. They can cartel-finalize an attack chain by
coordinating signatures.

**Mitigation:** weight by **number of finality keys**, not by
hashpower share. Each miner gets one vote regardless of how many
blocks they produce. A pool that wants to fake more votes must
register more keys, and each key requires a real coinbase
attestation — which costs the pool a block reward to set up.

**Residual risk:** a determined adversary still pays the cost
to register `N` sybil keys. We accept this; the bar is "honest
majority of distinct miners," same as Bitcoin's "honest majority
of hashpower" assumption. The privacy-coin analog is "an
honest-majority assumption is unavoidable; what changes is what
the majority is OF."

### All miners refuse to sign

The chain still advances under pure PoW + Path B. Soft-finality
stalls. This is the *good* failure mode: degradation, not
catastrophe.

### Quorum loss (active set drops below MIN_QUORUM)

Soft-finality stalls. Node operators are alerted (a metric).
If the situation persists, a manual Path B checkpoint can fill
the gap; this is exactly what Path B is for.

### Late-signed reorg attack

An attacker mines a private chain, then publishes both blocks
AND finality signatures simultaneously. To finalize, they need
2/3 of the active miner set to also sign their chain — which by
construction they don't have, because the active set is the
public canonical chain's miners.

The only way this attack works is if the attacker IS 2/3 of the
miner set, in which case the attack is the legitimate canonical
chain by every definition we have.

### Time-warp attacks

The rule is stated entirely in block-height terms. There are
no clock readings. Time-warp is structurally impossible.
This is the largest single advantage over MESS.

---

## Implementation cost

| Area | Estimate |
|---|---|
| Coinbase serialization extension | 1 day |
| Active-set tracker in chain state | 2 days |
| Per-block sig verification + caching | 2 days |
| Soft-finality watermark | 1 day |
| Reorg-rule integration in validator | 1 day |
| Key-rotation message handler | 1 day |
| Wallet / coincync-rig signing support | 2 days |
| Testnet activation rehearsal | 1 day |
| Property tests + fuzz target | 2 days |
| Total | **~13 days** of focused work |

Plus the activation window itself (6+ months on testnet before
mainnet height-trigger), per CIP-007's risk policy for
consensus-changing CIPs.

---

## Comparison with other paths

| | A (MESS) | B (checkpoints) | C (PoW only) | **D (rolling)** |
|---|---|---|---|---|
| Operator dependency | none | high | none | none |
| Live-tip protection | yes (decay) | no (lag) | no | yes (LAG=100) |
| Tuning sensitivity | catastrophic | n/a | n/a | graceful |
| Auditability | low | high | high | high |
| Time-warp risk | yes | no | no | no |
| LOC of new consensus | 600-800 | 150 (shipped) | 0 | 400-600 |
| Layered with B? | yes | self | self | yes |

D dominates A on every axis except total LOC. D dominates C on
live-tip protection. D + B together cover the corner cases of
each individually:

- **B**: catches anything past `H_release - 14 days`.
- **D**: catches anything past `tip - LAG` once quorum holds.
- **B + D**: continuous protection from operator-cut + miner-cut
  finality, with B as the floor when miner participation drops
  and D as the ceiling for live operations.

---

## Open questions (for the testnet rehearsal phase)

1. **Should LAG be tunable per-fork?** A privacy-vs-finality
   tradeoff: shorter LAG means faster finality but a smaller
   reorg-resistance horizon. Default 100; revisit after testnet.

2. **Should W be coupled to MIN_OUTPUT_AGE?** Currently
   independent. Coupling them would simplify the mental model
   ("the active set is everyone who could still spend a recent
   coinbase") but couples two policies that may want to evolve
   separately.

3. **Should soft-final heights be permanent or sliding?**
   Currently permanent (once finalized, always finalized).
   Sliding ("only the most recent N soft-final heights are
   enforced") would help if the rule turns out to be
   over-eager. Permanent is safer; sliding is reversible. Lean
   permanent.

4. **Coinbase extra field budget.** 32B pubkey + 64B sig +
   8B target_height + 32B target_hash = 136B per block,
   forever. Compare 80B current. ~70% increase in coinbase
   metadata. Manageable but worth flagging in block-size
   analysis.

5. **Genesis-bootstrap.** The first `MIN_QUORUM` distinct
   miners get unconditional founding-set rights. Is that ok
   for our network? Yes for testnet; for mainnet we might
   pre-seed the active set in genesis with the project-known
   bootstrap miners.

---

## Why this isn't PoS

It looks like PoS-style finality (committee signs, finalizes),
but it isn't:

- **Voting weight is hashpower.** You only join the active set
  by mining a block (which costs work).
- **No staking.** No collateral, no slashing, no withdrawal
  delays, no bonded participation.
- **Sybil-resistance is identical to Bitcoin's.** The
  marginal cost of a fake miner is one block's worth of work.
- **The rule is a finality layer on top of PoW**, not a
  consensus replacement. PoW still picks blocks. Finality
  just refuses to roll them back.

Casper FFG is structurally similar but assumes a stake-bonded
validator set. We don't have one and don't want one.

---

## Decision (for the user)

Same shape as CIP-009:

- ☐ **Approve D for post-launch activation track.** Implementation
  begins after mainnet ships and the testnet has been live for
  ≥6 months. Activation height set at ≥18 months post-mainnet.
- ☐ **Defer.** Path B alone is enough; revisit if a real
  reorg-defense incident shows up.
- ☐ **Reject.** Stay on Path B + Path C only.

If approved: implementation goes into a dedicated branch, lands
behind a feature flag, gets rehearsed on testnet for the full
6-month window, then activated via CIP-007 Mode A.

---

## Out of scope

- **Slashing.** Miners who sign conflicting chains are not
  punished. The rule is purely additive — soft-finality only
  makes things refuse-to-reorg, never refuse-to-mine. Slashing
  introduces stake economics; we explicitly aren't going there.
- **Cross-chain finality.** This rule applies only to CoinCync's
  own chain. Bridge / atomic-swap finality are app-layer.
- **Light-client proofs of finality.** Eventual work; the
  signatures themselves are amenable to a SNARK-compressed
  finality proof for light clients, but that's CIP-016+.
