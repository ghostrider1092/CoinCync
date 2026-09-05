# WP-008 · Miner-Signed Rolling Checkpoints
### Soft finality, and how to build a consensus change without touching consensus

**Status:** **Gated** — feature `rolling-finality`, off by default; the consensus
hook is deliberately not wired · **Layer:** Consensus · **Series:**
[CoinCync Whitepapers](README.md)

---

## 1. Motivation

Proof-of-work gives probabilistic finality: a block is *probably* permanent, more
so with each confirmation. For a young chain with modest hashrate, "probably" is
thin. An attacker who can rent more hashrate than the network produces can rewrite
recent history, and the honest chain has no way to say "we already agreed on
this."

Hardcoded checkpoints answer that, badly: they require a release to move, they
centralise the decision in whoever ships the binary, and they cannot protect the
last hour — which is exactly the window a double-spend targets.

Rolling checkpoints let the *miners* — the parties whose work defines the chain —
continuously attest to what they have seen, giving soft finality that advances
with the tip and needs no release.

---

## 2. Threat addressed

| Attack | Assumption it needs | What we removed |
|---|---|---|
| **Deep reorg by rented hashrate** | Only accumulated work decides history | An attested prefix that honest nodes will not abandon |
| **Release-cadence finality** — protection only as recent as the last binary | Checkpoints ship in code | Attestations ride in blocks and advance continuously |
| **Attestation forgery** | Anyone can vote | Ed25519 signatures over a canonical anchor payload |
| **Sybil attestation** — spin up identities and out-vote the honest set | Any signer counts | `ActiveMinerSet` — only miners who have actually produced blocks count |
| **Instant-sybil** — mine one block, then attest to a fabricated past | An active miner's attestations count immediately | Attestations count only ≈`LAG` blocks after the miner's first block (§3.4) |

---

## 3. Design

### 3.1 Attestations in coinbase `extra`

Miners sign a canonical anchor payload and publish the attestation inside the
**coinbase `extra`** field of blocks they mine. The P2P layer carries the request
("sign the canonical anchor payload") and the Ed25519 signature response.

Riding in `extra` means attestations need no new block field and no structural
change — the same backwards-compatibility property the dead-man's-switch metadata
relies on (WP-015 §3.1). A `find_attestation` helper scans the coinbase `extra`
bytes for the wire magic and extracts the sub-slice, or reports there is none.

### 3.2 The tracker

The mechanism is a `FinalityTracker` state machine (with an `Ed25519Verifier` and
a wire codec) shipped as its own crate, wrapped by a thin consensus-layer adapter
exposing exactly two queries the node needs:

- the **reorg-rule check** — may this reorg be accepted?
- the **soft-final-height readout** — how far is finality established?

### 3.3 No persistence, by design

The tracker does not persist. On restart it is **rebuilt by replaying accepted
blocks** from `chain_tip − WINDOW` forward.

This is a deliberate simplification with a real payoff: `on_accepted_block` is
both the live-path primitive *and* the replay primitive, so there is exactly one
code path that advances tracker state. There is no separate restore routine to
drift out of agreement with the live path — the failure shape WP-006 §4.4
catalogues. Rebuild cost is bounded by the window.

### 3.4 The `ActiveMinerSet` and its natural lag

Only miners who have demonstrably produced blocks can have their attestations
counted. A consequence falls out of the design without needing a special rule:

A miner's `first_seen_height` is recorded when they first produce a block. Their
early attestations carry `target_height` values *before* that — so `is_active`
returns false for them, and those attestations do not count. In effect a miner's
voice activates roughly `LAG` blocks after their first block.

This is exactly the right behaviour, and it is worth noting that it emerged from
the structure rather than being bolted on: an attacker cannot mine one block and
immediately attest to a fabricated past, because their attestations only begin
counting after they have sustained participation.

### 3.5 Ordering invariant

Inside `on_accepted_block`, `record_block` is called **before**
`apply_attestation`. The reason is precise: `record_block` advances the tracker's
`chain_tip`, and `apply_attestation`'s future-target check
(`target_height <= chain_tip`) and its stale-pruning both depend on the tip being
current for the block being processed.

Semantically: *the block joins the chain first; the attestation it carries is then
evaluated against that updated chain state.* Reversing the order would evaluate an
attestation against a stale tip, rejecting valid attestations for the very block
that carries them.

### 3.6 Gated on purpose — and what the gate buys

The module is behind the `rolling-finality` Cargo feature, **off by default**.
With the feature off, the module does not compile in, the dependency is not
pulled, and node behaviour is **byte-identical** to a build without the file.

Three things are deliberately *not* done:

| Not done | Why |
|---|---|
| Wiring the reorg rule into `validate_block` | `src/consensus/validation.rs` is hash-locked (WP-007); the hook lands only after the CIP-011 activation decision |
| Defining activation heights | `ROLLING_FINALITY_*` constants belong in `src/constants.rs`, also hash-locked |
| Persisting tracker state | Replay is the single path (§3.3) |

This is the pattern worth generalising. **A consensus change was built, reviewed
and tested in full without touching a single consensus-locked file.** The adapter
provides the query; the hook that calls it is a separate, later, deliberate
commit. The hash lock (WP-007) is what forces this discipline, and the discipline
is what makes a consensus change reviewable as a small diff rather than as a large
one where the risky part hides among the plumbing.

The adapter is height-agnostic: the *caller* uses activation heights to decide
when to invoke it.

---

## 4. Security analysis

**What holds today.** Nothing — and that is the accurate statement. The feature is
off by default and the reorg hook is unwired, so rolling finality currently
provides **no protection on any live network**. Reorg defense today is entirely
WP-005 (MESS tiers, finality floor, hardcoded checkpoints).

**What it will hold once activated.** An attested prefix that honest nodes refuse
to abandon, signed by miners who have demonstrated participation, advancing
continuously with the tip.

**What it will not protect against, even then.**

- **A majority of the active miner set.** Miner-signed finality is secured by
  miners. An attacker who *is* the majority of the active set attests to whatever
  they like. This shifts the trust from "most hashrate now" to "most hashrate over
  the attestation window," which is a real improvement and not a different
  security model.
- **Liveness risk.** A finality rule that refuses reorgs can, if attestations
  stall or partition, refuse a legitimate reorganisation and split the network.
  This is the classic soft-finality failure mode and the main reason activation is
  gated behind an explicit decision rather than shipped on.
- **Key compromise.** A miner's Ed25519 signing key is a new secret with new
  handling requirements.
- **The window is a bound.** Soft finality covers `WINDOW` blocks; older history
  relies on hardcoded checkpoints and accumulated work.

---

## 5. Implementation

| Component | Location | Status |
|---|---|---|
| `FinalityTracker`, `Ed25519Verifier`, wire codec | `coincync-rolling-finality` crate | Built |
| Consensus adapter, `on_accepted_block`, `find_attestation` | `src/consensus/rolling_finality.rs` | Built, gated |
| Chain-side handle (`rolling_finality: Option<Arc<…>>`) | `src/chain.rs` | Present, dormant (`None`) |
| Anchor sign request / signature response | `src/network/protocol.rs` | Present |
| Reorg-rule hook in `validate_block` | — | **Not wired (intentional)** |
| `ROLLING_FINALITY_*` activation heights | — | **Not defined (intentional)** |
| Current reorg defense | `src/consensus/finality.rs`, `src/constants.rs` | Live (WP-005) |

**Specifications.** CIP-009.D (the rolling soft-finality rule), CIP-011 (the
integration and activation plan).

---

## 6. Known limits

- **Dormant.** Provides no protection until activated (§4).
- Activation is a hard fork requiring an operator rollout.
- Liveness/safety trade needs analysis against partition scenarios before
  activation.
- Miner signing-key management is an unaddressed operational surface.
- No live multi-miner test of the attestation flow.

---

## 7. References

- CIP-009.D, CIP-011 — the CoinCync improvement proposals defining the rule and
  its activation.
- Bitcoin's `assumevalid` and hardcoded checkpoints — the release-cadence approach
  §1 argues against.
- Grin/Ethereum finality-gadget literature — soft-finality liveness/safety trades.
- Internal: [WP-005 Reorg defense](WP-005-layered-reorg-defense.md),
  [WP-007 Hash lock](WP-007-critical-files-hash-lock.md),
  [WP-006 §4.4](WP-006-cumulative-work-determinism.md),
  [WP-017 §3.6](WP-017-light-wallet-sync.md).
