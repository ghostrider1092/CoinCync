# CIP-009.D production posture at v1.0 genesis: dormant or active

**Date:** 2026-05-23
**Status:** Decided — **Option A (dormant at genesis, CIP-007 activation later)**, see signed block below
**Refers to:** [CIP-009.D — Miner-signed rolling checkpoints](../cip/CIP-009-D-miner-signed-rolling-checkpoints.md), [CIP-009 — Reorg defense decision](../cip/CIP-009-reorg-defense-decision.md), [docs/security/reorg-defense.md](../security/reorg-defense.md)

---

## The question

At v1.0 mainnet genesis (October 1, 2026), does CIP-009.D — the miner-signed rolling-checkpoint construction that defends the live tip beyond the hardcoded checkpoint horizon — ship as:

- **(A) Dormant.** Code compiles in, gated behind a `rolling-finality` cargo feature, **off by default**. No signer set is elected. Genesis-day nodes run with Layers 1-5 of the reorg defense only (3-tier MESS hybrid + per-node rolling checkpoints + hardcoded consensus checkpoints). Layer 6 (CIP-009.D) is activated later via a CIP-007 hard-fork event.

- **(B) Active.** Layer 6 is on at genesis. An initial signer set is elected (5-of-9 or similar threshold) before the chain launches. Genesis block carries the bootstrap signer set. Live-tip protection from minute one.

Either is defensible. This document lays out the tradeoffs so the choice is on the record.

---

## What's already shipped (Layers 1-5)

Reorg defense as of v1.0.9-testnet-pre-audit:

| Layer | What | Status at v1.0 genesis |
| --- | --- | --- |
| 1-3 | 3-tier MESS hybrid (PoW-weight + difficulty-adjustment-aware penalty + max-reorg-depth cap) | Active, shipped pre-v1.0 |
| 4 | Per-node rolling checkpoints (local-only, no consensus impact) | Active |
| 5 | Hardcoded consensus checkpoints (cut by release process) | Active |
| 6 | CIP-009.D miner-signed rolling checkpoints | **THIS DECISION** |

The dormant-vs-active decision is **only about Layer 6.** Layers 1-5 are not at risk; they're battle-tested through testnet and the v1.0.9 hardening pass.

---

## Option A — Dormant at genesis (CIP-007 activation later)

**Mechanism.** Code present, feature-flag `rolling-finality` off in the default v1.0 binaries. The `coincync-rolling-finality` crate is in the workspace but the consensus path doesn't reach it unless the feature is on.

**Activation later** — when the community is ready, a CIP-007 hard-fork sets an activation block N. Pre-N: Layer 6 inactive. Post-N: Layer 6 active, requires signer set agreement (which gets bootstrapped at the CIP-007 event).

### Pros

- **Smaller audit perimeter at v1.0.** The audit firm reviews Layer 6 as documentation + dormant code, not as live consensus logic. Lower-risk engagement, smaller bill, tighter timeline. Real value when we have ~73k LOC already in scope.
- **No need for a genesis-day signer set.** Electing one before launch is a coordination problem — "who are the 9 trustworthy miners?" — that doesn't exist if Layer 6 is dormant.
- **Operator simplicity.** Genesis-day node config has fewer moving parts. Mainnet launch already has many surfaces (DNS, seed nodes, monitoring, faucet retirement, exchange handshakes if any). One fewer is one fewer.
- **The hardcoded-checkpoint horizon (Layer 5) is already substantial defense** for the first months while Layer 6 sits dormant. Release pipeline cuts checkpoints as the chain advances.
- **No "we already had a Layer 6 incident" liability at v1.0.** If Layer 6 has an unknown bug, it surfaces post-CIP-007 activation when the network is already real, not on day 1 when monitoring is still bedding in.

### Cons

- **Live tip is operator-trust-dependent for the dormant window.** Until CIP-007 activates Layer 6, the live tip past the last hardcoded checkpoint is defended only by the MESS hybrid (Layers 1-3). MESS is good but not consensus-final.
- **Release-pipeline single point of failure.** Layer 5 checkpoint cadence is "every X blocks, by the release process." Sick maintainer + holiday + supply-chain incident = checkpoint horizon stalls. This is the operational weakness CIP-009.D was designed to remove.
- **A CIP-007 activation is its own coordination event.** "Pick a block, elect the signer set, deploy the activation client, watch the fork happen" — not trivial. Some networks have lost months over CIP-style activations.
- **Marketing optics.** Genesis-day reorg-defense story is "MESS + checkpoints," not "the full six layers we designed." Audit firm probably won't care; vocal community members will.

### When this option is right

- Audit firm has a heavy schedule and trimming Layer 6 from the engagement saves real weeks.
- Confidence in Layer 6 implementation is high but not "ship-on-genesis" high — we want one more fuzz pass + one more independent review before it carries consensus weight.
- The community for an initial signer set is not yet large or organized enough to elect 9 trustworthy slots.

---

## Option B — Active at genesis

**Mechanism.** v1.0 binaries ship with `rolling-finality` feature on. Genesis block embeds an initial signer set. Signer rotation governed by CIP-009.D §X (signer-rotation rules).

**Bootstrap question:** who are the 9 signers? Three plausible answers:

1. **The maintainer + 8 known testnet operators** (named individuals, public commitments). Lower coordination cost, higher centralization concern at genesis.
2. **9 anonymous opt-ins from testnet, ranked by uptime + block contribution.** Closer to "permissionless" but selects on past behavior, not future commitment.
3. **No initial signers — Layer 6 activates passively when N signers self-elect.** Defers the bootstrap question to the network itself. Risk: signers might not show up; the layer is on but unused.

### Pros

- **Six-layer defense from minute one.** The full reorg-defense story we designed is the story we ship. No CIP-007 activation event to coordinate later.
- **Live tip protection without release-pipeline dependence** from day 1. The operational weakness CIP-009.D was designed to fix is fixed immediately.
- **Stronger audit-prep narrative.** "We designed six layers and shipped six layers" reads better than "we designed six and shipped five, the sixth is dormant" — to non-cryptographers especially.
- **No future activation event = no future coordination risk.** What ships at genesis is what runs.

### Cons

- **Audit perimeter is larger.** Layer 6 IS live consensus logic and the audit firm reviews it as such. More LOC, more findings risk, more bill.
- **Genesis signer-set election is a real coordination problem.** Whichever of (1)-(3) you pick, it's pre-launch coordination on top of everything else genesis needs.
- **Signer set is a centralization vector at genesis.** Even with a 5-of-9 threshold, "who picked these 9?" is a question the project answers with its credibility, not with code. Cypherpunk-purist users will critique.
- **Layer 6 has not been battle-tested under live adversarial conditions** — testnet is honest miners; mainnet has adversarial economic incentives that testnet can't simulate. An unknown Layer 6 bug surfaces at the worst possible time (mainnet day 1).
- **Signer rotation is not yet operationally-rehearsed.** Rotating signers via CIP-009.D §X is documented but not exercised in production. First rotation event has known-unknowns.

### When this option is right

- Audit firm is willing to include Layer 6 in the v1.0 engagement and has the scope-budget for it.
- A credible 9-signer bootstrap is available (named miners + public commitments).
- Confidence in Layer 6 from fuzz + property tests + audit is high enough to carry live mainnet load.

---

## What the implementation looks like either way

**Dormant (A):** the `rolling-finality` cargo feature defaults to **off** in the v1.0 binaries. Code stays in the tree. The audit firm reviews `crates/coincync-rolling-finality/` as documentation + dormant code, mentions it in the report as out-of-scope-for-runtime-but-reviewed-for-design.

**Active (B):** the `rolling-finality` cargo feature defaults to **on** in the v1.0 binaries. Genesis block carries the initial signer set. The audit firm reviews `crates/coincync-rolling-finality/` as live consensus code. Signer-set bootstrap procedure documented in a sibling `docs/launch/GENESIS-SIGNERS.md`.

Either path takes ~1 day of implementation work (a feature-flag toggle + signer-set serialization into the genesis block).

---

## Recommendation (subject to override)

**Lean toward (A) dormant at genesis.**

Three reasons:

1. **Audit-firm engagement is easier to scope cleanly** if Layer 6 isn't live consensus. The October 1, 2026 mainnet timeline is already tight; trimming Layer 6 from the audit window buys real timeline.
2. **The bootstrap signer-set problem is unresolved.** Without a credible answer to "who are the 9?", launching with active Layer 6 forces you to invent the answer under pressure. CIP-007 activation can be a year out, by which point the answer is obvious.
3. **Layer 5 (hardcoded checkpoints) carries genesis-day defense competently** — release-pipeline cadence is a known operational pattern that works for projects like Bitcoin (which has run on a much weaker defense than Layer 5 for 15+ years).

The only scenario where (B) wins decisively is if the audit firm signals they're comfortable including Layer 6 AND a credible 9-signer set is already pre-elected by mid-July 2026. If both happen, switch to (B). If either doesn't, (A) is the safer ship.

---

## Decision

```text
Decision:      A — dormant at genesis
Made on:       2026-05-23
Made by:       ghostrider1092 (maintainer)
Activation date if (A): TBD post-mainnet via CIP-007 (no fixed block-height commitment;
                        revisit when the network is large + organized enough to elect a
                        credible 9-signer set)
Genesis signer set if (B): n/a

Rationale (one paragraph):
The bootstrap signer-set problem is unresolved — there is no credible answer to "who are
the 9?" that survives cypherpunk-purist scrutiny on day 1, and inventing an answer under
pre-launch pressure is the kind of decision that ages badly. Trimming Layer 6 from the
audit firm's October-1 engagement keeps the perimeter cleanly scoped (Layers 1-5 +
the 73k LOC of base-chain code) and saves real timeline. Layer 5 hardcoded checkpoints
carry genesis-day defense competently — Bitcoin has run on much less for 15+ years.
Layer 6 code stays in the tree, gated behind `rolling-finality` off-by-default; the audit
firm reviews it as documentation + dormant code, not as live consensus logic. CIP-007
activation can happen post-mainnet when the signer-set question has an obvious answer.
```

---

## Follow-on work once the decision lands

**If (A):**

- Confirm `default-features = []` in the v1.0 binaries' Cargo.toml call sites for `coincync-rolling-finality`.
- Add a `--features rolling-finality` build path documented in `docs/v1.0-mainnet-audit-prep.md` so the audit firm knows how to exercise the dormant code if they want to.
- File a CIP-007 placeholder for the Layer 6 activation event (target: TBD post-mainnet).
- Update `docs/security/reorg-defense.md` §6 to mark Layer 6 as "designed, not yet active."

**If (B):**

- Resolve the genesis signer-set bootstrap (write `docs/launch/GENESIS-SIGNERS.md` with the 9 entries + public commitment from each).
- Confirm `default-features = ["rolling-finality"]` everywhere relevant.
- Run a fresh `cargo test --features rolling-finality --workspace` and ensure 100% green.
- Add Layer 6 to the audit-prep doc's priority-1 review targets.
- Schedule a signer-rotation rehearsal on testnet before mainnet.
- Update `docs/security/reorg-defense.md` §6 to mark Layer 6 as "active at genesis."
