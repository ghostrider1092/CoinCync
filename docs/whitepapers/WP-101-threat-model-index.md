# WP-101 · Threat Model Index
### Which adversary each mechanism defeats, and what state it is actually in

**Status:** Living · **Layer:** Cross-cutting · **Series:** [CoinCync Whitepapers](README.md)

---

## 1. What this is, and what it is not

[`docs/THREAT_MODEL.md`](../THREAT_MODEL.md) is the authoritative threat model: it
defines the trust model, names four adversary classes, and states the explicit
non-defenses. **Read that first.** This paper does not restate it.

This is the **index between that document and the code**. For each adversary
class it lists the mechanisms that stand against it, the paper describing each
one, and — the part that is easy to get wrong and easy to fake — **the state each
mechanism is actually in.**

The reason this exists as a separate document: a threat model naturally reads as
a list of things that protect you. Some of the entries below **do not protect
anyone yet**. A reader who cannot tell those apart at a glance has been misled by
a document that is individually accurate in every sentence.

### Status vocabulary

| Label | Meaning |
|---|---|
| **Shipped** | Active in consensus or the default build, covered by tests |
| **Gated** | Implemented, behind a non-default feature flag or disabled on a network |
| **Partial** | Core is live; a load-bearing piece is missing |
| **Placeholder** | Scaffolding exists; the mechanism does not |

---

## 2. Class A — chain-only adversary

*Reads every confirmed block. Cannot observe the network or run your wallet.*

| Mechanism | Paper | Status |
|---|---|---|
| Ring signatures (CLSAG), fixed ring size 16 | [WP-011](WP-011-transaction-uniformity.md) §3.1 | Shipped |
| Confidential amounts (RingCT + Bulletproofs+) | — (inherited; see WP-000) | Shipped |
| Stealth addresses — one-time output keys | — (inherited) | Shipped |
| Uniform transaction shape (exactly 2-in / 2-or-3-out) | [WP-011](WP-011-transaction-uniformity.md) §3.2 | Shipped — consensus-enforced |
| Decoy selection: gamma sampling, generation awareness, poison exclusion | [WP-010](WP-010-decoy-selection.md) | Shipped |
| Encrypted memos, padded to a fixed cap | [WP-014](WP-014-encrypted-memos.md) | Shipped — **padding is wallet convention, not consensus** |
| Auto-churn with Poisson intervals | [WP-015](WP-015-deadmans-switch-and-churn.md) §4 | Shipped (opt-in, off by default) |
| Subaddresses — unlinkable receive addresses | [WP-016](WP-016-subaddresses.md) | **Gated** — mainnet-disabled; received funds unspendable (W-1) |
| Dust quarantine — unsolicited outputs never auto-spent | [WP-018](WP-018-dust-quarantine.md) | **Partial** — core live, no CLI surface |
| Supply auditability — header-bound cumulative supply | [WP-002](WP-002-supply-auditability.md) | Shipped (genesis-active) |

**Weakest points against Class A.** Memo padding is honoured by our wallet, not
compelled by consensus — a modified wallet self-identifies its user
(WP-014 §4). Subaddresses are off on mainnet. Dust quarantine has no way for a
user to release a quarantined output yet.

---

## 3. Class B — network-observing adversary

*Sees P2P packets. ISP, Sybil peer cluster, DPI appliance.*

| Mechanism | Paper | Status |
|---|---|---|
| Dandelion++ stem/fluff origination privacy | [WP-020](WP-020-dandelion.md) | Shipped — **verified against the implementation 2026-09-04** |
| Exponential embargo timers (memoryless) | [WP-020](WP-020-dandelion.md) §3.4 | Shipped |
| Randomised stem-forward delay (mean 5 s) | [WP-020](WP-020-dandelion.md) §3.5 | Shipped |
| Wire size normalisation — 9-rung ladder, enforced on receipt | [WP-011](WP-011-transaction-uniformity.md) §3.4–3.5, [WP-012](WP-012-traffic-shaping.md) | Shipped |
| Timing jitter (0–200 ms) | [WP-012](WP-012-traffic-shaping.md) §3.3 | Shipped |
| Constant-rate cover traffic | [WP-012](WP-012-traffic-shaping.md) §3.1 | Shipped |
| Canonical user-agent (`/coincync/`) | [WP-011](WP-011-transaction-uniformity.md) §3.6 | **Placeholder** — policy defined, **not wired to the handshake** |
| Tor / onion transport | node CLI (`--tor`, `--onion-only`, `--proxy`) | Shipped |
| Netgroup-aware peer eviction | [WP-022](WP-022-relative-peer-eviction.md) | Shipped |
| Network-adjusted time (clock-skew self-isolation) | — (audit M-4) | Shipped — outbound-sampled only |

**Weakest points against Class B.** The canonical user-agent is specified but
unwired, so node build strings remain a re-identification handle. No mechanism
here has been evaluated against a real traffic classifier — WP-012 §4 says so
explicitly, and that gap applies to the whole row group.

---

## 4. Class C — chain + network adversary

*Both of the above. State actor, or analytics firm partnered with an ISP.*

Class C is not defeated by adding A's and B's defenses together, and this is the
section most likely to be over-claimed.

| Concern | Paper | Status |
|---|---|---|
| Feature composition — how the layers interact without eating each other | [WP-009](WP-009-privacy-feature-composition.md) | Shipped (2 gated exceptions) |
| Ordered propagation stack (who-first → size → timing → presence) | [WP-009](WP-009-privacy-feature-composition.md) §3.8 | Shipped |
| Transparency special-cases handled in *every* reader | [WP-017](WP-017-light-wallet-sync.md) §3.5 | Shipped (was a real bug) |
| Builder's filter ⊇ verifier's rules | [WP-010](WP-010-decoy-selection.md), [WP-009](WP-009-privacy-feature-composition.md) §3.2 | Shipped (was a real bug) |

**Honest position.** WP-009 §5 states it plainly: composition correctness is not a
privacy proof. We removed the collisions we found; the claim that none remain is
exactly the claim we could not have made about any of them beforehand. Against a
true global passive adversary, WP-012 §4 and WP-020 §4 both concede the limit —
Dandelion++ is designed against a *partial* adversary, and traffic shaping raises
cost rather than defeating end-to-end correlation. Tor/I2P transport is the
answer offered for this class, not our own mechanisms.

---

## 5. Class D — coercion / key-extraction adversary

*"Open the wallet or you're arrested."*

| Mechanism | Paper | Status |
|---|---|---|
| Selective disclosure proofs (balance / ownership / sum / source) | [WP-013](WP-013-selective-disclosure.md) | Shipped |
| Chain-anchored verification (`ChainAnchor` / `AnchorVerdict`) | [WP-013](WP-013-selective-disclosure.md) §3.3 | Shipped |
| Forward-secret `ViewKey` scopes | [WP-013](WP-013-selective-disclosure.md) §3.6 | Shipped — enforcement is **in-process only** |
| `ScopedViewKey` height range | [WP-013](WP-013-selective-disclosure.md) §3.6 | Shipped — **NOT cryptographically scoped** |
| Deniable wallets | — | **Placeholder** — not wired (see wiring map) |
| Dead-man's switch recovery | [WP-015](WP-015-deadmans-switch-and-churn.md) | **Placeholder** — metadata validates; **no spend path exists** |

**The two entries a reader must not misread.** A `ScopedViewKey` hands over the
**full view secret** — the height range is enforced by a cooperating scanner, not
by cryptography, so an adversarial recipient sees everything. And the dead-man's
switch **does not work**: a user can configure it, the CLI reports success, the
metadata goes on chain and validates, and the recovery address still cannot spend
anything, because `is_recovery_eligible` has no consensus caller. Both are
recorded in full in their papers. Against a coercion adversary, the sound
primitives are the §3.1 disclosure proofs — those are cryptographic.

---

## 6. Chain-integrity adversary (not a privacy class)

Not in `THREAT_MODEL.md`'s four classes, because it attacks the ledger rather
than the user. Included because a privacy chain that loses consensus integrity
protects nobody.

| Mechanism | Paper | Status |
|---|---|---|
| Difficulty stability — dual-anchor ASERT, genesis calibration, startup grace | [WP-001](WP-001-difficulty-stability.md) | Shipped |
| PoW binding — anchor, genesis-bound RandomX epochs, W^X on Windows | [WP-004](WP-004-pow-binding.md) | Shipped |
| Layered reorg defense — MESS tiers, finality floor, checkpoints | [WP-005](WP-005-layered-reorg-defense.md) | Shipped |
| Cumulative-work determinism | [WP-006](WP-006-cumulative-work-determinism.md) | Shipped |
| Equal-work tie-break on the **PoW hash** (ungrindable) | [WP-006](WP-006-cumulative-work-determinism.md), commit `e390929b` | Shipped |
| Merchant finality hints (`get_finality_info`) | [WP-005](WP-005-layered-reorg-defense.md) | Shipped |
| Miner-signed rolling checkpoints (soft finality) | [WP-008](WP-008-rolling-checkpoints.md) | **Gated** — dormant; protects nothing today |
| Consensus integrity by build gate (hash lock) | [WP-007](WP-007-critical-files-hash-lock.md) | Shipped — **`src/mainnet.rs` is NOT locked** |
| Reproducible builds and release attestation | [WP-026](WP-026-reproducible-builds.md) | Shipped — **not enforced in CI** |
| Snapshot checkpoint binding | [WP-024](WP-024-snapshot-bootstrap.md) | Shipped |
| Orphan reconnection / sync generations | [WP-021](WP-021-orphan-reconnection.md) | Shipped |
| Share-replay resistance (mining pools) | [WP-023](WP-023-share-replay-resistance.md) | Shipped |
| Emission integrity — asymptotic tail, 0% dev tax | [WP-003](WP-003-emission.md) | Shipped |

---

## 7. The standing gaps, in one place

Every "not Shipped" entry above, collected so nobody has to scan five tables:

| Gap | Where | Consequence |
|---|---|---|
| **Dead-man's switch has no spend path** | WP-015 §5.1 | A user's heirs get nothing, and the wallet reports success |
| **Subaddress funds unspendable** | WP-016 §4 | Gated off mainnet; W-1 |
| **`ScopedViewKey` is not cryptographic** | WP-013 §3.6 | Sharing one discloses the entire view history |
| **Canonical user-agent unwired** | WP-011 §5 | Build strings remain a node fingerprint |
| **Memo padding not consensus-enforced** | WP-014 §4 | A modified wallet self-identifies |
| **Dust quarantine has no CLI surface** | WP-018 §7 | Users cannot release quarantined outputs |
| **Rolling finality dormant** | WP-008 §4 | No soft finality today |
| **`src/mainnet.rs` not hash-locked** | WP-007 §4 | Mainnet genesis editable without tripping the gate |
| **Reproducible builds not in CI** | WP-026 §4 | Verification is manual; GitHub Actions blocked at account level |
| **Spark proof position leak** | WP-100 §5.2 | Gated off |
| **No traffic-classifier evaluation** | WP-012 §4 | Shaping effectiveness unmeasured |
| **No adversarial network evaluation of Dandelion++** | WP-020 §4 | Guarantee rests on protocol correctness, not measurement |

---

## 8. How to keep this honest

Three rules, learned from the failures in [WP-100](WP-100-solved-issues-ledger.md):

1. **A status is a claim about the code, not the design.** WP-015 said "Shipped"
   until someone checked whether `is_recovery_eligible` had a caller. It did not.
   Before writing Shipped, find the production call site.
2. **Doc comments are not evidence.** Three separate comments in this codebase
   described mechanisms the code did not implement — the memo nonce derivation,
   the equal-work tie-break rationale, and Dandelion++'s local-transaction
   handling. All three were caught by reading the code and are recorded in their
   papers.
3. **A gap moved out of this table must move into a commit, not a conversation.**

---

## 9. References

- [`docs/THREAT_MODEL.md`](../THREAT_MODEL.md) — the authoritative model this
  paper indexes.
- [WP-000 · Cynstra: Concentric Privacy](../cynstra-whitepaper.md) — the
  architecture these layers implement.
- [WP-009](WP-009-privacy-feature-composition.md) — why layers interfere and how
  we keep them from doing so.
- [WP-100](WP-100-solved-issues-ledger.md) — every failure found, and the
  assumption it died on.
