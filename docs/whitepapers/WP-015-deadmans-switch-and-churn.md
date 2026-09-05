# WP-015 · Dead-Man's Switch and Auto-Churn
### Inheritance without custody, and unlinkability without a schedule

**Status:** **Split — auto-churn Shipped; dead-man's switch DEFERRED
post-launch (its CLI was removed in v1: the metadata was inert, with no
consensus recovery-spend rule, so it could not do what its name promised).**
· **Layer:** Wallet · **Series:** [CoinCync Whitepapers](README.md)

---

## 1. Motivation

Two problems that look unrelated share a solution shape.

**Inheritance.** Self-custody means that if the owner dies, is incapacitated, or
loses their seed, the funds are gone. Every workaround — a shared seed, a
custodial escrow, a multisig with a lawyer — reintroduces the trusted third party
that self-custody exists to remove.

**Stale linkability.** An output sitting unspent for months accumulates context:
the transaction that created it, the counterparty who sent it, everything an
observer has learned since. Ring signatures protect the *spend*; they do not
refresh an output that has been sitting in view.

Both are solved by a wallet acting on the owner's behalf over long time horizons —
one on a timeout, one on a schedule. And both fail in the same way if the
mechanism is observable, because a transaction that is identifiably a recovery
setup, or identifiably a churn, tells an observer something specific about the
person who made it.

---

## 2. Threat addressed

| Attack / failure | Assumption it needs | What we removed |
|---|---|---|
| **Permanent loss on owner incapacity** | Self-custody has no recovery path | *(Intended)* owner-designated recovery address after a timeout — **see §5: not enforced** |
| **Custodial recovery** — an escrow or third party holds a key | Recovery requires someone else to hold something | Recovery key is set by the owner; no third party ever holds it |
| **Recovery-setup fingerprinting** | Recovery metadata is variable-size or a distinct output type | Fixed 42-byte TLV record in `extra` |
| **Long-term output linkability** | An unspent output's context is static | Periodic self-sends re-anchor outputs into fresh rings |
| **Churn-schedule fingerprinting** — periodic self-sends are a signature | A fixed interval is fine if amounts vary | Exponentially distributed intervals (a Poisson process) |
| **Churn-amount fingerprinting** — round or full-balance self-sends stand out | Any amount will do | Randomised percentage of spendable value |

---

## 3. Dead-man's switch — the design

### 3.1 Metadata in `extra`, not a new output type

Recovery metadata is a tagged TLV record in the transaction's `extra` field:

```
[0xDE]                       recovery tag
[output_index: u8]           which output this applies to
[recovery_address: 32 bytes] stealth address of the backup wallet
[timeout_blocks: u64 LE]     inactivity threshold
```

42 bytes per output, well inside the 256-byte `extra` limit.

Using `extra` rather than extending `TxOutput` is what makes the feature
**backwards compatible**: nodes that do not understand the tag ignore it, so no
fork is required to introduce the metadata. It is also what makes it uniform — the
record shares a field with other optional data and is fixed-size, so a
recovery-protected transaction is not identifiable as one.

That uniformity matters more here than almost anywhere else. Identifying
recovery-protected transactions identifies exactly the users who have publicly
declared that their keys may one day be out of their control — a list an attacker
would very much like to have.

Timeouts are bounded: minimum **720 blocks** (~24 hours), maximum **525,960**
(~2 years at 120-second blocks).

### 3.2 The intended consensus rule

At chain height `H`, an output created at height `C` carrying recovery metadata is
**recovery-eligible** when `H − C ≥ timeout_blocks`. A recovery spend then requires
the spender to prove ownership of `recovery_address` through the ordinary ring
signature and key image — no special-case signature scheme, no privileged path.

Two constitutional properties follow, and both hold by construction:

- **No supply violation** (Article I): recovery transfers coins, it never creates
  them.
- **No privacy violation** (Article III): the recovery address is a stealth
  address, so an observer cannot link it to a person.

The Bill of Rights basis is Amendment IV — *no person shall be deprived of
property without due process*. A dead-man's switch is argued to *be* due process:
the owner opted in explicitly, the timeout is publicly verifiable, and the
recovery key was chosen by the owner.

### 3.3 What is actually implemented

- `RecoveryMeta::encode` / `decode` / `encode_all` / `decode_all` — the TLV codec.
- `validate_recovery_extra` — called from transaction validation, so malformed
  metadata is rejected at admission.
- `is_recovery_eligible(creation_height, current_height)` — the eligibility
  predicate, as a pure function.
- Wallet CLI to configure a recovery address and timeout, and to display status.

---

## 4. Auto-churn — the design

Churn is a self-send whose purpose is to re-anchor outputs into fresh rings, so an
output's linkability does not accumulate with age.

**Timing is the hard part.** A periodic self-send is itself a signature: an
observer who sees transactions from the same wallet at a fixed cadence learns
the wallet is running churn, and the cadence becomes a fingerprint that survives
every other privacy layer. Intervals are therefore drawn from an **exponential
distribution** — a Poisson process — bounded by configurable minimum and maximum
delays (defaults 30 minutes to 2 hours). The exponential is memoryless: the time
since the last churn tells an observer nothing about when the next one comes. This
is the same reasoning that governs Dandelion++'s embargo timers (WP-020 §3.4).

**Amounts** are a randomised percentage of currently spendable value (defaults
10–50%), not the full balance and not a round number.

**Construction is delegated**, not reimplemented. Churn builds its self-send
through the same `SpendCoordinator` as an interactive send, inheriting identical
ring selection, RPC policy, reservation lifecycle, and safety checks. A separate
construction path would be a second implementation that must agree with the first
— exactly the failure shape WP-006 §4.4 catalogues, and one where divergence would
make churn transactions *distinguishable* from real payments, defeating the entire
purpose.

Churn is **off by default** and opt-in through the wallet CLI.

---

## 5. Security analysis

### 5.1 The dead-man's switch does not work — and this is the paper's most important claim

**`is_recovery_eligible` has no consensus caller.** There is no code path in
`src/consensus/`, `src/chain.rs`, or the wallet spend path that permits a recovery
address to spend an output after its timeout expires.

The consequence, stated plainly:

> A user can configure a dead-man's switch, the CLI will report it as configured,
> the metadata will be written to the chain and validated — and if that user dies,
> **the recovery address cannot spend anything**. The funds are lost exactly as if
> the feature had never been configured.

This is the most dangerous class of defect a wallet feature can have, because the
failure is silent, and it is only discovered by someone who cannot report it. It
is worse than an absent feature: an absent feature drives a user to arrange a real
backup, while a feature that reports success removes the reason to.

The status in this paper's header, and in the series index, has been corrected to
**Placeholder** accordingly. The metadata layer is real, validated, and
forward-compatible; the spend rule that would give it meaning does not exist.

Completing it requires a consensus change — recovery spends must be validated
against creation height and timeout — which means an activation height, an
operator rollout, and a careful look at how the rule composes with reorgs
(a recovery spend valid at height H may not be valid after a rollback below
`C + timeout`) and with the finality floor (WP-005).

**Interim guidance for operators:** treat the dead-man's switch as unimplemented.
Do not rely on it as an inheritance plan.

*Prior claim withdrawn.* This feature was previously counted among seven completed
privacy innovations. That count was wrong for this item, and the correction is
recorded here rather than made quietly.

### 5.2 Auto-churn

**What holds.** Timing is memoryless and bounded; amounts are randomised;
transactions are structurally identical to ordinary transfers because they are
built by the same coordinator.

**What this does not protect against.**

- **Churn costs fees and creates chain load.** It is a real, recurring cost paid
  for a probabilistic privacy gain.
- **Self-send patterns may still be inferable.** An observer with a strong prior —
  a known wallet, a distinctive amount distribution, sustained observation — may
  still detect churning. Poisson timing removes the *schedule* as a signal, not
  every signal.
- **Churn does not repair a weak ring.** If decoy selection is poor (WP-010), each
  churn produces another weakly-protected transaction rather than fixing the first
  one. Churning atop a broken sampler amplifies exposure.
- **Off by default** means it protects only users who find and enable it — an
  adoption gap that is itself an anonymity-set problem (WP-011 §1): the set of
  churning users is a set.

### 5.3 Composition

Both features write into the same `extra` field, and both must remain fixed-size
to preserve the uniform envelope (WP-011). A future feature adding
variable-length data to `extra` would break the fingerprint property for *all*
of them — a cross-feature constraint that belongs in review, not in any one
module.

---

## 6. Implementation

| Component | Location | Status |
|---|---|---|
| `RecoveryMeta` TLV codec, `is_recovery_eligible` | `src/transaction/recovery.rs` | Present, unwired predicate |
| `validate_recovery_extra` in tx validation | `src/transaction/validator.rs` | Live |
| `extra` attachment in the builder | `src/transaction/builder.rs`, `src/wallet/spend/types.rs` | Live |
| Recovery-spend consensus rule | — | **Missing** |
| `ChurnConfig`, `ChurnEngine`, exponential scheduling | `src/wallet/churn.rs` | Live |
| Churn construction via `SpendCoordinator` | `src/wallet/spend/` | Live |
| CLI: recovery configure/status, churn run | `src/bin/wallet_support/legacy.rs` | Live |

---

## 7. Known limits

- **The dead-man's switch has no spend path** (§5.1). Everything else in §3 is
  scaffolding until that lands.
- Completing it is a consensus change with reorg and finality interactions.
- Churn is opt-in and off by default.
- Churn's privacy gain is unquantified — no measurement of linkability reduction
  per churn on a live chain.
- Timeout bounds (720 / 525,960 blocks) are policy numbers.

---

## 8. References

- `docs/BILL_OF_RIGHTS.md` Amendment IV — the due-process basis for §3.2.
- `CONSTITUTION.md` Articles I and III — the supply and privacy constraints
  recovery is checked against.
- Monero churning practice and community guidance — prior art and its known
  limits.
- Internal: [WP-011 Uniformity](WP-011-transaction-uniformity.md),
  [WP-010 Decoy selection](WP-010-decoy-selection.md),
  [WP-020 §3.4](WP-020-dandelion.md),
  [WP-006 §4.4](WP-006-cumulative-work-determinism.md),
  [WP-100](WP-100-solved-issues-ledger.md).
