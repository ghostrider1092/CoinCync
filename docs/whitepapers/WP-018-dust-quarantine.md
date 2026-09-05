# WP-018 · Dust Quarantine
### Unsolicited outputs, and why accepting one costs more here than elsewhere

**Status:** **Shipped (core)** — classification, exclusion, acceptance and
persistence are live; the CLI surface and user-adjustable threshold are not ·
**Layer:** Wallet · **Series:** [CoinCync Whitepapers](README.md)

---

## 1. Motivation

Anyone can send you money. On a transparent chain that is a nuisance; on a
privacy chain it is an attack primitive, because an output the *attacker*
created is an output the attacker **knows belongs to you**.

They do not need to break any cryptography to use it. They need only wait for
your wallet to spend it, and then reason about what it was spent with.

The defence is not cryptographic either. It is a wallet policy: **do not spend
money you did not ask for, until you have said you want it.**

---

## 2. Threat addressed

| Attack | Assumption it needs | What we remove |
|---|---|---|
| **Targeted receive-and-spend correlation** — attacker sends you an output, then identifies the transaction that spends it | Your wallet will eventually spend any output it holds | Unsolicited outputs are never auto-selected |
| **Co-spend linking** — the attacker's output shares a transaction with a genuine one, proving both are yours | Wallets freely combine outputs | Quarantined outputs are excluded from selection entirely (§4.2) |
| **Balance-display coercion** — the user sees inflated balance and spends the attacker's output without noticing | All received value is shown as one number | Quarantined value is reported separately, not in spendable balance |
| **Accidental acceptance** | Spending is the default action for held funds | Acceptance is an explicit, informed step (§4.3) |

---

## 3. What this chain already blocks — and what it does not

Two consensus rules change the threat model enough that importing Bitcoin's
dust-attack analysis wholesale would be wrong.

### 3.1 Sub-threshold dust cannot exist

`MIN_OUTPUT_AMOUNT` (1 000 000 atomic units, 0.000001 CYNC) is enforced at
validation. There is no such thing as a 1-atomic-unit output on this chain, so an
attacker pays a real per-output floor. "Dust" here means *unsolicited small
outputs*, not sub-economic ones.

### 3.2 Consolidation is impossible, so the classic attack has no trigger

The canonical Bitcoin dust attack is: scatter dust across many addresses, wait
for the victim's wallet to **sweep it all into one transaction**, and cluster
every address that appears together.

CoinCync's uniform transaction shape (WP-011 §3.2) requires **exactly 2 inputs**
for every Transfer and Churn. There is no sweep. A wallet cannot combine 40 dust
outputs into one transaction no matter how it is configured, so the step the
attack waits for never happens.

### 3.3 What the 2-input rule gives back

The same rule makes the *remaining* attack sharper, and this is the finding that
shapes the design.

On a variable-input chain, spending an attacker's output alongside `n` others
leaks that those `n+1` outputs share a wallet — diluted across however many
inputs the wallet chose. Here every transaction has **exactly two** inputs. If
one of them is the attacker's known output, then the other input is **certainly**
the victim's, with no dilution at all.

So: the uniform-shape rule removes the mass-consolidation attack and concentrates
the residual leak into a clean, guaranteed one-bit disclosure. That is a good
trade overall, but it means the per-output decision matters more here, not less —
exactly the kind of cross-feature interaction WP-009 exists to catch.

### 3.4 What quarantine does *not* fix

**Ring pollution.** An attacker who creates many outputs knows those outputs are
theirs, and can discount them when they appear as decoys in *other people's*
rings, shrinking everyone's effective anonymity set. That harm is global rather
than victim-specific, it does not require the victim to do anything, and no
receiving-side policy touches it. It belongs to decoy selection (WP-010) and to
the economics of output creation.

Quarantine protects **the recipient's own linkability**. It is not an
anti-flooding measure and should not be described as one.

---

## 4. Design

### 4.1 Classification at scan time

An output is **quarantined** when the wallet has no reason to expect it. The
practical v1 signal is a **wallet-policy** amount threshold — deliberately
separate from the consensus `MIN_OUTPUT_AMOUNT`, because the consensus floor is a
chain-bloat rule and this is a privacy policy; tying them would make a consensus
change silently alter wallet behaviour.

Richer signals (does this match a payment the user was expecting? was this
address published for this counterparty?) are better and require UX that does not
exist yet. The amount threshold is the fallback that works with no UX at all,
and it must be user-adjustable, because a legitimately small payment is
indistinguishable from a hostile one by amount alone.

### 4.2 Exclusion, at the two chokepoints

Quarantined outputs are excluded from:

- **`spendable(...)`** — so they never inflate the balance the user acts on, and
- **`available_utxos(...)`** — so no selection path can pick one.

Both live in `src/wallet/balance.rs` and already share a filter predicate
(unspent, mature, unlocked, unreserved). Quarantine is one more clause on that
same predicate. Putting it there rather than in each caller is the point: a new
selection path added later inherits the rule instead of having to remember it —
the "enumerate every reader" discipline of WP-009 §4 rule 2, applied in advance
for once rather than after an incident.

They remain visible as a separate, clearly-labelled category. Hiding them
entirely would be worse: a user who cannot see an output cannot decide about it,
and unexplained missing money destroys trust in the wallet faster than any attack.

### 4.3 Acceptance is informed consent, not a checkbox

Because §3.3 means a quarantined output **cannot be spent in isolation on this
chain**, "accept" cannot honestly mean "spend it safely." It means:

> Spending this will place it in a transaction with one other of your outputs,
> and whoever sent it can then infer that the other output is yours too.

The wallet must say that, in those terms, at the point of acceptance. A generic
"accept funds?" prompt would be a lie by omission. Once accepted, the output
becomes ordinary and selectable — there is no second-class spending mode to hide
behind, and pretending otherwise would be worse than the honest warning.

### 4.4 Never a silent default

Quarantine must never be applied silently to a payment the user was waiting for.
The failure mode of an over-eager filter is "my payment didn't arrive", which
generates support load, teaches users to disable the feature, and is *worse for
privacy* than the attack it prevents. Default the threshold conservatively low.

---

## 5. Security analysis

**What this would hold.** An unsolicited output cannot be spent without an
explicit, informed decision; it never inflates spendable balance; no selection
path can pick one by accident.

**What it does not.**

- **Ring pollution is untouched** (§3.4).
- **Receipt itself is already observable to the sender.** They created the
  output; they know it is yours. Quarantine prevents the *second* inference (what
  else is yours), not the first.
- **Amount-threshold classification is crude.** It will quarantine legitimate
  small payments and pass hostile larger ones. It is a starting policy, not a
  detector.
- **An accepted output is fully ordinary.** The one-bit link in §3.3 is then real
  and unavoidable. The mechanism buys an informed choice, not immunity.
- **No protection for a wallet with one clean output.** A user holding exactly
  one non-quarantined UTXO cannot transact at all under the 2-input rule without
  accepting something. That is a genuine usability cliff and needs a real answer
  before this ships.

---

## 6. Implementation

| Step | Location | Status |
|---|---|---|
| `quarantined: bool` on the UTXO record, `#[serde(default)]` | `src/wallet/balance.rs` | **Live** |
| Classification at the single UTXO construction site | `src/wallet/scanner.rs` | **Live** |
| `QUARANTINE_AMOUNT_THRESHOLD` (10x the consensus floor) | `src/wallet/scanner.rs` | **Live** (fixed, not yet configurable) |
| Exclusion via the shared `is_selectable` predicate | `src/wallet/balance.rs` | **Live** |
| `quarantined_balance()` / `quarantined_utxos()` | `src/wallet/balance.rs` | **Live** |
| `accept_quarantined(key)` | `src/wallet/balance.rs` | **Live** |
| User-adjustable threshold | wallet config | **Missing** |
| CLI: list quarantined, accept with the §4.3 warning | `src/bin/wallet_support/legacy.rs` | **Missing** |

Two structural choices worth noting, both applying WP-009 §4 rule 2 *before* an
incident rather than after one:

- **One classification site.** `quarantined` is set where the UTXO is
  constructed — the only such place in the wallet — so every received output
  passes through the policy and no second scan path can bypass it.
- **One selectability predicate.** `spendable` and `available_utxos` were
  separate copies of the same filter. They now share `is_selectable`. The
  dangerous drift here is silent in one direction: an output excluded from the
  displayed balance but still reachable by selection would be spent without ever
  appearing to the user.

Coinbase outputs are not special-cased and do not need to be — block rewards
exceed the threshold by roughly five orders of magnitude even in the perpetual
tail, so a miner's own rewards never quarantine. Adding an `is_coinbase` branch
would mean threading a flag through `DecryptedOutput` for a case the arithmetic
already covers.

**Tests.** A quarantined output is absent from *both* chokepoints while
remaining visible via the quarantined accessors; acceptance makes it selectable
and is idempotent; and the flag survives a serialization round-trip *and* a
pre-field wallet file still loads (a flag that reset on reload would silently
un-quarantine everything at the next wallet open). Full lib suite 1184 pass.

---

## 7. Known limits

- **No user surface yet.** The mechanism is live in the wallet core, but nothing
  lists quarantined outputs or performs the §4.3 informed-consent acceptance, so
  a user currently has no way to release one. Until that lands the feature can
  strand small legitimate payments — it must not be considered finished.
- **Threshold is fixed, not configurable.** §4.1 requires it to be
  user-adjustable; it is currently a constant.
- Classification by amount is a placeholder for real expectation-matching.
- The single-clean-output cliff (§5) has no answer yet.
- Does not address ring pollution or output flooding.
- Interacts with the 2-input uniform shape in a way that makes acceptance
  consequential; that interaction should be re-checked if the shape rule ever
  changes.

---

## 8. References

- Bitcoin dust-attack literature and wallet coin-control practice — the prior art
  §3.2 explains does not transfer directly.
- Monero's handling of unsolicited outputs and churn guidance.
- Internal: [WP-011 §3.2](WP-011-transaction-uniformity.md) — the 2-input rule
  that reshapes this threat model,
  [WP-010 Decoy selection](WP-010-decoy-selection.md) — where ring pollution
  belongs,
  [WP-009](WP-009-privacy-feature-composition.md) — the composition discipline
  §3.3 and §4.2 apply.
