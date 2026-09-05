# WP-013 · Selective Disclosure
### Proving facts about private money — and anchoring those proofs to the chain

**Status:** Shipped (proofs + anchoring) · **Layer:** Wallet / Crypto ·
**Series:** [CoinCync Whitepapers](README.md)

---

## 1. Motivation

A privacy chain that offers no way to *voluntarily* prove anything forces its
users into a false choice: total opacity, or hand over the view key and give up
all privacy — past and future, every counterparty, forever.

Real users need to prove narrow facts. An exchange wants "this holder controls at
least X." A tax authority wants "this is everything received in 2026." A
counterparty wants "you own the output you say you own." An auditor wants "this
spend came from your wallet."

Each of those is a *single predicate*. Surrendering a view key answers all of
them and thousands of questions nobody asked. CoinCync's position is that
disclosure should be **voluntary, particular, and minimal** — and, critically,
that a disclosure must be **sound**, because a proof an auditor cannot trust is
worse than no proof at all.

---

## 2. Threat addressed

| Attack / failure | Assumption it needs | What we removed |
|---|---|---|
| **All-or-nothing disclosure** — proving one fact requires revealing everything | The only disclosure primitive is the view key | Four narrow predicate proofs, each revealing one fact |
| **Fabricated proof over an invented commitment** | The verifier accepts the prover's own chain reference | `ChainAnchor`: the verifier resolves the real output from *their own* chain view and the proof must match it |
| **Fabricated proof over a never-mined key** — a genuine ownership proof for a stealth key that was never on chain | Cryptographic validity implies chain membership | Same: anchoring separates "the math holds" from "this exists" |
| **Cross-proof forgery** — reusing one proof's transcript as another's | Proof transcripts are interchangeable | Domain separation per proof type |
| **Verifier-side privacy leak** — the act of checking a proof reveals what the verifier cares about | Fetching an output from a remote node is neutral | Documented as a hazard; anchor must come from the verifier's own node, and the CLI warns when it does not |
| **Silent verification ambiguity** — "false" meaning both "you cheated" and "I can't confirm" | A boolean is enough | Three-valued `AnchorVerdict` |

---

## 3. Design

### 3.1 Four predicate proofs

All are non-interactive (Fiat–Shamir), domain-separated, and self-contained: the
verifier needs the proof plus public chain data, nothing else.

| Proof | Predicate | Use |
|---|---|---|
| **Balance** | the commitment hides a value ≥ *threshold* | Exchange / solvency attestation |
| **Ownership** | the prover controls a specific stealth output | Counterparty confirmation |
| **Sum** | total received across a set of outputs in a period | Tax reporting |
| **Source** | a key image originated from this wallet | Attribution, dispute resolution |

The balance proof is representative of the construction. To prove `v ≥ t` for a
commitment `C = v·H + r·G`:

1. Form `C' = (v − t)·H + r'·G` with a **fresh** blinding `r'`.
2. Prove `v − t ≥ 0` with a Bulletproof range proof on `C'`.
3. Prove with a Schnorr proof that `C − t·H` and `C'` commit to the **same
   value** under different blindings.

The verifier learns `v ≥ t` and nothing more — not `v`, not `r`. Re-blinding at
step 1 is what prevents the proof from linking to other proofs over the same
commitment.

### 3.2 The anchoring gap — and why offline verification is not enough

This is the part of the design that came from a real reported defect
(junbyjun1238, issues #252/#253), and it generalises beyond CoinCync.

Every offline `verify_*` function checks that a proof is **internally
consistent**: the range-proof math holds, the Schnorr signature verifies, the
homomorphic sum balances. But each one reads its on-chain reference — the
commitment, the stealth address, the output set — from **data the prover
supplied**.

That proves *"I know a secret for this commitment"*. It does **not** prove
*"this commitment is a real output in the canonical chain."*

The consequences are concrete:

- A prover can produce a fully valid `OwnershipProof` for a stealth key they
  genuinely control **that was never mined**.
- A prover can produce a valid `BalanceProof` over a commitment they **invented**,
  attesting to a balance they do not have.

The offline verifiers return `true` for both. Every step of the cryptography is
correct; the *scope* of what the cryptography attests to was narrower than the
claim being made of it. This is the general shape of the failure: a proof system
is only as meaningful as the binding between its statement and reality.

### 3.3 `ChainAnchor` — binding statements to chain state

The `*_anchored` verifiers take a **`ChainAnchor`**: the real on-chain output —
`(tx_hash, output_index)`, its commitment, its stealth address, and its canonical
block height — resolved by the verifier **from their own trusted chain view**.
The proof's self-declared reference must match it.

The provenance rule is load-bearing and stated in the code as a requirement, not
a suggestion. The anchor MUST come from:

- the verifier's own full-node canonical chain view, or
- a block or transaction the verifier obtained and hash-checked themselves.

It must **never** be self-supplied by the prover. An anchor the prover provides
re-opens exactly the gap anchoring closes.

### 3.4 The verifier's own privacy — an unusual hazard

Anchoring introduces a leak in the opposite direction from the usual one.
Resolving an anchor means looking up a *specific output*. If the verifier asks a
**remote** node for it, that node learns **which outputs the verifier cares
about** — the counterparties they are auditing, the payments they are checking.

Verification is normally treated as privacy-neutral. Here it is not. The design
response is to require a local chain view for anchoring, and to have the wallet's
`disclose verify-*` commands **warn the operator** when the anchor is resolved
against a remote source. We flag it rather than silently blocking it, because an
operator without a full node still benefits from anchoring — they just need to
know what it costs them.

### 3.5 Three-valued verdicts

`AnchorVerdict` deliberately distinguishes three outcomes rather than returning a
boolean:

| Verdict | Meaning |
|---|---|
| `Valid` | Cryptographically sound **and** matches the trusted on-chain output |
| `CryptoInvalid` | The proof itself does not verify — malformed or forged |
| `AnchorMismatch` | The math holds, but the reference does not match chain state — the proof is **unanchored** |

Collapsing these into `false` would merge "this party attempted fraud" with "I
could not confirm this against my chain view," which are different facts calling
for different responses. Auditing tools need to tell them apart.

### 3.6 Scoped view keys — two mechanisms, different strengths

Two primitives once shared the "scoped view key" name. Only one ships in v1; the
other was removed for over-promising. Stating the difference is the point of this
section — the name invites exactly the wrong assumption.

**`ViewKey` (`src/crypto/view_keys.rs`) — derived, watermarked, in-process
enforced.** Derived per epoch via `hash_domain(b"COINCYNC_VIEWKEY_v2", …)` so a
key for one epoch does not yield another's, carrying a watermark and four scope
kinds: `EpochOnly`, `TimeRange`, `AmountCapped(n)`, `SingleUse`. The latter two
are enforced through `authorize_scan(epoch, amount)` against mutable state
(cumulative consumed amount; single-use fired). The secret is excluded from
`Serialize`, redacted in `Debug`, and zeroed on drop.

**`ScopedViewKey` (height range) — REMOVED in v1.** A second primitive once
shared the "scoped view key" name: it exported a `(from_height, to_height)` range
for period disclosure (a tax year, an audit window). **It was not
cryptographically scoped** — the exported material was the **full view secret**,
byte-identical for every range, with the range honoured only by cooperating
software. A recipient running their own scanner saw the holder's **entire** view
history, past and future. Because the name promised a bound the key could not
enforce, the type and its CLI (`disclose scoped-view-key` / `scan-scoped`) were
**removed in v1** rather than shipped behind a warning.

A real, cryptographically range-bound view key needs a protocol-level change (a
Monero-style view secret is monolithic — detecting an output requires it in full,
so it cannot be restricted to a height range without altering output derivation).
That is tracked as post-launch work. **Until then, the disclosure primitive is the
§3.1 predicate proofs** — those *are* cryptographic and sound against an
adversarial recipient, which is what a period disclosure actually needs.

*(A previous code comment also described time-scoped view keys as an innovation
over Monero. That comparative claim was dropped: it was never re-verified against
Monero source, and the series does not make novelty claims it has not checked.)*

---

## 4. Security analysis

**What holds.**

- The four predicate proofs are sound and zero-knowledge for their stated
  predicates, built on Bulletproofs range proofs and Schnorr equality proofs with
  per-type domain separation.
- Anchored verification binds a proof to canonical chain state, closing the
  fabricated-commitment and never-mined-key gaps.
- `AnchorVerdict` preserves the distinction between forgery and non-confirmation.
- `ViewKey` secrets do not serialise, do not print, and zero on drop.

**What this does not protect against.**

- **Period disclosure against an adversarial recipient.** The height-range
  `ScopedViewKey` that would have covered this was **removed in v1** because it
  could not enforce the bound (§3.6); use the §3.1 predicate proofs, which are
  cryptographic. There is no v1 primitive that hands an adversarial recipient a
  time-bounded *view* key — by design.
- **`AmountCapped` / `SingleUse` against an adversarial holder.** Enforcement is
  mutable in-process state. A holder running modified software resets the
  counter. These scopes constrain *cooperating* tooling; they are not capability
  revocation.
- **Unanchored verification.** The non-anchored `verify_*` functions remain
  exported and will accept a fabricated reference. They are correct for their
  narrow statement; a caller who treats them as chain-membership checks
  reintroduces #252/#253. Anchored variants are the ones to call.
- **Verifier-side output-lookup leakage** when anchoring against a remote node
  (§3.4) — warned, not eliminated.
- **Disclosure is irrevocable.** A proof or key, once shared, cannot be recalled;
  epoch rotation limits *future* exposure only.
- **Correlation across disclosures.** Multiple proofs to the same verifier, or
  colluding verifiers, can compose narrow facts into a broader picture. Each proof
  is minimal; a *sequence* of proofs is not.

**Historical defect on the record.** `ViewKey::key_data` once carried
`#[zeroize(skip)]` alongside a comment asserting the field was zeroized by the
struct derive. It was not — `zeroize_derive` excludes skipped fields from the
generated impl — so the documented forward-secrecy property was unenforced. The
attribute was removed. The transferable lesson matches WP-021 §4: **a comment
asserting a security property is not evidence the property holds.**

---

## 5. Implementation

| Component | Location |
|---|---|
| Four proof types, Fiat–Shamir, domain separation | `src/crypto/disclosure.rs` |
| `ChainAnchor`, `AnchorVerdict`, `verify_*_anchored` | `src/crypto/disclosure.rs` |
| Forward-secret `ViewKey`, scopes, `authorize_scan` | `src/crypto/view_keys.rs` |
| Wallet CLI: `disclose` / `disclose verify-*` (+ remote-anchor warning) | `src/bin/wallet_support/legacy.rs` |
| Range proofs, Pedersen commitments | `src/crypto/bulletproofs.rs`, `src/crypto/curve.rs` |

**Failure record.** Issues #252 / #253 (junbyjun1238) — the anchoring gap; see
WP-100. Contrast with `verify_balance_proof` in `src/consensus/validation.rs`,
which is the *consensus* amount-balance check and unrelated to this paper's
disclosure `BalanceProof`.

---

## 6. Known limits

- Height-range period disclosure is not available in v1: the `ScopedViewKey` that
  would have provided it could not enforce the range and was removed (§3.6). Use
  the §3.1 predicate proofs, which are cryptographic.
- `AmountCapped` / `SingleUse` bind cooperating software only.
- Unanchored verifiers remain callable and are a footgun by API shape.
- Anchoring requires a local chain view for full privacy.
- No proof is revocable once issued.
- Sum-proof anchoring resolves each referenced output through a caller-supplied
  lookup; the privacy of that lookup is the caller's responsibility.

---

## 7. References

- Bünz et al., *Bulletproofs* (2018) — the range-proof construction.
- Fiat & Shamir (1986) — non-interactive transformation.
- Monero's view-key and proof tooling (`get_tx_proof`, `check_reserve_proof`) —
  prior art for wallet-level disclosure, and the same anchoring concerns.
- Issues #252 / #253 (junbyjun1238) — the reported soundness gap this design
  closes.
- Internal: [WP-009 Privacy composition](WP-009-privacy-feature-composition.md),
  [WP-016 Subaddresses](WP-016-subaddresses.md),
  [WP-100](WP-100-solved-issues-ledger.md).
