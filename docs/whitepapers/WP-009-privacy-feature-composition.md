# WP-009 · Privacy Feature Composition
### How seven privacy features share one transaction without eating each other

**Status:** Shipped (with two gated exceptions) · **Layer:** Cross-cutting ·
**Series:** [CoinCync Whitepapers](README.md)

---

## 1. Motivation

Most privacy chains ship one or two privacy mechanisms. The literature covers
each in isolation: ring signatures here, confidential amounts there, network
anonymity somewhere else. What the literature does *not* cover is what happens
when you run seven of them **on the same transaction, in the same wallet, over
the same wire** — and that is where a real chain actually breaks.

CoinCync composes: stealth addresses, ring signatures with confidential amounts,
subaddresses, encrypted memos, view-tag scanning, light-sync digests, selective
disclosure, dead-man's-switch metadata, auto-churn, and a three-layer traffic
shaper. Every one of them wants to write something into the transaction or change
how it is scanned, relayed, or timed.

The recurring discovery is that **privacy features collide in three specific
ways**, and that nearly every privacy bug we found was a collision rather than a
flaw in any single feature. This paper is the composition rulebook we derived
from those failures.

---

## 2. The three collision classes

### 2.1 Fingerprint collisions — an optional feature is a label

If a feature is *optional* and *observable*, using it partitions the anonymity
set. A memo that makes a transaction 40 bytes larger identifies the memo users. A
churn transaction shaped differently from a payment identifies churners. The
privacy of every individual feature is capped by how many people use it.

**Rule: any feature that touches the observable transaction must be invisible in
the observable transaction.** In practice this means padding to a fixed cap, not
"only pay for what you use."

### 2.2 Path collisions — one output class, many readers

A transaction is read by several independent code paths: the full wallet scanner,
the light-sync scanner, the consensus validator, the decoy sampler. When a feature
introduces an output that behaves differently, *every* reader must learn about it
— and the ones that don't fail silently.

**Rule: a special-case output class needs its case in every path that reads
outputs.** Missing one produces a bug that looks like "funds missing" rather than
"parser wrong."

### 2.3 Rule-asymmetry collisions — the builder and the verifier disagree

The wallet *constructs* transactions; consensus *verifies* them. Any rule the
verifier enforces that the builder does not is a transaction the wallet will
happily build and the network will reject.

**Rule: selection must enforce every rule verification enforces.**

---

## 3. The collisions we actually hit

Each of these was a real defect, not a hypothetical.

### 3.1 Coinbase outputs vs. the confidential scan path *(path collision)*

Coinbase outputs are deliberately **not** confidential: plaintext amount,
zero-blinding commitment, public-data view tag. The confidential scan path —
view-tag gate → ECDH → amount decrypt → commitment recompute — fails on all three
counts.

The full wallet scanner had a coinbase case. **The light-sync scanner did not.**
A solo miner on light sync therefore saw a zero balance: their rewards existed on
chain and were invisible to their wallet. The fix flags coinbase outputs in the
block digest and gives the light scanner its own detection path (direct/ECDH
ownership, plaintext amount, zero blinding).

*Composition lesson:* transparency inside a privacy chain is itself a special
case, and it must be special-cased **everywhere**, including in the reader you
wrote last.

### 3.2 Decoy selection vs. the ring-signature verifier *(rule-asymmetry)*

The CLSAG verifier rejects identity-point ring members — a necessary guard. The
decoy sampler drew from the canonical output set, which *contains* an
identity-point output (the genesis placeholder). The wallet built valid-looking
rings the network refused, intermittently, and most often on a young chain where
the pool is small.

Neither component was wrong alone. The sampler enforced *its* rules; the verifier
enforced *its*; nobody owned the intersection.

*Composition lesson:* the builder's eligibility filter must be a superset of the
verifier's rejection rules, and that relationship should be stated in code, not
assumed.

### 3.3 Subaddresses vs. spend-key derivation *(path collision — still open)*

Subaddress detection and subaddress *spending* derive from different key
material: detection succeeds via the per-subaddress view key, while the
spend-side one-time-secret and key-image derivation omit the per-subaddress
offset. The result is the worst possible composition failure — funds you can
**see** and cannot **spend**.

This one is not fixed. It is gated off on mainnet by an explicit launch check,
kept live on test networks so the fix can be developed against a real
receive→spend round-trip.

*Composition lesson:* a feature is not composed until the **full lifecycle**
composes. "Receive works" is half a feature, and the dangerous half.

### 3.4 Encrypted memos vs. transaction uniformity *(fingerprint)*

A memo is attacker-visible length. Variable-length memos would sort users into
"memo users" and "non-memo users," and memo *size* would leak content class.
Memos are therefore encrypted to the recipient's view key **and padded to a fixed
cap**, so a transaction with a memo is indistinguishable in size from one
without.

### 3.5 Dead-man's-switch metadata vs. uniformity *(fingerprint)*

Recovery metadata rides in the transaction's `extra` field — the same field that
carries other optional data. A fixed-size record keeps a
dead-man's-switch-protected transaction from being identifiable as one, which
matters because identifying such transactions identifies exactly the users who
have declared their keys may be at risk.

### 3.6 Auto-churn vs. the transaction graph *(fingerprint)*

Churn is self-sending to break linkability, and it only works if churn
transactions are **indistinguishable from real transfers**. That constrains their
shape (same structure, same ring size, same padding) and their *timing* —
Poisson-distributed intervals rather than a fixed schedule, because a periodic
self-send is a signature.

### 3.7 View tags vs. scan privacy *(deliberate trade)*

A view tag is a one-byte filter that lets a wallet skip ~255/256 of the ECDH work.
It is a genuine, quantified privacy cost paid for a large scanning-cost win — the
tag narrows the candidate set for an observer by the same factor it narrows it for
the owner. We take the trade (as Monero does) and record it as a trade, not a free
win.

### 3.8 The propagation stack — ordering matters *(layer composition)*

Four mechanisms touch a transaction's journey to the network, and they compose
**in order**:

1. **Dandelion++** decides *who* first learns of the transaction (stem phase
   before fluff), defeating first-broadcast origin attribution.
2. **Uniform envelope** normalises the *size* of every post-handshake message at
   the Noise-record layer, so message length reveals nothing about content.
3. **Timing jitter** breaks the correlation between an action and its packet.
4. **Cover traffic** ensures the absence of a message is also not a signal.

Get the order wrong and you undo yourself: normalising size *after* a
size-revealing hop, or jittering a message whose length already identified it,
buys nothing. Each layer removes a distinct observable (who-first, size, timing,
presence) and the set only works complete.

### 3.9 Ring size vs. a young chain *(a composition we could not win)*

Uniformity says ring size must be fixed for everyone. A young chain does not have
enough outputs to fill large rings. These genuinely conflict, and the resolution
is honest rather than clever: a bootstrap minimum of **11** below height 10,000,
full **16** thereafter — a declared, temporary, chain-wide weakening rather than
a per-user choice. Everyone in the bootstrap era shares the same reduced ring, so
the anonymity set is smaller but *not partitioned*.

*Composition lesson:* when two privacy requirements truly conflict, degrade
**uniformly and visibly**, never per-user and silently.

---

## 4. The composition rules

Derived from the above, these are the rules we now apply to any new privacy
feature:

1. **Uniformity beats optionality.** If a feature is observable, make it
   universal or make it invisible (pad to a fixed cap). Never make it a visible
   user choice.
2. **Enumerate every reader.** A new output class or field must be handled in the
   full scanner, the light scanner, the validator, and the decoy sampler — or
   explicitly, in writing, in none of them.
3. **The builder's filter ⊇ the verifier's rules.** Anything consensus rejects,
   construction must exclude.
4. **Compose the whole lifecycle.** Detect, spend, scan, disclose, recover — a
   feature ships when all of them work, not when receive works.
5. **Timing is content.** A feature with a schedule (churn, cover traffic,
   embargo timers) must randomise it, or the schedule identifies the feature.
6. **Degrade uniformly.** When a privacy property cannot be met, weaken it for
   everyone and say so; never let some users be more identifiable than others.
7. **Layers must be ordered and complete.** Partial propagation privacy is
   frequently *worse* than none, because it creates a smaller, more confident
   set of candidates.

---

## 5. Security analysis

**What holds.** Optional-looking features (memos, recovery metadata, churn) are
size- and shape-uniform; the propagation stack removes who-first, size, timing,
and presence as observables; the builder now mirrors the verifier's ring rules;
coinbase is handled in both scanners.

**What this does not claim.** Composition correctness is not privacy *proof*. We
have removed the collisions we found; the argument that no further collisions
exist is exactly the argument we could not make about any of the seven above
before we found them. The honest position is that this class of bug is
under-studied, our record shows we keep finding them, and the rules in §4 are a
process for finding more — not a guarantee that none remain.

**Open exceptions.** §3.3 (subaddress spend) is unresolved and gated off mainnet.
The Spark proof position leak (WP-100 §5.2) is likewise gated. Both are listed
because a composition paper that hides its uncomposed features would be
self-defeating.

---

## 6. Implementation

| Concern | Location |
|---|---|
| Coinbase detection, both scanners | `src/wallet/scanner.rs`, `src/wallet/lightsync.rs` |
| Decoy eligibility mirroring verifier | `src/wallet/decoy_selection/allocation.rs`, `src/crypto/clsag.rs` |
| Subaddress gate (mainnet-disabled) | `src/bin/wallet_support/legacy.rs` |
| Memo encryption + padding cap | `src/constants.rs`, wallet send path |
| Recovery metadata (fixed-size, in `extra`) | wallet send path, `src/wallet/` |
| Auto-churn (Poisson intervals) | `src/bin/wallet_support/legacy.rs` |
| Propagation stack | `src/network/dandelion.rs`, `src/network/traffic_shaping.rs`, `src/network/framing.rs` |
| Ring-size schedule | `src/constants.rs` (`ring_size_at_height`) |

**Failure record.** WP-100 §5.1 (decoy/verifier asymmetry), §5.3 (light-sync
coinbase), §5.4 (subaddress spend), §5.2 (Spark leak).

---

## 7. Known limits

- The rules in §4 are **derived from our own failures**, so they are biased
  toward the collision classes we have already suffered. Others likely exist.
- No formal model backs the claim that the composed system is as private as its
  weakest component; that is an open research question for this design.
- Two features remain uncomposed and gated (§5).
- The propagation stack's ordering argument is qualitative, not measured; a
  traffic-analysis evaluation against a live network is future work.

---

## 8. References

- Bojja Venkatakrishnan et al., *Dandelion++* (2018) — origin-attribution
  resistance.
- Monero view-tag introduction — the scanning/privacy trade taken deliberately.
- Möser et al. (2018) — why uniformity failures are exploitable in practice.
- Internal: [WP-010 Decoy selection](WP-010-decoy-selection.md),
  [WP-011 Uniformity](WP-011-transaction-uniformity.md),
  [WP-012 Traffic shaping](WP-012-traffic-shaping.md),
  [WP-020 Dandelion++](WP-020-dandelion.md),
  [WP-100](WP-100-solved-issues-ledger.md).
