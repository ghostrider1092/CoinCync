# Extending Spark

### A versioned program for improving a proven private-transaction protocol — without replacing it.

**Whitepaper · Draft v0.1**
*CoinCync (testnet) → Cynstra (mainnet) · companion to the Cynstra whitepaper and
`docs/design/cip-spark-v3-scanning.md`*

> **Status — honest framing.** This is a design-stage draft. It describes a
> roadmap and the reasoning behind it. Where it states a result as *measured* or
> *proven*, the number or proof is cited; everything else is *proposed* and marked
> as such. Nothing here is activated on any chain: the on-wire advancements are
> gated and activation-locked until independently reviewed and hardened. This paper is written to
> invite scrutiny of the design, not to announce a product.

---

## Abstract

Lelantus-Spark, by Aram Jivanyan and Aaron Feickert, is a private-transaction
protocol with strong properties: a one-of-many membership proof over an
accumulator (anonymity set = the whole pool, not a fixed ring), a clean
view-key / diversified-address model, and compact VRF linking tags for
double-spend prevention. CoinCync adopts Spark as its single shielded engine.

This paper's contribution is **not a new primitive**. It is a disciplined,
versioned program for *extending* Spark along the axes its authors reasonably
left for later — wallet scanning cost, addressing ergonomics, proof aggregation,
selective disclosure, threshold custody — each advancement shipped **one version
at a time**, each an *additive layer* on Spark's existing foundation, and each
subjected to the same rule: **if it replaces a Spark primitive, it is out of
scope.** We believe the more valuable and more honest contribution to private
money is to take a sound construction and improve it in the open, crediting its
authors, rather than to announce another from-scratch scheme.

---

## 1. Motivation: build on the foundation, don't reinvent it

The incentive structure of the space rewards novelty: a new coin, a new scheme, a
new name. The result is a graveyard of under-reviewed cryptography and a user
base fragmented across systems that each re-solve the same problems slightly
differently and slightly worse.

Spark is already good. It was designed carefully, it has been analyzed, and it
sits on a lineage (Lelantus, and the broader one-of-many-proofs literature) that
has had real eyes on it. The engineering question that actually matters for users
is not "what can we invent instead?" but "what are the rough edges on this proven
thing, and can we smooth them without weakening what makes it sound?"

That is the whole thesis of this program. Every advancement below is chosen
because it is a genuine improvement a Spark user would feel — faster wallet sync,
better addresses, cheaper verification, provable receipts — and because it can be
expressed as an *addition* to Spark rather than a replacement of any part of it.

---

## 2. Design philosophy

**Extend, don't replace.** The selection rule for every version is mechanical: an
advancement is in scope only if it layers on top of Spark's existing primitives —
its coins, its view keys, its diversifiers, its accumulator, its tags. Anything
that swaps out a primitive (for example, replacing the pool-membership proof with
a full-chain-membership construction such as FCMP++) is a *different protocol's*
thesis and is explicitly parked, however attractive, because it discards the very
foundation this program is built to honor and improve.

**Credit the source.** Spark is Jivanyan and Feickert's work. This program's
output — specifications, a reproducible verifier, test vectors, a formal treatment
of the properties we rely on — is intended to be contributed back to the privacy
commons, not fenced off. A healthy privacy ecosystem is many independent
implementations that fail differently; we want to add to Spark's resilience, not
fork its community.

**Best, proven in the open — not first.** We make no "most private" claim. Where an
advancement reuses a mechanism proven elsewhere (Sapling/Jamtis view tags, FROST
thresholds), we say so and inherit its scrutiny; where our composition is younger
than the parts it joins, we say that too. Each on-wire version ships only behind a
coordinated activation and independent review. Rigor and openness are the moat.

**One advancement per version.** Versions are small and legible on purpose. Each
is a discrete, reviewable, independently-valuable step, with its own CIP, its own
activation (if it touches consensus), and its own section here. Small steps are
easier to review, easier to roll back, and easier for others to adopt piecemeal.

---

## 3. Where Spark stands in CoinCync (the baseline we extend)

- **v1 — native sketch.** A CoinCync-native Halo2 shielded store. Superseded; gated off.
- **v2 — libspark Spark (live at testnet height 29 000).** The real Lelantus-Spark
  engine via a vendored C++ library behind an FFI connector. It provides: mint and
  spend over an accumulator pool; Grootle one-of-many membership proofs; 34-byte
  VRF linking tags; a Sapling-style transparent↔shielded value bridge; content
  binding against coin replay; and a batched block-level verifier. This is the
  substrate the extension program builds on.

Everything in §4 is an addition on top of this v2 substrate.

---

## 4. The versioned extension roadmap

Each version is one headline advancement. The primary line is ordered by
dependency and user value; cross-cutting tracks advance continuously and reinforce
every version.

### v3 — Scanning & Addressing *(current; detailed in §5)*
Make finding your own coins cheap. A static analysis of libspark's identify path
(§5.2) showed the Monero/Sapling **view tag** does not help Spark — Spark already
fast-rejects non-owned coins — so v3 instead **parallelizes and optimizes the
per-coin scalar-multiplication** that dominates scanning (wallet-only, no fork),
adds incremental scan caching, and standardizes **diversified sub-addresses** from
Spark's existing diversifier. *Attacks the O(pool) scan that is the wallet's
dominant cost — without a coin-format change.*

### v4 — Proof Aggregation
Extend the batched-multiexp verifier (already implemented — a block's range proofs
share one multiexponentiation) toward **one aggregated spend proof per block**,
amortizing the Grootle membership cost across all of a block's spends. *Scaling:
smaller blocks, cheaper verification, permanently closing the verify-cost gap to
the fastest one-of-many systems.*

### v5 — Payment Proofs
A **selective-disclosure receipt**: a holder can prove, to a chosen party, that a
specific payment occurred (or that holdings meet a threshold) without revealing
the transaction on-chain or to anyone else. This compounds CoinCync's existing
off-chain aggregate-disclosure work and keeps the ledger private by default.

### v6 — Threshold Spark
**FROST-style** threshold / multisig control of the Spark spend key, so custody
can be split across parties or devices without a transparent multisig footprint.

### v7 — Confidential Asset Types
Multiple asset types sharing **one anonymity set**. Spark's structure accommodates
an asset tag; a single large pool protects every asset better than many small
per-asset pools.

### v8 — Oblivious Light-Client Scanning (OMR)
For mobile/light clients: a semi-trusted server scans the chain **obliviously** and
returns a small digest, without learning which coins are the client's and without
the client downloading the chain. The privacy-maximalist scanning path, promoted
from a v3 stretch to its own version because it is a research effort in
its own right.

### Cross-cutting tracks (continuous)
- **Operational privacy:** automated decoy churn ("ghost mode"), denomination /
  output uniformity to shrink the amount fingerprint, and Dandelion++ propagation
  for shielded transactions.
- **Verifiability (the moat):** a provable total-shielded-supply attestation, a
  **public, reproducible verifier with test vectors contributed back** to the
  Spark ecosystem, and a formal / machine-checked specification of the security
  properties the chain relies on.

---

## 5. v3 in detail — Scanning & Addressing

### 5.1 The problem
To identify its coins, a Spark wallet runs, for every coin in every block, a full
view-key recovery (`identify_view_only` in the connector): elliptic-curve work that
reconstructs the coin's recipient material and tests ownership. A wallet owns a
vanishing fraction of the pool, so nearly all of this work is wasted. As the pool
grows, scanning is the dominant wallet cost. There is no cheap pre-filter today.

### 5.2 Why NOT view tags (the B1 finding)
The obvious move — copy Monero/Sapling and add a 1-byte **view tag** to each coin
— does not transfer to Spark, and a static analysis of the real `Coin::identify`
path shows why. Monero/Sapling view tags win because scanning there does a cheap
shared-secret step and then an *expensive trial-decryption* per output; the tag
lets a wallet skip that decryption for non-matches. **Spark already skips it.**
libspark's identify, for a non-owned coin, first compares a one-hash
`key_commitment` against the coin and rejects immediately — before any
decryption. What remains per non-owned coin is a single elliptic-curve
scalar-multiplication (the shared secret) plus that hash; the heavy
commitment-recomputation runs only for coins the wallet actually owns.

A view tag is derived *from* that shared secret, so it cannot avoid the one
operation that dominates — computing the shared secret *is* the
scalar-multiplication — and the tail it would save is already a hash compare.
So a view tag would buy Spark almost nothing while costing a coin-format
consensus change. **We reject it.** This is exactly the kind of result the
"measure before you build" discipline exists to catch.

### 5.3 What actually makes Spark scanning fast
The scan cost is `pool_size × (one scalar-mul + one hash)`. The lever is the
scalar-mul, and it is attacked **without any consensus change**:
- **Parallelize** the per-coin `K · s1` across a block's coins and across blocks.
- Use an **optimized fixed-scalar multiplication** for the wallet's view scalar.
- **Cache** cover-set anchors and scan position so resume is incremental.

All of this is wallet-side and ships now, with no consensus change. The only piece
of the scanning story that must wait is **oblivious light-client scanning (OMR, v8)** —
a different problem (don't scan the chain at all), not a view tag. The net effect
of B1 is that v3's scanning win got *simpler and sooner*: no coin-format fork.

### 5.4 Addressing
Spark's diversified addresses already let one spend key mint unlimited unlinkable
receiving addresses. v3 standardizes a deterministic sub-address derivation
(index → diversifier) and a bech32m encoding, so a wallet can hand out a fresh
address per invoice without new keys and without address reuse. This is key
management and encoding only — no on-chain change.

### 5.5 What ships when
v3 splits cleanly:
- **Now, wallet-only (no consensus change):** parallel and batched scan,
  witness/anchor caching with incremental resume, deterministic sub-addresses, and
  view-only wallets. These deliver a felt improvement without touching the
  consensus wire format.
- **Later (gated):** nothing in v3's core scanning win — B1 dropped the coin-format
  fork. The only scanning work that must wait is oblivious light-client scanning (OMR),
  which is tracked separately as v8.

---

## 6. Honest limitations

- **Claims are unvalidated until measured.** The scan speedup, the proof-aggregation
  savings, and the privacy theorem in §5.3 are *projected* until a prototype and a
  benchmark (and, for the theorem, a proof) exist. This paper will carry the
  numbers only once they do.
- **On-wire advancements need a coordinated fork and independent review.** Nothing on-wire
  activates before that review completes.
- **Composition risk.** Adding layers to a proven protocol can introduce
  interactions the base construction never had. Each version is reviewed not only
  in isolation but for its effect on the properties of the versions beside it.
- **OMR is frontier.** v8's oblivious retrieval is younger and heavier than the
  rest of the program and is sequenced accordingly.

---

## 7. Credits & references

CoinCync's shielded engine is **Lelantus-Spark**, by **Aram Jivanyan and Aaron
Feickert**; this program extends their protocol and does not claim their work as
its own. The scanning advancements draw on the view-tag designs of **Zcash
Sapling** and **Monero's Jamtis**; threshold custody draws on **FROST**; the
honesty posture and layered-privacy framing follow the companion **Cynstra**
whitepaper.

*(Formal citations to the Lelantus-Spark paper, the Sapling and Jamtis
specifications, and the FROST paper to be added in the next revision.)*

---

*Draft v0.1 — 2026-11-11. Program thesis and v3 scope set with the maintainer.
Next revisions land measured numbers (B1, scan benchmark), the §5.3 theorem, and
formal references. Companion spec: `docs/design/cip-spark-v3-scanning.md`.*
