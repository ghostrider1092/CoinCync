# CIP — Spark v3: scanning & addressing

**Status:** design (DRAFT; nothing built). Planning only. The on-wire parts are
**in a later phase** (coordinated fork, like the h29000 shielded activation); the
wallet-only parts can ship under the already-lifted CyncHub build freeze.
**Depends on:** the live v2 path — `SparkPayload`/`SparkPoolStore` (see
[[cip-spark-block-format]]), the libspark FFI connector
(`export_incoming_view_key`, `identify_view_only`, diversified addresses), and
CyncHub's background sync.
**Goal:** make finding your own shielded coins cheap. Today scanning is
`O(total pool coins)` full libspark recoveries per wallet per sync; this CIP cuts
the dominant cost with a **view tag** pre-filter and standardized **diversified
addressing**, split into a now-shippable wallet-only slice and a later (gated)
coordinated-fork slice.

Positioning: this is the near-term v3 thesis (chosen over FCMP++ full-chain
membership, which stays the long-horizon "v4" moat). See
[[coincync-next-gen-privacy-roadmap]], [[coincync-strategy-narrow-shielded]].

## 0. Guiding principle — EXTEND Spark, don't reinvent it
Spark (Lelantus-Spark, Jivanyan–Feickert) already reasoned through the hard
parts: the one-of-many accumulator, the view-key / diversifier key model, and
the VRF linking tags. The crypto-space reflex is to invent a *new* scheme; v3
does the harder, better thing — take that sound foundation and improve it. This
is also the selection rule for what belongs in v3:

- **In scope:** changes that are **additive layers on Spark's own primitives** —
  view tags on Spark coins, sub-addresses derived from Spark's diversifier, OMR
  over Spark's existing outputs. The proven core stays; we build on top.
- **Out of scope (defer):** anything that **replaces** a Spark primitive. FCMP++
  swaps out the membership proof entirely → not v3, by this rule. (That is *why*
  it is deferred, not just a timing call.)

This matches "the BEST verifiable-privacy chain, proven in the open — not the first"
([[coincync-position-best-not-first]]) and "build the hard thing"
([[coincync-build-the-hard-thing]]): improve the real cryptography, credit its
author, don't chase novelty for its own sake.

---

## 1. The problem (measured against the real code)

To find its coins, the wallet calls, for **every coin in every block**:

```
spark-connector: identify_view_only(ivk = (s1, P2), coin, serial_context)
    -> Ok(Some(IdentifiedCoin { value, memo })) | Ok(None)   // "mine" | "not mine"
```

`identify_view_only` is a full libspark recovery: it reconstructs the coin's
recipient key material from the incoming view key and checks it against the
coin's committed bytes. That is elliptic-curve work **per coin**, and ~all of it
is wasted — a wallet owns a vanishing fraction of the pool. As the pool fills
(post-h29000, then real traffic), this is the dominant wallet cost and CyncHub's
scanning bottleneck. There is **no cheap pre-filter** today: every coin pays the
full recovery.

What Spark already gives us (so v3 builds on it, not around it):
- **Incoming view key** `(s1, P2)` — watch-only identification (`export_incoming_view_key`).
- **Diversified addresses** — 11-byte diversifier, bech32m (`address_from_seed`,
  `IncomingViewKeyBytes`, `diversifier` in `lelantus_spark.rs`).
- **256-byte memos**, and **34-byte VRF linking tags** `T = (U−D)·s⁻¹` for spends.
- **No view tag** — nothing lets the scanner reject a non-owned coin cheaply.

---

## 2. Core mechanism — REVISED by B1: NOT view tags

> **B1 FINDING (2026-11-11, static analysis of libspark `Coin::identify`) —
> on-wire view tags are the WRONG lever for Spark.** This reverses the earlier
> Q1 lean. Why: Spark's identify already fast-rejects a non-owned coin the way a
> view tag would. In `AEAD::decrypt_and_verify` (`aead.cpp`) the FIRST step is
> `commit_aead(prekey)` compared to the coin's stored `key_commitment` — a single
> hash — which throws **before** any ChaCha20 decryption. The expensive
> trial-decrypt that Monero/Sapling view tags skip, Spark already skips. What
> remains per non-owned coin is **one EC scalar-mul** (`K · s1`,
> `coin.cpp:154/169`) plus that one hash; the EC-heavy `validate()`
> (`coin.cpp:111`) runs ONLY for owned coins. A view tag is derived FROM the
> shared secret, so it cannot remove the mul (computing the secret IS the mul),
> and the tail it would save is already a hash-compare. Net: a view tag buys
> ~nothing here and would cost a coin-format consensus fork. **Rejected for
> Spark.**
>
> **Revised v3 direction:** the scan cost is `pool_size × (one EC mul + one
> hash)`, so attack the **mul**, not the tail — (a) parallelize + optimize the
> per-coin `K · s1` (NOW, wallet-only, NO fork), and (b) OMR for light
> clients (v8). v3 becomes mostly Slice A; the coin-format fork is dropped. See
> revised §3.

*(Historical — the view-tag mechanism, kept for the record and to explain why it
does not transfer to Spark.)* Attach a short **view tag** (1 byte, tunable) to each coin, derived
deterministically from the ECDH shared secret between the coin's ephemeral key
and the recipient's incoming view key (Sapling / Jamtis style). On scan the
wallet computes the expected tag and compares one byte; only on a match does it
run the full `identify_view_only`. A 1-byte tag rejects ~255/256 non-owned coins
before the expensive tail → roughly two orders of magnitude fewer full
recoveries.

**Honest nuance — what the tag actually saves.** The recovery has two parts: (a)
derive the shared secret (the DH mul), (b) reconstruct the coin's value /
commitment / memo and check ownership. A Sapling-style tag is derived *from* the
shared secret, so it skips (b) for non-matches but **not** (a). The real win
therefore depends on libspark's split: if (b) dominates, the tag is a big win as
a pure wire add; if (a) dominates, we need a Jamtis-style construction where a
single cheap shared EC step gates the per-coin DH. **Open benchmark (B1):**
profile `identify_view_only` into (a)/(b) on the real backend before committing
to a tag design — the answer picks the construction.

**This is a coin-wire-format change** → it changes what the pool commits to →
**consensus** → fingerprint change → coordinated fork (in a later phase, own libspark
C++ change). It is NOT a wallet-side change.

### Privacy cost — weighed, and why a 1-byte tag is acceptable
A view tag is a **linkability surface**, so we justify it rather than wave it
through. The argument that it is an acceptable cost under **private by default +
large anon set** ([[coincync-privacy-adoption-vs-delisting]]):

1. **No cross-coin fingerprint.** The tag is derived from the *per-coin* shared
   secret, so two coins sent to the same address get independent, pseudo-random
   tags. An observer cannot use tags to cluster one recipient's coins — the
   failure mode of a careless construction, which the design forbids (tag MUST be
   per-coin unlinkable).
2. **Orthogonal to spend anonymity (Q4 theorem).** The tag rides on a coin's
   *receipt*; a **spend's** anonymity is the Grootle membership proof over the
   pool/cover set, which never reveals or uses the tag. So the tag cannot shrink
   the effective anon set of a spend. This is stated as a theorem to prove in the
   security section, not assumed.
3. **Marginal adversary gain is negligible.** A 1-byte tag only tells an observer
   a coin is in 1 of 256 buckets; owner, value, and address stay hidden behind the
   commitment and view key. It materially helps exactly one party — someone who
   *already holds your view key* and wants to scan faster, i.e. the intended use.
4. **Precedent + reversibility.** Sapling and Monero/Jamtis shipped 1-byte view
   tags after this same debate; the scan win (orders of magnitude) dominates the
   bounded linkability. Tag size is a **tunable parameter** (0 = none), and OMR
   (§5) remains the zero-on-wire-linkability alternative if further review disagrees.

Net: accept a 1-byte tag because its privacy cost is **provably bounded** (points
1–2) and its benefit is large (§1), and document that bound for review.

---

## 3. The two slices (this is the important split)

### Slice A — NOW, wallet-only, NO consensus change
Ships under the lifted CyncHub build freeze; no wire change, no fork, no gating
dependency. Real CyncHub wins now:
- **Parallel + batched scan.** Call `identify_view_only` across a block's coins
  in parallel; batch RPC block fetch (background_sync already has batching hooks).
- **Witness / anchor caching.** Cache cover-set anchors and per-wallet scan
  position so a resume is incremental, not a rescan (background_sync has reorg
  rewind + `RescanFrom` already).
- **Standardized diversified sub-addresses.** The diversifier already exists;
  define a per-payment sub-address scheme + encoding so users stop reusing one
  address (private-by-default, better anon-set usage). Wallet + address codec
  only.
- **View-only wallet UX.** `export_incoming_view_key` already supports watch-only;
  surface it in CyncHub (reviewer / watch wallets) — complements the disclosure
  work ([[coincync-aggregate-disclosure]]).

**Added by B1 — optimize the per-coin mul (still Slice A, no fork).** Since the
scan cost is dominated by the `K · s1` scalar-mul per coin, parallelize it across
a block's coins and across blocks, and use an optimized fixed-scalar mul for `s1`.
This is the primary v3 scanning win and needs NO wire change.

### Slice B — LATER (GATED)
- **OMR** (§5 / v8) — the light-client scanning path. This is now the ONLY
  later (gated) piece of the scanning story; the view-tag coin-format fork is
  **dropped** (B1: it buys ~nothing for Spark).

Rationale: B1 collapsed v3's scanning win into Slice A — wallet-only, shippable now,
no coin-format fork. That is a strictly better outcome (ships sooner, no consensus
risk). Slice B is reduced to the genuinely-different light-client problem (OMR),
gated on further review (the usual testnet-only discipline).

---

## 4. Addressing (sub-addresses)
Spark's diversified addresses mean one spend key can mint unlimited unlinkable
receiving addresses. v3 standardizes:
- A **sub-address derivation** (index → diversifier) so CyncHub can hand out a
  fresh address per invoice/contact without new keys.
- A **bech32m encoding** with a version/network HRP already in use
  (`address_from_seed` returns bech32m).
- **No on-chain change** — this is key management + encoding (Slice A).

---

## 5. OMR — Oblivious Message Retrieval (stretch / alternative)
Let a semi-trusted server scan the chain for a light client and return a small
digest, **without** learning which coins are the client's. This is the real
answer for mobile CyncHub (no full-chain download, no on-wire tag linkability).
It is heavy crypto (homomorphic retrieval), an own research + review track, and
would be **v3.5 / later (gated)**. Flagged here because it is the privacy-preserving
alternative to on-wire view tags (§2) — the two are a design *choice*, not a
sequence. **Q1 is resolved to view tags (§2); OMR is deferred to v3.5** as the
fallback if review rejects any on-wire linkability.

---

## 6. Open questions
- **Q1 (direction): RE-RESOLVED (2026-11-11, by B1) → NOT view tags.** B1's static
  analysis of `Coin::identify` shows Spark already fast-rejects via `key_commitment`,
  so an on-wire view tag buys ~nothing and would cost a fork (§2). v3's scanning
  win is instead (a) parallelize/optimize the per-coin `K · s1` mul (now, no
  fork) and (b) OMR for light clients (v8). The coin-format fork is dropped.
- **B1 (benchmark): the static analysis already answered the design question** (tag
  vs no-tag); a runtime profile of `identify` into mul-vs-tail now only needs to
  confirm the mul dominates (expected) and to size the Slice-A parallelism win.
- **B1 (benchmark):** profile `identify_view_only` into DH vs recovery-tail to
  pick the tag construction (Sapling-style vs Jamtis-style).
- **Q2 (tag size):** 1 byte (256×, more partitioning) vs none; is any on-wire
  linkability acceptable under the "best verifiable-privacy" positioning?
- **Q3 (format room):** does libspark's `Coin` serialization have a clean place
  for a tag, or does this need a CoinCync-side wrapper? (affects whether it's a
  libspark-core change or a payload-level add.)
- **Q4 (anon set):** prove a tag cannot shrink a spend's effective cover-set
  anonymity (membership proof is over the pool, tag is per-coin — should be
  orthogonal, but state it as a theorem to check).

## 7. Non-goals / constraints
- Does not touch the hash-locked consensus core; Slice B lands as a coordinated
  fork, never a unilateral core edit ([[coincync-fuse-box-standard]]).
- Disclosure stays off-chain ([[coincync-attestation-onchain-stamp]]); view-only
  keys are the watch path, not an on-chain reveal.
- Stays feature-gated and activation-locked until hardened
  ([[coincync-feature-freeze-finish-chain]]).
- No scope sprawl: this is the ONE near-term v3 track; FCMP++ membership is a
  separate, later CIP.

---

---

## Appendix A — The versioned extension roadmap (one advancement per version)

Spark evolves **one advancement at a time**, each a discrete, shippable version
that *extends* a Spark primitive (never replaces one — §0). v1/v2 are history; v3
is this CIP; v4+ are the candidate line, each to get its own CIP when it starts.
Every item is an extension of Spark's own foundation.

**Lineage so far**
- **v1 — native sketch.** CoinCync-native Halo2 `ShieldedStore`/`ShieldedPayload`. Legacy, gated off.
- **v2 — libspark Spark (LIVE at h29000).** Real Lelantus-Spark engine: accumulator, Grootle membership, VRF linking tags, Option-B bridge, batched verify.

**Primary version line (each = one headline advancement)**
- **v3 — Scanning & Addressing** *(this CIP).* Per-coin `K·s1` mul parallelize/optimize + incremental scan caching + Jamtis-style sub-addresses (B1 dropped view tags). *Kills the O(pool) scan, no fork.*
- **v4 — Proof Aggregation.** Block-level aggregated Grootle spend proofs; extends the batched-multiexp verify (D) from shared-multiexp to one proof per block. *Scaling / closes the Firo gap for good.* [fork] L
- **v5 — Payment Proofs.** Selective-disclosure receipts — prove you paid X without revealing the tx; compounds the aggregate-disclosure work ([[coincync-aggregate-disclosure]]). [pre] M
- **v6 — Threshold Spark.** FROST-style multisig / threshold on the spend key. [fork] L
- **v7 — Confidential Assets.** Multiple asset types sharing one anon set (Spark supports asset tags conceptually). [fork] L
- **v8 — OMR Light Scanning.** Oblivious outsourced scanning for mobile (the v3.5 stretch, promoted to its own version). [fork] L

**Cross-cutting tracks (continuous, not a single version — reinforce every version)**
- *Operational privacy:* auto-churn "ghost mode" ⚡, denomination/output uniformity, Dandelion++ for shielded propagation.
- *Verifiability (the moat):* provable total shielded supply, a public reproducible verifier + test vectors **contributed back to the Spark ecosystem**, and a formal/machine-checked spec of the core security properties.

**Per-item tags** *( [pre] now, wallet-side · [fork] later coordinated fork (gated) · S/M/L effort · ⚡ in-flight )*

| # | Idea | Version/Track | Tag |
|---|------|---------------|-----|
| 1 | ~~View tags~~ → per-coin mul parallelize/optimize (B1: tags don't help Spark) | v3 | [pre] M |
| 2 | Jamtis sub-addresses (Janus-resistant) | v3 | [pre] M |
| 3 | OMR oblivious scanning | v8 | [fork] L |
| 4 | Witness/anchor caching + incremental scan | v3 | [pre] S ⚡ |
| 5 | Aggregated spend proofs | v4 | [fork] L |
| 6 | Cover-set anchor precompute | v4 | [pre] M |
| 7 | Parallel/GPU batch verify | v4 | [pre] M ⚡ |
| 8 | Payment proofs / disclosure receipts | v5 | [pre] M ⚡ |
| 9 | Structured encrypted memos | v5 | [pre] S |
| 10 | Confidential asset types | v7 | [fork] L |
| 11 | Atomic shielded swaps / junction | Swap backend | [fork] L ⚡ |
| 12 | Deterministic sub-address derivation | v3 | [pre] S |
| 13 | View-only / reviewer keys in CyncHub | v3 | [pre] S ⚡ |
| 14 | Threshold / multisig Spark | v6 | [fork] L |
| 15 | Hardware-wallet Spark signing | v6 | [pre] M |
| 16 | Auto-churn "ghost mode" | Op track | [pre] M ⚡ |
| 17 | Denomination uniformity | Op track | [fork] M |
| 18 | Dandelion++ shielded propagation | Op track | [pre] S |
| 19 | Provable total shielded supply | Verify track | [pre] M |
| 20 | Public verifier + test vectors (contributed back) | Verify track | [pre] M |
| 21 | Formal / machine-checked spec | Verify track | [pre] L |

**Explicitly OUT (violates §0 — replaces, not extends):** FCMP++ / full-chain
membership swaps out Spark's membership proof. Parked as a far-horizon, separate
thesis; not on this line.

---

*Draft 1 — scope/thesis set with the user 2026-11-11; Q1 resolved to view-tags
core (OMR → v8). Next: run B1 (profile `identify_view_only`) before building the
tag; wallet-side Slice A + the v3 wallet items can proceed independently. Companion:
`docs/spark-extensions-whitepaper.md`.*
