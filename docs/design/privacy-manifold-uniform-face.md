<!-- markdownlint-disable MD036 -->
# Underground — The Privacy Manifold (one face for many schemes)

**Status:** Design note (idea stage — pre-CIP)
**Type:** Standards Track candidate (transaction format + consensus + wallet)
**Created:** 2026-09-09
**Layer:** Transaction envelope + Consensus (verification dispatch) + Network (traffic shape)
**Depends on:** [CIP-005 — Lelantus Spark](../cip/CIP-005-lelantus-spark.md), `src/crypto/privacy_connector.rs` (the connector this generalises)
**Status of crypto:** Invariants #1, #2, #4, #5 are engineering (no new crypto). Invariant #3 (shared anonymity set) is new cryptographic design and MUST be audited before it is live.

---

## The mechanical idea

On an oil rig, many wells feed a **manifold**. Once flow is commingled into the export pipeline, you cannot tell which well a barrel came from. Plumbing does the same with **connectors** (sealed couplings that join pipes without letting them foul each other), **standard fittings** (any pipe mates with any other because the diameters are fixed), **check valves** (flow goes one way — no backflow), and a **blind flange** (an unused port is capped, sealed shut).

CoinCync should treat its privacy schemes the same way. Today CLSAG, Spark, MimbleWimble, and the shielded pool are separate pipes. If we ever run more than one, an outside observer sorts every transaction by which pipe it came out of — and separate pipes mean **separate, smaller anonymity sets**, which is how privacy features "eat each other." The fix is a **privacy manifold**: the schemes stay isolated *inside* (sealed connectors), but everything leaves through *one export pipeline* that looks identical no matter which well fed it.

**One sentence:** inside, many schemes; outside, one face.

| Rig / plumbing part | Blockchain mechanism |
|---|---|
| Sealed connector / coupling | `privacy_connector.rs` — isolates each scheme so one can't reach into another or into consensus |
| Manifold (commingled export) | One shared anonymity set — origin scheme is untraceable at the output |
| Standard fittings (fixed diameter) | Fixed-size transactions — every spend is the same byte length on the wire |
| Check valve (no backflow) | One uniform nullifier format — prevents double-spend, same shape for every scheme |
| Blind flange (capped port) | Fail-closed gate — `CONNECTOR_AUDITED = false`, `start_height = u64::MAX` until a scheme is audited |

---

## Why (the problem this solves)

Privacy features cannibalise each other in five ways. A real solution has to survive **all five**, and the trap is closing one while opening another:

1. **Anonymity-set fragmentation** — a second scheme splits users into two smaller pools; both are weaker than one big pool. (This is what hollowed out Zcash in practice.)
2. **Conversion linkage** — moving value between two pools links them. (CoinCync's cross-scheme value converter is a `STUB — NOT A REAL CONVERTER` precisely because of this.)
3. **Optionality fingerprint** — using an optional feature marks you as one of the few who did.
4. **Metadata divergence** — different proof sizes, fees, and timing let an observer sort users without breaking any crypto.
5. **Disclosure leakage** — "let someone see" features over-reveal. (Partly addressed already by scoped view keys.)

The insight that reframes all of this: **the adversary is the outside observer, not the schemes.** Making the schemes blind to each other (isolation) is good safety hygiene but does nothing for the observer — and isolated pools make fragmentation *worse*. So the manifold must do two jobs at once: **isolate inward** (connectors, for safety) and **unify outward** (one indistinguishable face, for anonymity).

---

## The five invariants

### 1. One envelope — never a per-scheme transaction type
The live transaction type stays `{Coinbase, Transfer, Churn}` (`transaction/types.rs`). We do **not** add `TxType::Spark` / `TxType::Shielded` — that enum variant *is* the fingerprint. A spend of any scheme is a `Transfer` carrying an **opaque, fixed-layout proof blob**. Which verifier runs is chosen from a **committed/encrypted selector**, never a plaintext "scheme = 2" byte. *(This hidden selector is the single most important thing to get right — see Hard parts.)*

### 2. Standard fittings — fixed-size proofs
CLSAG (~1 KB), Spark (~3 KB+), and shielded proofs are different sizes; size alone classifies them. Every spend proof is padded to a **fixed ceiling `L`** so all transactions are byte-identical in length. Everyone pays the max size — that bandwidth cost *is* the privacy (same reason Tor pads its cells). Pure engineering, no new crypto. Highest leverage for the least risk; build it first.

### 3. The manifold — one shared anonymity set
The deep one, and the only part that is new cryptography. Instead of CLSAG drawing decoys from the UTXO set and Spark from its own accumulator, **every output enters one global commitment accumulator**, and *every* scheme proves "I own one coin in this single set." The proof systems differ internally; the **hiding set is shared**, so there are no separate pools to fragment. CoinCync already has the seed — `SparkAccumulator` / `storage/spark.rs` is a global accumulator over all coins; this extends it to hold *all* outputs and points every scheme's membership proof at the same root. **This part must be prototyped and audited before it is live.**

### 4. Check valve — one nullifier format
Double-spend tags differ per scheme (key images for CLSAG, serial tags for Spark) and are themselves a distinguisher. Normalise: every spend emits a **32-byte nullifier in one identical format** into one shared spent-set, whatever the scheme. The connector maps each scheme's native tag into the common space. Cheap; closes a distinguisher most designs miss.

### 5. One export pressure — uniform fees and timing
- **Fees:** one schedule keyed off the uniform size `L`, not per-scheme, so the fee can't leak the scheme.
- **Timing / propagation:** every spend goes through the same Dandelion++ stem and the existing traffic-shaping (`network/dandelion.rs`), so the wire footprint is identical.

---

## What code it touches

| Area | Change | Risk |
|------|--------|------|
| `transaction/types.rs` | keep one spend type; add an opaque fixed-layout proof container + committed scheme selector | medium — format change, needs care that the selector never leaks |
| `crypto/privacy_connector.rs` | become the manifold: dispatch verification on the committed selector with near-constant work; present ONE `verify_spend()` interface to consensus | medium |
| `consensus/validation.rs` | call the single uniform verifier instead of scheme-specific paths | medium; consensus-critical, needs tests |
| proof encoders (`clsag.rs`, `lelantus_spark.rs`, …) | pad every proof to fixed size `L` | low |
| `storage/` accumulator + nullifier set | one global accumulator (invariant #3); one nullifier format (invariant #4) | **high (invariant #3) — new crypto, audit-gated** |
| `mempool.rs` / fee schedule / `network/dandelion.rs` | uniform fee on size `L`; shared stem + shaping | low–medium |

---

## The two things that will actually bite

1. **The selector leak.** Any observable "which scheme" hint — a byte, a size, a fee quirk, or a *timing* difference in verification — undoes the whole feature. Verification must present one interface and do near-constant work; the connector dispatches internally on a committed hint. Assume an adversary with a stopwatch.
2. **The shared accumulator is real cryptography.** Invariants #1, #2, #4, #5 are format/engineering you can ship without new crypto. Invariant #3 — one anonymity set spanning different proof systems — is research-adjacent and must be prototyped behind the existing feature flag and externally reviewed before activation. Do not ship it on vibes; that is how you build a more original way to lose funds.

---

## The MVP (shippable now, no new crypto)

You do not need a second scheme live to start — and this is the clever part: **freeze the uniform face now, while only CLSAG is live.** Lock in invariants #1 (one envelope), #2 (fixed size `L`), #4 (one nullifier format), and #5 (uniform fee/timing) today, so the *shape* is frozen. Then when Spark (or any scheme) turns on, it is **already wearing the same face** — no fork-visible change, no new fingerprint, because the mask predates the second actor walking on stage. Invariant #3 (the shared accumulator) comes later, behind the audit.

This MVP is pure engineering and it is the highest-value thing in the note: it makes the differentiator *true in production* the day it ships, instead of waiting on the hard crypto.

---

## Honest limits

- **This is mostly a format/architecture guarantee, not a new primitive** — except invariant #3, which is. That is a feature: most of it ships without cryptographic risk.
- **Fixed size `L` costs bandwidth.** Everyone pays the largest proof's size. Real tradeoff, not free.
- **A shared anonymity set couples the schemes' failure surface.** If one scheme's proof system is broken, it can mint into the *shared* set. Invariant #3 needs a soundness argument that a break in scheme A can't forge membership usable by scheme B. This is the crux the audit must settle.
- **Still rides on the schemes themselves.** Spark is `sketch`, off by default, and unaudited; the manifold does not change that. It changes how schemes are *presented*, not whether they are sound.

---

## Open questions

1. **Selector construction.** How is the scheme selector committed so the verifier can route without any public discriminator, and with constant-time dispatch?
2. **`L`.** What fixed size accommodates the largest intended proof without crippling bandwidth? Bucket or single value? (Buckets reintroduce distinguishability.)
3. **Shared-accumulator soundness.** Can CLSAG-style and Spark-style membership proofs share one accumulator without a break in one enabling a forge in the other? This is the audit-blocking question.
4. **Graduation.** MVP (invariants #1/#2/#4/#5) as a near-term transaction-format change; invariant #3 as a later, audited hard fork — one CIP or two?

---

## Next steps

1. Prototype the fixed-size envelope + committed selector behind the existing feature flags, with a test that two different schemes produce byte-identical transactions.
2. Add a distinguisher test-suite: given a mixed set of transactions, assert an observer cannot classify them by size, fee, nullifier format, or verification timing.
3. Draft the shared-accumulator soundness claim precisely enough to hand to the same reviewer track as the Spark spend proof.
