<!-- markdownlint-disable MD036 -->
# CIP-005 — Lelantus Spark

**Status:** Sketch (pre-Draft)
**Type:** Standards Track (consensus change, hard fork)
**Created:** 2026-05-07
**Layer:** Consensus + Wallet
**Depends on:** none (composes with, but does not require, CIP-003 / CIP-004)

---

## Abstract

Activate Firo's Lelantus Spark protocol as an alternative private-spend mechanism alongside CLSAG-16 ring signatures. Spark uses a **one-out-of-many proof** over a vector commitment to the entire historical anonymity set — currently capped at 16,384 coins, roughly 1000× the anonymity set of a CLSAG-16 ring. Each spend produces a serial tag that lets verifiers detect double-spends without learning anything about which coin was spent.

CoinCync's existing `src/crypto/lelantus_spark.rs` (906 LoC) implements the Schnorr-style one-out-of-many proof construction over the same Ristretto primitives used by CLSAG. This CIP defines the activation path: how Spark spends are encoded in transactions, how the chain maintains the Spark accumulator state, and how wallets mint and spend Spark notes.

---

## Motivation

**Anonymity-set ceiling.** CLSAG-16 caps the per-input anonymity set at 16 ring members. For most users this is fine — 16 decoys is enough to defeat casual chain analysis — but for high-value transactions or transactions in low-volume periods, 16 decoys can be statistically thin. Spark's 16,384-element set is structurally three orders of magnitude harder to deanonymize.

**Defense in depth via primitive diversity.** CLSAG and the one-out-of-many proof rest on different cryptographic assumptions. A future cryptanalysis attack against CLSAG (or its specific Schnorr ring construction) does not automatically break Spark, and vice versa. Users gain resilience to single-primitive failures.

**Optional, not mandatory.** Unlike Articles III's mandatory privacy primitives, Spark is an additional spend mode. CLSAG-16 remains the default. Users opt into Spark for high-anonymity-set spends; the cost is a larger proof (~3 KB versus ~1 KB for CLSAG-16) and slightly higher verification time.

---

## Status & Implementation

**Sketch (pre-Draft).** Implementation surface exists but is gated behind the `sketch-lelantus-spark` cargo feature, which is OFF by default. Default builds do not compile [`src/crypto/lelantus_spark.rs`][lib]; the production audit perimeter is unchanged.

The existing 906-LoC implementation provides:

- `SparkNote` — a minted coin with secret serial, blinding factor, value
- `SparkAccumulator` — vector commitment over the entire mint history
- `SparkSpendProof` — Schnorr-style one-out-of-many proof over a 16,384-coin window, plus a serial-tag double-spend detector
- Mint, spend, and verification functions

Activation is gated by a new `Chain.spark_state: Option<SparkAccumulator>` field (not yet defined) staying as `None` until this CIP reaches Active.

**Activation requires:**

1. CIP-005 reaches Active via 95% miner version-bit signaling
2. New transaction type `TxType::SparkSpend` added to `src/transaction/types.rs`
3. Block header gets a `spark_set_root: [u8; 32]` field committing to the post-block accumulator state
4. Mempool validates Spark spends against the current accumulator + serial-tag history
5. Wallet adds `mint_spark` / `spend_spark` operations alongside existing CLSAG flows

[lib]: ../../src/crypto/lelantus_spark.rs

---

## Mechanism

### Mint

A Spark mint creates a coin with:

```text
SparkNote = (v, s, r)
C = v*G + s*H + r*K
```

Where `G` is the standard Ristretto basepoint, `H` is the value generator (matching Pedersen commitments), and `K` is a third independent generator dedicated to Spark serials. The owner publishes only `C`; `(v, s, r)` stays in the wallet.

The chain appends `C` to the Spark accumulator and updates `spark_set_root` in the next block header.

### Spend

To spend a Spark coin at position `l` in the accumulator:

1. The wallet derives a "coin key" `x_l` such that `x_l*G = C_l - v*G - r*K` — i.e. the `H`-coefficient of the commitment.
2. The wallet emits a Schnorr ring signature over the public keys `P_i = (C_i - v*G - r*K)` for every `i` in the anonymity set, signing with `x_l` at the real position. This is the `SparkSpendProof`.
3. The wallet emits a **serial tag** `T = s*G`. The tag is deterministic from the secret serial `s`, so spending the same coin twice yields the same tag — verifiers detect double-spends by tracking the set of seen tags.
4. The transaction outputs are normal CoinCync outputs (Pedersen commitments + Bulletproofs+ range proofs).

Verification:

- Recompute the public keys `P_i` from the published anonymity set and the spent value `v` (which is published in cleartext or committed via Bulletproofs+).
- Verify the Schnorr ring signature.
- Reject if `T` has been seen before in any prior block.

### Anonymity-set window

Spark's proof verifies in O(log N) where N is the anonymity-set size. At N = 16,384, the proof is ~3 KB and verification is ~50 ms on a modern CPU. The window is rolling: each spend specifies its own 16,384-coin slice of the accumulator, anchored at a recent block height.

This gives users explicit control over the anonymity set used for a given spend: a more recent window is faster to verify but smaller; an older window includes more historical coins but is slower for the verifier (one extra accumulator traversal step per ~10,000 mints in between).

---

## Privacy Properties

**Spend privacy.** Observers learn that a Spark spend occurred and see the 16,384-coin window referenced. They do not learn which coin within that window was spent.

**Cross-spend linkability.** Two Spark spends from the same wallet are unlinkable as long as the spent coins were from independent mints. The serial tag `T` is per-coin, not per-wallet.

**Sender / receiver identity.** Unchanged — Spark spends produce normal Pedersen-committed outputs that go through the existing stealth-address machinery.

**Compatibility with CLSAG-16.** Spark and CLSAG operate on the same chain, on the same UTXO set. A wallet can hold both Spark and CLSAG outputs and choose per-spend which mode to use. CLSAG inputs and Spark spends can mix in the same transaction.

---

## Security Considerations

**Serial-tag uniqueness.** The serial `s` MUST be drawn from a high-entropy CSPRNG at mint time. A predictable serial allows an attacker to compute the tag and front-run the genuine spend, locking the coin permanently. The reference implementation uses `OsRng`, matching every other key-generation path in CoinCync.

**Accumulator integrity.** The Spark accumulator is a Merkle-style vector commitment. The chain header commits to its root; a node that loses the historical mint sequence cannot reconstruct it without re-syncing from genesis (or from a trusted snapshot anchor). Nodes operating after CIP-005 activates MUST persist the mint sequence.

**Anonymity-set freshness.** A user spending a freshly-minted coin into a window where their own mint is the most recent entry has a smaller effective anonymity set (the rolling window has fewer "older" decoys). Wallets SHOULD enforce a minimum mint-age (e.g. 100 blocks) before allowing a Spark spend.

**Performance under load.** Spark proof verification is ~50× slower than CLSAG-16 verification. A block packed with 100 Spark spends takes ~5 seconds to fully verify versus ~100 ms for CLSAG-only. This affects fee market design: Spark spends MUST carry a higher fee floor proportional to verification cost.

---

## Constitutional Fit

| Article | Constraint | This CIP |
|---|---|---|
| Article III — Mandatory privacy | All transactions must be privacy-preserving | ✅ Spark is a privacy-improving alternative; mandatory privacy is preserved by both CLSAG and Spark |
| Article XIV — Hard-fork procedure | 95% miner signaling + version bits | ✅ Required activation path |
| Article XV — Spirit and Construction | No mechanisms that reduce decentralization | ✅ Verification is single-threaded but feasible on Pi-class hardware (~50 ms per spend) |
| Article XVI — Constraints on emission/fees | Fee market unchanged | ⚠️ Spark spends require a higher fee floor; this CIP modifies the fee multiplier table for Spark transactions |
| Article XVIII — Interpretation | Node operators decide via fork acceptance | ✅ Standard CIP process |

**No constitutional articles are amended by this CIP**; Article XVI's fee-multiplier table is a parameterized config, not a constitutional clause.

---

## Open Questions

1. **Default spend mode.** Should new wallets default to CLSAG (smaller proof, faster verify) or Spark (larger anonymity set, slower verify)? Open question pending UX research.

2. **Spark-only mode.** Should a future CIP-006 deprecate CLSAG and make Spark the only spend mode? This would reduce primitive diversity (against the defense-in-depth motivation) but eliminate the dual-flow audit cost.

3. **Mint-age minimum.** What's the right value for the wallet-side mint-age guard against own-mint anonymity-set thinness? Grin uses 1440 blocks (1 day at 60s); CoinCync at 120s blocks → 720 blocks for the same wall-clock window. Open question: 720 or tighter?

4. **Batch verification.** A block with multiple Spark spends could in principle batch-verify them faster than verifying each independently. Reference implementation does not; future optimization deferred to a separate CIP.

---

## Implementation Plan (after Discussion → Active)

1. Define `Chain.spark_state: Option<Arc<SparkAccumulator>>` in `src/chain.rs`.
2. Add `TxType::SparkSpend` variant to `src/transaction/types.rs`; define encoding for `SparkSpendProof` and serial tag.
3. Add `spark_set_root: [u8; 32]` field to `BlockHeader` in `src/consensus/header.rs`. Initialize to `[0u8; 32]` for pre-fork blocks.
4. Wire mint logic into block validation: every Spark mint output appends to the accumulator; the block header's `spark_set_root` must match the post-append root.
5. Wire spend logic into mempool: maintain a serial-tag set, reject txs whose tag is already in the set, validate the one-out-of-many proof against the spend's specified accumulator window.
6. Add wallet mint / spend operations in `src/wallet/`. Schema migration: add `spark_notes` table (mint position, value, serial, blinding, status).
7. Update `critical_files.lock` for `src/transaction/types.rs` and `src/consensus/header.rs`.
8. Add fuzz target over the one-out-of-many proof construction.
9. Propose miner version-bit assignment, transition status from Discussion → Active.

---

## References

- "Lelantus Spark" by Aram Jivanyan & Aaron Feickert (2021) — original protocol specification
- Firo (formerly Zcoin) — production Lelantus Spark deployment since 2022
- "One-out-of-Many Proofs" by Groth & Kohlweiss (2015) — the underlying proof construction
