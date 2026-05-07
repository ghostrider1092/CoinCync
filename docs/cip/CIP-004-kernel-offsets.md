<!-- markdownlint-disable MD036 -->
# CIP-004 — Kernel Offsets

**Status:** Sketch (pre-Draft)
**Type:** Standards Track (consensus change, hard fork)
**Created:** 2026-05-07
**Layer:** Consensus + Transaction format
**Depends on:** CIP-003 (cut-through + block-level aggregation)

---

## Abstract

Adopt MimbleWimble-style **kernel offsets** as a complement to CLSAG-16 ring signatures. A kernel offset is a single curve point — `r_offset * G` — that a sender adds to a transaction's blinding factors before signing the kernel. The kernel signature is then over `excess + offset`, and the offset is published in the transaction. This breaks the otherwise-direct linkage between input and output blinding factors: even if a future cryptanalysis or implementation flaw recovered an output's blinding factor, the offset prevents that knowledge from chaining backward to identify the spending transaction.

Combined with CIP-003 cut-through and block-level aggregation, kernel offsets give CoinCync transaction-graph privacy that does not depend solely on ring-signature decoy quality.

---

## Motivation

**Defense in depth for the privacy stack.** CLSAG-16 hides which ring member spent — but only as long as the cryptography holds. Future attacks against any of the underlying primitives (ed25519, BLAKE3 domain tags, the specific CLSAG construction) would weaken ring privacy. Kernel offsets add a *separate* unlinkability layer: even if rings break, the kernel offset still prevents identifying a transaction's predecessor by blinding-factor inspection.

**Smaller transactions on average.** A kernel offset is a single 32-byte curve point. After CIP-003 aggregation, a block's kernels combine into one aggregate kernel; the offsets within the block aggregate too, into a single 32-byte block offset. Per-block byte cost: 32 bytes. The savings versus per-transaction kernels with separate signatures: 96 bytes × N transactions. On a typical 50-tx block, this saves ~4.7 KB.

**Composability with CIP-003.** Cut-through prunes spent outputs; block aggregation merges per-tx kernels. Kernel offsets are what make the aggregation cryptographically sound — without offsets, the aggregate kernel reveals more than the sum of its parts (specifically, common blinding factors leak). Grin's protocol pairs them for exactly this reason.

---

## Status & Implementation

**Sketch (pre-Draft).** No production-path code; no consensus impact today. Implementation surface reserved at:

- [`src/crypto/kernel_offset.rs`](../../src/crypto/kernel_offset.rs) — `KernelOffset` and `OffsetExcess` types, all method bodies are `unimplemented!()` panics. Compiled only when `sketch-kernel-offsets` feature is enabled (off by default).

The stub exists so the trait surface and storage layout for the eventual CIP are reserved without committing to the cryptographic implementation.

**Activation requires:**

1. CIP-003 must be in Active status first (this CIP composes on cut-through + aggregation infrastructure)
2. CIP discussion window (60+ days)
3. Reference implementation that wires `KernelOffset` into the transaction-builder + block-aggregator paths
4. Audit pass on the offset construction (focus area: nonce generation, offset randomness)
5. 95% miner version-bit signaling at the fork height (Article XIV)

---

## Mechanism

### Per-transaction offset

When a wallet constructs a transaction, after computing the per-input/per-output Pedersen commitments, it generates a fresh random scalar `r_offset`. The kernel excess becomes:

```text
excess_unblinded = sum(r_out) - sum(r_in)
excess_published = excess_unblinded - r_offset

kernel = {
    excess: excess_published * G,
    signature: schnorr_sign(privkey = excess_published, message = tx_data),
    fee: <unchanged>,
    offset: r_offset,                    // 32 bytes, NEW
}
```

Verifiers check the kernel signature using `excess + offset*G` as the implicit signing key — this matches `excess_unblinded * G`, which equals `(sum(r_out) - sum(r_in)) * G`, which equals `(sum(v_out) - sum(v_in) + fee) * G = fee * G` if and only if values balance.

### Block-level offset aggregation

When CIP-003 aggregation combines kernels in a block:

```text
block_kernel = {
    excess: sum(kernel_i.excess),
    signature: musig2_aggregate(kernel_i.signature for i in txs),
    fee: sum(kernel_i.fee),
    offset: sum(kernel_i.offset),         // single 32-byte aggregate
}
```

The block contains one aggregate offset for the entire block. Per-transaction offsets are not retained.

### Storage impact

After cut-through (CIP-003) prunes the block's outputs and inputs, the surviving kernel record drops from:

```text
Pre-CIP-004: per-tx kernels = N * (32 + 64 + 8) = 104N bytes
With CIP-004: aggregate kernel + offset = 32 + 64 + 8 + 32 = 136 bytes per block
```

For a block with 50 transactions: ~5.0 KB → 136 bytes. The compression ratio improves with throughput.

---

## Security Considerations

**Offset randomness is the security boundary.** A predictable `r_offset` provides no defense — an attacker who knows the offset can subtract it back out and recover the original blinding-factor relationship. The reference implementation must use the platform CSPRNG (`getrandom` crate, identical to existing key-generation paths) and must NOT derive the offset from any transaction-visible value.

**Aggregation must be order-independent.** Within a block, kernel offsets are summed. The order miners pack transactions in the block must not affect the aggregate offset (the offset is the same whether txs A then B or B then A — addition is commutative). The reference implementation must include test cases verifying order-independence.

**Wallet recovery.** Kernel offsets are not stored in the wallet — they're consumed at signing time. A wallet rescanning history after disk loss does not need to reconstruct historical offsets. The chain-side aggregate offset is sufficient for kernel verification.

**Composability with disclosure proofs.** Per-tx audit (per CIP-003 security considerations) requires the original transaction transcript including the original `r_offset`. Wallet must persist offsets in its outgoing-tx record alongside the existing fields. Schema migration: add `offset_blob: [u8; 32]` to `wallet_tx_outgoing` table.

**Interaction with stealth addresses + view keys.** Kernel offsets do not affect stealth-address derivation or view-key scanning — those work on output public keys, not on kernel excesses. No changes to `src/wallet/scanner.rs` or `src/wallet/view_keys.rs` required for this CIP.

---

## Constitutional Fit

| Article | Constraint | This CIP |
|---|---|---|
| Article III — Mandatory privacy | Privacy must improve, not degrade | ✅ Adds an unlinkability layer that does not depend on CLSAG ring soundness |
| Article XIV — Hard-fork procedure | 95% miner signaling + version bits | ✅ Required activation path |
| Article XVI — Constraints on emission/fees | Fee math unchanged | ✅ Per-block fee remains `sum(tx fees)` |
| Article XVIII — Interpretation | Node operators decide via fork acceptance | ✅ Standard CIP process |

**No constitutional articles are amended.**

---

## Open Questions

1. **Activation gating with CIP-003.** Should CIP-004 hard-fork at the same height as CIP-003 (one combined upgrade) or strictly later (two sequential upgrades)? Combined is operationally simpler; sequential is auditor-friendlier (each fork has a narrower diff to review).

2. **Wallet storage migration.** Existing wallets don't have an `offset_blob` column. Migration must add the column with a NULL default for pre-fork transactions. Open question: should pre-fork transactions get a synthetic zero offset for uniform encoding, or a distinct `legacy_no_offset` marker?

3. **Compatibility with CIP-005 Lelantus Spark.** Spark spends use a different signature primitive (one-of-many proofs, not Schnorr). If CIP-005 ever activates, kernel offsets need a parallel construction for Spark spends. Open question: defer until CIP-005 is no longer Sketch?

4. **CSPRNG audit boundary.** The offset generator path (CSPRNG → wallet builder → kernel signer) must be auditable. Open question: should there be a `KernelOffsetGenerator` trait so test code can inject deterministic offsets for property-based testing without touching production CSPRNG paths?

---

## Implementation Plan (after CIP-003 Active → CIP-004 Discussion)

1. Promote `src/crypto/kernel_offset.rs` from stub to real: implement `KernelOffset::generate()`, `KernelOffset::aggregate()`, `KernelOffset::verify_against()`.
2. Add `offset` field to `Kernel` struct in `src/transaction/types.rs`.
3. Wire offset generation into `src/transaction/builder.rs` `Builder::sign_kernel`.
4. Wire offset aggregation into the `BlockAggregator` impl from CIP-003.
5. Add `offset_blob` column to `wallet_tx_outgoing` schema in `src/db/wallet.rs`.
6. Add migration for existing wallets (NULL → synthetic zero or marker).
7. Update fee-validation to verify `excess + offset*G` (not just `excess`).
8. Add property-based tests over random transaction sets verifying aggregation correctness + order-independence.
9. Update `critical_files.lock` for `src/transaction/types.rs` (kernel format change) and `src/constants.rs` (activation height).
10. Propose miner version-bit assignment, transition status from Discussion → Active.

---

## References

- Grin protocol — original kernel-offset specification (combined with cut-through)
- Beam protocol — production deployment of kernel offsets
- "MimbleWimble" by Tom Elvis Jedusor (2016) — original whitepaper introducing kernel construction
- Litecoin MWEB / LIP-002 — kernel offsets in a sidechain context
