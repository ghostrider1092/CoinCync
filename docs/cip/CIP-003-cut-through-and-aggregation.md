<!-- markdownlint-disable MD036 -->
# CIP-003 — Cut-Through and Block-Level Aggregation

**Status:** Sketch (pre-Draft)
**Type:** Standards Track (consensus change, hard fork)
**Created:** 2026-05-07
**Layer:** Consensus + Storage

---

## Abstract

Adopt two MimbleWimble-style chain-compaction techniques on top of CoinCync's existing CLSAG-16 / Bulletproofs+ / stealth-address privacy stack:

1. **Cut-through.** Once an output's commitment is spent by a later input, both can be erased from the canonical chain after a reorg-protection depth, leaving only the transaction *kernel* (excess commitment + Schnorr signature + fee). The chain stops growing linearly with cumulative spends.
2. **Block-level aggregation.** Within a single block, all transaction kernels can be combined into a single aggregate kernel. Observers see one set of inputs, one set of outputs, and one signature per block — they cannot reconstruct which inputs paid which outputs.

The two techniques compose: aggregation provides per-block transaction-graph privacy on top of ring signatures, and cut-through reclaims storage from already-aggregated history. Grin's chain runs at roughly 10× compression versus an equivalent transparent ledger; the same proof should hold here.

---

## Motivation

**The permanent-storage problem.** Every privacy chain accumulates state forever — every output ever created remains spendable until referenced as an input, and even after that the spend record is permanent. Monero's chain is approaching 200 GB after ten years. A CoinCync user running a node on a low-end laptop or Raspberry Pi five years post-mainnet will eventually hit storage exhaustion.

**The transaction-graph problem.** CLSAG-16 ring signatures hide *which* of a ring of 16 outputs was spent, but they don't hide that *some* output in that ring was spent. Repeated transactions in the same block, observed in linkable order, leak partial graph information through timing analysis and fee correlation. Block-level aggregation breaks the linkable order — every spend in a block becomes simultaneous.

**Why now (post-mainnet, not pre-mainnet).** Cut-through is a consensus-changing modification that requires a hard fork. The pre-mainnet codebase is being kept tight to minimize audit scope. After mainnet has demonstrated stability for ~12 months and the chain has accumulated enough real history to motivate compaction, this CIP becomes both economically necessary and operationally testable.

---

## Status & Implementation

**Sketch (pre-Draft).** No production-path code. Two implementation surfaces already exist in the tree:

- [`src/crypto/mw_cutthrough.rs`](../../src/crypto/mw_cutthrough.rs) — the `CutThroughEngine`, `MwKernel`, and `CutThroughStats` types. Currently inert: `Chain.cut_through: Option<...>` is constructed as `None` everywhere.
- [`src/network/block_aggregation.rs`](../../src/network/block_aggregation.rs) — interface stub for the per-block kernel aggregator. Compiled only when `sketch-block-aggregation` feature is enabled (off by default).

Both modules exist so the compile graph and storage layout for the eventual CIP are reserved. Activation is gated by the `cut_through: None` initialization remaining unchanged in `src/chain.rs` until this CIP reaches Active status.

**Activation requires:**

1. CIP discussion window (60+ days, per the CIP process)
2. Reference implementation that flips `cut_through: Some(...)` and wires the aggregator into the block-validation path
3. Audit pass on the activation diff specifically (not on the existing inert modules — those are already in audit scope)
4. 95% miner version-bit signaling at the fork height (Article XIV)
5. Coordinated upgrade window for node operators

---

## Mechanism — Cut-through

A CoinCync transaction's outputs commit value via Pedersen commitments `C = v*G + r*H`. When a later input spends `C`, the chain has both `C` (in the earlier block's output set) and `C` (in the later block's input set, referenced by ring + key image).

After `MW_CUTTHROUGH_DEPTH` blocks (target: 100, matching the reorg-defense window), the engine identifies cut-through candidates: pairs `(output_block_height, input_block_height)` where the same commitment appears as both an output and an input.

For each candidate, the chain replaces the (output, input) pair with a single **kernel record**:

```text
kernel = {
    excess: Point,        // sum(r_out) - sum(r_in) on G
    signature: Signature, // Schnorr signature with excess as the key
    fee: Amount,          // unchanged
}
```

The kernel proves the original transaction balanced (`sum(out) - sum(in) = fee`) without retaining either side individually. Verifiers re-check the kernel signature against the kernel excess; storage drops the original output and input records.

**Reorg safety.** Cut-through is applied only after `MW_CUTTHROUGH_DEPTH` confirmations — deeper than the `H-16 / 100-block` reorg-defense window. A re-org at depth ≥ `MW_CUTTHROUGH_DEPTH` is a black-swan event already considered out of scope by the rest of the protocol; cut-through inherits that posture.

**Ring-signature interaction.** CLSAG-16 spends reference *output commitments* by ring position. Cut-through removes some output commitments after they are spent. The chain retains a **historical anchor set** — a Merkle root over all ever-existing commitments — so ring members can still be referenced by historical position even after their underlying commitments are pruned.

---

## Mechanism — Block-level Aggregation

Each transaction in a candidate block produces a kernel as above. The aggregator combines kernels from the same block:

```text
agg_kernel = {
    excess: sum(kernel_i.excess),
    signature: musig2_aggregate(kernel_i.signature for i in block_txs),
    fee: sum(kernel_i.fee),
}
```

The block contains: input set (union of all transaction inputs), output set (union of all transaction outputs), and one aggregate kernel. There is no per-transaction grouping visible on chain.

This produces **on-chain CoinJoin** for free: every block is structurally indistinguishable from a single mass-CoinJoin of every transaction it contains.

**Privacy properties added:**

- Within a block, inputs and outputs cannot be paired by transaction (transaction graph erased at block scale)
- The fee market continues to work — total block fee is the sum of individual fees, and miners select transactions for inclusion the same way
- Existing CLSAG-16 ring signatures continue to hide the spend within each input — this CIP composes additively

**Privacy properties NOT added:**

- Cross-block transaction linkage (still requires Dandelion++ + ring sigs + traffic shaping for that)
- Sender / receiver identity (still requires stealth addresses)

---

## Security Considerations

**Cut-through is irreversible.** Once the original output is pruned from disk, recovering its blinding factor requires the receiver's wallet history. A node that loses its wallet AND attempts to re-scan the chain *after* cut-through has occurred for that wallet's outputs cannot recover them. The recommended mitigation is the existing wallet-rescan cadence: rescan before every backup, never let a wallet drift more than `MW_CUTTHROUGH_DEPTH` blocks behind without confirming via a held copy of the original output set.

**Aggregation breaks selective disclosure.** A user who wants to prove a single transaction occurred (e.g., for tax accounting) cannot do so on-chain after aggregation — the per-tx kernel no longer exists. Existing CoinCync support for **scoped view keys** and **disclosure proofs** (`src/crypto/disclosure.rs`) handles this off-chain: the user retains the original transaction transcript and proves it cryptographically to a verifier of their choosing. This CIP must not be activated until disclosure-proof tooling is mature enough that users won't lose access to per-tx auditability.

**Ring members must remain referenceable.** Ring signatures pick decoys from historical outputs. If cut-through prunes those outputs, a verifier checking an old ring signature must be able to re-derive the ring members. The historical anchor Merkle root preserves this property — implementation must ensure no ring signature ever references an output prunable before its own block's signature is verified.

**Aggregation is a cryptographic operation, not just storage.** Combining MuSig2 signatures requires careful nonce-handling. A bad implementation can leak signing keys. Reference implementation must use a signature-aggregation library that has been independently audited (e.g., `schnorr_fun` or equivalent).

---

## Constitutional Fit

| Article | Constraint | This CIP |
|---|---|---|
| Article III — Mandatory privacy | Privacy must improve, not degrade | ✅ Adds block-graph privacy on top of ring signatures |
| Article XIV — Hard-fork procedure | 95% miner signaling + version bits | ✅ Required activation path |
| Article XV — Spirit and Construction | No mechanisms that reduce decentralization | ✅ Storage compaction *increases* decentralization (Pi-class nodes remain viable) |
| Article XVIII — Interpretation | Node operators decide via fork acceptance | ✅ Standard CIP process |

**No constitutional articles are amended by this CIP.** It strictly adds capabilities while leaving every privacy commitment intact.

---

## Open Questions

1. **MW_CUTTHROUGH_DEPTH.** Grin uses 1440 blocks (1 day at 60s blocks). CoinCync block time is 120s — 720 blocks gives the same wall-clock window. The H-16 reorg-defense parameter is 100 blocks. Cut-through depth must be ≥ reorg-defense depth + a comfort margin. Open question: 720 (Grin parity) or 200 (tighter, more aggressive compaction)?

2. **Disclosure-proof maturity.** Per the security note above, this CIP cannot ship until per-tx auditability is preserved out-of-band. Open question: target maturity bar for `src/crypto/disclosure.rs` before activation is acceptable?

3. **Storage migration.** Existing nodes need to apply cut-through retroactively to their pre-fork chain copy after activation. Open question: in-place migration (slow, less downtime) or full re-sync from peers post-fork (fast, full downtime)?

4. **Aggregation order in mempool.** When a miner builds a block, in what order are kernels aggregated? Random vs. fee-rate-sorted vs. tx-id-sorted has implications for fingerprinting. Open question: protocol-mandated canonical order or miner-discretion?

---

## Implementation Plan (after Discussion → Active)

1. Promote `src/crypto/mw_cutthrough.rs` from inert to active: instantiate `CutThroughEngine` in `Chain::new()` behind a height gate equal to the activation block.
2. Wire `src/network/block_aggregation.rs` as a real `BlockAggregator` impl, called from `mempool::package_block`.
3. Bump `MW_CUTTHROUGH_DEPTH` constant in `src/constants.rs` from current placeholder to the value chosen in (1) above.
4. Add migration tests covering the activation height boundary (block N-1 = un-cut, block N = cut).
5. Add fuzz target for kernel-aggregation correctness against random transaction sets.
6. Update `critical_files.lock` for the constants change.
7. Document the activation height + final parameter set in this CIP, transition status from Discussion → Active, propose miner version-bit assignment.

---

## References

- Grin protocol — original Mimblewimble cut-through specification
- Beam protocol — production MW deployment
- Litecoin MWEB (LIP-002) — MimbleWimble extension block on a non-MW chain
- Tari — hybrid Monero-style stealth addresses + MW cut-through
