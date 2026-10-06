# CIP — Unlinkable *unspent* treasury solvency

**Status:** design (grounded; NOT built — this is the audit-critical part)
**Depends on:** [[cip-unlinkable-solvency]] (the *held* proof, built + gated on `sketch-gk-proof`)
**Goal:** prove the hidden treasury output is **currently unspent** (not merely
*held at `as_of_height`*), without revealing which output it is.

## Why "held" is all we have today
The shipped proof anchors set members as real on-chain outputs and range-proves
value ≥ threshold. It says nothing about spent status, because in a ring model a
spend is hidden — the network cannot mark a specific output spent. "Unspent" is
knowable only via the output's **key image** `KI = x·Hp(P)` (revealed on-chain
when spent). The freshness window (`MAX_SOLVENCY_STALENESS_BLOCKS`) + chain-pin
bound *staleness*; they do not prove unspent.

## The crux: binding "unspent output" == "solvent output"
We already have the pieces to check spent status:
- `ChainView::key_image_spent` / the `is_key_image_spent` RPC — the spent-set check.
- **CLSAG** (`clsag_sign`/`clsag_verify`) — a ring signature that reveals `KI`
  and proves ownership of *one* ring member **without revealing which**.
- Spark **V2/V3** spend proofs publish a nullifier; **V4** hides the serial with
  the linking tag **deferred**.

So "prove I own one of these N, here's its `KI`, and `KI ∉ spent-set`" is close
to CLSAG. The hard part is **soundly tying that owned/unspent member to the same
member the value proof ranges over**. Two independent one-of-many proofs (one
over `{Cᵢ−V}` for value, one over the ring for the key image) hide *independent*
indices `l` and `l'`. Without forcing `l == l'`, a prover can range-prove a large
(spent) output and key-image-prove a different (small, unspent) one — claiming
"solvent AND unspent" while no single output is both.

Forcing `l == l'` requires a **single proof over one `l`-bit-decomposition with
two linear constraints** (value binding to `V`, key-image binding to `KI`) —
i.e. the fused Triptych/CLSAG-with-value step. This is exactly the deferred,
audit-critical work on `feat/shielded-txtype`; it is NOT a patch on top of the
current proof.

## Design A — reveal `KI`, fused binding (tractable, with a known cost)
- Anonymity set over `(Pᵢ, Cᵢ)` pairs.
- One fused proof (extend `prove_one_of_many_gen_ctx` to carry the key-image
  constraint, or lift Triptych): same hidden `l` binds both `Cₗ`↔`V` (value ≥
  threshold) and `Pₗ`↔revealed `KIₗ`.
- Verifier: `KIₗ ∉ spent-set` (existing check) + anchoring + range + chain-pin.
- **Cost:** revealing `KIₗ` leaks *retroactively* — when the treasury is later
  spent, its on-chain `KI` links back to this proof, deanonymizing it in
  hindsight. Mitigation: **rotate the treasury** (spend to a fresh output) after
  each audit, so the audited output is retired before its `KI` ever appears.

## Design B — ZK non-membership (leak-free, heavier)
Keep `KI` hidden (committed) and prove `KI ∉ spent-set` in zero knowledge against
an accumulator over the spent-key-image set. No forward leak, but it needs a
spent-set accumulator (RSA/Merkle) maintained by the node + a ZK non-membership
proof — substantially more crypto, over a large, constantly-growing set.

## Recommendation
Build **A** as its own focused, audit-critical effort, fused with the shielded
spend work (it *is* that work — the linking tag). Do not rush it into the
solvency feature. Ship order: (1) key-image binding in the one-of-many, proven
inert for existing callers + a soundness suite (`l==l'` enforced; split-output
attack rejected); (2) reveal-KI unspent verify against the spent set; (3) wire +
regtest with a genuinely-spent decoy rejected. Consider **B** only if the
forward-linkage cost is unacceptable and treasury rotation is not an option.

## Shipped interim (not this)
Freshness window + chain-pin ([[coincync-treasury-protection]]) bound staleness
and detect fork/desync — the honest 80% until A lands.
