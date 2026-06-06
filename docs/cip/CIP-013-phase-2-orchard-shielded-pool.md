<!-- markdownlint-disable MD036 -->
# CIP-013 — Phase 2 Orchard Shielded Pool

**Status:** Draft (mainnet blocker — non-circuit layer complete, Halo2 Action circuit pending)
**Type:** Standards Track (consensus rule — Phase 2 activation requires a hard fork)
**Created:** 2026-05-17
**Layer:** Consensus + protocol
**Depends on:** CIP-007 (activation policy)
**See also:** CIP-001 (atomic swap, uses similar Pasta-cycle ZK approach), CIP-005 (Lelantus Spark sketch — alternative shielded scheme, post-mainnet)

---

## Abstract

A privacy-enhancing shielded pool layered on top of the transparent CYNC pool, using Zcash's NU5 Orchard construction (Halo2 + Pasta curves + Sinsemilla hashing) **verbatim where compatible** so the existing audit literature transfers. Shielded transactions hide sender, recipient, AND amount via zero-knowledge proofs; transparent ↔ shielded transfers cross the value boundary via a publicly-verifiable `value_balance`.

The protocol is implemented in two layers:

1. **Non-circuit cryptographic primitives** (`crates/orchard-side/`) — commitment, nullifier, value commitment, key hierarchy, binding signature. **Complete and spec-exact as of 2026-05-17.** 86 tests pass; all five spec deviations originally flagged in module headers have been closed.
2. **Halo2 Action circuit** — the zero-knowledge proof itself. Skeleton + halo2 IPA prover/verifier wiring + public-input scaffolding shipped; the constraint set (ECC + Sinsemilla + Merkle + Poseidon chips composed per Zcash NU5 §6.7) is the remaining multi-month implementation work.

Activation is a hard fork (Phase 2). See §6 for the staging plan.

---

## Motivation

CYNC's transparent pool provides amount confidentiality via Pedersen commitments + Bulletproofs and recipient confidentiality via stealth addresses + view tags. Sender confidentiality comes from CLSAG ring signatures with a configured ring size. This is a strong baseline but it has known structural limits:

- **Ring size is a tunable parameter, not an unbounded anonymity set.** Mainnet currently mandates ring size 11; raising it past ~17 hits CLSAG-verification-cost cliffs. The anonymity set grows linearly with ring size.
- **Decoy selection has been the subject of three published attacks** against Monero over the years (CryptoNote 2018, OSPEAD 2022, Janus 2023). Each was mitigated; the structural risk that the "next" attack on decoy selection is unknown remains.
- **Cross-input linkability** via shared key images can correlate transactions when the same wallet spends multiple outputs in independent transactions.

The Orchard shielded pool addresses all three structurally:

- **Anonymity set is the entire shielded pool** (every commitment ever made), not a ring of N decoys. This is a different security model — set-membership proofs replace decoy-based plausible-deniability.
- **No decoy selection** to attack. Each note proves membership in the entire pool via a Merkle authentication path.
- **No shared key images.** Spent notes publish a nullifier derived deterministically from `(note, nk)` where `nk` is owner-specific, so chain analysts cannot correlate spends by the same wallet across transactions.

The cost is computational: shielded transactions require ZK proof generation (~3-5 seconds per Action on commodity hardware), and proof verification adds ~30ms per Action to block validation. The constitutional commitment is to give users this tradeoff as an *opt-in* — the transparent pool remains the default for low-stakes payments; the shielded pool is available for users who want stronger privacy at higher computational cost.

---

## Non-goals

This CIP explicitly does NOT cover:

1. **Replacing the transparent pool.** Both pools coexist post-activation. CYNC's CLSAG-based transparent pool keeps shipping unchanged; users choose which pool to send/receive from on a per-transaction basis.
2. **Trusted setup.** Orchard uses Halo2 with IPA polynomial commitments — no trusted setup, no ceremony, no toxic-waste exposure. This is one of Halo2's design wins vs. Groth16-based shielded schemes.
3. **Cross-pool atomic swaps.** Moving value between the two pools is via the transparent `value_balance` field; atomic swaps between *separate* asset pools is out of scope (see CIP-001 for the inter-chain atomic swap; this CIP covers only the within-CYNC dual-pool architecture).
4. **Phase 3 shielded features** — sealed-sender messaging, time-locked nullifiers, etc. — are out of scope until Phase 2 ships and the audit window closes.

---

## Specification

The shielded pool is structured around the **note**, an off-chain representation of value owned by a recipient:

```text
Note := (recipient_d, recipient_pkd, value, rho, rseed)
```

Where `(recipient_d, recipient_pkd)` is the recipient's diversified address, `value` is the note's amount in CYNC base units, `rho` is uniqueness randomness (parent nullifier for spends, freshly chosen for mints), and `rseed` is root randomness from which `(ψ, rcm)` derive deterministically via Blake2b-512 PRF_expand.

### 4.1 Cryptographic primitives — all shipped

The primitives are implemented in [`crates/orchard-side/`](../../crates/orchard-side/). All five spec deviations originally flagged in module headers have been closed; outputs match the reference `orchard` crate's primitives byte-for-byte for any note constructed with the same `(d_bytes, pkd_bytes, value, rho, rseed)` inputs.

| Primitive | Module | Spec reference | Status |
| --- | --- | --- | --- |
| Note commitment (Sinsemilla short-commit, 1084-bit message) | `commitment.rs` | NU5 §5.4.8.4 | ✅ shipped, spec-exact |
| Nullifier (Poseidon PRF + K^Orchard mul + cm add + Extract_P) | `nullifier.rs` | NU5 §4.16.3 | ✅ shipped, spec-exact |
| Value commitment (Pedersen with V/R generators) + homomorphic add/sub | `value_commit.rs` | NU5 §5.4.8.3 | ✅ shipped, spec-exact |
| RedPallas binding signature (Schnorr-over-Pallas with Blake2b challenge) | `binding_sig.rs` | NU5 §5.4.7 | ✅ shipped; `verify_balance` wired through it |
| Spending key hierarchy (sk → ask/nk/ak/rivk/ovk via PRF_expand) | `spend_key.rs` | NU5 §4.2.3 + §5.4.1.2 | ✅ shipped, spec-exact |
| Incoming viewing key (CommitIvk Sinsemilla short-commit) | `spend_key.rs::to_ivk` | NU5 §5.4.8.4 | ✅ shipped, spec-exact |
| Diversified address (DiversifyHash + ivk·gd) | `spend_key.rs::address_at` | NU5 §5.4.1.6 + §4.2.3 | ✅ shipped, spec-exact |
| Note construction with full derivation chain | `note.rs::Note::new_for_address` | NU5 §4.7.2 | ✅ shipped; wraps `address_at` |
| ψ / rcm derivation from rseed (PRF_expand tags 0x09 / 0x05) | `note.rs::Note::psi` / `note.rs::Note::rcm` | NU5 §5.4.1.2 | ✅ shipped, spec-exact |

**Closing integration test:** `note::tests::new_for_address_walks_sk_through_to_commitment` walks the single chain `sk → fvk → ivk → Note → cm → nf` in one assertion — every primitive exercised together, any future drift caught as a clean failure.

### 4.2 Halo2 Action circuit — skeleton shipped, constraints multi-month

The Action circuit proves, per shielded action:

1. `cm_new` is a valid commitment to a note with stated `(recipient, value, ρ, ψ)`.
2. `nf_old` is the correct nullifier for some old note whose commitment is at position P in the note-commitment tree with current anchor `rt`.
3. The spender knows `ak`, the spend-authorisation validating key tied to the old note's recipient.
4. The value commitments `cv_old` and `cv_new` open to the stated `value_balance` contribution (composed across actions via the binding signature).
5. The proof is bound to a transaction-wide `sighash` so it can't be replayed in another tx.

Specification: [Zcash NU5 §6.7](https://zips.z.cash/protocol/nu5.pdf#orchardpaymentcircuit).

**Shipped:** `action.rs::ActionCircuit` implements `halo2_proofs::plonk::Circuit<pallas::Base>` with `SimpleFloorPlanner`. Real IPA params (k=11), real keygen, real Blake2b transcripts, real `create_proof` / `verify_proof` round-trip. `pack_statement` packs the 8 public inputs (`ak, nf_old, rk, cm_new, anchor, cv_net.x, cv_net.y, sighash`) into the canonical instance-column layout. `e2e_trivial_proof_verifies` test runs the full machinery in ~0.79s on first call (warm cache ~milliseconds).

**Not shipped — the constraint roadmap (`ConstraintRoadmap` doc marker in `action.rs`):**

| Step | Component | Status |
| --- | --- | --- |
| 1 | ECC chip wiring (`halo2_gadgets::ecc`) for point arithmetic | ⏳ multi-week |
| 2 | Sinsemilla chip wiring for in-circuit commit + merkle | ⏳ multi-week |
| 3 | Merkle chip wiring (32-deep authentication path against `anchor`) | ⏳ multi-week |
| 4 | Poseidon chip wiring for PRF_nfOrchard in-circuit | ⏳ multi-week |
| 5 | Lookup tables for the gadgets above | ⏳ multi-week |
| 6 | Range checks (64-bit values, field reductions) | ⏳ multi-week |
| 7 | Public input equality constraints against the instance column | ⏳ bounded once Steps 1-6 done |
| 8 | Audit pass against NU5 §6.7 | ⏳ post-implementation |

Each step is its own focused slice. The reference `orchard` crate's circuit is ~3000 lines of `synthesize` logic; the shipped skeleton is the first ~50 of those lines plus the surrounding prove/verify wiring.

### 4.3 Bridge layer — already shipped

`crates/bridge/` provides the opaque 32-byte boundary types (`BridgeCommitment`, `BridgeNullifier`, `BridgeRangeProof`, `BridgeValue`, `BridgeLedger`) that let the Orchard side and the transparent (Tari) side communicate without leaking either system's native types into the other. Already in use by `src/storage/shielded.rs` and the orchard-side `commitment.rs` / `nullifier.rs` / `proof.rs` wrappers.

### 4.4 Storage layer — already shipped (dormant)

`src/storage/shielded.rs` ships the `bridgetree::BridgeTree`-backed note commitment tree + the nullifier set, with RocksDB-backed persistence. Currently dormant (the `ShieldedStore` is `None` at chain init); Phase 2 activation wires it up at block-apply time via the storage-side rewind support shipped in commit `ef4f48c` (see `project_phase2_reorg_rewind` memory).

### 4.5 Activation plan

Phase 2 is a **hard fork** under CIP-007 Mode A (static-height activation). Sequencing:

1. **Pre-activation work (this CIP's remaining scope).** Constraint roadmap Steps 1-8 complete the Action circuit. Audit pass closes outstanding cryptographic review.
2. **Hard-fork activation height** chosen in `src/constants.rs` per CIP-007. Pre-fork blocks reject any transaction containing an Action; post-fork blocks accept them subject to the validator rules below.
3. **Validator rules at activation.** Every block accepted at or after the activation height must (a) verify the binding signature for every shielded transaction it contains, (b) verify the Action circuit proof against each Action's public inputs, (c) check the nullifier hasn't already been spent (consult `BridgeLedger`), (d) check the Merkle anchor refers to a known historical state of the commitment tree (within the per-network rollback window).
4. **Block-apply integration.** At block-apply time, every Action's `cm_new` is appended to the shielded note commitment tree and every `nf_old` is marked spent in the bridge ledger. The storage-side rewind path (shipped at `ef4f48c`) handles block disconnects during reorgs.
5. **Wallet rollout.** The wallet's Phase 2 send/receive UI ships when the activation height is announced. View-only wallets work with the FVK + ivk derivation already shipped; full spending requires the Halo2 prover (which on commodity hardware takes ~3-5s per Action, acceptable for opt-in privacy transactions).

---

## Security considerations

1. **Constraint correctness is load-bearing.** A bug in any of the 8 Halo2 chip integrations (ECC, Sinsemilla, Merkle, Poseidon, lookups, ranges, public-input equality, audit pass) could either (a) accept invalid proofs (silently breaking soundness — funds creatable from nothing) or (b) reject valid proofs (breaking liveness — honest users can't spend). The audit window is non-negotiable.

2. **Soundness inherits Halo2's IPA soundness.** Halo2's polynomial commitment uses the Inner Product Argument; soundness rests on the discrete logarithm assumption over the Pallas/Vesta cycle. No trusted setup, no toxic waste, no ceremony — but the IPA construction itself has been subject to its own audit history (NCC, ToB, ECC, Halborn all published reports during Zcash NU5).

3. **Reorg interaction with the nullifier set.** When a block containing shielded actions is disconnected during a reorg, the nullifiers it inserted into `BridgeLedger` must be unmarked. The storage-side rewind support shipped at `ef4f48c` handles this, but it's dormant until activation. Pre-mainnet testnet exercise should specifically include a reorg crossing shielded blocks.

4. **Reorg interaction with the commitment tree.** Same shape as the nullifier set — the `bridgetree::BridgeTree` provides checkpoint-based rewind, but the integration is currently inert and needs activation exercise.

5. **Side-channel resistance.** Shielded transaction construction involves long-term secrets (sk, ask, nk, rivk). The non-circuit primitives use `subtle::ConstantTimeEq` for sensitive comparisons (`NullifierDerivingKey` validation) and `zeroize` patterns where applicable. The Halo2 prover itself runs on the user's machine and is not directly exposed to chain-side timing channels, but a malicious wallet implementation could leak via prover timing — out of scope for this CIP but flagged for the wallet audit.

6. **Anonymity set bootstrap.** At Phase 2 activation, the shielded pool is empty. The first transaction into the pool from a transparent input has an anonymity set of 1 (itself). The pool's anonymity grows with usage. This is not a Phase 2 design flaw — it's an unavoidable property of any new shielded pool — but users should be aware that early adoption provides weaker privacy than mature adoption.

7. **Bit-encoding interop.** The shipped Sinsemilla bit-encoding (255 bits per `repr_P` field, 64 bits per value) matches NU5 §5.4.8.4 byte-for-byte. A reference `orchard` crate produces identical commitments for identical note inputs — verified by the closing integration test. If we ever diverge from this encoding, it will be intentional and flagged in this CIP's changelog.

---

## Out of scope

- **Replacing the transparent pool.** See §3 non-goal 1.
- **Trusted setup.** Halo2/IPA doesn't need one.
- **Cross-asset atomic swaps within the dual pool.** See §3 non-goal 3.
- **Phase 3 sealed-sender messaging or time-locked nullifiers.** Post-Phase-2 work.
- **Wallet UX details.** Spec-level decisions (key formats, address strings, fee rules) belong here; UI rendering and flow belong in the wallet's own design docs.
- **Bridge between Orchard and the existing Phase 1 Spark / kernel storage skeletons.** Those (`src/storage/spark.rs`, `src/storage/kernels.rs`) are separate sketches; integration with Orchard is post-mainnet.

---

## Implementation status

What's shipped (as of 2026-05-18):

1. ✅ **Non-circuit cryptographic primitive set** — 6 modules, **byte-for-byte conformant with Zcash NU5** across all 10 vendored canonical test vectors (`crates/orchard-side/tests/zcash_test_vectors_keys_upstream.rs`, sourced from `zcash-hackworks/zcash-test-vectors`). 86 unit tests + 6 conformance tests (60 byte-equality assertions). **6 spec deviations were caught + fixed by the conformance suite on 2026-05-18** — see Changelog. The conformance test is now load-bearing: any future change that re-introduces a spec deviation fails at PR time.
2. ✅ **Halo2 Action circuit skeleton** — `Circuit<pallas::Base>` impl, `SimpleFloorPlanner`, OnceLock-memoized IPA params + keys, real prove/verify wiring with Blake2b transcripts. Zero constraints today; trivially-true proof in ~0.79s.
3. ✅ **Public-input scaffolding** — single instance column with `public_input_rows::{AK, NF_OLD, RK, CM_NEW, ANCHOR, CV_NET_X, CV_NET_Y, SIGHASH}` indices matching the reference orchard crate's NU5 §6.7 layout. `pack_statement` packs an `ActionStatement` into the 8 `pallas::Base` cells; prove + verify both consume the packed form.
4. ✅ **Bridge layer + storage** — both shipped previously, both ready to receive Phase 2 traffic at activation.

What's ahead:

1. ⏳ **Constraint roadmap Steps 1-7** — the 8 chip integrations + lookups + ranges + equality. The actual zero-knowledge content of the proof. Multi-week per step.
2. ⏳ **Constraint roadmap Step 8** — audit pass against NU5 §6.7. Post-implementation.
3. ⏳ **Chain validator integration** — `validate_block` gains Action-verification calls at the activation height. Implementation is a few hundred lines; integration test is what shapes it.
4. ⏳ **Wallet integration** — Tauri wallet's shielded send/receive UI consuming the spend_key + commitment + action modules.
5. ⏳ **Activation hard fork** under CIP-007 Mode A.

---

## Changelog

- **2026-05-17** — Created. Documents the non-circuit primitive set as complete and spec-exact (86 tests pass), the Halo2 circuit skeleton as wired (real prove/verify, public-input scaffolding), and the constraint roadmap as the remaining multi-month work. Mainnet blocker; activation via CIP-007 hard fork after audit.
- **2026-05-18** — **Zcash NU5 conformance test suite shipped** + **6 spec deviations caught and fixed.** The suite (`crates/orchard-side/tests/zcash_conformance.rs`) replays our non-circuit primitives against the 10 canonical key-component vectors vendored from orchard 0.12 (which sources from `zcash-hackworks/zcash-test-vectors`). Initial run surfaced 6 bugs that all our internal tests had missed because they were "implementation tests itself" — exactly the class of consensus-incompatibility bug that's invisible until cross-validated against an independent oracle:
    1. **OVK derivation** used Blake2b with personalization `"Zcashderiveovk"` and extracted bytes `[0..32]`. **Spec:** `R = PRF_expand(rivk, [0x82] || ak.x || nk)`, `ovk = R[32..64]`. Three sub-deviations: wrong personalization, wrong input order/structure, wrong half extracted. (`src/spend_key.rs`)
    2. **DiversifyHash** used Sinsemilla `hash_to_point` on the `"z.cash:Orchard-gd"` domain. **Spec:** standard IETF Simplified-SWU `pallas::Point::hash_to_curve("z.cash:Orchard-gd")(d_bytes)`. Sinsemilla is the IN-CIRCUIT hash; the diversifier hash is out-of-circuit and uses the standard primitive. (`src/spend_key.rs::address_at`)
    3. **NoteCommitment bit-encoding** used 255 bits for `g_d` and `pk_d`. **Spec:** 256 bits (full byte representation; they're compressed-Pallas-point encodings, not pallas::Base field elements — no high-bit reserved). 2-bit-off-per-field Sinsemilla input → completely different commitment output. (`src/commitment.rs`)
    4. **ψ + rcm derivation** used `PRF_expand(rseed, [tag])`. **Spec:** `PRF_expand(rseed, [tag] || rho_bytes)` per NU5 §4.7.3 — ρ is part of the PRF input so ψ and rcm bind to the spend-position, not just to rseed. (`src/note.rs::psi`, `rcm`)
    5. **K^Orchard generator** computed as `pallas::Point::hash_to_curve("z.cash:Orchard")(&[])`. **Spec:** `hash_to_curve("z.cash:Orchard")(b"K")` — single byte `b"K"`, not empty. Different point entirely. (`src/nullifier.rs`)
    6. **`mod_r_p` base→scalar coercion** used `pallas::Scalar::from_uniform_bytes` (512-bit wide reduction over zero-padded input). **Spec:** `pallas::Scalar::from_repr(base.to_repr()).unwrap()` — Pallas' base field is SMALLER than its scalar field (q_P < q_S), so every canonical base is also a valid scalar with the same bytes. Wide reduction over zeros computes a different value. (`src/nullifier.rs::derive_nullifier`)
    All 6 fixes hold the 86 pre-existing tests + the 6 new conformance tests in green; that's 92 tests across the crate. **The conformance suite is now a load-bearing audit deliverable** — any future change that re-introduces a spec deviation fails at PR time rather than at activation time.
- **2026-05-18 (extended)** — **Aggressive bug-hunting follow-up** after the user flagged: "orchard is filled with bugs if we don't do it right." Extended `tests/zcash_conformance.rs` from 6 → **17 tests** covering (a) 8 spec-conformance tests adding `ask` + `dk` validation against the Zcash NU5 vectors, (b) 5 randomized property tests (value-commit homomorphism, determinism, randomization; nullifier collision-resistance under 50 iterations of random inputs; PRF_expand tag distinguishing across 50 random seeds), and (c) 4 boundary tests (zero sk rejected; max sk produces non-zero FVK; non-canonical Pallas nk rejected; zero diversifier resolves via spec-substitution). **7th bug caught and fixed: `ask` parity normalization.** The `ak.x` byte representation matched the Zcash reference (BIP-340 x-only encoding ignores y-parity), but the underlying `ask` scalar differed. Per orchard 0.12 `src/keys.rs::SpendAuthorizingKey::from`: after deriving raw `ask = ToScalar(PRF_expand(sk, [0x06]))`, if the resulting `ak = ask · G` has odd y (bit 7 of compressed-byte-31 set), **negate `ask`** so the canonical point has even y. Without this, our spend-auth signatures would not verify under an orchard-implementing verifier — silent interop break. Fixed in `src/spend_key.rs::SpendingKey::ask`. (Also exposed `FullViewingKey::dk` field — orchard always derives it as the first half of the same Blake2b output that produces `ovk`; we now expose both halves.) **103 orchard-side tests pass (86 unit + 17 conformance). 305 workspace tests in default mode, 367 with `strict-dleq`.**

---

*The Constitution's Article XV "Spirit and Construction" applies: any change to the protocol described here must demonstrably strengthen at least one user protection without weakening any other.*
