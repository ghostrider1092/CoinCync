<!-- markdownlint-disable MD036 MD013 -->
# Atomic Swap — Cryptographic Design Note

**Companion to:** CIP-001 (CYNC↔BTC Atomic Swap)
**Status:** Draft for review
**Created:** 2026-05-14
**Audience:** Cryptography reviewers (Monero Research Lab, prospective audit firms), CoinCync implementers
**Scope:** The cryptographic core only — adaptor signatures, joint-key construction, cross-curve binding. CIP-001 remains the protocol-level specification (roles, state machine, timeout policy, liquidity bootstrapping). This note is the deep companion that CIP-001 gestures at but does not specify.

---

## 1. Why this note exists

CIP-001 says, in its Cryptographic Primitives section:

> *"CoinCync — Adaptor signatures over the CLSAG ring-signature scheme on Ed25519. The CLSAG construction is designed to admit adaptor variants; the technique is identical to Monero's implementation in the Comit project."*

And the `crates/coincync-swap/src/adaptor.rs` scaffold declares a `CyncAdaptorSig` type alongside `BtcAdaptorSig`, implying two symmetric adaptor-signature primitives — one per chain.

**This framing is imprecise, and getting it precise is the purpose of this note.** The COMIT / Farcaster construction that CIP-001 cites as prior art does *not* use an adaptor signature on the Monero-side ring signature. There is no "CLSAG adaptor signature" primitive in production xmr-btc-swap. The correct construction is described in §3. The imprecision is harmless in CIP-001 (a protocol-level document) but would be a real bug if carried into implementation, so this note fixes it before the cryptographic work begins.

This note is also the artifact CoinCync commits, in its NLnet NGI0 grant application, to publish for Monero Research Lab review before implementation starts.

---

## 2. License boundary

The COMIT `xmr-btc-swap` reference implementation is **GPL-3.0**. CoinCync is **MIT**. The two licenses are incompatible for code reuse: **no COMIT source may be copied into CoinCync.**

What *is* freely usable: the protocol design, the published Farcaster specification and its security proofs, the academic literature on adaptor signatures and cross-curve discrete-logarithm-equality proofs. This note is a clean-room design derived from public specifications and papers, not from reading COMIT's source. Implementers must maintain that boundary: study the spec and the math, never the GPL code.

---

## 3. The construction (corrected)

### 3.1 What CIP-001's "CLSAG adaptor" should actually say

The CYNC side of the swap uses **a 2-of-2 joint spend key with ordinary CLSAG signing**. There is no adaptor signature on the ring signature itself. All adaptor signatures live on the **Bitcoin** side. The two are bound by **cross-curve discrete-logarithm-equality proofs** exchanged during negotiation.

The consequence is a strong privacy property and a strong simplicity property:

- **Privacy:** the CYNC lock output and the CYNC sweep are *bit-for-bit indistinguishable* from any other CYNC transaction. Same CLSAG shape, same stealth-address structure, same Bulletproofs+ range proof. There is no swap-specific structure on the CYNC chain at all — not a special output type, not a timelock, not a script (CYNC, like Monero, has no script layer to carry one).
- **Simplicity:** `src/crypto/clsag.rs` requires **no changes**. The existing `clsag_sign` (clsag.rs:172) and `clsag_verify` (clsag.rs:303) are used unmodified. The swap's cryptographic novelty is entirely in new code: 2-party key management, secp256k1 adaptor signatures, and the cross-curve proof.

### 3.2 Key setup

Let the CYNC group be the prime-order Ristretto255 group with generator `G` (CoinCync uses `curve25519-dalek` `RistrettoPoint`; see `src/crypto/curve.rs`). Let the Bitcoin group be secp256k1 with generator `G'`.

Each party generates a CYNC key *share*:

- Alice: `s_a` (Ristretto scalar), publishes `S_a = s_a · G`
- Bob: `s_b` (Ristretto scalar), publishes `S_b = s_b · G`

The CYNC lock output is sent to a stealth address whose **spend public key is the joint key**:

```
S = S_a + S_b      (Ristretto point addition)
```

The corresponding joint spend secret is `s = s_a + s_b`. Neither party can compute `s` alone. Whichever party ends up learning the *other's* share can compute `s` and sweep the locked CYNC with an ordinary CLSAG signature.

The parties also agree on a **shared view key** for the joint address during negotiation, so both can scan the CYNC chain for the locked output and its confirmations. (The view key reveals the output to both swap participants — and only them — which is exactly the intended visibility. It does not weaken third-party privacy: a chain analyst without the view key sees nothing.)

### 3.3 Where the adaptors live: the Bitcoin side

The Bitcoin lock is a 2-of-2 between Alice and Bob (P2WSH today; P2TR / MuSig2 once the Schnorr-only path is chosen — see §6). Spending it requires both signatures. The mechanism that makes the swap atomic is that one party hands the other an **adaptor signature** — their half of the 2-of-2, "encrypted" under a curve point — rather than a finished signature.

There are exactly **two** adaptor signatures in a swap, both on Bitcoin:

1. **Claim-path adaptor (Bob → Alice).** Bob gives Alice an adaptor signature on the BTC *claim* transaction, encrypted under the point `S_a` (Alice's CYNC key share, lifted to secp256k1 — see §3.4). Alice — and only Alice, because only she knows `s_a` — can complete it into a valid signature. The act of completing it and broadcasting the claim **publishes `s_a` to Bob**: Bob computes `s_a = complete_sig − adaptor_sig` from the on-chain data. Bob now holds `s_a + s_b = s` and sweeps the CYNC. Swap succeeds.

2. **Refund-path adaptor (Alice → Bob).** Alice gives Bob an adaptor signature on the BTC *refund* transaction, encrypted under the point `S_b`. If the swap is cancelled (Bob never proceeds, or a timeout elapses) and Bob takes the refund path, broadcasting the BTC refund **publishes `s_b` to Alice**. Alice now holds `s_a + s_b = s` and sweeps the CYNC back to herself. Swap refunds — no principal lost.

The asymmetry CIP-001 describes (`btc_timeout_blocks < cync_timeout_blocks`) is enforced entirely by Bitcoin-side timelocks on these two transaction paths. The CYNC side has **no timelocks of its own** — see §3.6.

### 3.4 Cross-curve discrete-log-equality proof (CDLP)

The claim-path adaptor is encrypted under `S_a`, but `S_a` is a *Ristretto* point and the Bitcoin adaptor lives in *secp256k1*. The adaptor must be encrypted under a secp256k1 point `S_a' = s_a · G'` that has the **same discrete logarithm** `s_a` as the Ristretto point `S_a = s_a · G`.

A party cannot simply assert this — they must *prove* it without revealing `s_a`. That is the cross-curve discrete-log-equality proof: a zero-knowledge proof that "the secp256k1 point `S_a'` and the Ristretto point `S_a` are commitments to the same scalar."

The standard construction (Farcaster's reference, derived from the MRL discussion and the underlying bit-decomposition / ring-signature-per-bit technique) proves equality of a scalar across two groups of different order. Notes specific to CoinCync:

- **Ristretto255 is cleaner than raw Ed25519 for this.** Ristretto is a prime-order group: it eliminates the cofactor-8 subtleties that complicate the Monero-side proof in the original secp256k1↔Ed25519 construction. The bit-decomposition proof still works; the per-bit ring signatures simply target a prime-order group, removing one class of small-subgroup edge cases. Implementers should treat this as a simplification, not a new risk — but it does mean the proof is *not* byte-identical to Farcaster's, so it needs its own test vectors and its own review.
- **The scalar order mismatch remains.** secp256k1's group order and Ristretto255's group order are both ~2^252–2^256 but unequal. The proof must bound the scalar to the *smaller* of the two orders so it is a valid discrete log in both groups. This is the single most error-prone part of the whole construction and is flagged in §7 as a primary review target.

The CDLP is exchanged and verified during the negotiation phase, **before either party commits an on-chain transaction**. CIP-001 already gates this correctly: `verify_cross_curve_proof` failing is a mandatory abort (`adaptor.rs:65`, `coordinator.rs` `HandshakeAction::VerifyAdaptorMaterial`).

### 3.5 The Bitcoin adaptor signature itself

On secp256k1 the adaptor signature is standard and well-reviewed:

- **Schnorr (BIP-340) preferred.** The adaptor variant: a pre-signature `(R + T, s')` where `T` is the encryption point. Completion: `s = s' + t` where `t` is the discrete log of `T`. Recovery: `t = s − s'`. This is the cleanest construction and is what a P2TR / MuSig2 deployment should use.
- **ECDSA fallback.** The ECDSA adaptor (the "encrypted signature" of Fournier / the original atomic-swap literature) is also production-reviewed and is what current xmr-btc-swap uses against today's Bitcoin network. Slightly more complex; needs the additional zero-knowledge proof that the encryption is well-formed.

CoinCync should implement the Schnorr adaptor as the primary path and decide on the ECDSA fallback based on the Bitcoin Core deployment window at implementation time (CIP-001 Open Question 1).

### 3.6 The CYNC side has no swap-specific structure — correcting CIP-001 §"Protocol Phases"

CIP-001 step 2 says:

> *"Alice constructs a CYNC transaction whose output is a stealth address spendable by Bob's pub key + the adaptor secret (success path) or by Alice's refund key after `cync_timeout_blocks` (refund path)."*

**This is not implementable as written.** CYNC, like Monero, has no script layer. An output cannot carry an "or" condition or a timelock. There is exactly one way to spend a CYNC output: a valid CLSAG signature under its one-time key.

The correct statement: Alice's CYNC lock is an **ordinary transfer to the joint stealth address** derived from `S = S_a + S_b`. It has one spend condition — knowledge of `s = s_a + s_b` — and no timeout. The "success path / refund path" branching is *not* on the CYNC chain. It is entirely a function of *which party learns the other's share first*, and that race is arbitrated by the Bitcoin-side timelocks:

- Swap proceeds → Alice completes the claim adaptor → Bob learns `s_a` → Bob sweeps CYNC. (Success.)
- Swap cancels → Bob takes the BTC refund → Alice learns `s_b` → Alice sweeps CYNC back. (Refund.)

CIP-001's state machine (`Negotiated → AliceLocked → BobLocked → SecretRevealed → Completed`, with `Refunded` branches) remains valid as a *logical* model and matches the implemented `protocol.rs` `State` enum. The correction is purely about the *on-chain CYNC representation*: there is no second CYNC transaction type, no CYNC refund transaction, no CYNC timelock. `cync_timeout_blocks` in `SwapParameters` (`protocol.rs:194`) is a *coordination* deadline — the wall-clock point past which Alice's coordinator should give up waiting and pursue the refund race on Bitcoin — not an on-chain CYNC timelock. The `is_timeout_safe()` check (`protocol.rs:253`) is still correct and still necessary; it is comparing the two Bitcoin-relevant deadlines expressed in wall-clock time.

CIP-001 should be amended to reflect this. This note recommends the amendment; CIP-001's own changelog process applies.

---

## 4. CoinCync-specific considerations

### 4.1 Bulletproofs+ vs. Bulletproofs — no interaction with the adaptor

The grant application flagged "Bulletproofs+ vs. Bulletproofs compatibility with adaptor signatures" as a technical risk. On closer analysis the risk is **lower than stated**, and the design note records why so the audit can confirm it quickly rather than re-derive it:

The adaptor signatures are on **spend keys** (the secp256k1 2-of-2). The range proofs — whether Bulletproofs (`src/crypto/bulletproofs.rs` v2) or Bulletproofs+ (v3, `tari_bulletproofs_plus`) — are on **amount commitments**, a structurally separate part of the transaction. The adaptor construction never touches a range proof or a Pedersen commitment. The CYNC lock and CYNC sweep carry whatever range proof a normal CYNC transaction of that height carries; the swap protocol is oblivious to which.

The one place to *confirm* (not assume) compatibility: the CLSAG `mu_c` aggregate coefficient (`clsag.rs:145` `compute_aggregate_coefficients`) binds the commitment component into the ring signature. Since the CYNC sweep uses *ordinary* `clsag_sign` with no adaptor on the ring signature, `mu_c` behaves exactly as in any other transaction. There is no new interaction. The audit should verify this claim holds, but the design does not depend on novel behavior here.

### 4.2 Scoped view keys — orthogonal to the swap

CoinCync's scoped view keys (`src/crypto/view_keys.rs`, `ViewKeyScope::{EpochOnly, TimeRange, AmountCapped, SingleUse}`) are a *recipient-side* feature: they govern what a delegated view key can see. The swap's joint address uses an ordinary (full, unscoped) shared view key agreed during negotiation, because both swap participants legitimately need to see the locked output and its confirmations for the full duration of the swap. Scoped view keys neither help nor hinder the swap and need not be involved. If a future swap participant wants to *delegate* visibility of their swap activity to an auditor, the existing scoped-view-key machinery applies unchanged, after the fact, exactly as it would for any other transaction.

### 4.3 Ristretto255 vs. Ed25519

CoinCync's CLSAG operates over Ristretto255 (`PublicPoint` = `RistrettoPoint`), not raw Ed25519 like Monero. For the swap this is a **net positive**: Ristretto255 is a prime-order group, so the joint-key construction `S = S_a + S_b` and the CDLP both avoid cofactor handling. There is no torsion-point attack surface on the CYNC side of the swap. The cost is that the CDLP and its test vectors are not byte-identical to Farcaster's secp256k1↔Ed25519 proof — they must be regenerated and independently reviewed for Ristretto255. See §7.

---

## 5. Impact on the existing `coincync-swap` crate

The Explore-mapped current state: `protocol.rs`, `state.rs`, `coordinator.rs` are fully implemented; `adaptor.rs`, `btc.rs`, `cync.rs` are typed stubs returning `Error::NotImplemented`.

Changes this design implies:

| File | Change |
|---|---|
| `src/crypto/clsag.rs` | **None.** Ordinary `clsag_sign` / `clsag_verify` used unmodified. |
| `adaptor.rs` | **`CyncAdaptorSig` should be removed.** There is no CYNC-side adaptor signature. Replace with: a `CyncKeyShare` type (`s_a` / `s_b` and the `S_a` / `S_b` points), and a `JointSpendKey` type. `BtcAdaptorSig`, `CrossCurveDlProof`, `AdaptorSecret` stay. `decrypt_btc_adaptor` and `recover_secret_from_btc_sig` stay and become the core operations. |
| `btc.rs` | Implement against a secp256k1 library (add `secp256k1` + `bitcoin` crates — currently absent from `Cargo.toml`, see Explore note 7). Schnorr adaptor primary, ECDSA fallback. |
| `cync.rs` | Implement `build_lock_tx` as an *ordinary* transfer to the joint stealth address — no special output type. Implement the sweep as an *ordinary* CLSAG spend once `s = s_a + s_b` is known. |
| New: `cdlp.rs` | Cross-curve discrete-log-equality proof over secp256k1 ↔ Ristretto255. The single most novel and review-critical module. |
| New: `keyshare.rs` | 2-party key-share generation and the joint-key / joint-view-key agreement. |
| `coordinator.rs` | No structural change — `HandshakeAction::VerifyAdaptorMaterial` already lifts verification to a side effect. The handshake messages (`Message::AdaptorMaterial`) carry the CDLP and the BTC adaptors; their payload definitions get filled in. |
| `protocol.rs` | No change to the state machine. Possibly a doc-comment clarifying that `cync_timeout_blocks` is a coordination deadline, not an on-chain timelock (§3.6). |

The headline: **the hard, novel work is `cdlp.rs` and the secp256k1 adaptor in `btc.rs`.** Everything CYNC-side reuses primitives that already exist and are already in the consensus-critical path, which is the safest possible position to be in.

---

## 6. Open design decisions

1. **Schnorr-only vs. ECDSA fallback (CIP-001 OQ1).** Recommendation: implement Schnorr (BIP-340) adaptor as primary. Ship ECDSA fallback only if the Bitcoin Core deployment window at implementation time still has meaningful non-Taproot reach. Revisit at implementation start.
2. **MuSig2 for the Bitcoin 2-of-2.** If Schnorr-only, the Bitcoin lock should be a P2TR output with a MuSig2 2-of-2 rather than a P2WSH 2-of-2 multisig script. MuSig2 makes the Bitcoin side indistinguishable from a single-sig spend — strictly better privacy, and well-reviewed. Recommendation: yes, pair Schnorr-only with MuSig2.
3. **CDLP construction choice.** The Farcaster bit-decomposition proof is the known-good starting point. Open question whether a more modern construction (e.g. a CDLP built on a different proof system) is worth the added review surface. Recommendation: start from the known-good Farcaster construction adapted to Ristretto255; do not innovate here.
4. **`AdaptorSecret` semantics.** With the corrected construction, the "secret" revealed by a swap is a *CYNC key share* (`s_a` or `s_b`), a Ristretto scalar. The `AdaptorSecret([u8;32])` type in `adaptor.rs:35` should be documented as "a Ristretto scalar in canonical byte form" and validated as such on construction.

---

## 7. Primary review targets

For Monero Research Lab and for the eventual audit firm, the parts of this design that most need adversarial scrutiny, in priority order:

1. **The CDLP scalar-order bound (§3.4).** The proof must constrain the shared scalar to a value that is a valid discrete log in *both* secp256k1 and Ristretto255. An off-by-one or a missing range constraint here is a fund-loss bug. This is the highest-risk single item.
2. **CDLP soundness over Ristretto255 specifically.** The construction is adapted, not copied, from the secp256k1↔Ed25519 original. The adaptation is believed to be a simplification (prime-order target), but "believed to be a simplification" is exactly the kind of claim that needs an independent proof, not a design-note assertion.
3. **Adaptor completeness and extractability on the Bitcoin side.** Standard, well-reviewed primitives — but the *integration* (which transaction each adaptor signs, which timelock gates it) must be checked against the refund-safety argument in CIP-001 §"Timeout Safety".
4. **Joint-key sweep indistinguishability.** Confirm that a CLSAG signature produced with `s = s_a + s_b` is, in distribution, identical to any other CLSAG signature — i.e. that the joint origin of the key leaves no statistical trace. Expected to hold trivially (a sum of two uniform scalars is uniform) but should be stated and confirmed.
5. **The `mu_c` non-interaction claim (§4.1).** Confirm the adaptor construction genuinely never touches the commitment-binding path of CLSAG.

---

## 8. Test-vector plan

Before implementation is considered complete, the crate must ship:

- **CDLP vectors:** known scalar → (secp256k1 point, Ristretto255 point, proof) triples, plus negative vectors (proofs that must fail: wrong point, out-of-range scalar, malformed).
- **Bitcoin adaptor vectors:** pre-signature → completion → recovery round-trips for both Schnorr and (if shipped) ECDSA.
- **Joint-key vectors:** `s_a`, `s_b` → `S`, then a full CLSAG sign/verify under `s = s_a + s_b` proving it verifies as an ordinary signature.
- **Full-protocol integration vectors:** a recorded happy-path swap and a recorded refund-path swap, on regtest Bitcoin + a CYNC testnet, replayable deterministically.
- **Timeout-edge vectors:** the exhaustive timeout cases CIP-001 §"Timeout Safety" demands, exercised against `protocol.rs::is_timeout_safe`.

---

## 9. References

- **CIP-001** — `docs/cip/CIP-001-atomic-swap.md`. Protocol-level specification this note accompanies.
- **Farcaster project** — research-grade XMR↔BTC protocol specification with security proofs. `farcaster-project.github.io`. Design reference (not code — see §2).
- **COMIT `xmr-btc-swap`** — production reference implementation, GPL-3.0. Design reference only; **no code reuse** (§2).
- **Adaptor signatures** — the "encrypted signatures" / scriptless-scripts literature; Poelstra's original notes; the formal treatment in the Farcaster spec.
- **Cross-curve DL-equality** — the bit-decomposition construction discussed in the Monero Research Lab and formalized in the Farcaster spec.
- **CoinCync CLSAG** — `src/crypto/clsag.rs`. Used unmodified.
- **CoinCync curve layer** — `src/crypto/curve.rs` (Ristretto255 `PublicPoint`, `SecretScalar`, `KeyImage`, `Commitment`).

---

## 10. Changelog

- **2026-05-14** — Draft created. Corrects the "CLSAG adaptor signature" framing inherited from CIP-001 and the `adaptor.rs` scaffold; specifies the 2-of-2 joint-key + Bitcoin-side-adaptor construction; identifies `cdlp.rs` as the primary novel work; records the Bulletproofs+ non-interaction analysis.

---

*This is an informational design note. It does not modify consensus, the wire protocol, or any shipped code. Its claims are explicitly offered for adversarial review; §7 lists where that review should focus. Per the Constitution's Article XV, any protocol change derived from this note must demonstrably strengthen at least one user protection without weakening any other.*
