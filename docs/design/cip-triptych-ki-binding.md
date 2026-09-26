# CIP — Triptych key-image binding (fused one-of-many, step 1)

**Status:** design + build in progress (gated `sketch-gk-proof`, UNAUDITED,
never in a production build, unwired from consensus)
**Parent:** [[cip-unlinkable-unspent]] (Design A — reveal-tag fused binding)
**Depends on:** the Groth-Kohlweiss one-of-many in `crypto/groth_kohlweiss.rs`
**This step:** bind a revealed key-image *tag* to the SAME hidden index `l` the
one-of-many already proves value-membership over, so "solvent output" and
"the output whose spend-key I know" are provably the same output. Enforce
`l == l'`; reject the split-output attack. NOT yet the unspent check against a
spent-set (that is step 2) and NOT the Monero per-member `Hp(P)` key image
(that is the CLSAG-fused variant, deferred within Design A).

## What the base proof already gives
For a ring `C_0..C_{N-1}` (N = 2^m) the GK proof proves, at a hidden index `l`,
that `C_l` is a commitment to zero in `blind_gen`. Internally it forms
`P_i(x) = ∏_j (f_j if i_j=1 else x−f_j)`, a degree-`m` polynomial whose x^m
coefficient is `δ(i,l)`, and checks

```
Σ_i P_i(x)·C_i − Σ_k x^k·gk_k == z_d·blind_gen          (value/membership)
```

because `Σ_i P_i(x)·C_i = x^m·C_l + Σ_{k<m} x^k·(Σ_i p_{i,k}·C_i)` and the
`gk_k = (Σ_i p_{i,k}·C_i) + ρ_k·blind_gen` commitments cancel the low-order
terms, leaving `x^m·C_l = x^m·r·blind_gen`.

## The fused key-image tag (this step)
Add a parallel public-key ring `P_i` (the one-time public keys of the SAME
outputs, `P_i = x_i·G`, `G = RISTRETTO_BASEPOINT`), a fixed NUMS generator `U`
(independent of `G`/value_gen/blind_gen), and a revealed linking tag `T`.

The prover knows the spend key `x_l` of member `l` (`P_l = x_l·G`) and sets
`T = x_l·U`. Reusing the SAME `p_{i,k}` coefficients (hence the same `f_j`,
same challenge `x`, same hidden `l`):

**Round 1 (extra):** fresh `σ_k` (k = 0..m−1),
```
gkp_k = (Σ_i p_{i,k}·P_i) + σ_k·G            // absorbs low-order P-terms, blinds in G
gkt_k = σ_k·U                                // same σ_k, over U
```
reveal `T = x_l·U`.

**Round 2 (extra):** `zp = x_l·x^m − Σ_k σ_k·x^k`.

**Verifier (extra):**
```
(P)  Σ_i P_i(x)·P_i − Σ_k x^k·gkp_k == zp·G
(T)  x^m·T          − Σ_k x^k·gkt_k == zp·U
```

Derivation of (P): `Σ_i P_i(x)·P_i = x^m·P_l + Σ_k x^k·(Σ_i p_{i,k}·P_i)`;
subtract `gkp_k` → `x^m·P_l − Σ_k x^k·σ_k·G = x^m·x_l·G − (Σσ_k x^k)·G = zp·G`.
Derivation of (T): `x^m·T − Σ_k x^k·σ_k·U = (x^m·x_l − Σσ_k x^k)·U = zp·U`.
The SAME `zp` satisfies both, tying `T`'s `x_l` to the `x_l` proven at index `l`.

## Why `l == l'` (the whole point)
`P_i(x)` is computed once and reused for the value accumulator and the
public-key accumulator. GK special soundness (rewind on two challenges) extracts
the bits `l_j` from the `f_j`, i.e. a SINGLE index `l`. There is no second,
independent index available to the key-image relation — it is driven by the same
`f_j`. So the output whose value-part is zero (`C_l−V` opens to value `V`) is the
same output whose spend key `x_l` produced `T`. A split-output prover who
value-proves index `l` but key-image-proves `l' ≠ l` cannot: only one set of
`f_j` exists in the proof, and (P) telescopes to `x^m·P_l` for that one `l`.

## Fiat-Shamir
The fused challenge binds everything the base challenge binds PLUS the `P_i`
ring, `U`, `T`, and the `gkp`/`gkt` vectors. Generators are not hashed, so the
verifier must pass the identical `(value_gen, blind_gen, G, U)` it agreed on.

## Soundness suite (acceptance for this step)
1. Honest fused proof verifies (value at `l` AND tag `T = x_l·U` at `l`).
2. **Split-output attack rejected:** value witness at `l`, spend key at `l'≠l`
   → no single `zp` satisfies (P) for the shared `f_j` → reject.
3. Tampered `T` (wrong `x`, identity, other member's key) → reject.
4. Wrong `U` at verify → reject.
5. Base callers unaffected: `prove/verify_one_of_many[_gen]_ctx` byte-identical.

## Not in this step
- Step 2: prove `T ∉ spent-tag-set` (the unspent check) — needs the tag to be
  the network's canonical nullifier form, or a ZK non-membership (Design B).
- Monero-compatible `KI = x·Hp(P)` fusion (per-member hash-to-point) — heavier;
  the fixed-`U` tag here is the tractable first rung.
- Consensus wiring. Stays fail-closed and gated until audited + soaked.

## Step 2 — route decision (RECORDED) and why the tag must change
The additive tag `T = x_l·U` above proves the `l == l'` *machinery* works, but it
is **not** CoinCync's canonical shielded nullifier. That nullifier is the
Lelantus-Spark **VRF tag** `T = (U − D)·s⁻¹` (Dodis-Yampolskiy inversion),
verified by the Chaum multiplicative relation `T·s = U − D`
([[cip-shielded-spend-composition]], transcribed verbatim from Firo `chaum.cpp`).
An unspent check `T ∉ spent-set` is only meaningful when `T` is the SAME tag the
chain records on a shielded spend — i.e. the VRF tag produced by the
libspark-backed spend path (the `spark-connector` FFI).

**Route decision: B (FFI-tag alignment).** The value-and-index binding stays the
native GK construction built here (step 1). The *unspent* half defers to the
libspark VRF nullifier, so `T ∉ spent-set` is checked against the real, audited
nullifier set. Rationale:
- A native from-memory VRF one-of-many is explicitly forbidden by
  [[cip-shielded-spend-composition]] ("that is how subtly-unsound proofs get
  shipped") and would not inherit Firo's audit.
- The VRF serial `s` lives in Spark's separate serial commitment `S = F·s + D`;
  the current fused coin would need the `(C, S)` two-commitment restructure to
  carry it natively. FFI sidesteps that.
- Matches the standing strategy: one audited Spark pool, originality in the
  integration ([[coincync-strategy-narrow-shielded]]).

### The audit-critical remainder (NOT to be hand-rolled from memory)
Binding this proof's *hidden index* to the libspark *per-coin VRF tag* — without
revealing which coin — is the Triptych/Omniring embedded-tag problem. It must be
transcribed from the Lelantus-Spark paper / Firo reference and externally
audited. The step-1 machinery here (shared `P_i(x)` across two accumulators) is
the index-binding skeleton it plugs into; the VRF Chaum relation replaces the
additive tag equation `(T)`. Concretely, the tag accumulator becomes the
multiplicative/inverse relation `T·s_l = U − D_l` over the serial-commitment ring
`{S_i}`, fused on the same `f_j`. Pin the exact Σ-protocol + generators before
coding; until then the shielded spend is not end-to-end and stays gated
(`SHIELDED_TX_ACTIVATION_HEIGHT = u64::MAX`).
