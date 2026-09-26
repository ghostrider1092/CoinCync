# CIP-Shielded, Increment 2c#1 — the real spend proof (Groth-Kohlweiss)

**Status:** DESIGN. No production code yet. Replaces the unaudited O(n) Schnorr
stand-in (`crypto/lelantus_spark.rs`) with a log-size one-out-of-many proof.
Nothing activates until this is implemented, property-tested, externally
audited, and passes the 24h live soak — shielded stays gated off
(`SHIELDED_TX_ACTIVATION_HEIGHT = u64::MAX`) throughout.

## Why

The stand-in's `SparkSpendProof` carries `anon_set_indices`, `challenges`, and
`responses` vectors **all of length n** (the anonymity set size) — the proof and
verification are **O(n)**. That caps practical anonymity sets and bloats blocks.
The Groth-Kohlweiss (GK15) construction proves the same statement in **O(log n)**
proof size and verification — the difference between a ~few-hundred-member ring
and a whole-chain anonymity set. This is the piece that makes the shielded pool
genuinely private *and* scalable — the originality the audit asked for.

## What we already have (unchanged by this CIP)

- Commitment: `C = v·G + s·H + r·K` (`spark_commit`), three independent
  NUMS generators G/H/K.
- Serial tag: `T = s·G` (`spark_serial_tag`) — the double-spend nullifier.
- The **real accumulator**: `storage::ShieldedStore` (a `bridgetree` Merkle tree
  + nullifier set + checkpoint/rewind). The GK proof proves membership against a
  set of commitments; the accumulator supplies that set / its root.
- The consensus **frame** (Increments 1–2c#3): wire type, activation gate,
  validation dispatch with a fail-closed proof slot, real-accumulator apply,
  pre-apply contextual double-spend on both apply paths, header-root gate.

## The statement to prove

Given public commitments `C_0 … C_{N-1}` (from the accumulator, N padded to
`2^m`), a serial tag `T`, and the spend's re-randomization, the prover knows a
secret index `l`, serial `s`, and randomness such that:

1. **Membership:** `C_l` is the prover's coin — equivalently, after subtracting
   the prover's re-randomization `C'`, the derived set `c_i = C_i − C'` has
   `c_l = Com(0; r̂)` (a commitment to zero) for known `r̂`. (GK one-of-many.)
2. **Serial binding:** `T = s·G` uses the *same* serial `s` committed in `C_l`
   (links the nullifier to the spent coin so a second spend of the same coin
   reproduces `T`).

…all without revealing `l`. Zero-knowledge hides which coin; special-soundness
guarantees a valid proof implies knowledge of a real opening (no forgery, no
inflation); the serial tag guarantees O(1) double-spend detection.

## Protocol (GK15 one-of-many, Fiat-Shamir NIZK)

Let `m = log2(N)`, and `l = (l_0,…,l_{m-1})` the bit-decomposition of the secret
index. `Com(x; r) = x·G + r·K` is the auxiliary Pedersen commitment.

**Prover, round 1 (commit):** for each bit `j ∈ 0..m` sample `r_j, a_j, s_j, t_j`:
- `cl_j = Com(l_j; r_j)`  (commit the bit)
- `ca_j = Com(a_j; s_j)`
- `cb_j = Com(l_j·a_j; t_j)`  (these two prove `l_j ∈ {0,1}`)

Define, for each set index `i` with bits `i_j`, the degree-`m` polynomial
`p_i(x) = ∏_j ( l_j·x + a_j if i_j=1 else x − (l_j·x + a_j) )`
`      = δ_{i,l}·x^m + Σ_{k=0}^{m-1} p_{i,k}·x^k`
(so `p_i` has an `x^m` term iff `i = l`). Sample `ρ_0..ρ_{m-1}` and send
`G_k = Σ_i c_i·p_{i,k} + Com(0; ρ_k)` for `k ∈ 0..m`.

**Challenge:** `x = H(domain ‖ accumulator_root ‖ {C_i} ‖ {cl_j,ca_j,cb_j} ‖
{G_k} ‖ T ‖ message)` — one Fiat-Shamir challenge over the full transcript
(domain-separated, binds the anon set root, serial tag, and the spend message).

**Prover, round 2 (respond):** for each `j`:
- `f_j = l_j·x + a_j`
- `z_{a,j} = r_j·x + s_j`
- `z_{b,j} = t_j·(x − f_j) + s_j'` (bit-ness response per GK15)
and the final `z_d = r̂·x^m − Σ_k ρ_k·x^k`.

**Verifier checks** (all in the group; `pubkeys`/`c_i` derived from the anon set):
- bit-ness, per `j`: `Com(f_j; z_{a,j}) = x·cl_j + ca_j` and
  `Com(f_j·(x−f_j); z_{b,j}) = (x−f_j)·cl_j + cb_j`.
- one-of-many: `Σ_i c_i·∏_j( f_j if i_j=1 else x−f_j ) − Σ_k x^k·G_k = Com(0; z_d)`.
- serial: `T` links to the spent coin's serial (a paired Schnorr/linking check
  on the `H`-generator residue, following the Lelantus-Spark spend proof).

All equations hold iff the prover knew a valid opening at some hidden `l` with
serial `s` — the security follows GK15 special-soundness + the Fiat-Shamir
transform in the ROM.

## Proof struct (log-size) — the new wire form

```
GkOneOfManyProof {           // all scalars/points are 32-byte canonical encodings
    cl: Vec<[u8;32]>,        // m  bit commitments
    ca: Vec<[u8;32]>,        // m
    cb: Vec<[u8;32]>,        // m
    gk: Vec<[u8;32]>,        // m  the G_k commitments
    f:  Vec<[u8;32]>,        // m  responses f_j
    za: Vec<[u8;32]>,        // m
    zb: Vec<[u8;32]>,        // m
    zd: [u8;32],             // final response
}
SparkSpendProofV2 {
    serial_tag: [u8;32],
    proof:      GkOneOfManyProof,
    // anon set is referenced by the accumulator root + a Merkle path/positions,
    // NOT enumerated as O(n) indices as in the stand-in.
    message:    [u8;32],
}
```
Size: `≈ 7m + 1` scalars/points = **O(log N)** (vs the stand-in's `≈ 3N`).

## Interface (preserves the existing seam)

Mirror the current signatures so `check_shielded_tx`'s ACTIVATION SLOT and the
wallet builder swap cleanly:
- `prove_spark_spend_v2(note, anon_set: &[RistrettoPoint], real_index, message, rng) -> Result<SparkSpendProofV2>`
- `verify_spark_spend_v2(proof, anon_set: &[RistrettoPoint]) -> Result<()>`
- `batch_verify_sparks_v2(&[(proof, anon_set)]) -> Result<()>` (shared randomizer;
  must agree exactly with per-proof verify, incl. empty batch = ok).

`anon_set` is resolved from `ShieldedStore` by the accumulator root + positions
(no per-member indices on the wire).

## Non-negotiables before activation

1. **Canonical decoding everywhere.** All scalars via `from_canonical_bytes`
   (not `from_bytes_mod_order` — the stand-in's `SparkNote::*_scalar` and the
   audit note at lelantus_spark.rs:203 must be fixed), all points via a
   canonical Ristretto decode. Non-canonical malleability is a classic
   consensus-split / double-spend vector.
2. **Transcript rigor.** One domain-separated Fiat-Shamir hash over the entire
   statement (root, all commitments, serial tag, message). No missing binding →
   no weak-Fiat-Shamir forgery.
3. **Constant-time / zeroized secrets.** Serial/randomness zeroized on drop
   (already done for `SparkNote`); prover randomness from a CSPRNG.
4. **Property tests:** completeness (honest proof verifies), soundness
   (tampering any field, wrong index, forged serial, non-power-of-two padding,
   empty/one-element sets all rejected), batch==single agreement, and the
   Monero/Zcash historical-attack class (non-canonical, identity points,
   malleable encodings) — alongside the existing `historical_attacks/` suite.
5. **External audit** of the construction + implementation. This is the piece
   that must be audited before mainnet is ever unparked.

## Implementation plan (next, dedicated)

1. New module `crypto/groth_kohlweiss.rs` behind an off-by-default feature; the
   `GkOneOfManyProof` struct + borsh + canonical codecs, with round-trip tests.
2. Prover: bit-decomposition, round-1 commitments, polynomial coefficients,
   round-2 responses. Verifier: the three checks above.
3. Property/soundness test battery (item 4 above).
4. `SparkSpendProofV2` in the `ShieldedPayload`; wire `verify_spark_spend_v2`
   into the ACTIVATION SLOT (still gated); resolve `anon_set` from `ShieldedStore`.
5. Wallet builder produces V2 proofs; regtest end-to-end (mint → spend → mine →
   validate+apply → double-spend rejected → reorg-rewind), behind the gate.
6. Audit → then, and only then, propose a real `SHIELDED_TX_ACTIVATION_HEIGHT`.

## Reference

Groth & Kohlweiss, "One-out-of-Many Proofs: Or How to Leak a Secret and Spend a
Coin" (EUROCRYPT 2015); Lelantus / Lelantus-Spark (Jivanyan) for the
coin/serial/spend adaptation. The exact response algebra and the serial-binding
term follow those papers and are pinned in the implementation with test vectors.
