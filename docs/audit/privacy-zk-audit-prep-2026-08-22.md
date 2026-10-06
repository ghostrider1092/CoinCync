# Audit Prep — Hand-Rolled Zero-Knowledge Constructions (2026-08-22)

This document is for an external cryptographic reviewer. It specifies the two
hand-rolled zero-knowledge constructions CoinCync introduced, states the exact
security property each must provide, gives the threat model, and maps the
review targets to the code and tests.

**Status of both constructions:** feature-gated **off**, not part of the RingCT
mainnet consensus transaction format, and routed only through the
`privacy_connector` boundary whose master interlock `CONNECTOR_AUDITED` ships
`false`. They will not guard real funds until this review is complete and the
schemes are activated at a scheduled hard-fork height. Nothing here is live.

Everything below is grounded in the source; file references are the review
targets.

---

## A. Lelantus Spark spend proof — dual-base serial-tag binding

**Files:** `src/crypto/lelantus_spark.rs` (`prove_spark_spend`,
`verify_spark_spend`). Feature `sketch-lelantus-spark`.

### What it is
A one-out-of-many (AOS-style) ring signature that proves the prover knows the
opening of one commitment in an anonymity set, **and** binds a serial tag
`T = s·G` (the public nullifier used for double-spend detection) to the *same*
secret `s`.

- Commitment: `C = v·G + s·H + r·K` (`spark_commit`).
- Ring public keys: `P_i = C_i − v·G − r·K` (`spark_pubkey`); for the real coin
  `P_real = s·H`.
- Serial tag: `T = s·G` (`spark_serial_tag`).

### Security property to review
**Soundness of the tag binding (this is the fix — "H-1"):** a prover must not be
able to produce a verifying proof whose serial tag `T' ≠ s·G` for the `s` that
opens the real ring member. If they could, they could present a fresh tag on
each spend and defeat double-spend detection (unlimited double-spends).

### Construction (the fix)
The ring is a **dual-base** proof. At each step the transcript hashes a companion
G-side commitment alongside the H-side one, sharing the same `(z_i, c_i)`:

```
L_i  = z_i·H + c_i·P_i      (H-side, proves P_real = s·H)
L'_i = z_i·G + c_i·T        (G-side, proves T      = s·G, same s)
```

The real opener uses one nonce `k` for both `k·H` and `k·G`; closing the ring
(`z_real = k − c_real·s`) forces `T = s·G` for the verifier's recomputation to
match. Both `prove_spark_spend` and `verify_spark_spend` hash `L_i` **and**
`L'_i` at the seed, at every step, and at the ring-close check.

### Threat model / attacker capabilities
- Chooses the anonymity set and the real index; knows `s`, `v`, `r` for the real
  coin.
- Controls proof generation entirely (can deviate from the honest prover).
- Goal 1 (soundness): forge a proof for a coin they do not own.
- Goal 2 (double-spend): produce a verifying proof with a tag `T' ≠ s·G`.
- Goal 3 (malleability): mutate an existing proof to another verifying proof.

### Points a reviewer should scrutinize
1. Fiat-Shamir transcript completeness — is every proof element and the context
   (message, index, `T`) bound so the proof is non-malleable and
   context-bound? (`fs_challenge` inputs at seed/step/close.)
2. The n=1 degenerate path (collapses to a Schnorr-style proof) — is the tag
   binding still enforced there? (`verify_spark_spend`, `n == 1` branch.)
3. Scalar canonicality of peer-supplied challenges/responses (`PeerScalar`).
4. Whether the shared `(value, randomness)` used in the tests is a test-only
   simplification vs. the intended per-coin derivation (it is test-only; confirm
   the production opening derivation is sound).

### Test coverage (review targets)
- Completeness n=1/2/3/5: `lelantus_spark` unit tests.
- Forged-tag rejection: `double_spend_forged_serial_tag_is_rejected`.
- Tamper/context rejection: `soundness_rejects_*` unit tests.
- Randomized: `tests/property_invariants_spark_mw.rs` (`spark_completeness`,
  `spark_tamper_rejected`, `spark_wrong_pubkeys_rejected`).

---

## B. MimbleWimble cut-through kernel — excess signature

**Files:** `src/crypto/mw_cutthrough.rs` (`build_signed_kernel`, `sign_kernel`,
`verify_kernel_signature`, `CutThroughEngine::verify_kernel_set`). Compiled in
the default build but **inert** (no production caller registers candidates).

### What it is
Each kernel carries a Schnorr signature over base `G` proving the signer knows
`x` where the kernel's public excess is `excess = x·G + fee·H`. The signature is
over `P = excess − fee·H` (which must be a pure blinding `x·G`).

### Security property to review
**No hidden value (this is the fix):** a kernel must not be able to carry a
`v·H` component beyond the declared `fee`. Aggregate balance
(`Σ excess == Σ fee·H`) alone is insufficient — canceling `+v·H` / `−v·H`
components across kernels balance in aggregate while hiding value creation. The
per-kernel signature over base `G` makes any residual `H` component unsignable.

### Construction
- Nonce is deterministic (RFC-6979-style) from `(x, fee, height)` — review the
  nonce derivation for reuse/bias (`kernel_sig_nonce`).
- Challenge binds `R`, `P`, `fee`, `height` (`kernel_sig_challenge`) so a
  signature cannot be lifted onto a kernel with a different fee/height.
- Verification: `s·G == R + e·P` with `P = excess − fee·H`.

### Threat model
- Chooses excess points and fees freely; goal is to pass `verify_kernel_set`
  while a kernel encodes value creation, or to forge/replay a signature.

### Points a reviewer should scrutinize
1. The deterministic nonce derivation — is it safe against nonce reuse across
   distinct messages, and free of bias? (`kernel_sig_nonce`.)
2. Domain separation of the two hash tags (`KERNEL_SIG_NONCE_TAG`,
   `KERNEL_SIG_CHALLENGE_TAG`).
3. Canonicality checks on `R` (decompress) and `s` (`from_canonical_bytes`).
4. Whether `verify_kernel_set`'s aggregate-plus-per-kernel checks are jointly
   sufficient for the intended MW soundness in the eventual live design (the
   module is inert today; the live wiring does not exist yet).

### Test coverage (review targets)
- Sign/verify round-trip + tamper: `sign_verify_kernel_roundtrip`.
- Unsigned/invalid rejection: `verify_kernel_set_rejects_unsigned_kernel`.
- Inflation rejection: `verify_kernel_set_rejects_hidden_value_inflation`.
- Randomized: `tests/property_invariants_spark_mw.rs`
  (`mw_kernel_sign_verify_roundtrip`, `mw_kernel_tamper_rejected`,
  `mw_hidden_value_inflation_rejected`).

---

## C. The activation boundary (review as a unit)

**File:** `src/crypto/privacy_connector.rs`.

Both schemes reach chain state only through this connector. A reviewer should
confirm the interlocks are fail-closed and cannot be bypassed:
- `CONNECTOR_AUDITED` (ships `false`) gates all mainnet use and the value
  converter.
- `ConnectorGate::check` requires: not killed, scheme compiled, mainnet ⇒
  audited, activation height reached, plus a per-block rate limit.
- `convert_value` is an explicit **stub** (no ZK equal-value protocol exists) and
  errors while unaudited.

---

## D. What we are asking for

1. Review the two constructions (A, B) against their stated soundness properties
   and threat models.
2. Confirm the connector boundary (C) is fail-closed and non-bypassable.
3. Flag any transcript/nonce/canonicality issue, and any gap between the tests
   and the properties.

An external sign-off here is the precondition for flipping `CONNECTOR_AUDITED`
and scheduling activation. Until then these remain gated and inert.
