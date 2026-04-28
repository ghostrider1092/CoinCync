# Tier 12 — Post-Quantum Resistance

_Threat model and forward-looking assertions for when quantum computing is plausible._

---

## The threat

Shor's algorithm breaks every cryptographic primitive in CoinCync that relies on the discrete logarithm problem:

- **CLSAG ring signatures** — forgeable
- **Stealth address derivation** — reversible
- **Pedersen commitments** — binding property broken
- **Bulletproofs+ range proofs** — soundness broken

## Timeline

- **Optimistic:** 2032-2038
- **Middle estimate:** 2040-2050
- **Pessimistic:** Never

## Testable assertions now

### 12.1 — No cryptographic operation is unbounded
Post-quantum primitives are larger/slower. Code with unbounded loops becomes unworkable at PQ sizes.

### 12.2 — All primitives are upgradeable
Is there a `Signature` trait, a `Commitment` trait? Or is `RistrettoPoint` hardcoded in 300 places?

### 12.3 — Hash function outputs are large enough
Grover's gives quadratic speedup. Need 256-bit hashes minimum for 128-bit PQ security.

### 12.4 — Symmetric crypto uses 256-bit keys
AES-128 has only 64-bit PQ security. AES-256 has 128-bit PQ security.

## Status

**Currently:** Not urgent. No action required pre-mainnet.
**Action:** Document migration path. Monitor NIST PQC standardization.
