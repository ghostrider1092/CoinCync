<!-- markdownlint-disable MD036 MD013 -->
# Farcaster reference test vectors

**Source:** [github.com/farcaster-project/farcaster-node](https://github.com/farcaster-project/farcaster-node) (and the `farcaster-core` companion crate).
**Import status:** STUB — directory scaffolded, vectors not yet imported.
**Import git SHA:** _to be filled in when first batch is imported_
**Import date:** _to be filled in when first batch is imported_
**Upstream license:** LGPL-3.0 for `farcaster-node`, MIT for `farcaster-core` (verify at import time).

## What lives in this directory

- `SCHEMA.md` — JSON schema each vector file conforms to (one vector per file).
- `btc-adaptor/*.json` — BIP-340 Schnorr adaptor signature vectors (parallel to Comit's, lets us cross-check both reference impls match each other).
- `ed25519-adaptor/*.json` — Monero-style ed25519 adaptor sig vectors. Our impl uses Ristretto255 (the strictly stronger prime-order sibling); these vectors validate the underlying scalar/point arithmetic even though our group representation differs.
- `dleq-cross-curve/*.json` — Cross-curve DLEQ vectors.
- `wire-protocol/*.json` — Protocol message format vectors (deferred; lower-priority than crypto).

## Why these vectors in addition to Comit's

Two independent reference impls verifying the same primitives independently is
stronger than one. If Comit and Farcaster ever disagree on a vector, *that's
the bug we want to catch.* Cross-checking against both eliminates the risk of
a shared upstream-library bug that infected both Comit and us but not Farcaster
(or vice versa).

## Acceptance criteria for "vectors imported"

- ≥ 10 vectors per primitive category
- All vectors run through `tests/external_vectors.rs` with `assert_eq!` on bytes
- Cross-check pass: for each shared primitive, run the same input through both
  Comit's and Farcaster's vector and verify our output matches both
- This file's "Import status" updated to `IMPORTED`, with SHA + date filled in
