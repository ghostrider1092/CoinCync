<!-- markdownlint-disable MD036 MD013 -->
# Comit reference test vectors

**Source:** [github.com/comit-network/xmr-btc-swap](https://github.com/comit-network/xmr-btc-swap)
**Import status:** STUB — directory scaffolded, vectors not yet imported.
**Import git SHA:** _to be filled in when first batch is imported_
**Import date:** _to be filled in when first batch is imported_
**Upstream license:** MIT (as of the latest tagged release; verify at import time)

## What lives in this directory

- `SCHEMA.md` — JSON schema each vector file conforms to (one vector per file).
- `btc-adaptor/*.json` — BIP-340 Schnorr adaptor signature vectors (create, verify, decrypt, recover).
- `dleq-cross-curve/*.json` — Maxwell-Poelstra cross-curve DLEQ vectors (prove, verify).
- `state-machine/*.json` — Protocol-level vectors for the swap state machine (optional; deferred).

## Why these vectors

Comit's `xmr-btc-swap` has been in production since 2021 and was reviewed by
Kudelski Security. Their BIP-340 adaptor and cross-curve DLEQ implementations
have ~3 years of real-world swap evidence + a public third-party audit. Matching
their outputs bit-for-bit gives us cryptographic-correctness assurance grounded
in someone else's track record, not just our test suite.

## Acceptance criteria for "vectors imported"

- ≥ 10 vectors per primitive category
- All vectors run through `tests/external_vectors.rs` with `assert_eq!` on bytes
- This file's "Import status" updated to `IMPORTED`, with SHA + date filled in
