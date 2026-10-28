# Vendored third-party source — attribution

The `src/` tree here is vendored from **Firo** (`github.com/firoorg/firo`),
pinned at tag **`v0.14.18.1`** = commit
**`c03cd0a1c68e1af8274349d1234d142ae7d02d1e`**, used under the **MIT License**:

> Copyright (c) 2016-2026 The Firo Core developers
> Copyright (c) 2009-2026 The Bitcoin Core developers
> (full text: firoorg/firo `COPYING`)

It is compiled only when the `spark-connector` crate's **`libspark-ffi`** feature
is enabled (see `../build.rs`). It provides Firo's Lelantus-Spark implementation
(`src/libspark/`), its secp256k1 C++ primitives (`src/secp256k1/`), and the
Bitcoin-core crypto/serialization it depends on (`src/crypto/`, `src/*.h`).

## Verbatim vs. modified

- **Verbatim (unmodified) Firo:** everything under `src/libspark/` (EXCEPT the
  single CoinCync consensus delta in `params.cpp`/`params.h`, documented below),
  `src/secp256k1/`, `src/crypto/`, `src/support/`, `src/compat/`, and the
  Bitcoin-core root headers (`serialize.h`, `streams.h`, `hash.h`, `uint256.*`,
  etc.). **No cryptographic / proof code is modified.**
- **CoinCync consensus delta — the ONLY change to Firo's `libspark` tree:**
  `src/libspark/params.{cpp,h}` add a `Params::get_coincync()` factory
  (n=8, m=3 => N=512), CoinCync's RATIFIED production Grootle anon-set. It adds a
  new parameter set *alongside* Firo's `get_default()` / `get_test()`; it touches
  no existing Firo code path and no proof/verify logic. The `Params` ctor is
  unchanged, so the one-of-many (Grootle) math is byte-identical to upstream at
  the chosen (n,m). N=512 was selected from the verify-cost benchmark
  (`docs/design/cip-shielded-anonset.md`) for IBD viability vs. Firo's
  `get_default` N=32768 (~2.7 s/block base multiexp). This factory is the one
  line of the provenance pin that is NOT byte-identical to firo v0.14.18.1.
- **Minimal shims (node *infrastructure*, NOT crypto):**
  - `src/util.h` and `src/sync.h` — replaced with minimal equivalents. The
    originals dragged in `boost::thread` / `boost::filesystem` / logging /
    `tinyformat` that libspark does not use; the shims provide only what libspark
    references (`cmp::*` helpers, a `std::recursive_mutex`-backed
    `CCriticalSection`/`LOCK`, no-op `LogPrintf`, `FIRO_UNUSED`).
  - `shims/boost/optional.hpp` — maps `boost::optional` → `std::optional`
    (`serialize.h`'s only Boost use; libspark never instantiates it).
  - `shims/chainparams.h`, `shims/primitives/mint_spend.h` — satisfy vestigial
    includes (libspark uses no symbols from them, bar an unused
    `GetPubCoinValueHash` declaration).

These shims control the *build environment* only; Firo's Spark crypto and proof
code compile exactly as written. See `docs/design/cip-shielded-libspark-ffi.md`.

## Provenance verification

The pin was confirmed against upstream: `src/version.h`
(`PROTOCOL_VERSION = 90031`, `MIN_FIRO_CLIENT_VERSION = 141000`) matches
firo@`v0.14.18.1`, and the vendored verbatim crypto files `libspark/grootle.cpp`,
`libspark/chaum.cpp`, and `libspark/spend_transaction.cpp` are **byte-identical**
to that tag after LF normalization (SHA-256 equal). An auditor can reproduce:

```sh
tag=v0.14.18.1
for f in grootle chaum spend_transaction; do
  diff <(tr -d '\r' < src/libspark/$f.cpp) \
       <(curl -s https://raw.githubusercontent.com/firoorg/firo/$tag/src/libspark/$f.cpp)
done
```

The only vendored-side departures from this tag are the build-environment shims
listed above and the additive `getVout()` accessor in `libspark/spend_transaction.h`
(CoinCync #258 — a read-only getter, no crypto change).
