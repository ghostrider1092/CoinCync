# Vendored third-party source — attribution

The `src/` tree here is vendored from **Firo** (`github.com/firoorg/firo`,
`master`), used under the **MIT License**:

> Copyright (c) 2016-2026 The Firo Core developers
> Copyright (c) 2009-2026 The Bitcoin Core developers
> (full text: firoorg/firo `COPYING`)

It is compiled only when the `spark-connector` crate's **`libspark-ffi`** feature
is enabled (see `../build.rs`). It provides Firo's Lelantus-Spark implementation
(`src/libspark/`), its secp256k1 C++ primitives (`src/secp256k1/`), and the
Bitcoin-core crypto/serialization it depends on (`src/crypto/`, `src/*.h`).

## Verbatim vs. modified

- **Verbatim (unmodified) Firo:** everything under `src/libspark/`,
  `src/secp256k1/`, `src/crypto/`, `src/support/`, `src/compat/`, and the
  Bitcoin-core root headers (`serialize.h`, `streams.h`, `hash.h`, `uint256.*`,
  etc.). **No cryptographic code is modified.**
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
