# CIP — libspark FFI cross-platform build (Linux/Clang + 64-bit limbs)

**Status: PROVEN on Linux (2026-10-19).** `libspark-ffi` — previously MSVC-only —
now builds and runs correctly on Linux (WSL Ubuntu, clang-18, rustc 1.88.0):
`spark-connector` compiles; its gated crypto suite is **23 passed / 0 failed**
with the 64-bit-limb path; and a full `coincync-node --features "testnet
sketch-gk-proof libspark-ffi"` builds to an x86-64 ELF. Verify-cost at the
ratified N=512 (get_coincync): **single 45.6 ms/spend, batched 7.3 ms/spend
(6.28×)** — ~1.44× faster than the MSVC 32-bit-limb build (65.6 / 10.4). Four
blockers were cleared, all in our shim/build layer (no Firo crypto edited):
endian defines, the `CDataStream::write` append, the `5x52`/`4x64` limb
selection, and `HAVE___INT128` (the last discovered during the port — the 64-bit
limb impls need it to typedef `uint128_t`). MSVC byte-identity reconfirm is the
one remaining gate before commit. **Author track:** shielded (Spark) pool.
**Why now:** the anon-set verify-cost bench showed shielded Grootle verify at
~100× Firo. Investigation (2026-10-19) found this is **not** a missing-batched-
multiexp bug — libspark's Pippenger batched multiexp is present and runs
(`vendor/src/secp256k1/src/cpp/MultiExponent.cpp` → `secp256k1_ecmult_multi_var`
→ `secp256k1_ecmult_pippenger_batch`, with no silent naive fallback). The cost
is a **build/platform** artifact with two levers, plus a hard portability gap.

This doc is the executable plan. It is written while a bench holds the
`spark-connector` C++ toolchain; the edits below are applied once that frees.

## Problem statement

Two independent issues produce the measured gap and block a Linux build:

1. **Unoptimized vendored C++ in our usual (debug) builds.** `build.rs` set no
   explicit opt level, so the `cc` compile inherited the cargo profile — every
   debug soak/test compiled the crypto at `/Od`. **Fixed 2026-10-19**: `build.rs`
   `common` closure now sets `b.opt_level(2)` unconditionally (asserts kept, no
   `NDEBUG`, so the audit-track invariant checks still fire). Re-bench pending.

2. **`libspark-ffi` only compiles on MSVC today.** Two blockers stop the
   Linux/Clang (and GCC) build; while MSVC-only, the Linux production fleet
   cannot run a shielded node at all, *and* MSVC is forced onto the slow 32-bit
   secp256k1 limbs (below). Both blockers are in **our shim layer**, not in the
   pinned Firo crypto (firo v0.14.18.1, byte-verbatim under `vendor/src`).

### Blocker A — endian compat header redefinition
`vendor/src/compat/endian.h` is the Bitcoin Core compat header, fully guarded by
autoconf macros (`HAVE_ENDIAN_H`, `HAVE_DECL_HTOBE16..LE64`). This vendored build
ships no `bitcoin-config.h`, so on Linux none of those are defined: the header
does **not** include glibc `<endian.h>` and instead emits its own inline
`htobe64`/… which then collide with the glibc macros pulled in transitively (via
`byteswap.h`/system headers). MSVC never sees glibc, so it compiles clean today.

### Blocker B — `CDataStream` iterator-triple `insert`
`csrc/shim.cpp:404` and `:438`:
```cpp
ss.insert(ss.end(), tx_stream.begin(), tx_stream.end());
```
`CDataStream::insert`'s range overload (`streams.h:251`) takes
`std::vector<char>::const_iterator`, but `tx_stream.begin()/end()` return
`std::vector<char, zero_after_free_allocator<char>>::iterator` — a different
allocator type. MSVC's iterators collapse to a convertible pointer type so it
resolves; libstdc++ (g++/clang) treats them as distinct → no matching overload →
compile error.

## Fixes (all target-gated so the MSVC build stays byte-identical)

### Fix 1 — endian defines (build.rs, Linux target only)
In `build.rs`, when `CARGO_CFG_TARGET_OS == "linux"`, add to the `common`
closure:
```rust
b.define("HAVE_ENDIAN_H", "1");
for m in ["HTOBE16","HTOLE16","BE16TOH","LE16TOH",
          "HTOBE32","HTOLE32","BE32TOH","LE32TOH",
          "HTOBE64","HTOLE64","BE64TOH","LE64TOH"] {
    b.define(&format!("HAVE_DECL_{m}"), "1");
}
```
This makes the compat header include glibc `<endian.h>` and skip its own inline
defs. No source edit. (If `byteswap.h` also collides, add `HAVE_BYTESWAP_H=1` by
the same gate — confirm during the first Linux compile.)

### Fix 2 — portable append (shim.cpp, unconditional)
Replace both iterator-triple inserts with the byte/size `write`, which exists on
this `CDataStream` (`streams.h:103`) and appends identically:
```cpp
ss.write(tx_stream.data(), tx_stream.size());
```
`data()` (`streams.h:248`) + `size()` (`streams.h:239`). Byte-identical output on
MSVC (both `insert(end,…)` and `write` append the same bytes), so this is a pure
portability fix, not cfg-gated. Our code, not Firo's.

### Fix 3 — 64-bit limbs on Clang/GCC (build.rs, non-MSVC target only)
MSVC lacks `__int128`, forcing `USE_FIELD_10X26`/`USE_SCALAR_8X32` (32-bit). On
Clang/GCC select the fast path instead:
```rust
if target_is_msvc {
    b.define("USE_FIELD_10X26", None).define("USE_SCALAR_8X32", None);
} else {
    b.define("USE_FIELD_5X52", None).define("USE_SCALAR_4X64", None);
}
```
This is the lever that recovers most of Firo's edge (Firo benches on Linux/GCC
with 64-bit limbs). The secp256k1 source already contains both implementations;
this only selects which compiles.

## macOS

macOS is handled by the **same** target gating, by construction — no extra
`build.rs` branch is required:

- Non-MSVC → `5x52`/`4x64` + `HAVE___INT128` (Apple clang has `__int128` on both
  x86_64 and arm64).
- Non-Windows → no `WIN32` defines; link `crypto`, no Win32 syslibs.
- The endian defines stay **`target_os == "linux"` only** (not "non-Windows") on
  purpose: the vendored `compat/endian.h` / `byteswap.h` have their own
  `#elif defined(__APPLE__)` branches (`<libkern/OSByteOrder.h>`), reached only
  when `HAVE_ENDIAN_H` is unset. Defining `HAVE_ENDIAN_H` on macOS would force a
  non-existent `<endian.h>` include and break the build — so macOS must *not*
  get the Linux endian defines. (A `build.rs` comment guards this invariant.)

### macOS build recipe (for the Mac testers)

```bash
brew install openssl@3 cmake llvm            # OpenSSL (keg-only) + randomx deps
export SPARK_OPENSSL_DIR="$(brew --prefix openssl@3)"   # has include/ + lib/
export LIBCLANG_PATH="$(brew --prefix llvm)/lib"        # for randomx bindgen (node build)
# connector only (fast crypto check):
cargo test -p spark-connector --features libspark-ffi
# full shielded node:
cargo build --release --bin coincync-node \
  --features "testnet sketch-gk-proof libspark-ffi"
```

**Status: unverified** — correct by construction + file-scan, but there is no Mac
in this environment to build on. The Mac testers running the recipe above is the
verification; any gap it surfaces (Homebrew prefix layout, a missing Apple
framework such as `Security`/`CoreFoundation`, libc++ quirk) is then a small
build-config follow-up, not a crypto change.

## Test plan (after the toolchain frees)

1. **MSVC regression (byte-identity):** the shim `write` change must not alter
   output. Re-run `cargo test --release -p spark-connector --features
   "libspark-ffi"` on Windows; all existing FFI tests green. The verify bundle
   bytes are unchanged (append semantics identical).
2. **Linux compile:** build `spark-connector --features libspark-ffi` under WSL
   Clang-18 (needs a Linux OpenSSL static-md equiv for `SPARK_OPENSSL_DIR`).
   Iterate on any residual header gaps (expect `byteswap.h` at most).
3. **Linux correctness + speed:** run `libspark_verify_cost_benchmark` and
   `libspark_verify_batch_split_bench` (`--features "libspark-ffi
   spark-prod-params"`) on Linux and compare N=32768 against the MSVC `/O2`
   number. Expected: the 64-bit-limb Linux build approaches Firo's published
   cost, closing the gap without touching any crypto.
4. **Full shielded suite** on the gated Windows build remains the consensus gate
   (unchanged by any of this).

## Provenance / audit note

No file under `vendor/src` (Firo crypto: secp256k1, libspark, Bitcoin-core
crypto) is modified — the byte-verbatim pin (firo v0.14.18.1) and `build.rs`'s
"no crypto is modified" invariant hold. Fix 1 and Fix 3 are `build.rs` `-D`
defines that select pre-existing in-tree code paths; Fix 2 edits only our own
`csrc/shim.cpp` and is byte-identical on the current (MSVC) target.
