// Builds the vendored Firo libspark FFI backend — ONLY when the `libspark-ffi`
// feature is enabled. With the feature off (the default) this is a no-op, so a
// normal CoinCync build never invokes the C++ toolchain, secp256k1, or OpenSSL.
//
// Requires env SPARK_OPENSSL_DIR pointing at an OpenSSL install (a directory
// containing include/ and lib/, e.g. a vcpkg x64-windows-static-md prefix).
//
// libspark + secp256k1 + Bitcoin-core crypto under vendor/src are VERBATIM Firo;
// only node-infrastructure headers (vendor/src/util.h, sync.h, and vendor/shims/*)
// are minimal shims — no crypto is modified. See
// docs/design/cip-shielded-libspark-ffi.md.

use std::path::PathBuf;

fn main() {
    if std::env::var("CARGO_FEATURE_LIBSPARK_FFI").is_err() {
        return; // feature off: no native build
    }

    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let vendor = manifest.join("vendor");
    let src = vendor.join("src");
    let s256 = src.join("secp256k1");
    let lspk = src.join("libspark");
    let shims = vendor.join("shims");

    let ossl = PathBuf::from(std::env::var("SPARK_OPENSSL_DIR").expect(
        "libspark-ffi requires SPARK_OPENSSL_DIR to point at an OpenSSL install \
         (a directory with include/ and lib/)",
    ));
    println!("cargo:rerun-if-env-changed=SPARK_OPENSSL_DIR");
    println!("cargo:rerun-if-changed=csrc/shim.cpp");

    // Target detection for cross-platform build selection. MSVC lacks
    // `__int128` (so it can't use secp256k1's fast 64-bit limbs), and the
    // Windows platform defines must not leak into a Linux build. These select
    // pre-existing in-tree code paths only — no vendored Firo crypto is edited.
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let is_msvc = target_env == "msvc";
    let is_windows = target_os == "windows";

    let common = |b: &mut cc::Build| {
        // Force the vendored C/C++ (secp256k1 + libspark) to compile OPTIMIZED
        // regardless of the cargo profile. Without this the `cc` build inherits
        // the profile's OPT_LEVEL, so our usual debug soaks/tests compiled the
        // crypto at `/Od` — the Grootle/Pippenger multiexp over a large cover
        // set is then dramatically slower than it should be (a big chunk of the
        // observed ~100x-vs-Firo verify cost was simply unoptimized C++, not a
        // missing batched multiexp — the Pippenger path is present). We set the
        // opt level explicitly and KEEP asserts on (no NDEBUG) so the crypto's
        // debug-time invariant checks still fire on the audit track.
        b.opt_level(2);
        b.include(&shims) // shims FIRST: boost/optional, chainparams, primitives/mint_spend
            .include(&src)
            .include(&s256)
            .include(s256.join("src"))
            .include(&lspk)
            .include(ossl.join("include"))
            .define("USE_NUM_NONE", None)
            .define("USE_FIELD_INV_BUILTIN", None)
            .define("USE_SCALAR_INV_BUILTIN", None)
            .define("SECP256K1_BUILD", None)
            .warnings(false);

        // secp256k1 field/scalar backend. MSVC has no `__int128`, so it must use
        // the 32-bit limb impls (`10x26`/`8x32`); Clang/GCC use the fast 64-bit
        // limbs (`5x52`/`4x64`) — the field-arithmetic edge Firo's Linux build
        // has and the MSVC build cannot match.
        if is_msvc {
            b.define("USE_FIELD_10X26", None)
                .define("USE_SCALAR_8X32", None);
        } else {
            // The 64-bit limb impls use `uint128_t`, which secp256k1's util.h
            // only typedefs under HAVE___INT128 (vendored build ships no
            // autoconf config). Clang/GCC have the extension (verified).
            b.define("USE_FIELD_5X52", None)
                .define("USE_SCALAR_4X64", None)
                .define("HAVE___INT128", None);
        }

        // Windows-only platform defines — must NOT be set on Linux, or
        // <windows.h>-shaped assumptions leak into the glibc build.
        if is_windows {
            b.define("WIN32", None)
                .define("NOMINMAX", None)
                .define("WIN32_LEAN_AND_MEAN", None);
        }

        // Linux/glibc: make the Bitcoin-core compat/endian.h defer to the system
        // <endian.h>. It ships no bitcoin-config.h, so without these HAVE_* it
        // emits its own inline htobe*/le* that collide with glibc's macros. Pure
        // build-config; no source edit.
        //
        // INVARIANT — keep this `linux` ONLY, never widen to "non-Windows":
        // macOS must NOT get HAVE_ENDIAN_H. compat/endian.h and byteswap.h have
        // their own `#elif defined(__APPLE__)` branches (<libkern/OSByteOrder.h>)
        // reached only when HAVE_ENDIAN_H is unset; defining it on macOS forces a
        // non-existent <endian.h> include and breaks the Mac build. (macOS still
        // gets the 64-bit limbs + HAVE___INT128 from the non-MSVC branch above.)
        if target_os == "linux" {
            b.define("HAVE_ENDIAN_H", "1");
            for m in [
                "HTOBE16", "HTOLE16", "BE16TOH", "LE16TOH", "HTOBE32", "HTOLE32",
                "BE32TOH", "LE32TOH", "HTOBE64", "HTOLE64", "BE64TOH", "LE64TOH",
            ] {
                b.define(&format!("HAVE_DECL_{m}"), "1");
            }
        }
    };

    // secp256k1 C library.
    let mut c = cc::Build::new();
    common(&mut c);
    c.file(s256.join("src").join("secp256k1.c"))
        .define("ECMULT_WINDOW_SIZE", "15")
        .define("ECMULT_GEN_PREC_BITS", "4");
    c.compile("secp256k1");

    // C++: secp_primitives + full libspark + Bitcoin-core crypto + the C shim.
    let mut cpp = cc::Build::new();
    common(&mut cpp);
    cpp.cpp(true).std("c++17");
    // Audit-gated anon-set params: with the `spark-prod-params` feature on, the
    // shim's shim_params() selects Firo's production Grootle params
    // (get_default, N=32768) instead of get_test(). Used for the verify-cost
    // benchmark and a future audit-gated production build; the SHIPPED default
    // stays get_test() (feature off). See docs/design/cip-shielded-anonset.md.
    if std::env::var("CARGO_FEATURE_SPARK_PROD_PARAMS").is_ok() {
        cpp.define("SPARK_PROD_PARAMS", None);
    }
    let files = [
        s256.join("src").join("cpp").join("GroupElement.cpp"),
        s256.join("src").join("cpp").join("Scalar.cpp"),
        s256.join("src").join("cpp").join("MultiExponent.cpp"),
        lspk.join("keys.cpp"),
        lspk.join("coin.cpp"),
        lspk.join("params.cpp"),
        lspk.join("util.cpp"),
        lspk.join("hash.cpp"),
        lspk.join("aead.cpp"),
        lspk.join("kdf.cpp"),
        lspk.join("transcript.cpp"),
        lspk.join("bech32.cpp"),
        lspk.join("f4grumble.cpp"),
        lspk.join("schnorr.cpp"),
        lspk.join("chaum.cpp"),
        lspk.join("grootle.cpp"),
        lspk.join("bpplus.cpp"),
        lspk.join("spend_transaction.cpp"),
        lspk.join("mint_transaction.cpp"),
        src.join("crypto").join("sha256.cpp"),
        src.join("crypto").join("sha512.cpp"),
        src.join("crypto").join("hmac_sha512.cpp"),
        src.join("crypto").join("hmac_sha256.cpp"),
        src.join("crypto").join("aes.cpp"),
        src.join("crypto").join("chacha20.cpp"),
        src.join("uint256.cpp"),
        src.join("support").join("cleanse.cpp"),
        manifest.join("csrc").join("shim.cpp"),
    ];
    for f in files {
        cpp.file(f);
    }
    cpp.compile("spark_libspark");

    println!("cargo:rustc-link-search=native={}", ossl.join("lib").display());
    if is_windows {
        // MSVC: OpenSSL import lib is `libcrypto.lib`; plus the Win32 system
        // libs libspark's crypto/entropy paths pull in.
        println!("cargo:rustc-link-lib=libcrypto");
        for l in ["advapi32", "crypt32", "ws2_32", "user32", "gdi32"] {
            println!("cargo:rustc-link-lib={l}");
        }
    } else {
        // Linux/Unix: link OpenSSL's `crypto` (the system default search path
        // resolves libcrypto.{a,so}); no Win32 system libs. The C++ standard
        // library for the compiled objects is linked by the `cc` crate.
        println!("cargo:rustc-link-lib=crypto");
    }
}
