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

    let common = |b: &mut cc::Build| {
        b.include(&shims) // shims FIRST: boost/optional, chainparams, primitives/mint_spend
            .include(&src)
            .include(&s256)
            .include(s256.join("src"))
            .include(&lspk)
            .include(ossl.join("include"))
            .define("USE_NUM_NONE", None)
            .define("USE_FIELD_INV_BUILTIN", None)
            .define("USE_SCALAR_INV_BUILTIN", None)
            .define("USE_FIELD_10X26", None)
            .define("USE_SCALAR_8X32", None)
            .define("SECP256K1_BUILD", None)
            .define("WIN32", None)
            .define("NOMINMAX", None)
            .define("WIN32_LEAN_AND_MEAN", None)
            .warnings(false);
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
    println!("cargo:rustc-link-lib=libcrypto");
    for l in ["advapi32", "crypt32", "ws2_32", "user32", "gdi32"] {
        println!("cargo:rustc-link-lib={l}");
    }
}
