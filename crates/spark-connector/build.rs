// Builds the vendored Firo libspark FFI backend — ONLY when the `libspark-ffi`
// feature is enabled. With the feature off (the default) this is a no-op, so a
// normal CoinCync build never invokes the C++ toolchain, secp256k1, or OpenSSL.
//
// OpenSSL is located by `find_openssl`: SPARK_OPENSSL_DIR (a directory containing
// include/ and lib/, e.g. a vcpkg x64-windows-static-md prefix) always wins and is
// required on Windows/MSVC; on Linux/macOS it falls back to pkg-config `libcrypto`,
// then to Homebrew's openssl@3 on macOS.
//
// libspark + secp256k1 + Bitcoin-core crypto under vendor/src are VERBATIM Firo;
// only node-infrastructure headers (vendor/src/util.h, sync.h, and vendor/shims/*)
// are minimal shims — no crypto is modified. See
// docs/design/cip-shielded-libspark-ffi.md.

use std::path::PathBuf;

/// Locate OpenSSL for the native build. Returns (include dirs, link-search
/// dirs, link-lib names) so `main` can emit the link lines itself, *after* the
/// two static archives `cc` produces (order matters for the C++ objects).
fn find_openssl(target_os: &str) -> (Vec<PathBuf>, Vec<PathBuf>, Vec<String>) {
    if let Ok(dir) = std::env::var("SPARK_OPENSSL_DIR") {
        let d = PathBuf::from(dir);
        // Debian multiarch keeps libcrypto under lib/<triplet>; search those too.
        let mut search = vec![d.join("lib"), d.join("lib64")];
        if let Ok(rd) = std::fs::read_dir(d.join("lib")) {
            search.extend(rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()));
        }
        // MSVC links the import library `libcrypto.lib`; Unix links `-lcrypto`.
        let lib = if target_os == "windows" {
            "libcrypto"
        } else {
            "crypto"
        };
        return (vec![d.join("include")], search, vec![lib.to_string()]);
    }
    if target_os != "windows" {
        if let Ok(p) = pkg_config::Config::new()
            .cargo_metadata(false)
            .probe("libcrypto")
        {
            return (p.include_paths, p.link_paths, p.libs);
        }
        if target_os == "macos" {
            for prefix in ["/opt/homebrew/opt/openssl@3", "/usr/local/opt/openssl@3"] {
                let d = PathBuf::from(prefix);
                if d.join("include/openssl/crypto.h").exists() {
                    return (
                        vec![d.join("include")],
                        vec![d.join("lib")],
                        vec!["crypto".to_string()],
                    );
                }
            }
        }
    }
    panic!(
        "libspark-ffi: OpenSSL not found. Install libssl-dev (Debian/Ubuntu), openssl-devel \
         (Fedora) or `brew install openssl@3` (macOS), or set SPARK_OPENSSL_DIR to a prefix \
         containing include/ and lib/ (required on Windows)."
    );
}

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

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let (ossl_include, ossl_search, ossl_libs) = find_openssl(&target_os);
    println!("cargo:rerun-if-env-changed=SPARK_OPENSSL_DIR");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rerun-if-changed=csrc");
    println!("cargo:rerun-if-changed=vendor");

    let common = |b: &mut cc::Build| {
        b.include(&shims) // shims FIRST: boost/optional, chainparams, primitives/mint_spend
            .include(&src)
            .include(&s256)
            .include(s256.join("src"))
            .include(&lspk)
            .includes(&ossl_include)
            .define("USE_NUM_NONE", None)
            .define("USE_FIELD_INV_BUILTIN", None)
            .define("USE_SCALAR_INV_BUILTIN", None)
            .define("USE_FIELD_10X26", None)
            .define("USE_SCALAR_8X32", None)
            .define("SECP256K1_BUILD", None)
            .warnings(false);
        if target_os == "windows" {
            // compat.h keys on WIN32 to pull in winsock2/windows.h, and NOMINMAX
            // keeps std::min/max usable under MSVC.
            b.define("WIN32", None)
                .define("NOMINMAX", None)
                .define("WIN32_LEAN_AND_MEAN", None);
        }
        if target_os == "linux" {
            // glibc ships <endian.h>/<byteswap.h> and defines htobe16 & co. as
            // macros. Say so, as autoconf's bitcoin-config.h would, so the
            // vendored compat headers skip their inline fallbacks; otherwise those
            // expand into redefinitions of glibc's __bswap_* and GCC rejects them.
            // macOS takes the headers' own __APPLE__ branch and needs nothing.
            b.define("HAVE_ENDIAN_H", None)
                .define("HAVE_BYTESWAP_H", None);
            for sym in [
                "HTOBE16", "HTOLE16", "BE16TOH", "LE16TOH", "HTOBE32", "HTOLE32", "BE32TOH",
                "LE32TOH", "HTOBE64", "HTOLE64", "BE64TOH", "LE64TOH", "BSWAP_16", "BSWAP_32",
                "BSWAP_64",
            ] {
                b.define(&format!("HAVE_DECL_{sym}"), "1");
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

    for dir in &ossl_search {
        println!("cargo:rustc-link-search=native={}", dir.display());
    }
    for lib in &ossl_libs {
        println!("cargo:rustc-link-lib={lib}");
    }
    if target_os == "windows" {
        for l in ["advapi32", "crypt32", "ws2_32", "user32", "gdi32"] {
            println!("cargo:rustc-link-lib={l}");
        }
    }
    // `cc` already links the C++ runtime (msvcrt / stdc++ / c++) for .cpp(true).
}
