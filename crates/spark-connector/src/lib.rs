//! # spark-connector — the shielded engine's own section
//!
//! This crate isolates CoinCync's Spark shielded engine behind a single clean
//! Rust API (the "talking connector"). The rest of CoinCync — consensus, wallet
//! — depends only on the [`SparkBackend`] trait and the plain types here, and
//! **never** on secp256k1, OpenSSL, or a C++ toolchain. Those dependencies live
//! only inside the (default-off) `libspark-ffi` backend, so a normal CoinCync
//! build never pulls them in.
//!
//! ## Why a connector, in its own crate
//!
//! The pinned construction (see `docs/design/cip-shielded-spend-composition.md`)
//! is Firo's audited Spark; the plan is to *bind* to it via FFI rather than
//! reimplement (`docs/design/cip-shielded-libspark-ffi.md`). That drags in a
//! secp256k1 / Bitcoin-core / SHA-512 C++ subtree. Containing all of it in one
//! member crate behind one feature is how we keep that blast radius off the main
//! node: the connector is the *seam*, the FFI is an implementation detail.
//!
//! ## Status
//!
//! Seam only. [`StubBackend`] is **fail-closed** (every operation errors), so the
//! shielded path stays inert until a real backend lands, is reviewed, and
//! activation is flipped. The `libspark-ffi` backend is a placeholder.

use core::fmt;

/// Errors at the connector boundary. Kept dependency-free (no `thiserror`) so the
/// crate stays light and standalone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorError {
    /// No real backend is wired — the fail-closed default.
    NotWired,
    /// A backend rejected the input (malformed bytes, failed verification, …).
    Rejected(String),
    /// Marshalling between CoinCync and engine-native encodings failed.
    Marshalling(String),
}

impl fmt::Display for ConnectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectorError::NotWired => write!(f, "spark backend not wired (fail-closed)"),
            ConnectorError::Rejected(m) => write!(f, "spark backend rejected: {m}"),
            ConnectorError::Marshalling(m) => write!(f, "spark marshalling error: {m}"),
        }
    }
}

impl std::error::Error for ConnectorError {}

pub type Result<T> = core::result::Result<T, ConnectorError>;

/// Engine-native serialization of a coin (opaque to CoinCync; the backend owns
/// the format — e.g. libspark's `Coin`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinBytes(pub Vec<u8>);

/// Engine-native serialization of a spend transaction / proof bundle
/// (Grootle + Chaum + range + balance).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendBytes(pub Vec<u8>);

/// A double-spend nullifier (the Spark linking tag `T = (U−D)·s⁻¹`), in the
/// engine's canonical point encoding. CoinCync stores/dedups these; it does not
/// interpret them.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Nullifier(pub Vec<u8>);

/// What a view key recovers from a coin it owns: the cleartext amount plus a memo.
/// (Recovering value does NOT grant spend authority — that needs the spend key,
/// which the connector never exposes to detection.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentifiedCoin {
    pub value: u64,
    pub memo: Vec<u8>,
}

/// The Spark engine, behind the connector. Every method speaks CoinCync's plain
/// types on the outside and marshals to the engine on the inside. Backends:
/// [`StubBackend`] (fail-closed) now; a libspark FFI backend later.
pub trait SparkBackend {
    /// Create a shielded output coin addressed to `address` for `value`.
    fn create_output(&self, address: &[u8], value: u64, memo: &[u8]) -> Result<CoinBytes>;

    /// Build a spend over `cover_set`, moving `value_balance` across the veil
    /// (public, Sapling-style) with the given `fee`. `spend_material` is the
    /// wallet's opaque selection of owned notes + keys (backend-defined).
    fn build_spend(
        &self,
        cover_set: &[CoinBytes],
        spend_material: &[u8],
        fee: u64,
        value_balance: i64,
    ) -> Result<SpendBytes>;

    /// Verify a spend against `cover_set` + the public `fee`/`value_balance`.
    /// On success returns the spent coins' nullifiers (for the double-spend set).
    /// Fail-closed on any error.
    fn verify_spend(
        &self,
        cover_set: &[CoinBytes],
        spend: &SpendBytes,
        fee: u64,
        value_balance: i64,
    ) -> Result<Vec<Nullifier>>;

    /// Identify + recover an owned coin's value with an incoming/full view key.
    /// `Ok(None)` means "not ours". Never yields spend authority.
    fn identify(&self, view_key: &[u8], coin: &CoinBytes) -> Result<Option<IdentifiedCoin>>;
}

/// The fail-closed default backend: every operation errors [`ConnectorError::NotWired`].
/// This is what the shielded path resolves to until a real backend is compiled
/// in and reviewed — so a missing/mis-built backend can never silently accept.
pub struct StubBackend;

impl SparkBackend for StubBackend {
    fn create_output(&self, _address: &[u8], _value: u64, _memo: &[u8]) -> Result<CoinBytes> {
        Err(ConnectorError::NotWired)
    }
    fn build_spend(&self, _c: &[CoinBytes], _m: &[u8], _f: u64, _vb: i64) -> Result<SpendBytes> {
        Err(ConnectorError::NotWired)
    }
    fn verify_spend(&self, _c: &[CoinBytes], _s: &SpendBytes, _f: u64, _vb: i64) -> Result<Vec<Nullifier>> {
        Err(ConnectorError::NotWired)
    }
    fn identify(&self, _v: &[u8], _c: &CoinBytes) -> Result<Option<IdentifiedCoin>> {
        Err(ConnectorError::NotWired)
    }
}

/// The libspark FFI backend (Firo's audited Spark, via a C shim) — vendored under
/// `vendor/`, built by `build.rs` behind this feature. See
/// `docs/design/cip-shielded-libspark-ffi.md`.
#[cfg(feature = "libspark-ffi")]
pub mod ffi {
    //! Vendored `libspark` + secp256k1 backend, behind a thin C shim. Building
    //! this feature pulls in the C++ toolchain + OpenSSL (via `SPARK_OPENSSL_DIR`).
    use super::*;

    extern "C" {
        fn spark_ffi_selftest() -> core::ffi::c_int;
        fn spark_ffi_spend_verify_roundtrip() -> core::ffi::c_int;
    }

    /// Run the vendored-libspark self-test: builds a real coin + recovers its VRF
    /// tag, and runs a Chaum tag-proof prove→verify round-trip. Returns true iff
    /// the vendored crypto + proof machinery is live. Proves the FFI build works.
    pub fn selftest() -> bool {
        // Safety: the shim takes/returns only a plain int and touches no Rust memory.
        unsafe { spark_ffi_selftest() == 1 }
    }

    /// Build a valid V2 `SpendTransaction`, serialize it to bytes, deserialize it,
    /// and verify the round-tripped transaction. Returns true iff verify passes —
    /// proving the `SpendBytes` boundary carries a real, verifiable spend (the
    /// core of `verify_spend`). Stage 3b.
    pub fn spend_verify_roundtrip() -> bool {
        // Safety: plain-int shim, no Rust memory touched.
        unsafe { spark_ffi_spend_verify_roundtrip() == 1 }
    }

    /// The libspark-backed [`SparkBackend`].
    ///
    /// Stage 3a: the vendored build is live (see [`selftest`]). The
    /// create/spend/verify/identify **marshalling** (CoinCync bytes ⇄ libspark
    /// serializations, over the C shim) is Stage 3b — until it lands these return
    /// a clear error, so the connector stays fail-closed even with the feature on.
    pub struct LibsparkBackend;

    impl SparkBackend for LibsparkBackend {
        fn create_output(&self, _address: &[u8], _value: u64, _memo: &[u8]) -> Result<CoinBytes> {
            Err(ConnectorError::Rejected("libspark create marshalling not wired (Stage 3b)".into()))
        }
        fn build_spend(&self, _c: &[CoinBytes], _m: &[u8], _f: u64, _vb: i64) -> Result<SpendBytes> {
            Err(ConnectorError::Rejected("libspark build_spend marshalling not wired (Stage 3b)".into()))
        }
        fn verify_spend(&self, _c: &[CoinBytes], _s: &SpendBytes, _f: u64, _vb: i64) -> Result<Vec<Nullifier>> {
            Err(ConnectorError::Rejected("libspark verify marshalling not wired (Stage 3b)".into()))
        }
        fn identify(&self, _v: &[u8], _c: &CoinBytes) -> Result<Option<IdentifiedCoin>> {
            Err(ConnectorError::Rejected("libspark identify marshalling not wired (Stage 3b)".into()))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn libspark_selftest_passes() {
            assert!(selftest(), "vendored libspark self-test failed");
        }

        #[test]
        fn spend_serialize_deserialize_verify_round_trips() {
            assert!(
                spend_verify_roundtrip(),
                "SpendTransaction serialize->deserialize->verify round-trip failed"
            );
        }

        #[test]
        fn backend_fail_closed_until_marshalling() {
            let b = LibsparkBackend;
            assert!(b.verify_spend(&[], &SpendBytes(vec![]), 0, 0).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_is_fail_closed_on_every_operation() {
        let b = StubBackend;
        assert_eq!(b.create_output(&[], 1, &[]).unwrap_err(), ConnectorError::NotWired);
        assert_eq!(b.build_spend(&[], &[], 0, 0).unwrap_err(), ConnectorError::NotWired);
        assert_eq!(
            b.verify_spend(&[], &SpendBytes(vec![]), 0, 0).unwrap_err(),
            ConnectorError::NotWired
        );
        assert_eq!(b.identify(&[], &CoinBytes(vec![])).unwrap_err(), ConnectorError::NotWired);
    }

    #[test]
    fn backend_is_object_safe() {
        // The consensus/wallet hold a `&dyn SparkBackend`, so the trait must be
        // object-safe; this is a compile-time assertion of that.
        let b: Box<dyn SparkBackend> = Box::new(StubBackend);
        assert!(b.identify(&[], &CoinBytes(vec![1, 2, 3])).is_err());
    }

    #[test]
    fn error_display_is_stable() {
        assert_eq!(ConnectorError::NotWired.to_string(), "spark backend not wired (fail-closed)");
    }
}
