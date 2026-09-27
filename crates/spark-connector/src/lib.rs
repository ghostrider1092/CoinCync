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
    ///
    /// `serial_context` is the coin's deterministic serial context (as passed at
    /// mint). It is NOT carried in the coin wire form, so a scanner must supply
    /// the same context the coin was minted with; both sides must agree or the
    /// coin fails to identify. Pass `&[]` for a coin minted with the empty
    /// (default) context.
    fn identify(
        &self,
        view_key: &[u8],
        coin: &CoinBytes,
        serial_context: &[u8],
    ) -> Result<Option<IdentifiedCoin>>;

    /// Auditor-side **unspent-solvency** check. Verifies a shielded spend proof
    /// (Grootle membership + Chaum tag-binding + range/balance) and then
    /// enforces that every linking tag it reveals is **not** in `spent_tags` —
    /// i.e. the proven-owned, in-range coin is currently UNSPENT. Returns the
    /// (unspent) tags on success; fail-closed if verification fails OR any tag
    /// is already spent.
    ///
    /// This is the composition Route B rests on: the hidden-index↔VRF-tag
    /// binding comes from libspark's audited spend proof, and the `T ∉
    /// spent-set` membership test is what turns "I own an in-range coin" into
    /// "I own an in-range coin that is still unspent" — without revealing which
    /// coin. Provided as a default method so it is uniform across backends.
    fn verify_solvency(
        &self,
        cover_set: &[CoinBytes],
        spend: &SpendBytes,
        fee: u64,
        value_balance: i64,
        spent_tags: &[Nullifier],
    ) -> Result<Vec<Nullifier>> {
        let tags = self.verify_spend(cover_set, spend, fee, value_balance)?;
        for t in &tags {
            if spent_tags.contains(t) {
                return Err(ConnectorError::Rejected(
                    "linking tag already in the spent set — coin is NOT unspent".into(),
                ));
            }
        }
        Ok(tags)
    }
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
    fn identify(&self, _v: &[u8], _c: &CoinBytes, _ctx: &[u8]) -> Result<Option<IdentifiedCoin>> {
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

    use core::ffi::c_int;

    extern "C" {
        fn spark_ffi_selftest() -> c_int;
        fn spark_ffi_spend_verify_roundtrip() -> c_int;
        fn spark_ffi_make_verify_bundle(out: *mut u8, cap: c_int) -> c_int;
        fn spark_ffi_verify_bundle(
            ptr: *const u8,
            len: c_int,
            out_tags: *mut u8,
            tags_cap: c_int,
            out_tags_len: *mut c_int,
        ) -> c_int;
        fn spark_ffi_gen_address(out: *mut u8, cap: c_int) -> c_int;
        fn spark_ffi_create_output(
            addr_ptr: *const u8,
            addr_len: c_int,
            value: u64,
            memo_ptr: *const u8,
            memo_len: c_int,
            out: *mut u8,
            cap: c_int,
        ) -> c_int;
        fn spark_ffi_create_recover_roundtrip(value: u64, out_recovered: *mut u64) -> c_int;
        fn spark_ffi_build_spend(output_value: u64, out: *mut u8, cap: c_int) -> c_int;
        fn spark_ffi_cover_set_size() -> c_int;
        fn spark_ffi_mint_to_seed(
            seed: *const u8,
            seed_len: c_int,
            value: u64,
            ctx_ptr: *const u8,
            ctx_len: c_int,
            out: *mut u8,
            cap: c_int,
        ) -> c_int;
        fn spark_ffi_build_spend_over_set(
            seed: *const u8,
            seed_len: c_int,
            set_ptr: *const u8,
            set_len: c_int,
            spend_index: u64,
            ctx_ptr: *const u8,
            ctx_len: c_int,
            output_value: u64,
            recip_addr_ptr: *const u8,
            recip_addr_len: c_int,
            out: *mut u8,
            cap: c_int,
        ) -> c_int;
        fn spark_ffi_serial_context(
            op_ptr: *const u8,
            op_len: c_int,
            out: *mut u8,
            cap: c_int,
        ) -> c_int;
        fn spark_ffi_build_mint_bundle(
            seed: *const u8,
            seed_len: c_int,
            values: *const u64,
            n_values: c_int,
            ctx_ptr: *const u8,
            ctx_len: c_int,
            out: *mut u8,
            cap: c_int,
        ) -> c_int;
        fn spark_ffi_verify_mint_bundle(
            ptr: *const u8,
            len: c_int,
            out_total: *mut u64,
            out_coins: *mut u8,
            coins_cap: c_int,
            out_coins_len: *mut c_int,
        ) -> c_int;
        fn spark_ffi_spend_outputs(
            ptr: *const u8,
            len: c_int,
            out_coins: *mut u8,
            coins_cap: c_int,
            out_coins_len: *mut c_int,
            out_ctx: *mut u8,
            ctx_cap: c_int,
            out_ctx_len: *mut c_int,
        ) -> c_int;
        fn spark_ffi_address_from_seed(seed: *const u8, seed_len: c_int, out: *mut u8, cap: c_int) -> c_int;
        fn spark_ffi_identify(
            seed: *const u8,
            seed_len: c_int,
            coin_ptr: *const u8,
            coin_len: c_int,
            ctx_ptr: *const u8,
            ctx_len: c_int,
            out_value: *mut u64,
            out_memo: *mut u8,
            memo_cap: c_int,
            out_memo_len: *mut c_int,
        ) -> c_int;
        fn spark_ffi_export_incoming_view_key(
            seed: *const u8,
            seed_len: c_int,
            out_s1: *mut u8,
            s1_cap: c_int,
            out_s1_len: *mut c_int,
            out_p2: *mut u8,
            p2_cap: c_int,
            out_p2_len: *mut c_int,
        ) -> c_int;
        fn spark_ffi_identify_view_only(
            s1_ptr: *const u8,
            s1_len: c_int,
            p2_ptr: *const u8,
            p2_len: c_int,
            coin_ptr: *const u8,
            coin_len: c_int,
            ctx_ptr: *const u8,
            ctx_len: c_int,
            out_value: *mut u64,
            out_memo: *mut u8,
            memo_cap: c_int,
            out_memo_len: *mut c_int,
        ) -> c_int;
    }

    /// A wallet's WATCH-ONLY shielded view key: the exported incoming-view-key
    /// material `(s1, P2)`. It scans/identifies owned coins but carries NO spend
    /// authority. `s1` is 32 bytes, `P2` 34 bytes.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct IncomingViewKeyBytes {
        pub s1: Vec<u8>,
        pub p2: Vec<u8>,
    }

    /// Export the watch-only incoming view key `(s1, P2)` for the wallet derived
    /// from `seed`. A holder can [`identify_view_only`] owned coins but cannot
    /// spend. `None` on error.
    pub fn export_incoming_view_key(seed: &[u8]) -> Option<IncomingViewKeyBytes> {
        let mut s1 = vec![0u8; 32];
        let mut s1_len: c_int = 0;
        let mut p2 = vec![0u8; 34];
        let mut p2_len: c_int = 0;
        // Safety: pointers/lengths valid for the call; shim writes <= caps.
        let rc = unsafe {
            spark_ffi_export_incoming_view_key(
                seed.as_ptr(),
                seed.len() as c_int,
                s1.as_mut_ptr(),
                s1.len() as c_int,
                &mut s1_len,
                p2.as_mut_ptr(),
                p2.len() as c_int,
                &mut p2_len,
            )
        };
        if rc != 1 {
            return None;
        }
        s1.truncate(s1_len.max(0) as usize);
        p2.truncate(p2_len.max(0) as usize);
        Some(IncomingViewKeyBytes { s1, p2 })
    }

    /// WATCH-ONLY identify: recover a coin's value/memo using only an exported
    /// view key `(s1, P2)` and the coin's serial context — no seed/spend key.
    /// `Ok(None)` means "not ours". Never yields spend authority.
    pub fn identify_view_only(
        view_key: &IncomingViewKeyBytes,
        coin: &CoinBytes,
        serial_context: &[u8],
    ) -> Result<Option<IdentifiedCoin>> {
        let mut value: u64 = 0;
        let mut memo = vec![0u8; 256];
        let mut memo_len: c_int = 0;
        // Safety: pointers/lengths valid for the call; shim writes only outputs.
        let rc = unsafe {
            spark_ffi_identify_view_only(
                view_key.s1.as_ptr(),
                view_key.s1.len() as c_int,
                view_key.p2.as_ptr(),
                view_key.p2.len() as c_int,
                coin.0.as_ptr(),
                coin.0.len() as c_int,
                serial_context.as_ptr(),
                serial_context.len() as c_int,
                &mut value,
                memo.as_mut_ptr(),
                memo.len() as c_int,
                &mut memo_len,
            )
        };
        if rc != 1 {
            return Ok(None); // not ours (or malformed) — fail-closed to "not mine"
        }
        memo.truncate(memo_len.max(0) as usize);
        Ok(Some(IdentifiedCoin { value, memo }))
    }

    /// The bech32m address of the wallet derived from `seed`. `None` on error.
    pub fn address_from_seed(seed: &[u8]) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 1024];
        let len = unsafe {
            spark_ffi_address_from_seed(seed.as_ptr(), seed.len() as c_int, buf.as_mut_ptr(), buf.len() as c_int)
        };
        if len <= 0 {
            return None;
        }
        buf.truncate(len as usize);
        Some(buf)
    }

    /// Generate a fresh Spark recipient address (bech32m string bytes). `None` on
    /// error. (Wallet key persistence is a separate concern; this yields a valid
    /// address to create coins to.)
    pub fn gen_address() -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 1024];
        let len = unsafe { spark_ffi_gen_address(buf.as_mut_ptr(), buf.len() as c_int) };
        if len <= 0 {
            return None;
        }
        buf.truncate(len as usize);
        Some(buf)
    }

    /// Create a coin, then recover its value with the recipient keys, and confirm
    /// the recovered value matches. Proves send-side coin creation is recoverable.
    pub fn create_recover_roundtrip(value: u64) -> bool {
        let mut recovered: u64 = 0;
        // Safety: shim writes only to `recovered`.
        unsafe { spark_ffi_create_recover_roundtrip(value, &mut recovered) == 1 && recovered == value }
    }

    /// Build a valid self-contained verify bundle (a real spend + its verify
    /// context), for tests and as the format `verify_spend` consumes. `None` on
    /// error. In production CoinCync's wallet produces this via `build_spend`.
    pub fn make_verify_bundle() -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 1 << 16];
        // Safety: shim writes at most `cap` bytes into `buf` and returns the length.
        let len = unsafe { spark_ffi_make_verify_bundle(buf.as_mut_ptr(), buf.len() as c_int) };
        if len <= 0 {
            return None;
        }
        buf.truncate(len as usize);
        Some(buf)
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

    /// Derive the deterministic serial context for a coin at `outpoint`
    /// (e.g. `tx_hash ‖ output_index`). Both the mint and the later spend must
    /// use the identical outpoint, so a coin's context is recomputable from its
    /// on-chain position without being stored. `None` on error.
    pub fn serial_context(outpoint: &[u8]) -> Option<Vec<u8>> {
        let mut out = vec![0u8; 32];
        // Safety: pointers/lengths valid for the call; shim writes <= cap into `out`.
        let n = unsafe {
            spark_ffi_serial_context(
                outpoint.as_ptr(),
                outpoint.len() as c_int,
                out.as_mut_ptr(),
                out.len() as c_int,
            )
        };
        if n <= 0 {
            return None;
        }
        out.truncate(n as usize);
        Some(out)
    }

    /// Build an authenticated shield-in mint bundle (a libspark
    /// `MintTransaction`) to the `seed` wallet for `values`, bound to `context`.
    /// The bundle carries a Schnorr value proof so a verifier can trust each
    /// coin's public value without the recipient's view key. `None` on error.
    pub fn build_mint_bundle(seed: &[u8], values: &[u64], context: &[u8]) -> Option<Vec<u8>> {
        let mut out = vec![0u8; 1 << 16];
        // Safety: pointers/lengths valid for the call; shim writes <= cap into `out`.
        let len = unsafe {
            spark_ffi_build_mint_bundle(
                seed.as_ptr(),
                seed.len() as c_int,
                values.as_ptr(),
                values.len() as c_int,
                context.as_ptr(),
                context.len() as c_int,
                out.as_mut_ptr(),
                out.len() as c_int,
            )
        };
        if len <= 0 {
            return None;
        }
        out.truncate(len as usize);
        Some(out)
    }

    /// Verify a mint bundle and return the total AUTHENTICATED minted value
    /// (`Σ v`, proven to match the coins' commitments) together with the
    /// individual minted coins (to feed the pool). `None` if the value proof
    /// fails, the bundle is malformed, or the sum overflows — fail-closed.
    /// A shield-in tx is sound iff the total equals the value that entered the
    /// pool (`−value_balance`), which the transparent bridge ties to the
    /// transparent commitments.
    pub fn verify_mint_bundle(bundle: &[u8]) -> Option<(u64, Vec<CoinBytes>)> {
        let mut total: u64 = 0;
        let mut coins_buf = vec![0u8; 1 << 16];
        let mut coins_len: c_int = 0;
        // Safety: shim reads `bundle`, writes `total` + up to coins_buf.len() into coins_buf.
        let rc = unsafe {
            spark_ffi_verify_mint_bundle(
                bundle.as_ptr(),
                bundle.len() as c_int,
                &mut total,
                coins_buf.as_mut_ptr(),
                coins_buf.len() as c_int,
                &mut coins_len,
            )
        };
        if rc != 1 {
            return None;
        }
        // Parse coins: [u32 count][ (u32 len)(bytes) ]...
        let buf = &coins_buf[..(coins_len.max(0) as usize)];
        let mut off = 0usize;
        let rd = |b: &[u8], o: &mut usize| -> Option<u32> {
            if *o + 4 > b.len() {
                return None;
            }
            let v = u32::from_le_bytes([b[*o], b[*o + 1], b[*o + 2], b[*o + 3]]);
            *o += 4;
            Some(v)
        };
        let count = rd(buf, &mut off)? as usize;
        let mut coins = Vec::with_capacity(count);
        for _ in 0..count {
            let l = rd(buf, &mut off)? as usize;
            if off + l > buf.len() {
                return None;
            }
            coins.push(CoinBytes(buf[off..off + l].to_vec()));
            off += l;
        }
        Some((total, coins))
    }

    /// Extract a spend bundle's OUTPUT coins (change/payments) and their shared
    /// serial context (libspark derives it as `serialize(spend tags)`, so it is
    /// deterministic + recoverable). Feeds the pool after a spend verifies, so
    /// the pool grows with spend outputs symmetric with the mint feed. `None` on
    /// error. Call only on a bundle that already verified.
    pub fn spend_outputs(bundle: &[u8]) -> Option<(Vec<CoinBytes>, Vec<u8>)> {
        let mut coins_buf = vec![0u8; 1 << 16];
        let mut coins_len: c_int = 0;
        let mut ctx_buf = vec![0u8; 4096];
        let mut ctx_len: c_int = 0;
        // Safety: shim reads `bundle`, writes up to the buffer caps.
        let rc = unsafe {
            spark_ffi_spend_outputs(
                bundle.as_ptr(),
                bundle.len() as c_int,
                coins_buf.as_mut_ptr(),
                coins_buf.len() as c_int,
                &mut coins_len,
                ctx_buf.as_mut_ptr(),
                ctx_buf.len() as c_int,
                &mut ctx_len,
            )
        };
        if rc != 1 {
            return None;
        }
        ctx_buf.truncate(ctx_len.max(0) as usize);
        let buf = &coins_buf[..(coins_len.max(0) as usize)];
        let mut off = 0usize;
        let rd = |b: &[u8], o: &mut usize| -> Option<u32> {
            if *o + 4 > b.len() {
                return None;
            }
            let v = u32::from_le_bytes([b[*o], b[*o + 1], b[*o + 2], b[*o + 3]]);
            *o += 4;
            Some(v)
        };
        let count = rd(buf, &mut off)? as usize;
        let mut coins = Vec::with_capacity(count);
        for _ in 0..count {
            let l = rd(buf, &mut off)? as usize;
            if off + l > buf.len() {
                return None;
            }
            coins.push(CoinBytes(buf[off..off + l].to_vec()));
            off += l;
        }
        Some((coins, ctx_buf))
    }

    /// The Grootle cover-set cardinality `N = n_grootle ^ m_grootle` for the
    /// active params — the exact number of coins a caller must supply to
    /// [`build_spend_over_set`]. `None` on error.
    pub fn cover_set_size() -> Option<usize> {
        let n = unsafe { spark_ffi_cover_set_size() };
        if n <= 0 {
            return None;
        }
        Some(n as usize)
    }

    /// Mint a cover coin owned by the wallet derived from `seed`, bound to the
    /// serial `context`. The returned [`CoinBytes`] is recoverable+spendable by
    /// the same seed via [`build_spend_over_set`] with the identical `context`.
    /// `None` on error.
    pub fn mint_to_seed(seed: &[u8], value: u64, context: &[u8]) -> Option<CoinBytes> {
        let mut out = vec![0u8; 4096];
        // Safety: pointers/lengths valid for the call; shim writes <= cap into `out`.
        let len = unsafe {
            spark_ffi_mint_to_seed(
                seed.as_ptr(),
                seed.len() as c_int,
                value,
                context.as_ptr(),
                context.len() as c_int,
                out.as_mut_ptr(),
                out.len() as c_int,
            )
        };
        if len <= 0 {
            return None;
        }
        out.truncate(len as usize);
        Some(CoinBytes(out))
    }

    /// Build a shielded spend over a CALLER-SUPPLIED `cover_set`, spending the
    /// coin the `seed` wallet owns at `spend_index` (minted with `context`) and
    /// paying `output_value` back to the WALLET (a change/consolidation
    /// self-spend). Returns the verify bundle [`SpendBytes`] (what
    /// [`LibsparkBackend::verify_spend`] consumes), or `None` on error. The cover
    /// set marshals as `[u32 count][ (u32 len)(coin bytes) ]...`.
    pub fn build_spend_over_set(
        seed: &[u8],
        cover_set: &[CoinBytes],
        spend_index: usize,
        context: &[u8],
        output_value: u64,
    ) -> Option<SpendBytes> {
        // Empty recipient → the shim pays the output back to the spender.
        build_spend_inner(seed, cover_set, spend_index, context, output_value, &[])
    }

    /// Build a shielded spend that pays `output_value` to `recipient_addr` (a
    /// bech32m Spark address, as bytes) — a shielded→shielded TRANSFER to another
    /// wallet. The spend consumes the spender's owned coin at `spend_index`; its
    /// output coin re-enters the pool and is recoverable/spendable by the
    /// recipient (fee = input − `output_value`). Returns the verify bundle, or
    /// `None` on error (bad index, `output_value` ∉ (0, input), bad address, …).
    pub fn build_spend_to_address(
        seed: &[u8],
        cover_set: &[CoinBytes],
        spend_index: usize,
        context: &[u8],
        output_value: u64,
        recipient_addr: &[u8],
    ) -> Option<SpendBytes> {
        if recipient_addr.is_empty() {
            return None; // a transfer must name a recipient
        }
        build_spend_inner(seed, cover_set, spend_index, context, output_value, recipient_addr)
    }

    /// Shared spend builder: `recipient_addr` empty → self-spend, else transfer.
    fn build_spend_inner(
        seed: &[u8],
        cover_set: &[CoinBytes],
        spend_index: usize,
        context: &[u8],
        output_value: u64,
        recipient_addr: &[u8],
    ) -> Option<SpendBytes> {
        // Marshal the cover set: [u32 count][ (u32 len)(bytes) ]...
        let mut set = Vec::with_capacity(4 + cover_set.iter().map(|c| 4 + c.0.len()).sum::<usize>());
        set.extend_from_slice(&(cover_set.len() as u32).to_le_bytes());
        for c in cover_set {
            set.extend_from_slice(&(c.0.len() as u32).to_le_bytes());
            set.extend_from_slice(&c.0);
        }
        let mut out = vec![0u8; 1 << 17];
        // Safety: all pointers/lengths valid for the call; shim writes <= cap into `out`.
        let len = unsafe {
            spark_ffi_build_spend_over_set(
                seed.as_ptr(),
                seed.len() as c_int,
                set.as_ptr(),
                set.len() as c_int,
                spend_index as u64,
                context.as_ptr(),
                context.len() as c_int,
                output_value,
                recipient_addr.as_ptr(),
                recipient_addr.len() as c_int,
                out.as_mut_ptr(),
                out.len() as c_int,
            )
        };
        if len <= 0 {
            return None;
        }
        out.truncate(len as usize);
        Some(SpendBytes(out))
    }

    /// The libspark-backed [`SparkBackend`].
    ///
    /// Stage 3a: the vendored build is live (see [`selftest`]). The
    /// create/spend/verify/identify **marshalling** (CoinCync bytes ⇄ libspark
    /// serializations, over the C shim) is Stage 3b — until it lands these return
    /// a clear error, so the connector stays fail-closed even with the feature on.
    pub struct LibsparkBackend;

    impl SparkBackend for LibsparkBackend {
        /// Create a shielded output coin addressed to `address` (a bech32m Spark
        /// address, as bytes) for `value` with `memo`. The sender needs only the
        /// recipient's public address.
        fn create_output(&self, address: &[u8], value: u64, memo: &[u8]) -> Result<CoinBytes> {
            let mut out = vec![0u8; 4096];
            // Safety: pointers/lengths valid for the call; shim writes <= cap into `out`.
            let len = unsafe {
                spark_ffi_create_output(
                    address.as_ptr(),
                    address.len() as c_int,
                    value,
                    memo.as_ptr(),
                    memo.len() as c_int,
                    out.as_mut_ptr(),
                    out.len() as c_int,
                )
            };
            if len <= 0 {
                return Err(ConnectorError::Rejected("libspark create_output failed".into()));
            }
            out.truncate(len as usize);
            Ok(CoinBytes(out))
        }
        /// Build a wallet-issued spend, producing the verify bundle
        /// `verify_spend` consumes. `spend_material` carries the output value
        /// (u64 LE) for this first functional cut; wiring real selected-note /
        /// cover-set marshalling (over `cover_set`) is the wallet-integration
        /// follow-up. Fails closed on an invalid request (e.g. over-spend).
        fn build_spend(&self, _cover_set: &[CoinBytes], spend_material: &[u8], _f: u64, _vb: i64) -> Result<SpendBytes> {
            if spend_material.len() < 8 {
                return Err(ConnectorError::Marshalling("spend_material must carry output value (u64 LE)".into()));
            }
            let output_value = u64::from_le_bytes(spend_material[..8].try_into().unwrap());
            let mut out = vec![0u8; 1 << 16];
            // Safety: shim writes <= cap into `out`, returns the length.
            let len = unsafe { spark_ffi_build_spend(output_value, out.as_mut_ptr(), out.len() as c_int) };
            if len <= 0 {
                return Err(ConnectorError::Rejected("libspark build_spend failed (invalid request?)".into()));
            }
            out.truncate(len as usize);
            Ok(SpendBytes(out))
        }
        /// Verify a shielded spend. `spend` is a self-contained verify bundle
        /// (see [`make_verify_bundle`]) carrying the `SpendTransaction` plus the
        /// verifier-side context libspark needs (cover set, its representation,
        /// output coins, block hash). Returns the linking-tag nullifiers on a
        /// valid spend; fail-closed otherwise.
        fn verify_spend(&self, _cover_set: &[CoinBytes], spend: &SpendBytes, _f: u64, _vb: i64) -> Result<Vec<Nullifier>> {
            let mut tags = vec![0u8; 8192];
            let mut tags_len: c_int = 0;
            // Safety: pointers/lengths are valid for the duration of the call; the
            // shim only reads `spend` and writes up to `tags.len()` into `tags`.
            let rc = unsafe {
                spark_ffi_verify_bundle(
                    spend.0.as_ptr(),
                    spend.0.len() as c_int,
                    tags.as_mut_ptr(),
                    tags.len() as c_int,
                    &mut tags_len,
                )
            };
            if rc != 1 {
                return Err(ConnectorError::Rejected("shielded spend failed verification".into()));
            }
            let tl = tags_len.max(0) as usize;
            if tl < 4 {
                return Err(ConnectorError::Marshalling("tag buffer too short".into()));
            }
            let count = u32::from_le_bytes([tags[0], tags[1], tags[2], tags[3]]) as usize;
            let mut out = Vec::with_capacity(count);
            let mut off = 4usize;
            for _ in 0..count {
                if off + 34 > tl {
                    return Err(ConnectorError::Marshalling("truncated nullifier tags".into()));
                }
                out.push(Nullifier(tags[off..off + 34].to_vec()));
                off += 34;
            }
            Ok(out)
        }
        /// Scan a coin with a `view_key` (here the wallet seed; a true view-only
        /// key path is a follow-up). `serial_context` must match the context the
        /// coin was minted with (`&[]` for the empty default) — it is set on the
        /// coin before recovery, since it is not carried in the wire form.
        /// `Ok(None)` means "not ours" — not an error.
        fn identify(
            &self,
            view_key: &[u8],
            coin: &CoinBytes,
            serial_context: &[u8],
        ) -> Result<Option<IdentifiedCoin>> {
            let mut value: u64 = 0;
            let mut memo = vec![0u8; 256];
            let mut memo_len: c_int = 0;
            // Safety: pointers/lengths valid for the call; shim writes only into the outputs.
            let rc = unsafe {
                spark_ffi_identify(
                    view_key.as_ptr(),
                    view_key.len() as c_int,
                    coin.0.as_ptr(),
                    coin.0.len() as c_int,
                    serial_context.as_ptr(),
                    serial_context.len() as c_int,
                    &mut value,
                    memo.as_mut_ptr(),
                    memo.len() as c_int,
                    &mut memo_len,
                )
            };
            if rc != 1 {
                return Ok(None); // not ours (or malformed) — fail-closed to "not mine"
            }
            memo.truncate(memo_len.max(0) as usize);
            Ok(Some(IdentifiedCoin { value, memo }))
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
        fn verify_spend_accepts_valid_bundle_and_returns_nullifiers() {
            let bundle = make_verify_bundle().expect("failed to build verify bundle");
            let b = LibsparkBackend;
            let nullifiers = b
                .verify_spend(&[], &SpendBytes(bundle), 0, 0)
                .expect("valid bundle must verify");
            assert_eq!(nullifiers.len(), 1, "one input => one linking-tag nullifier");
            assert_eq!(nullifiers[0].0.len(), 34, "tag is a 34-byte group element");
        }

        #[test]
        fn create_output_produces_a_wellformed_coin() {
            let addr = gen_address().expect("generate recipient address");
            let b = LibsparkBackend;
            let coin = b.create_output(&addr, 500, b"hi").expect("create_output");
            assert!(!coin.0.is_empty(), "coin bytes must be non-empty");
        }

        #[test]
        fn created_coin_value_round_trips_through_recovery() {
            assert!(create_recover_roundtrip(4242), "created coin must recover its value");
        }

        #[test]
        fn build_spend_then_verify_spend_closes_the_loop() {
            let b = LibsparkBackend;
            // Build a wallet spend (output value 50), then verify it — the trio
            // create -> build -> verify, all through the connector API.
            let material = 50u64.to_le_bytes().to_vec();
            let spend = b.build_spend(&[], &material, 0, 0).expect("build_spend");
            let nullifiers = b.verify_spend(&[], &spend, 0, 0).expect("built spend must verify");
            assert_eq!(nullifiers.len(), 1, "one input => one nullifier");
        }

        #[test]
        fn identify_recovers_owned_coin_and_rejects_foreign() {
            let b = LibsparkBackend;
            let seed = b"wallet-seed-alpha";
            let addr = address_from_seed(seed).expect("address from seed");
            let coin = b.create_output(&addr, 777, b"hello").expect("create_output");

            // Owner scans -> recovers value + memo.
            let owned = b.identify(seed, &coin, &[]).expect("identify call").expect("coin is ours");
            assert_eq!(owned.value, 777);
            assert_eq!(owned.memo, b"hello");

            // A different wallet does not recognize it.
            assert!(
                b.identify(b"wallet-seed-beta", &coin, &[]).unwrap().is_none(),
                "a foreign wallet must not identify the coin"
            );
        }

        #[test]
        fn view_only_key_scans_owned_coin_without_the_seed() {
            let seed_a = b"view-only-seed-A";
            let seed_b = b"view-only-seed-B";
            let ctx = serial_context(b"vk:tx:0").expect("ctx");

            // A coin owned by A, bound to ctx.
            let coin = mint_to_seed(seed_a, 4_200, &ctx).expect("mint to A");

            // Export A's WATCH-ONLY view key (s1, P2). No seed needed to scan after.
            let vk_a = export_incoming_view_key(seed_a).expect("export A's view key");
            assert_eq!(vk_a.s1.len(), 32, "s1 is a 32-byte scalar");
            assert_eq!(vk_a.p2.len(), 34, "P2 is a 34-byte group element");

            // The view key recovers the coin's value WITHOUT the seed.
            let owned = identify_view_only(&vk_a, &coin, &ctx)
                .expect("identify call")
                .expect("A's view key owns the coin");
            assert_eq!(owned.value, 4_200);

            // A foreign view key (B's) does NOT recognize A's coin.
            let vk_b = export_incoming_view_key(seed_b).expect("export B's view key");
            assert!(
                identify_view_only(&vk_b, &coin, &ctx).unwrap().is_none(),
                "a foreign view key must not identify the coin"
            );

            // View-only recovery matches seed-based recovery (same value).
            let b = LibsparkBackend;
            let via_seed = b.identify(seed_a, &coin, &ctx).unwrap().expect("seed identifies");
            assert_eq!(via_seed.value, owned.value, "view-only sees the same value as the seed");
        }

        #[test]
        fn build_spend_rejects_overspend() {
            let b = LibsparkBackend;
            // Output far exceeds the input note's value => build fails closed.
            let material = u64::MAX.to_le_bytes().to_vec();
            assert!(b.build_spend(&[], &material, 0, 0).is_err(), "over-spend must fail");
        }

        #[test]
        fn verify_spend_rejects_tampered_bundle() {
            let mut bundle = make_verify_bundle().expect("failed to build verify bundle");
            // The SpendTransaction (proofs) is serialized LAST, so tamper near the
            // end — the range-proof tail. (Flipping earlier can hit a cover-set
            // coin's encrypted memo, which verification legitimately ignores.)
            let n = bundle.len();
            bundle[n - 10] ^= 0x01;
            let b = LibsparkBackend;
            assert!(
                b.verify_spend(&[], &SpendBytes(bundle), 0, 0).is_err(),
                "tampered spend must be rejected"
            );
        }

        #[test]
        fn backend_fail_closed_until_marshalling() {
            let b = LibsparkBackend;
            assert!(b.verify_spend(&[], &SpendBytes(vec![]), 0, 0).is_err());
        }

        #[test]
        fn mint_bundle_authenticates_total_value_and_rejects_tamper() {
            // A shield-in mint bundle: build for known values, verify, and get
            // back the total AUTHENTICATED value (the Schnorr value proof ties
            // each coin's commitment to its public value).
            let seed = b"mint-bundle-seed";
            let ctx = serial_context(b"mint:tx:0").expect("ctx");
            let values = [100u64, 200, 300, 400];
            let bundle = build_mint_bundle(seed, &values, &ctx).expect("build mint bundle");
            let (total, coins) = verify_mint_bundle(&bundle).expect("mint bundle verifies");
            assert_eq!(total, 1000, "total = Σ minted values, authenticated");
            assert_eq!(coins.len(), values.len(), "one coin per minted value");

            // Tampering the bundle (flip a byte in the proof/coin region) fails.
            let mut bad = bundle.clone();
            let n = bad.len();
            bad[n - 8] ^= 0x01;
            assert!(verify_mint_bundle(&bad).is_none(), "tampered mint bundle rejected");
        }

        #[test]
        fn spend_over_caller_supplied_cover_set_verifies() {
            // The real-marshalling path: CoinCync holds the cover set, mints an
            // owned note into it, and drives a spend over THAT set (not the shim's
            // internal fixture). This is the Route-B seam for shielded solvency.
            let seed = b"treasury-seed-omega";
            let n = cover_set_size().expect("cover set size");
            assert!(n >= 2, "need a non-trivial cover set");

            // Mint N cover coins owned by the seed wallet, each with a known,
            // distinct serial context.
            let mut coins = Vec::with_capacity(n);
            let mut ctxs = Vec::with_capacity(n);
            for i in 0..n {
                let mut ctx = [0u8; 32];
                ctx[0] = i as u8;
                ctx[1] = 0x5a;
                let coin = mint_to_seed(seed, 1_000 + i as u64, &ctx).expect("mint cover coin");
                coins.push(coin);
                ctxs.push(ctx.to_vec());
            }

            // Spend the owned coin at index 1 (value 1001), paying 400 back (fee 601).
            let spend_index = 1usize;
            let bundle = build_spend_over_set(seed, &coins, spend_index, &ctxs[spend_index], 400)
                .expect("build spend over caller-supplied set");

            // The bundle must verify and yield exactly one linking-tag nullifier.
            let b = LibsparkBackend;
            let tags = b
                .verify_spend(&[], &bundle, 0, 0)
                .expect("caller-set spend must verify");
            assert_eq!(tags.len(), 1, "one input => one nullifier tag");
            assert_eq!(tags[0].0.len(), 34, "tag is a 34-byte group element");
        }

        #[test]
        fn transfer_pays_recipient_who_recovers_the_output_coin() {
            // Shielded→shielded TRANSFER: A spends an owned coin to B's address.
            // The spend's output coin must be recoverable by B (and NOT by A) —
            // the property that makes a real send (vs. a self-spend) work.
            let a = b"sender-seed-A";
            let b_seed = b"recipient-seed-B";
            let addr_b = address_from_seed(b_seed).expect("B's address");
            let n = cover_set_size().expect("cover set size");

            // A mints its cover set (owns every coin).
            let mut coins = Vec::with_capacity(n);
            let mut ctxs = Vec::with_capacity(n);
            for i in 0..n {
                let mut ctx = [0u8; 32];
                ctx[0] = i as u8;
                ctx[1] = 0xa5;
                coins.push(mint_to_seed(a, 5_000 + i as u64, &ctx).expect("mint"));
                ctxs.push(ctx.to_vec());
            }

            // A spends its coin at index 2 (value 5002), paying 3_000 to B (fee 2002).
            let spend_index = 2usize;
            let bundle =
                build_spend_to_address(a, &coins, spend_index, &ctxs[spend_index], 3_000, &addr_b)
                    .expect("build transfer to B");

            let backend = LibsparkBackend;
            let tags = backend.verify_spend(&[], &bundle, 0, 0).expect("transfer verifies");
            assert_eq!(tags.len(), 1, "one input → one nullifier");

            // The output coin re-enters the pool with its recoverable context.
            let (out_coins, out_ctx) = spend_outputs(&bundle.0).expect("extract spend outputs");
            assert_eq!(out_coins.len(), 1, "one payment output");

            // B recovers the 3_000 coin; A cannot see it (it is not A's).
            let recovered = backend
                .identify(b_seed, &out_coins[0], &out_ctx)
                .expect("identify call")
                .expect("B owns the transfer output");
            assert_eq!(recovered.value, 3_000, "B receives the transferred value");
            assert!(
                backend.identify(a, &out_coins[0], &out_ctx).unwrap().is_none(),
                "the sender must NOT be able to recover a coin paid to the recipient"
            );

            // A self-spend (no recipient) still pays A: identify with A succeeds.
            let self_bundle =
                build_spend_over_set(a, &coins, spend_index, &ctxs[spend_index], 3_000)
                    .expect("self-spend builds");
            let (self_out, self_ctx) = spend_outputs(&self_bundle.0).expect("self outputs");
            assert!(
                backend.identify(a, &self_out[0], &self_ctx).unwrap().is_some(),
                "a self-spend's change is recoverable by the spender"
            );
        }

        #[test]
        fn partial_cover_set_smaller_than_N_verifies() {
            // (c) Grootle accepts any set size in [1, N] and pads internally,
            // so a real (partial) cover set — fewer than N coins — must still
            // build and verify.
            let seed = b"treasury-seed-partial";
            let n = cover_set_size().expect("cover set size");
            let partial = (n / 2).max(2); // strictly fewer than N
            let mut coins = Vec::with_capacity(partial);
            let mut ctxs = Vec::with_capacity(partial);
            for i in 0..partial {
                let mut ctx = [0u8; 32];
                ctx[0] = i as u8;
                ctx[1] = 0x7c;
                coins.push(mint_to_seed(seed, 2_000 + i as u64, &ctx).expect("mint"));
                ctxs.push(ctx.to_vec());
            }
            let spend_index = partial - 1;
            let bundle = build_spend_over_set(seed, &coins, spend_index, &ctxs[spend_index], 300)
                .expect("partial-set spend builds");
            let b = LibsparkBackend;
            let tags = b.verify_spend(&[], &bundle, 0, 0).expect("partial-set spend verifies");
            assert_eq!(tags.len(), 1);
        }

        #[test]
        fn deterministic_serial_context_round_trips_and_binds_outpoint() {
            // (a1) The serial context derived from an outpoint is deterministic,
            // so a coin minted at that outpoint is recoverable/spendable using
            // only the outpoint later — and a WRONG outpoint's context cannot
            // recover the coin (fail-closed).
            let seed = b"treasury-seed-ctx";
            let n = cover_set_size().expect("cover set size");

            // Same outpoint → same context (determinism).
            let outpoint = b"tx:abcd1234:vout:1";
            let ctx = serial_context(outpoint).expect("derive ctx");
            assert_eq!(ctx, serial_context(outpoint).expect("derive ctx again"));
            assert_ne!(ctx, serial_context(b"tx:abcd1234:vout:2").unwrap(), "distinct outpoints differ");

            // Mint the whole cover set; the owned coin uses the outpoint-derived ctx.
            let spend_index = 2usize;
            let mut coins = Vec::with_capacity(n);
            for i in 0..n {
                let op = format!("tx:cover:vout:{i}");
                let c = serial_context(op.as_bytes()).expect("ctx");
                coins.push(mint_to_seed(seed, 5_000 + i as u64, &c).expect("mint"));
            }
            let owned_op = format!("tx:cover:vout:{spend_index}");
            let owned_ctx = serial_context(owned_op.as_bytes()).expect("owned ctx");

            // Correct outpoint context → spend builds + verifies.
            let bundle = build_spend_over_set(seed, &coins, spend_index, &owned_ctx, 900)
                .expect("outpoint-derived ctx spends");
            let b = LibsparkBackend;
            assert!(b.verify_spend(&[], &bundle, 0, 0).is_ok());

            // Wrong outpoint context → cannot recover the coin → fail-closed.
            let wrong_ctx = serial_context(b"tx:cover:vout:999").expect("wrong ctx");
            assert!(
                build_spend_over_set(seed, &coins, spend_index, &wrong_ctx, 900).is_none(),
                "a mismatched serial context must not produce a spend"
            );
        }

        #[test]
        fn verify_solvency_accepts_unspent_and_rejects_spent_tag() {
            // (b) The unspent-solvency check: verify the spend, then require its
            // linking tag ∉ spent-set. Unspent → Ok; tag already spent → reject.
            let seed = b"treasury-seed-solvency";
            let n = cover_set_size().expect("cover set size");
            let mut coins = Vec::with_capacity(n);
            let mut ctxs = Vec::with_capacity(n);
            for i in 0..n {
                let mut ctx = [0u8; 32];
                ctx[0] = i as u8;
                ctx[1] = 0x9e;
                coins.push(mint_to_seed(seed, 3_000 + i as u64, &ctx).expect("mint"));
                ctxs.push(ctx.to_vec());
            }
            let spend_index = 1usize;
            let bundle = build_spend_over_set(seed, &coins, spend_index, &ctxs[spend_index], 700)
                .expect("build solvency proof");
            let b = LibsparkBackend;

            // Unspent: empty spent set → solvency holds, returns the tag.
            let tags = b
                .verify_solvency(&[], &bundle, 0, 0, &[])
                .expect("unspent coin proves solvency");
            assert_eq!(tags.len(), 1);

            // Now that tag is recorded as spent → the SAME proof must be rejected.
            let spent = tags.clone();
            assert!(
                b.verify_solvency(&[], &bundle, 0, 0, &spent).is_err(),
                "a spent linking tag must fail the unspent-solvency check"
            );
        }

        #[test]
        fn spend_over_set_rejects_bad_index_and_overspend() {
            let seed = b"treasury-seed-beta";
            let n = cover_set_size().expect("cover set size");
            let mut coins = Vec::with_capacity(n);
            let mut ctxs = Vec::with_capacity(n);
            for i in 0..n {
                let mut ctx = [0u8; 32];
                ctx[0] = i as u8;
                let coin = mint_to_seed(seed, 500 + i as u64, &ctx).expect("mint");
                coins.push(coin);
                ctxs.push(ctx.to_vec());
            }
            // Out-of-range index → fail closed.
            assert!(
                build_spend_over_set(seed, &coins, n + 5, &ctxs[0], 100).is_none(),
                "out-of-range spend_index must fail"
            );
            // Over-spend (output >= input value at index 2 = 502) → fail closed.
            assert!(
                build_spend_over_set(seed, &coins, 2, &ctxs[2], 10_000).is_none(),
                "over-spend must fail"
            );
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
        assert_eq!(b.identify(&[], &CoinBytes(vec![]), &[]).unwrap_err(), ConnectorError::NotWired);
    }

    #[test]
    fn backend_is_object_safe() {
        // The consensus/wallet hold a `&dyn SparkBackend`, so the trait must be
        // object-safe; this is a compile-time assertion of that.
        let b: Box<dyn SparkBackend> = Box::new(StubBackend);
        assert!(b.identify(&[], &CoinBytes(vec![1, 2, 3]), &[]).is_err());
    }

    #[test]
    fn error_display_is_stable() {
        assert_eq!(ConnectorError::NotWired.to_string(), "spark backend not wired (fail-closed)");
    }
}
