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

    /// BATCH-verify K spends over ONE shared `cover_set` together — amortizing
    /// the shared cover-set multiexp across all K (~Kx vs K single verifies; see
    /// docs/design/cip-shielded-anonset.md). All spends MUST share the one cover
    /// set (the caller groups a block's spends by cover_set_id + anchor first).
    /// `fees[i]`/`value_balances[i]` pair with `spends[i]`; returns per-spend
    /// nullifiers (`out[i]` ↔ `spends[i]`). DEFAULT: verify each spend
    /// individually (correct, unamortized) so every backend works; a backend
    /// overrides it for the batched speedup. Fail-closed and ATOMIC: any spend
    /// failing rejects the whole batch.
    fn verify_spend_batch(
        &self,
        cover_set: &[CoinBytes],
        spends: &[SpendBytes],
        fees: &[u64],
        value_balances: &[i64],
    ) -> Result<Vec<Vec<Nullifier>>> {
        let mut out = Vec::with_capacity(spends.len());
        for (i, s) in spends.iter().enumerate() {
            out.push(self.verify_spend(cover_set, s, fees[i], value_balances[i])?);
        }
        Ok(out)
    }

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
        // CLOSE THE EMPTY-COVER-SET FALLBACK (#258 / #308). `verify_spend` treats
        // an empty cover set as the permissive STATELESS admit — it verifies the
        // spender's OWN embedded set instead of a node-resolved one, so a spender
        // could prove membership in a set they made up. This method is the
        // AUTHORITATIVE solvency entry (node-resolved set + spent-tag check), so it
        // must never run permissively: require a non-empty node set here, at the
        // trust boundary, independent of any individual caller's own guard.
        if cover_set.is_empty() {
            return Err(ConnectorError::Rejected(
                "authoritative solvency verify requires a non-empty node-resolved cover set \
                 (empty would fall back to the spender's own bundle set — #258)"
                    .into(),
            ));
        }
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
            set_ptr: *const u8,
            set_len: c_int,
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
        fn spark_ffi_spend_ltags(
            ptr: *const u8,
            len: c_int,
            out_tags: *mut u8,
            tags_cap: c_int,
            out_tags_len: *mut c_int,
        ) -> c_int;
        fn spark_ffi_verify_spend_batch(
            set_ptr: *const u8,
            set_len: c_int,
            spends: *const u8,
            spend_lens: *const c_int,
            k: c_int,
            out_tags: *mut u8,
            tags_cap: c_int,
            out_tags_len: *mut c_int,
        ) -> c_int;
        fn spark_ffi_spend_fee(ptr: *const u8, len: c_int, out_fee: *mut u64) -> c_int;
        fn spark_ffi_spend_tags(
            ptr: *const u8,
            len: c_int,
            out_tags: *mut u8,
            tags_cap: c_int,
            out_tags_len: *mut c_int,
        ) -> c_int;
        fn spark_ffi_spend_vout(ptr: *const u8, len: c_int, out_vout: *mut u64) -> c_int;
        fn spark_ffi_coin_ltag(
            seed: *const u8,
            seed_len: c_int,
            coin_ptr: *const u8,
            coin_len: c_int,
            ctx_ptr: *const u8,
            ctx_len: c_int,
            out: *mut u8,
            cap: c_int,
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

    /// Marshal a cover set to the flat FFI wire form
    /// `[u32 count][ (u32 len)(coin bytes) ]...` (the form the shim parses). An
    /// empty cover set marshals to an empty buffer so the shim sees `set_len == 0`
    /// and keeps its legacy (stateless) behaviour (#258).
    pub(crate) fn marshal_cover_set(cover_set: &[CoinBytes]) -> Vec<u8> {
        if cover_set.is_empty() {
            return Vec::new();
        }
        let mut set =
            Vec::with_capacity(4 + cover_set.iter().map(|c| 4 + c.0.len()).sum::<usize>());
        set.extend_from_slice(&(cover_set.len() as u32).to_le_bytes());
        for c in cover_set {
            set.extend_from_slice(&(c.0.len() as u32).to_le_bytes());
            set.extend_from_slice(&c.0);
        }
        set
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

    /// STATELESS, DoS-safe extraction of a spend bundle's linking tags T
    /// (`getUsedLTags`) — for mempool double-spend dedup on UNTRUSTED input. Does
    /// NOT verify the proof and needs no cover set (unlike [`LibsparkBackend::verify_spend`]),
    /// and does not touch output coins (unlike [`spend_outputs`]). The shim bounds
    /// the attacker-controlled `output_count` before allocating, so a crafted
    /// bundle can't force a large allocation. Returns the tags (a deterministic
    /// function of the spent coin, so two spends of the same coin yield the same
    /// tag), or `None` on malformed/oversized input (fail-closed — the caller
    /// rejects the tx). Same `[u32 count][34-byte tag]...` wire form as
    /// `spark_ffi_verify_bundle`.
    pub fn spend_ltags(bundle: &[u8]) -> Option<Vec<Nullifier>> {
        let mut tags = vec![0u8; 8192];
        let mut tags_len: c_int = 0;
        // Safety: shim reads `bundle`, writes up to `tags.len()` into `tags`.
        let rc = unsafe {
            spark_ffi_spend_ltags(
                bundle.as_ptr(),
                bundle.len() as c_int,
                tags.as_mut_ptr(),
                tags.len() as c_int,
                &mut tags_len,
            )
        };
        if rc != 1 {
            return None;
        }
        let tl = tags_len.max(0) as usize;
        if tl < 4 {
            return None;
        }
        let count = u32::from_le_bytes([tags[0], tags[1], tags[2], tags[3]]) as usize;
        let mut out = Vec::with_capacity(count);
        let mut off = 4usize;
        for _ in 0..count {
            if off + 34 > tl {
                return None;
            }
            out.push(Nullifier(tags[off..off + 34].to_vec()));
            off += 34;
        }
        Some(out)
    }

    /// Read a spend bundle's PUBLIC internal fee (`input − Σ pool outputs`) — the
    /// value the bundle releases across the veil to the miner (amounts stay
    /// hidden). Consensus binds the tx's public `value_balance` to this so a
    /// shielded spend cannot claim a different fee than the bundle actually
    /// released (cross-veil inflation guard). `None` on a malformed bundle
    /// (fail-closed). Call on a bundle whose structure already verified.
    pub fn spend_fee(bundle: &[u8]) -> Option<u64> {
        let mut fee: u64 = 0;
        // Safety: the shim reads `bundle` and writes a single u64 to `fee`.
        let rc = unsafe { spark_ffi_spend_fee(bundle.as_ptr(), bundle.len() as c_int, &mut fee) };
        if rc != 1 {
            return None;
        }
        Some(fee)
    }

    /// Extract a spend bundle's linking tags WITHOUT verifying its proof — the
    /// tags `T` are read straight off the wire by deserialization (as the fee is),
    /// so this is a cheap, no-multiexp read. This is the APPLY-path counterpart to
    /// re-running [`SparkBackend::verify_spend_batch`]: once the validation gate
    /// has proof-verified the block, apply only needs the tags for
    /// `mark_tag_spent`, and re-deriving them via the full Grootle multiexp is pure
    /// redundancy. Returns the same `Nullifier`s a successful verify would return
    /// (identical bytes, identical layout). `None` on a malformed bundle
    /// (fail-closed). MUST only be trusted for a bundle already verified elsewhere
    /// (the chain verifies at the gate before applying); it performs NO
    /// verification itself.
    pub fn spend_tags(bundle: &[u8]) -> Option<Vec<Nullifier>> {
        let mut tags = vec![0u8; 8192];
        let mut tags_len: c_int = 0;
        // Safety: the shim reads `bundle` and writes <= tags.len() into `tags`.
        let rc = unsafe {
            spark_ffi_spend_tags(
                bundle.as_ptr(),
                bundle.len() as c_int,
                tags.as_mut_ptr(),
                tags.len() as c_int,
                &mut tags_len,
            )
        };
        if rc != 1 {
            return None;
        }
        let tl = tags_len.max(0) as usize;
        if tl < 4 {
            return None;
        }
        let count = u32::from_le_bytes([tags[0], tags[1], tags[2], tags[3]]) as usize;
        let mut out = Vec::with_capacity(count);
        let mut off = 4usize;
        for _ in 0..count {
            if off + 34 > tl {
                return None;
            }
            out.push(Nullifier(tags[off..off + 34].to_vec()));
            off += 34;
        }
        Some(out)
    }

    /// Read a spend bundle's libspark `vout` — the transparent output value in
    /// libspark's own balance equation (`input = Σ outputs + f + vout`). The
    /// Option-B value model ALWAYS keeps `vout = 0` (value crosses the veil via
    /// the bundle fee `f`, bound to the tx's public `value_balance`); a bundle
    /// with `vout > 0` still satisfies the libspark balance proof but would make
    /// the node's pool accounting drift above the real pooled value (a silent
    /// burn), so consensus rejects `vout != 0`. `None` on a malformed bundle
    /// (fail-closed). Call on a bundle whose structure already verified.
    pub fn spend_vout(bundle: &[u8]) -> Option<u64> {
        let mut vout: u64 = 0;
        // Safety: the shim reads `bundle` and writes a single u64 to `vout`.
        let rc = unsafe { spark_ffi_spend_vout(bundle.as_ptr(), bundle.len() as c_int, &mut vout) };
        if rc != 1 {
            return None;
        }
        Some(vout)
    }

    /// Derive the linking tag (`Nullifier`) of an owned `coin` (minted with
    /// `context`) for the `seed` wallet — the tag it reveals when spent. A wallet
    /// checks it against the pool's spent set (`is_spark_pool_tag_spent`) to
    /// exclude already-spent notes from its balance and from spend selection.
    /// `None` if the coin is not owned by `seed` or on FFI failure.
    pub fn coin_ltag(seed: &[u8], coin: &CoinBytes, context: &[u8]) -> Option<Nullifier> {
        let mut out = vec![0u8; 64];
        // Safety: the shim reads the inputs and writes <= cap bytes into `out`.
        let len = unsafe {
            spark_ffi_coin_ltag(
                seed.as_ptr(),
                seed.len() as c_int,
                coin.0.as_ptr(),
                coin.0.len() as c_int,
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
        Some(Nullifier(out))
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
        fn verify_spend(&self, cover_set: &[CoinBytes], spend: &SpendBytes, _fee: u64, _value_balance: i64) -> Result<Vec<Nullifier>> {
            // #258: when a NODE-RESOLVED cover set is supplied it is authoritative
            // (the shim verifies the Grootle proof against it, not the spender's
            // bundle). An empty set keeps the legacy stateless (permissive) admit.
            //
            // Option-B value model: the spend keeps libspark `vout = 0` (its output
            // re-enters the pool); the value crossing the veil is the bundle's
            // internal fee, bound to the tx's public `value_balance` at the
            // consensus layer (`verify_block_spark_v2`: `value_balance ==
            // spend_fee(bundle)`) and to `tx.fee` by the transparent value bridge.
            // So `value_balance` is NOT bound here — the old `getVout() ==
            // value_balance` check would force `value_balance == 0` and make a
            // fee-paying transfer unmineable. The bundle's own balance proof
            // conserves input == outputs + fee.
            let set = marshal_cover_set(cover_set);
            let mut tags = vec![0u8; 8192];
            let mut tags_len: c_int = 0;
            // Safety: pointers/lengths are valid for the duration of the call; the
            // shim only reads `spend`/`set` and writes up to `tags.len()` into `tags`.
            let rc = unsafe {
                spark_ffi_verify_bundle(
                    spend.0.as_ptr(),
                    spend.0.len() as c_int,
                    set.as_ptr(),
                    set.len() as c_int,
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
        /// Batched verify over ONE shared node cover set via libspark's `vector`
        /// overload — amortizes the cover-set multiexp across all K spends
        /// (~Kx vs K single verifies). Marshals the node set once + the K bundles
        /// concatenated; the shim verifies them together and returns one linking
        /// tag per single-input v2 spend. Fail-closed/atomic: any spend failing
        /// rejects the whole batch.
        fn verify_spend_batch(
            &self,
            cover_set: &[CoinBytes],
            spends: &[SpendBytes],
            _fees: &[u64],
            _value_balances: &[i64],
        ) -> Result<Vec<Vec<Nullifier>>> {
            let k = spends.len();
            if k == 0 {
                return Ok(Vec::new());
            }
            if cover_set.is_empty() {
                return Err(ConnectorError::Marshalling(
                    "batched verify requires a node-authoritative cover set".into(),
                ));
            }
            // Shared node cover set (flat form) — marshaled ONCE for all K.
            let mut set_wire =
                Vec::with_capacity(4 + cover_set.iter().map(|c| 4 + c.0.len()).sum::<usize>());
            set_wire.extend_from_slice(&(cover_set.len() as u32).to_le_bytes());
            for c in cover_set {
                set_wire.extend_from_slice(&(c.0.len() as u32).to_le_bytes());
                set_wire.extend_from_slice(&c.0);
            }
            // K bundles concatenated + their lengths.
            let mut blob = Vec::with_capacity(spends.iter().map(|s| s.0.len()).sum());
            let mut lens: Vec<c_int> = Vec::with_capacity(k);
            for s in spends {
                lens.push(s.0.len() as c_int);
                blob.extend_from_slice(&s.0);
            }
            let mut tags = vec![0u8; 4 + k * 64]; // 34 B/tag; 64 generous headroom
            let mut tags_len: c_int = 0;
            // Safety: all pointers/lengths are valid for the call; the shim reads
            // `set_wire`/`blob`/`lens` and writes <= tags.len() into `tags`.
            let rc = unsafe {
                spark_ffi_verify_spend_batch(
                    set_wire.as_ptr(),
                    set_wire.len() as c_int,
                    blob.as_ptr(),
                    lens.as_ptr(),
                    k as c_int,
                    tags.as_mut_ptr(),
                    tags.len() as c_int,
                    &mut tags_len,
                )
            };
            if rc != 1 {
                return Err(ConnectorError::Rejected(
                    "batched shielded spend failed verification".into(),
                ));
            }
            // Parse [u32 k][34-byte tag]... — one tag per single-input v2 spend.
            let tl = tags_len.max(0) as usize;
            if tl < 4 {
                return Err(ConnectorError::Marshalling("batch tag buffer too short".into()));
            }
            let count = u32::from_le_bytes([tags[0], tags[1], tags[2], tags[3]]) as usize;
            if count != k {
                return Err(ConnectorError::Marshalling(
                    "batch returned a tag count != number of spends".into(),
                ));
            }
            let mut out = Vec::with_capacity(k);
            let mut off = 4usize;
            for _ in 0..k {
                if off + 34 > tl {
                    return Err(ConnectorError::Marshalling("batch tag truncated".into()));
                }
                out.push(vec![Nullifier(tags[off..off + 34].to_vec())]);
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
        fn cover_set_size_is_ratified_production_not_test_params() {
            // The shim routes every libspark call through cc_params() =
            // get_coincync() (Grootle n=8, m=3), CoinCync's RATIFIED production
            // anon-set, so the cover-set capacity is N = 8^3 = 512 — NOT the
            // get_test() N = 2^4 = 16 that made the shielded anonymity set the
            // same size as a CLSAG ring and broke spends once the pool passed 16
            // coins, and NOT Firo's get_default() N = 8^5 = 32768, whose
            // ~2.7 s/block base multiexp is not IBD-viable here.
            assert_eq!(
                cover_set_size(),
                Some(512),
                "the shim must use CoinCync's ratified (get_coincync) Grootle parameters"
            );
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
            // Stateless path (empty set → the bundle's own cover set is used and
            // the #258 strict membership + vout binding are deferred to the
            // authoritative store-aware verify). The fee/value_balance args are
            // not enforced on this permissive path.
            let bundle = make_verify_bundle().expect("failed to build verify bundle");
            let b = LibsparkBackend;
            let nullifiers = b
                .verify_spend(&[], &SpendBytes(bundle), 0, 0)
                .expect("valid bundle must verify");
            assert_eq!(nullifiers.len(), 1, "one input => one linking-tag nullifier");
            assert_eq!(nullifiers[0].0.len(), 34, "tag is a 34-byte group element");
        }

        // Helper: mint an N-coin cover set owned by `seed` (coin i has value
        // `base + i`, all under `ctx`), spend the coin at `index` paying
        // `out_value`. Returns (bundle, cover_set, fee).
        #[cfg(test)]
        fn build_strict_spend(seed: &[u8], base: u64, index: usize, out_value: u64)
            -> (SpendBytes, Vec<CoinBytes>, u64)
        {
            let n = 8usize; // #259: small cover set for the fixture (Grootle pads; real N=512)
            let ctx = serial_context(b"strict:tx:0").expect("ctx");
            let mut cover_set = Vec::with_capacity(n);
            for i in 0..n {
                if i == index {
                    cover_set.push(mint_to_seed(seed, base + i as u64, &ctx).expect("owned"));
                } else {
                    let s = format!("strict-decoy-{i}");
                    cover_set.push(mint_to_seed(s.as_bytes(), base + i as u64, &ctx).expect("decoy"));
                }
            }
            let bundle = build_spend_over_set(seed, &cover_set, index, &ctx, out_value)
                .expect("build_spend_over_set");
            let fee = (base + index as u64) - out_value;
            (bundle, cover_set, fee)
        }

        #[test]
        fn verify_rejects_a_substituted_cover_set() {
            // #258 core break (1): a spender cannot prove membership in a set the
            // node did not resolve. The SAME valid bundle, verified against a
            // DIFFERENT node cover set, must fail — the Grootle proof is checked
            // against the node's coins and the recomputed `rep` won't match.
            let b = LibsparkBackend;
            let (bundle, good_set, fee) = build_strict_spend(b"strict-A", 1_000, 2, 400);
            // Correct node set → verifies.
            assert!(
                b.verify_spend(&good_set, &bundle, fee, 0).is_ok(),
                "the node's real cover set must verify"
            );
            // A different node set (fresh coins) → rejected.
            let (_b2, other_set, _f2) = build_strict_spend(b"strict-B", 9_000, 2, 400);
            assert!(
                b.verify_spend(&other_set, &bundle, fee, 0).is_err(),
                "a substituted cover set must be rejected"
            );
        }

        #[test]
        fn verify_spend_ignores_value_balance_binding_is_consensus_layer() {
            // Option-B value model: the connector's verify_spend checks ONLY the
            // libspark spend proof (Grootle membership + linking-tag binding)
            // against the cover set. It does NOT bind `fee`/`value_balance` — the
            // spend keeps libspark `vout = 0` (its output re-enters the pool) and
            // the value crossing the veil (the bundle's internal fee) is bound to
            // the tx's public `value_balance` at the CONSENSUS layer
            // (`chain::verify_block_spark_v2`: `value_balance == spend_fee(bundle)`;
            // and the transparent value bridge:
            // `spark_payload::verify_transparent_shielded_balance`), covered by the
            // value-bridge conservation proptest — NOT here. This test documents
            // that real contract: the `value_balance` arg does not change
            // verify_spend's verdict.
            //
            // (A prior version of this test asserted `verify_spend(.., 0, 5)` is
            // Err — a value_balance binding this layer never performed; since
            // `_value_balance` is ignored it would in fact return the same verdict
            // as `(.., 0, 0)`, so the old assertion was false and only "passed"
            // because the ffi test build was not run in CI. Corrected to assert the
            // real behaviour so the audit looks for the binding at the consensus
            // layer, where it actually lives.)
            let b = LibsparkBackend;
            let (bundle, set, _fee) = build_strict_spend(b"strict-vb", 1_000, 2, 400);
            assert!(
                b.verify_spend(&set, &bundle, 0, 0).is_ok(),
                "a well-formed spend verifies against its real cover set"
            );
            assert!(
                b.verify_spend(&set, &bundle, 0, 5).is_ok(),
                "verify_spend ignores value_balance; the cross-veil binding is consensus-layer"
            );
        }

        #[test]
        fn create_output_produces_a_wellformed_coin() {
            let addr = gen_address().expect("generate recipient address");
            let b = LibsparkBackend;
            let coin = b.create_output(&addr, 500, b"hi").expect("create_output");
            assert!(!coin.0.is_empty(), "coin bytes must be non-empty");
        }

        #[test]
        fn spend_ltags_matches_verified_tags_and_rejects_garbage() {
            // #172: the STATELESS, DoS-safe tag extractor must return the SAME
            // linking tags as the full verify (so mempool dedup matches the
            // block-level double-spend guard), and fail closed on bad input.
            let bundle = make_verify_bundle().expect("failed to build verify bundle");
            let verified = LibsparkBackend
                .verify_spend(&[], &SpendBytes(bundle.clone()), 24, 0)
                .expect("valid bundle verifies");
            let stateless = spend_ltags(&bundle).expect("stateless tag extraction");
            assert_eq!(stateless, verified, "stateless tags must equal verified tags");
            assert_eq!(stateless.len(), 1, "one input => one linking tag");
            assert_eq!(stateless[0].0.len(), 34, "tag is a 34-byte group element");

            // Fail-closed on garbage / truncated input — no panic, no large alloc.
            assert!(spend_ltags(&[]).is_none(), "empty bundle rejected");
            assert!(spend_ltags(&[0xFFu8; 16]).is_none(), "garbage bundle rejected");
            assert!(
                spend_ltags(&bundle[..bundle.len() / 2]).is_none(),
                "truncated bundle rejected"
            );
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
            // Fixture spend: input 124 - output 50 => fee 74, vout 0 (stateless).
            let nullifiers = b.verify_spend(&[], &spend, 74, 0).expect("built spend must verify");
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
                b.verify_spend(&[], &SpendBytes(bundle), 24, 0).is_err(),
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
            let n = 8usize; // #259: small cover set for the fixture (Grootle pads; real N=512)
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
            // #258 strict path: the node supplies the SAME cover set the spend
            // was built over. coins[1] = 1001, output 400 => fee 601, vout 0.
            let b = LibsparkBackend;
            let tags = b
                .verify_spend(&coins, &bundle, 601, 0)
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
            let n = 8usize; // #259: small cover set for the fixture (Grootle pads; real N=512)

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
            // coins[2] = 5002, paid 3000 to B => fee 2002, vout 0 (strict).
            let tags = backend.verify_spend(&coins, &bundle, 2002, 0).expect("transfer verifies");
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
            let n = 8usize; // #259: small cover set for the fixture (Grootle pads; real N=512)
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
            // coins[spend_index] = 2000 + spend_index, paid 300 => fee = value - 300.
            let fee = (2_000 + spend_index as u64) - 300;
            let tags = b.verify_spend(&coins, &bundle, fee, 0).expect("partial-set spend verifies");
            assert_eq!(tags.len(), 1);
        }

        #[test]
        fn deterministic_serial_context_round_trips_and_binds_outpoint() {
            // (a1) The serial context derived from an outpoint is deterministic,
            // so a coin minted at that outpoint is recoverable/spendable using
            // only the outpoint later — and a WRONG outpoint's context cannot
            // recover the coin (fail-closed).
            let seed = b"treasury-seed-ctx";
            let n = 8usize; // #259: small cover set for the fixture (Grootle pads; real N=512)

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
            // coins[2] = 5002, paid 900 => fee 4102, vout 0 (strict).
            assert!(b.verify_spend(&coins, &bundle, 4102, 0).is_ok());

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
            let n = 8usize; // #259: small cover set for the fixture (Grootle pads; real N=512)
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
            // coins[1] = 3001, paid 700 => fee 2301, vout 0 (strict path).
            let tags = b
                .verify_solvency(&coins, &bundle, 2301, 0, &[])
                .expect("unspent coin proves solvency");
            assert_eq!(tags.len(), 1);

            // Now that tag is recorded as spent → the SAME proof must be rejected.
            let spent = tags.clone();
            assert!(
                b.verify_solvency(&coins, &bundle, 2301, 0, &spent).is_err(),
                "a spent linking tag must fail the unspent-solvency check"
            );
        }

        #[test]
        fn spend_tags_matches_verify_tags_without_verifying() {
            // #1 (apply-path multiexp elision): `ffi::spend_tags` recovers a
            // spend's linking tags by PLAIN DESERIALIZATION — no Grootle multiexp —
            // and must return EXACTLY the tags a full `verify_spend` returns. This
            // is the invariant that lets the chain's apply path skip re-verifying a
            // block whose proofs the validation gate already verified, and just
            // extract the tags for the `mark_tag_spent` double-spend guard.
            let seed = b"treasury-seed-spend-tags";
            let n = cover_set_size().expect("cover set size");
            let mut coins = Vec::with_capacity(n);
            let mut ctxs = Vec::with_capacity(n);
            for i in 0..n {
                let mut ctx = [0u8; 32];
                ctx[0] = i as u8;
                ctx[1] = 0x5c;
                coins.push(mint_to_seed(seed, 4_000 + i as u64, &ctx).expect("mint"));
                ctxs.push(ctx.to_vec());
            }
            let spend_index = 3usize;
            let bundle = build_spend_over_set(seed, &coins, spend_index, &ctxs[spend_index], 800, 0)
                .expect("build spend");

            let b = LibsparkBackend;
            // The node-authoritative verify (the gate's path) and the cheap
            // extraction (the apply path) must agree byte-for-byte.
            let verified = b.verify_spend(&coins, &bundle, 0, 0).expect("verify");
            let extracted = spend_tags(&bundle.0).expect("extract tags");
            assert_eq!(extracted.len(), 1, "single-input v2 spend reveals one tag");
            assert_eq!(
                extracted, verified,
                "cheap-extracted tags must equal the verified tags"
            );

            // Extraction is pure parsing → fail-closed on a malformed bundle.
            assert!(spend_tags(&[]).is_none(), "empty bundle → None");
        }

        #[test]
        fn spend_over_set_rejects_bad_index_and_overspend() {
            let seed = b"treasury-seed-beta";
            let n = 8usize; // #259: small cover set for the fixture (Grootle pads; real N=512)
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
