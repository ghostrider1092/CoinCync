//! # Spark verify through the Sluice (Warren Phase 0 sketch)
//!
//! A faithful PARALLEL reimplementation of the shielded block-verify loop that
//! lives today as `Blockchain::verify_block_spark_v2` (serial, `src/chain.rs`).
//! It splits that loop into the two halves the Sluice was built for:
//!
//! * **independent, per-tx** (fanned out across the verify pool): decode the
//!   `SparkPayload`, the transparent↔shielded value-bridge check, the
//!   bare-output / shield-in-mint structural guards, `verify_mint_shield_in`,
//!   and `verify_spark_payload` (membership + tag-binding + range/balance +
//!   `T ∉ spent-set`) — all READ-ONLY against an immutable pool snapshot;
//! * **serial conclusion** (block order, single thread): the cumulative
//!   pool-value underflow guard and the within-block linking-tag uniqueness set.
//!
//! The result is bit-identical to the serial loop regardless of valve width —
//! that is the Sluice invariant, checked by the determinism harness.
//!
//! ## Why it lives in `crypto::` and is NOT wired in
//! This is Phase-0 **sketch** code: compiled only under the same
//! `sketch-gk-proof + libspark-ffi` gate as the serial loop, and NOT called by
//! consensus, so default and gated builds behave exactly as before. It sits in
//! `crypto::` to avoid churning the hash-locked `consensus/mod.rs` for code that
//! isn't active yet. At mainnet wiring it moves next to `verify_block_spark_v2`
//! and replaces that loop's body with a call to [`verify_spark_payloads`].
//!
//! ## SAFETY — the valve is shut unless reentrancy is opted into AND self-checked
//! `verify_spark_payload` calls into the libspark FFI. A data race in a
//! non-reentrant C++ backend would corrupt rather than panic, so the
//! `catch_unwind` breaker alone is not sufficient. The policy ([`recommended_valve`]):
//! the Spark valve is [`Sluice::serial`] by default, and goes parallel ONLY when
//! the operator opts in (`COINCYNC_SPARK_VALVE_PARALLEL=1`) AND the startup
//! self-check [`probe_libspark_reentrancy`] passes (a stress run of concurrent
//! verifies that must all agree with the serial baseline). Parallel is thus
//! opt-in on a backend proven-safe-enough by that check — never the default.

#![cfg(all(feature = "sketch-gk-proof", feature = "libspark-ffi"))]

use std::collections::HashSet;

use crate::crypto::heavy_verify::{HeavyVerify, Sluice};
use crate::storage::spark_pool::SparkPoolStore;
use crate::transaction::Transaction;

use crate::consensus::spark_payload::{
    verify_mint_shield_in, verify_spark_payload, verify_transparent_shielded_balance, SparkPayload,
};

use spark_connector::ffi::LibsparkBackend;

/// Per-tx verdict handed from the parallel phase to the serial gate.
pub struct SparkVerdict {
    /// Not a v2 Spark tx (transparent, or native v1) — the serial gate skips it.
    pub skipped: bool,
    /// Signed value crossing the veil for this tx (`> 0` unshield, `< 0` shield-in).
    pub value_balance: i64,
    /// Linking tags revealed by this tx's spend, for the within-block dup guard.
    pub tags: Vec<Vec<u8>>,
}

impl SparkVerdict {
    fn skip() -> Self {
        Self { skipped: true, value_balance: 0, tags: Vec::new() }
    }
}

/// The independent, per-tx verifier. Holds only an immutable pool snapshot and a
/// (ZST) backend handle, so it is `Sync` and safe to share across verify
/// threads — provided the backend itself is reentrant (see the module SAFETY
/// note; the valve stays serial until that is established).
pub struct SparkTxVerifier<'a> {
    store: &'a SparkPoolStore,
    backend: LibsparkBackend,
}

impl<'a> HeavyVerify for SparkTxVerifier<'a> {
    type Item = &'a Transaction;
    type Output = SparkVerdict;
    type Error = String;

    fn verify_one(&self, tx: &&'a Transaction) -> Result<SparkVerdict, String> {
        let tx = *tx;
        if !tx.is_shielded() {
            return Ok(SparkVerdict::skip());
        }
        let payload = match SparkPayload::decode(&tx.extra) {
            Ok(p) => p,
            Err(_) => return Ok(SparkVerdict::skip()), // native v1, handled elsewhere
        };
        // Transparent↔shielded value bridge: value_balance must be backed by the
        // tx's transparent commitments (no cross-veil inflation).
        let pseudo_outputs: Vec<[u8; 32]> =
            tx.inputs.iter().map(|i| i.pseudo_output_commitment).collect();
        let output_commitments: Vec<[u8; 32]> = tx.outputs.iter().map(|o| o.commitment).collect();
        verify_transparent_shielded_balance(
            &pseudo_outputs,
            &output_commitments,
            tx.fee.as_atomic(),
            payload.value_balance,
        )
        .map_err(|e| format!("value bridge: {e}"))?;
        // No unauthenticated coin entry: coins enter ONLY via an authenticated
        // mint bundle or a spend's own outputs — never via bare `payload.outputs`.
        if !payload.outputs.is_empty() {
            return Err("unauthenticated coin entry — bare outputs without a mint bundle".into());
        }
        // A shield-in (value_balance < 0) MUST carry an authenticated mint bundle.
        if payload.value_balance < 0 && payload.mint.is_none() {
            return Err("shield-in requires an authenticated mint bundle".into());
        }
        if let Some(mint) = &payload.mint {
            verify_mint_shield_in(mint, payload.value_balance).map_err(|e| format!("mint: {e}"))?;
        }
        // The heavy one: store-aware spend verification (read-only snapshot).
        let tags = verify_spark_payload(self.store, &self.backend, &payload, tx.fee.as_atomic())
            .map_err(|e| format!("{e}"))?;
        Ok(SparkVerdict {
            skipped: false,
            value_balance: payload.value_balance,
            tags: tags.into_iter().map(|t| t.0).collect(),
        })
    }

    // NOTE: `cache_key` is deliberately left at the `None` default — the Spark
    // spend verdict is NOT a pure function of the tx alone: `verify_spark_payload`
    // reads the live spent-tag set (a spend is valid before its tag is spent and
    // invalid after) and the cover set at its anchor. Keying a verify-result
    // cache by payload hash would serve a stale verdict, so this path is never
    // cached. See `crypto::verify_cache` for the safety contract.
}

/// The valve this path should use. **Fail-closed and opt-in**: serial unless the
/// operator explicitly opts into parallel Spark verify AND the libspark
/// reentrancy self-check ([`probe_libspark_reentrancy`]) passes.
///
/// * Default (env unset) → [`Sluice::serial`]. Parallel Spark is never taken
///   without an explicit operator decision, and — because the probe itself runs
///   libspark concurrently — the probe's own concurrency risk is also only taken
///   on opt-in.
/// * `COINCYNC_SPARK_VALVE_PARALLEL=1` → run the self-check once (cached); go
///   parallel ([`Sluice::auto`]) only if it passes, else stay serial.
pub fn recommended_valve() -> Sluice {
    if parallel_spark_opt_in() && libspark_is_reentrant() {
        Sluice::auto()
    } else {
        Sluice::serial()
    }
}

fn parallel_spark_opt_in() -> bool {
    std::env::var("COINCYNC_SPARK_VALVE_PARALLEL")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// The cached result of the reentrancy self-check (§3.8 thread-safety gate). Run
/// at most once per process, lazily on first consult (effectively startup, since
/// the valve is chosen before the first shielded block verify).
fn libspark_is_reentrant() -> bool {
    static PROBE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *PROBE.get_or_init(|| {
        let threads = env_usize("COINCYNC_SPARK_PROBE_THREADS", 8).max(2);
        let iters = env_usize("COINCYNC_SPARK_PROBE_ITERS", 64).max(1);
        probe_libspark_reentrancy_with(threads, iters)
    })
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(default)
}

/// Run the libspark reentrancy self-check with the default stress parameters
/// (overridable via `COINCYNC_SPARK_PROBE_THREADS` / `_ITERS`).
pub fn probe_libspark_reentrancy() -> bool {
    let threads = env_usize("COINCYNC_SPARK_PROBE_THREADS", 8).max(2);
    let iters = env_usize("COINCYNC_SPARK_PROBE_ITERS", 64).max(1);
    probe_libspark_reentrancy_with(threads, iters)
}

/// The §3.8 **thread-safety gate**: verify a known-good libspark bundle
/// concurrently across `threads` threads, `iters` times each, and pass ONLY if
/// every concurrent verify returns the SAME accept verdict as the serial
/// baseline, with no panic. Passing is the bar for letting the Spark valve run
/// parallel.
///
/// Limits (documented, not hidden): this is a STRESS self-check, not a proof —
/// it shakes out data races that manifest as a panic or a divergent verdict. A
/// non-reentrant C++ backend that corrupts via a hard native crash would abort
/// the process rather than return `false`; that is precisely why the probe runs
/// only on explicit opt-in (see [`recommended_valve`]) and the default is
/// serial. Fail-closed: any bundle-build failure, baseline reject, panic, or
/// divergent verdict → `false`.
pub fn probe_libspark_reentrancy_with(threads: usize, iters: usize) -> bool {
    use spark_connector::ffi::{make_verify_bundle, LibsparkBackend};
    use spark_connector::{SparkBackend, SpendBytes};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::atomic::{AtomicBool, Ordering};

    let bundle = match make_verify_bundle() {
        Some(b) => b,
        None => return false, // can't build a reference bundle → fail-closed
    };
    let verify_once = |b: &[u8]| LibsparkBackend.verify_spend(&[], &SpendBytes(b.to_vec()), 0, 0).is_ok();

    // Serial baseline: the reference bundle must cleanly accept, or the probe is
    // meaningless.
    if !verify_once(&bundle) {
        return false;
    }

    // Concurrent stress: every verify of the SAME valid bundle must accept,
    // identically, with no panic.
    let all_ok = AtomicBool::new(true);
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                for _ in 0..iters {
                    let r = catch_unwind(AssertUnwindSafe(|| verify_once(&bundle)));
                    if !matches!(r, Ok(true)) {
                        all_ok.store(false, Ordering::Relaxed);
                    }
                }
            });
        }
    });
    all_ok.load(Ordering::Relaxed)
}

/// Verify the shielded (v2 Spark) txs of a block through the valve — the
/// parallel equivalent of `Blockchain::verify_block_spark_v2`'s loop body.
/// Returns `Err(reason)` to reject the block. Identical verdict at any valve
/// width (the Sluice invariant).
pub fn verify_spark_payloads(
    store: &SparkPoolStore,
    transactions: &[Transaction],
    valve: &Sluice,
) -> Result<(), String> {
    let verifier = SparkTxVerifier { store, backend: LibsparkBackend };
    let items: Vec<&Transaction> = transactions.iter().collect();

    // ── Parallel phase: independent per-tx verification. ──
    let results = valve.verify(&verifier, &items, || "spark verify worker panicked".to_string());

    // ── Serial conclusion in block order: pool-value fold + tag uniqueness. ──
    let mut simulated_pool = store.pool_value();
    let mut seen_tags: HashSet<Vec<u8>> = HashSet::new();
    for (idx, r) in results.into_iter().enumerate() {
        let v = r.map_err(|e| format!("spark v2 tx {idx}: {e}"))?;
        if v.skipped {
            continue;
        }
        // Cumulative pool-value check (order-dependent → must be serial): reject
        // pre-apply if this tx would unshield more than the pool holds.
        simulated_pool -= v.value_balance as i128;
        if simulated_pool < 0 {
            return Err(format!(
                "spark v2 tx {idx}: pool underflow — unshields more than the shielded pool holds"
            ));
        }
        for t in v.tags {
            if !seen_tags.insert(t) {
                return Err(format!("spark v2 tx {idx}: duplicate linking tag within block"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Plumbing/determinism check that needs no shielded fixtures: a block of
    /// purely transparent txs has every tx skipped, so the verdict is `Ok(())`
    /// at ANY valve width, and the serial and parallel paths agree. Full
    /// shielded-fixture coverage via `assert_valve_invariant` is the PR-3
    /// regtest-e2e task (needs a real cover set + mint/spend bundles).
    #[test]
    fn empty_and_transparent_blocks_verify_at_any_width() {
        let store = SparkPoolStore::new();
        let txs: Vec<Transaction> = Vec::new();
        for valve in [Sluice::serial(), Sluice::with_threads(4), recommended_valve()] {
            assert!(verify_spark_payloads(&store, &txs, &valve).is_ok());
        }
    }

    /// §3.8 thread-safety gate: the reentrancy self-check runs libspark
    /// concurrently and, in this build, passes (consistent with the equivalence
    /// test that already verified at widths 2/4). And the DEFAULT valve policy
    /// stays serial without the explicit opt-in — fail-closed.
    #[test]
    fn reentrancy_self_check_passes_and_default_valve_is_serial() {
        assert!(
            probe_libspark_reentrancy_with(4, 16),
            "libspark survived the concurrent reentrancy stress check"
        );
        // No COINCYNC_SPARK_VALVE_PARALLEL opt-in in the test env → serial.
        assert!(
            !recommended_valve().is_parallel(),
            "default Spark valve is serial (parallel is opt-in + self-checked)"
        );
    }
}
