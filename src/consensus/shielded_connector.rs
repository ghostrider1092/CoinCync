//! Bridge: CoinCync consensus → the isolated [`spark_connector`] crate.
//!
//! [`backend`] is the **single swap point**. Today it returns the fail-closed
//! `StubBackend`, so the shielded path stays inert (identical to the old
//! hard-coded rejection). When the reviewed libspark FFI backend lands inside the
//! connector crate, it is returned here and this same path verifies for real —
//! with no change to any call site. Keeping that swap in one place, behind a
//! clean Rust API, is the whole point of the connector living in its own crate.

use crate::consensus::shielded::ShieldedPayload;
use crate::error::{Error, Result};
use spark_connector::{SparkBackend, SpendBytes};
#[cfg(not(feature = "libspark-ffi"))]
use spark_connector::StubBackend;

/// The active Spark backend — the single swap point.
///
/// With the `libspark-ffi` feature the vendored Firo libspark backend verifies
/// for real; without it the fail-closed `StubBackend` keeps shielded inert.
/// Either way consensus stays activation-gated (`SHIELDED_TX_ACTIVATION_HEIGHT =
/// u64::MAX`) until external review.
#[cfg(feature = "libspark-ffi")]
fn backend() -> impl SparkBackend {
    spark_connector::ffi::LibsparkBackend
}
#[cfg(not(feature = "libspark-ffi"))]
fn backend() -> impl SparkBackend {
    StubBackend
}

/// Verify a self-contained libspark shielded-spend **bundle** through the active
/// backend (see `spark_connector` — cover set + outputs + `SpendTransaction`).
/// This is the node-side entry the shielded tx path uses once the payload carries
/// the bundle (Stage 3e). Fail-closed on any error.
pub fn verify_bundle(bundle: &[u8]) -> Result<()> {
    backend()
        .verify_spend(&[], &SpendBytes(bundle.to_vec()), 0, 0)
        .map(|_nullifiers| ())
        .map_err(|e| {
            // Keep the "shielded … verifier" wording the consensus fail-closed test asserts.
            Error::InvalidTransaction(format!("shielded (Spark) bundle verifier rejected: {e}"))
        })
}

/// Verify a shielded payload through the connector; fail-closed on any error.
///
/// Marshals the payload to engine-native [`SpendBytes`] and routes to the
/// backend. The stateless dispatch (`check_shielded_tx`) has no store, so the
/// cover set is empty here — the stateful cover-set + double-spend verify runs
/// at block-apply. The error text preserves the historical "shielded … verifier"
/// contract asserted by consensus tests.
pub fn verify_payload(payload: &ShieldedPayload, fee: u64) -> Result<()> {
    let spend = SpendBytes(payload.encode());
    backend()
        .verify_spend(&[], &spend, fee, payload.value_balance)
        .map(|_nullifiers| ())
        .map_err(|e| {
            Error::InvalidTransaction(format!(
                "shielded (Spark) verifier via connector is fail-closed: {e}"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::shielded::{ShieldedPayload, SHIELDED_PAYLOAD_VERSION};

    #[test]
    fn connector_path_is_fail_closed() {
        // With the StubBackend the connector rejects every payload, and the error
        // keeps the "shielded"/"verifier" wording consensus tests rely on.
        let payload = ShieldedPayload {
            version: SHIELDED_PAYLOAD_VERSION,
            inputs: vec![],
            outputs: vec![],
            value_balance: 0,
            balance_proof: vec![],
        };
        let err = verify_payload(&payload, 0).unwrap_err().to_string();
        assert!(err.contains("shielded") && err.contains("verifier"), "got: {err}");
    }
}

/// With the libspark backend live, the NODE-side connector verifies a real spend
/// bundle end-to-end (and rejects a tampered one). Proves `backend()` is wired to
/// the functional `LibsparkBackend`.
#[cfg(all(test, feature = "libspark-ffi"))]
mod ffi_tests {
    use super::*;

    #[test]
    fn node_verifies_real_libspark_bundle() {
        let bundle = spark_connector::ffi::make_verify_bundle().expect("build verify bundle");
        assert!(verify_bundle(&bundle).is_ok(), "node must verify a real spend bundle");

        let mut bad = bundle;
        let n = bad.len();
        bad[n - 10] ^= 0x01; // tamper the proof region
        assert!(verify_bundle(&bad).is_err(), "node must reject a tampered spend");
    }

    /// SOAK (Stage 3e gate): drive the node's shielded verify path — build a
    /// fresh valid spend bundle, verify it through `verify_bundle` (must accept),
    /// tamper the proof region, verify again (must reject) — in a tight loop for
    /// `COINCYNC_SHIELDED_SOAK_SECS` (default 24h). Stresses the libspark FFI
    /// boundary (memory, exception safety, determinism) under sustained load.
    /// `#[ignore]` — run explicitly:
    ///   SPARK_OPENSSL_DIR=... cargo test --release --features testnet,sketch-gk-proof,libspark-ffi \
    ///     consensus::shielded_connector::ffi_tests::soak_shielded_verify -- --ignored --nocapture
    #[test]
    #[ignore]
    fn soak_shielded_verify() {
        use std::time::{Duration, Instant};
        let secs: u64 = std::env::var("COINCYNC_SHIELDED_SOAK_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(86_400);
        let deadline = Instant::now() + Duration::from_secs(secs);
        let (mut ok_count, mut reject_count): (u64, u64) = (0, 0);
        let mut iters: u64 = 0;
        eprintln!("{{\"event\":\"soak_start\",\"secs\":{secs}}}");
        while Instant::now() < deadline {
            let bundle = spark_connector::ffi::make_verify_bundle()
                .expect("soak: bundle build failed");
            if verify_bundle(&bundle).is_err() {
                panic!("soak: a freshly-built valid bundle FAILED to verify (iter {iters})");
            }
            ok_count += 1;

            let mut bad = bundle;
            let n = bad.len();
            bad[n - 10] ^= 0x01;
            if verify_bundle(&bad).is_ok() {
                panic!("soak: a TAMPERED bundle was ACCEPTED (iter {iters})");
            }
            reject_count += 1;

            iters += 1;
            if iters % 500 == 0 {
                eprintln!(
                    "{{\"event\":\"soak_progress\",\"iters\":{iters},\"accepted\":{ok_count},\"rejected\":{reject_count}}}"
                );
            }
        }
        eprintln!(
            "{{\"event\":\"soak_done\",\"iters\":{iters},\"accepted\":{ok_count},\"rejected\":{reject_count}}}"
        );
        assert!(iters > 0, "soak ran zero iterations");
    }
}
