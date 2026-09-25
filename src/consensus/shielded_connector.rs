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
use spark_connector::{SparkBackend, SpendBytes, StubBackend};

/// The active Spark backend. Fail-closed `StubBackend` until the reviewed
/// libspark FFI backend replaces it here (the one swap point).
fn backend() -> impl SparkBackend {
    StubBackend
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
