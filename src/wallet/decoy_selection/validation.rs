//! Boundary validation that binds a raw node covered response to its request.
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `snapshot match`** — INVARIANT: the response's snapshot id must equal
//!   the request's. THREAT: a response resolved against a different snapshot.
//!   TESTS: `covered_response_rejects_snapshot_order_and_height_mismatches`.
//! - **§2 `length match`** — INVARIANT: the response output count equals the
//!   requested locator count. THREAT: a truncated or padded response.
//!   TESTS: `covered_response_rejects_snapshot_order_and_height_mismatches`.
//! - **§3 `locator match`** — INVARIANT: each output's locator equals the
//!   requested locator in order. THREAT: reordered or substituted outputs.
//!   TESTS: `covered_response_rejects_snapshot_order_and_height_mismatches`.
//! - **§4 `height match`** — INVARIANT: each output's redundant height field
//!   matches its locator height. THREAT: inconsistent output metadata.
//!   TESTS: `covered_response_rejects_snapshot_order_and_height_mismatches`.
//! - **§5 `unique index`** — INVARIANT: the locator→index map is built from
//!   unique locators. THREAT: duplicate locators alias distinct outputs.
//!   TESTS: `covered_lookup_allocates_transaction_wide_unique_decoys`.
//! - **§6 `validate_covered_response`** — INVARIANT: a `ValidatedCoveredResponse`
//!   is returned only when snapshot, cardinality, ordering and heights all pass
//!   (fail-closed). THREAT: a partially-validated response reaches allocation.
//!   TESTS: `covered_response_rejects_snapshot_order_and_height_mismatches`,
//!   `allocation_rejects_real_identity_mismatch`.

use super::error::{DecoySelectionError, DecoySelectionResult};
use super::types::{CoveredRequest, SnapshotId, ValidatedCoveredResponse};
use crate::decoy::ResolvedDecoySnapshot;
use std::collections::HashMap;

pub fn validate_covered_response(
    request: CoveredRequest,
    response: ResolvedDecoySnapshot,
) -> DecoySelectionResult<ValidatedCoveredResponse> {
    let expected_snapshot = request.snapshot_id();
    let received_snapshot = SnapshotId::from_response(&response);
    if received_snapshot != expected_snapshot {
        return Err(DecoySelectionError::ResponseSnapshotMismatch {
            expected_height: expected_snapshot.height(),
            got_height: received_snapshot.height(),
            expected_policy_version: expected_snapshot.policy_version(),
            got_policy_version: received_snapshot.policy_version(),
            hash_matches: expected_snapshot.hash() == received_snapshot.hash(),
        });
    }

    if response.outputs.len() != request.locators().len() {
        return Err(DecoySelectionError::ResponseLengthMismatch {
            expected: request.locators().len(),
            got: response.outputs.len(),
        });
    }

    let mut output_index = HashMap::with_capacity(response.outputs.len());
    for (index, (expected, output)) in request
        .locators()
        .iter()
        .zip(&response.outputs)
        .enumerate()
    {
        if output.locator != *expected {
            return Err(DecoySelectionError::ResponseLocatorMismatch {
                index,
                expected: *expected,
                got: output.locator,
            });
        }
        if output.height != expected.height {
            return Err(DecoySelectionError::ResponseHeightMismatch {
                locator: *expected,
                output_height: output.height,
            });
        }
        let previous = output_index.insert(*expected, index);
        debug_assert!(previous.is_none(), "covered request locators are unique");
    }

    Ok(ValidatedCoveredResponse::new(
        request,
        response.outputs,
        output_index,
    ))
}
