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
