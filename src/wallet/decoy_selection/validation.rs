use super::snapshot::{eligible_heights, locator_is_in};
use crate::decoy::{DecoyDistributionSnapshot, OutputLocator, ResolvedDecoySnapshot};
use crate::error::{Error, Result};
use std::collections::HashSet;

pub fn validate_covered_response(
    snapshot: &DecoyDistributionSnapshot,
    requested: &[OutputLocator],
    response: &ResolvedDecoySnapshot,
) -> Result<()> {
    let all_heights = eligible_heights(snapshot, 0)?;

    if response.snapshot_height != snapshot.snapshot_height
        || response.snapshot_hash != snapshot.snapshot_hash
        || response.policy_version != snapshot.policy_version
    {
        return Err(Error::InvalidState(
            "decoy response snapshot metadata mismatch".into(),
        ));
    }
    if response.outputs.len() != requested.len() {
        return Err(Error::InvalidState(format!(
            "decoy response returned {} outputs for {} locators",
            response.outputs.len(),
            requested.len()
        )));
    }
    if requested.iter().copied().collect::<HashSet<_>>().len() != requested.len() {
        return Err(Error::InvalidState(
            "covered request contains duplicate locators".into(),
        ));
    }

    if requested
        .iter()
        .any(|locator| !locator_is_in(locator, &all_heights))
    {
        return Err(Error::InvalidState(
            "covered request contains a locator outside the decoy snapshot".into(),
        ));
    }

    for (locator, output) in requested.iter().zip(&response.outputs) {
        if output.locator != *locator || output.height != locator.height {
            return Err(Error::InvalidState(
                "decoy response does not preserve requested locator order".into(),
            ));
        }
    }

    Ok(())
}
