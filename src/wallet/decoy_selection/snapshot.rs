use crate::decoy::{
    DecoyDistributionSnapshot, HeightOutputCount, OutputLocator, DECOY_LOCATOR_POLICY_VERSION,
};
use crate::error::{Error, Result};

pub(super) fn validate_policy_version(snapshot: &DecoyDistributionSnapshot) -> Result<()> {
    if snapshot.policy_version == DECOY_LOCATOR_POLICY_VERSION {
        return Ok(());
    }

    Err(Error::InvalidState(format!(
        "unsupported decoy locator policy version {}",
        snapshot.policy_version
    )))
}

pub(super) fn snapshot_spend_height(snapshot: &DecoyDistributionSnapshot) -> Result<u64> {
    snapshot.snapshot_height.checked_add(1).ok_or_else(|| {
        Error::InvalidState("decoy snapshot cannot advance to a spend height".into())
    })
}

pub(super) fn eligible_heights(
    snapshot: &DecoyDistributionSnapshot,
    min_age: u64,
) -> Result<Vec<HeightOutputCount>> {
    validate_policy_version(snapshot)?;

    let max_height = snapshot_spend_height(snapshot)?
        .checked_sub(min_age)
        .ok_or_else(|| Error::InsufficientDecoys {
            available: 0,
            needed: 1,
        })?;

    let mut previous = None;
    for height in &snapshot.heights {
        if height.count == 0 || previous.is_some_and(|value| height.height <= value) {
            return Err(Error::InvalidState(
                "decoy distribution heights must be strictly increasing and non-empty".into(),
            ));
        }
        if height.height > snapshot.snapshot_height {
            return Err(Error::InvalidState(
                "decoy distribution contains a height above its snapshot".into(),
            ));
        }
        previous = Some(height.height);
    }

    Ok(snapshot
        .heights
        .iter()
        .take_while(|height| height.height <= max_height)
        .cloned()
        .collect())
}

pub(super) fn locator_is_in(locator: &OutputLocator, heights: &[HeightOutputCount]) -> bool {
    heights
        .binary_search_by_key(&locator.height, |height| height.height)
        .ok()
        .is_some_and(|index| locator.ordinal < heights[index].count)
}
