use super::error::{DecoySelectionError, DecoySelectionResult};
use super::types::{SnapshotId, ValidatedDecoySnapshot};
use crate::decoy::{DecoyDistributionSnapshot, DECOY_LOCATOR_POLICY_VERSION};

impl TryFrom<DecoyDistributionSnapshot> for ValidatedDecoySnapshot {
    type Error = DecoySelectionError;

    fn try_from(snapshot: DecoyDistributionSnapshot) -> DecoySelectionResult<Self> {
        if snapshot.policy_version != DECOY_LOCATOR_POLICY_VERSION {
            return Err(DecoySelectionError::UnsupportedPolicyVersion {
                got: snapshot.policy_version,
                supported: DECOY_LOCATOR_POLICY_VERSION,
            });
        }

        let spend_height = snapshot.snapshot_height.checked_add(1).ok_or(
            DecoySelectionError::SnapshotHeightOverflow {
                snapshot_height: snapshot.snapshot_height,
            },
        )?;

        let mut previous_height = None;
        let mut total_outputs = 0usize;
        let mut cumulative_counts = Vec::with_capacity(snapshot.heights.len());
        for bucket in &snapshot.heights {
            if bucket.count == 0 {
                return Err(DecoySelectionError::EmptyHeightBucket {
                    height: bucket.height,
                });
            }
            if let Some(previous) = previous_height {
                if bucket.height <= previous {
                    return Err(DecoySelectionError::NonIncreasingHeight {
                        previous,
                        current: bucket.height,
                    });
                }
            }
            if bucket.height > snapshot.snapshot_height {
                return Err(DecoySelectionError::HeightAboveSnapshot {
                    height: bucket.height,
                    snapshot_height: snapshot.snapshot_height,
                });
            }

            total_outputs = total_outputs
                .checked_add(bucket.count as usize)
                .ok_or(DecoySelectionError::PoolSizeOverflow)?;
            cumulative_counts.push(total_outputs);
            previous_height = Some(bucket.height);
        }

        let id = SnapshotId::from_distribution(&snapshot);
        Ok(Self::new(
            snapshot,
            cumulative_counts,
            id,
            spend_height,
        ))
    }
}
