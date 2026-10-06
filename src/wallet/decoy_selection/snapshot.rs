//! Boundary validation that turns a raw node snapshot into a
//! [`ValidatedDecoySnapshot`].
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `policy version`** — INVARIANT: a snapshot is rejected unless its
//!   `policy_version` equals `DECOY_LOCATOR_POLICY_VERSION`. THREAT: sampling
//!   under a stale or foreign locator policy. TESTS:
//!   `validated_snapshot_rejects_unsupported_policy`.
//! - **§2 `spend_height derivation`** — INVARIANT: spend height is
//!   `snapshot_height + 1` with the increment overflow-guarded. THREAT: an
//!   overflow or wrong spend height corrupts all age math.
//!   TESTS: (gap — no test constructs a `u64::MAX` snapshot height).
//! - **§3 `non-empty buckets`** — INVARIANT: every height bucket must have a
//!   count greater than zero. THREAT: an empty bucket breaks selection and
//!   cumulative counts. TESTS: `validated_snapshot_rejects_invalid_height_buckets`.
//! - **§4 `strictly increasing heights`** — INVARIANT: bucket heights are
//!   strictly increasing. THREAT: unordered buckets break binary search and the
//!   cumulative-count index. TESTS: `validated_snapshot_rejects_invalid_height_buckets`.
//! - **§5 `height <= snapshot`** — INVARIANT: no bucket height exceeds the
//!   snapshot height. THREAT: future outputs enter the decoy pool.
//!   TESTS: `validated_snapshot_rejects_invalid_height_buckets`.
//! - **§6 `cumulative counts`** — INVARIANT: prefix output counts accumulate
//!   without `usize` overflow (`PoolSizeOverflow` guarded). THREAT: overflow
//!   miscounts the eligible pool. TESTS: (gap — no test builds a
//!   usize-overflowing output pool).

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
