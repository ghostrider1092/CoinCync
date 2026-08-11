use super::error::{DecoySelectionError, DecoySelectionResult};
use crate::decoy::{
    DecoyDistributionSnapshot, HeightOutputCount, OutputLocator, ResolvedDecoyOutput,
    ResolvedDecoySnapshot,
};
use crate::primitives::{Hash, PublicKey};
use crate::transaction::DecoyOutput;
use std::collections::{HashMap, HashSet};

/// Identity shared by a distribution snapshot, its covered request and the
/// corresponding resolved response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotId {
    height: u64,
    hash: Hash,
    policy_version: u16,
}

impl SnapshotId {
    pub fn height(self) -> u64 {
        self.height
    }

    pub fn hash(self) -> Hash {
        self.hash
    }

    pub fn policy_version(self) -> u16 {
        self.policy_version
    }

    pub(super) fn from_distribution(snapshot: &DecoyDistributionSnapshot) -> Self {
        Self {
            height: snapshot.snapshot_height,
            hash: snapshot.snapshot_hash,
            policy_version: snapshot.policy_version,
        }
    }

    pub(super) fn from_response(response: &ResolvedDecoySnapshot) -> Self {
        Self {
            height: response.snapshot_height,
            hash: response.snapshot_hash,
            policy_version: response.policy_version,
        }
    }
}

/// A distribution snapshot whose policy version, height ordering and bucket
/// bounds have been checked once at the application boundary.
#[derive(Clone, Debug)]
pub struct ValidatedDecoySnapshot {
    distribution: DecoyDistributionSnapshot,
    cumulative_counts: Vec<usize>,
    id: SnapshotId,
    spend_height: u64,
}

impl ValidatedDecoySnapshot {
    pub fn snapshot_id(&self) -> SnapshotId {
        self.id
    }

    pub fn spend_height(&self) -> u64 {
        self.spend_height
    }

    pub(super) fn new(
        distribution: DecoyDistributionSnapshot,
        cumulative_counts: Vec<usize>,
        id: SnapshotId,
        spend_height: u64,
    ) -> Self {
        Self {
            distribution,
            cumulative_counts,
            id,
            spend_height,
        }
    }

    pub(super) fn eligible_heights(&self, min_age: u64) -> &[HeightOutputCount] {
        let end = self.eligible_height_count(min_age);
        &self.distribution.heights[..end]
    }

    pub(super) fn eligible_output_count(&self, min_age: u64) -> usize {
        let end = self.eligible_height_count(min_age);
        end.checked_sub(1)
            .map_or(0, |index| self.cumulative_counts[index])
    }

    pub(super) fn contains_locator(&self, locator: &OutputLocator) -> bool {
        self.distribution
            .heights
            .binary_search_by_key(&locator.height, |height| height.height)
            .ok()
            .is_some_and(|index| locator.ordinal < self.distribution.heights[index].count)
    }

    fn eligible_height_count(&self, min_age: u64) -> usize {
        let Some(max_height) = self.spend_height.checked_sub(min_age) else {
            return 0;
        };
        self.distribution
            .heights
            .partition_point(|height| height.height <= max_height)
    }
}

/// Ring parameters captured when a covered request is built.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RingPolicy {
    ring_size: usize,
    min_output_age: u64,
}

impl RingPolicy {
    pub(super) fn try_new(
        ring_size: usize,
        min_output_age: u64,
    ) -> DecoySelectionResult<Self> {
        if ring_size < 2 {
            return Err(DecoySelectionError::InvalidRingSize { got: ring_size });
        }
        Ok(Self {
            ring_size,
            min_output_age,
        })
    }

    fn ring_size(self) -> usize {
        self.ring_size
    }

    fn min_output_age(self) -> u64 {
        self.min_output_age
    }
}

/// One snapshot-bound covered lookup. Construction is restricted to the
/// sampling module, so callers cannot pair arbitrary locators with unrelated
/// snapshot metadata or allocation policy.
#[derive(Clone, Debug)]
pub struct CoveredRequest {
    snapshot_id: SnapshotId,
    spend_height: u64,
    policy: RingPolicy,
    real_locators: Vec<OutputLocator>,
    real_locator_set: HashSet<OutputLocator>,
    locators: Vec<OutputLocator>,
}

impl CoveredRequest {
    pub fn snapshot_id(&self) -> SnapshotId {
        self.snapshot_id
    }

    pub fn locators(&self) -> &[OutputLocator] {
        &self.locators
    }

    pub fn real_locators(&self) -> &[OutputLocator] {
        &self.real_locators
    }

    pub fn ring_size(&self) -> usize {
        self.policy.ring_size()
    }

    pub fn min_output_age(&self) -> u64 {
        self.policy.min_output_age()
    }

    pub fn spend_height(&self) -> u64 {
        self.spend_height
    }

    pub(super) fn new(
        snapshot: &ValidatedDecoySnapshot,
        policy: RingPolicy,
        real_locators: Vec<OutputLocator>,
        locators: Vec<OutputLocator>,
    ) -> Self {
        let real_locator_set: HashSet<_> = real_locators.iter().copied().collect();
        debug_assert_eq!(locators.len(), super::COVERED_LOOKUP_SIZE);
        debug_assert_eq!(real_locator_set.len(), real_locators.len());
        debug_assert_eq!(
            locators.iter().copied().collect::<HashSet<_>>().len(),
            locators.len()
        );
        debug_assert!(real_locator_set
            .iter()
            .all(|locator| locators.contains(locator)));
        Self {
            snapshot_id: snapshot.snapshot_id(),
            spend_height: snapshot.spend_height(),
            policy,
            real_locators,
            real_locator_set,
            locators,
        }
    }

    pub(super) fn real_locator_set(&self) -> &HashSet<OutputLocator> {
        &self.real_locator_set
    }

    pub(super) fn max_decoy_height(&self) -> Option<u64> {
        self.spend_height.checked_sub(self.min_output_age())
    }
}

/// A covered response that exactly matches one [`CoveredRequest`].
///
/// The locator index is built only after snapshot metadata, cardinality,
/// ordering and redundant output-height fields have been verified.
#[derive(Debug)]
pub struct ValidatedCoveredResponse {
    request: CoveredRequest,
    outputs: Vec<ResolvedDecoyOutput>,
    output_index: HashMap<OutputLocator, usize>,
}

impl ValidatedCoveredResponse {
    pub fn request(&self) -> &CoveredRequest {
        &self.request
    }

    pub fn outputs(&self) -> &[ResolvedDecoyOutput] {
        &self.outputs
    }

    pub(super) fn new(
        request: CoveredRequest,
        outputs: Vec<ResolvedDecoyOutput>,
        output_index: HashMap<OutputLocator, usize>,
    ) -> Self {
        Self {
            request,
            outputs,
            output_index,
        }
    }

    pub(super) fn resolved(&self, locator: &OutputLocator) -> Option<&ResolvedDecoyOutput> {
        self.output_index
            .get(locator)
            .map(|index| &self.outputs[*index])
    }
}

/// Identity of a selected wallet input as it must resolve in the canonical
/// output catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealOutputIdentity {
    locator: OutputLocator,
    public_key: PublicKey,
    commitment: [u8; 32],
}

impl RealOutputIdentity {
    pub fn new(
        locator: OutputLocator,
        public_key: PublicKey,
        commitment: [u8; 32],
    ) -> Self {
        Self {
            locator,
            public_key,
            commitment,
        }
    }

    pub fn locator(self) -> OutputLocator {
        self.locator
    }

    pub fn public_key(self) -> PublicKey {
        self.public_key
    }

    pub fn commitment(self) -> [u8; 32] {
        self.commitment
    }
}

/// One valid ring allocation. Fields are private so the decoy allocator is the
/// only production path that can create a ring.
pub struct AllocatedRing {
    decoys: Vec<DecoyOutput>,
    real_position: usize,
}

impl AllocatedRing {
    pub fn decoys(&self) -> &[DecoyOutput] {
        &self.decoys
    }

    pub fn real_position(&self) -> usize {
        self.real_position
    }

    pub(super) fn new(decoys: Vec<DecoyOutput>, real_position: usize) -> Self {
        Self {
            decoys,
            real_position,
        }
    }

    pub(crate) fn into_parts(self) -> (Vec<DecoyOutput>, usize) {
        (self.decoys, self.real_position)
    }
}

/// Transaction-wide ring allocation. Construction is restricted to the
/// allocator, which guarantees the same ring size for every input and no
/// decoy public-key reuse across the transaction.
pub struct AllocatedRings {
    ring_size: usize,
    real_outputs: Vec<RealOutputIdentity>,
    rings: Vec<AllocatedRing>,
}

impl AllocatedRings {
    pub fn ring_size(&self) -> usize {
        self.ring_size
    }

    pub fn len(&self) -> usize {
        self.rings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rings.is_empty()
    }

    pub fn rings(&self) -> &[AllocatedRing] {
        &self.rings
    }

    pub fn real_outputs(&self) -> &[RealOutputIdentity] {
        &self.real_outputs
    }

    pub(super) fn new(
        ring_size: usize,
        real_outputs: Vec<RealOutputIdentity>,
        rings: Vec<AllocatedRing>,
    ) -> Self {
        Self {
            ring_size,
            real_outputs,
            rings,
        }
    }
}

impl IntoIterator for AllocatedRings {
    type Item = AllocatedRing;
    type IntoIter = std::vec::IntoIter<AllocatedRing>;

    fn into_iter(self) -> Self::IntoIter {
        self.rings.into_iter()
    }
}
