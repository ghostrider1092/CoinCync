use crate::decoy::OutputLocator;
use crate::error::Error as WalletError;
use thiserror::Error;

pub type DecoySelectionResult<T> = std::result::Result<T, DecoySelectionError>;

/// Fail-closed errors produced while turning a node snapshot into signed rings.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DecoySelectionError {
    #[error("unsupported decoy locator policy version {got}; supported version is {supported}")]
    UnsupportedPolicyVersion { got: u16, supported: u16 },

    #[error("decoy snapshot height {snapshot_height} cannot advance to a spend height")]
    SnapshotHeightOverflow { snapshot_height: u64 },

    #[error("decoy distribution contains an empty bucket at height {height}")]
    EmptyHeightBucket { height: u64 },

    #[error(
        "decoy distribution heights are not strictly increasing: {previous} then {current}"
    )]
    NonIncreasingHeight { previous: u64, current: u64 },

    #[error(
        "decoy distribution height {height} is above snapshot height {snapshot_height}"
    )]
    HeightAboveSnapshot { height: u64, snapshot_height: u64 },

    #[error("decoy distribution output count exceeds this platform's addressable size")]
    PoolSizeOverflow,

    #[error("insufficient decoy outputs: {available} available, {needed} needed")]
    InsufficientDecoys { available: usize, needed: usize },

    #[error("covered request must contain at least one real output")]
    MissingRealOutputs,

    #[error("duplicate real output locator {0:?}")]
    DuplicateRealLocator(OutputLocator),

    #[error("invalid ring size {got}; minimum is 2")]
    InvalidRingSize { got: usize },

    #[error(
        "covered lookup size overflow for {input_count} inputs at ring size {ring_size}"
    )]
    CoveredLookupSizeOverflow {
        input_count: usize,
        ring_size: usize,
    },

    #[error(
        "covered lookup for {input_count} inputs at ring size {ring_size} needs {required_slots} slots; capacity is {capacity}"
    )]
    CoveredLookupCapacityExceeded {
        input_count: usize,
        ring_size: usize,
        required_slots: usize,
        capacity: usize,
    },

    #[error("real output locator {0:?} is not present in the validated snapshot")]
    RealLocatorOutsideSnapshot(OutputLocator),

    #[error(
        "decoy response snapshot mismatch: height {got_height} (expected {expected_height}), policy {got_policy_version} (expected {expected_policy_version}), hash match: {hash_matches}"
    )]
    ResponseSnapshotMismatch {
        expected_height: u64,
        got_height: u64,
        expected_policy_version: u16,
        got_policy_version: u16,
        hash_matches: bool,
    },

    #[error("decoy response returned {got} outputs for {expected} requested locators")]
    ResponseLengthMismatch { expected: usize, got: usize },

    #[error(
        "decoy response locator mismatch at index {index}: expected {expected:?}, got {got:?}"
    )]
    ResponseLocatorMismatch {
        index: usize,
        expected: OutputLocator,
        got: OutputLocator,
    },

    #[error(
        "decoy response height mismatch for {locator:?}: output reports height {output_height}"
    )]
    ResponseHeightMismatch {
        locator: OutputLocator,
        output_height: u64,
    },

    #[error("real output set does not match the real locators bound into the covered request")]
    RealOutputSetMismatch,

    #[error("covered response is missing real output locator {0:?}")]
    MissingRealOutput(OutputLocator),

    #[error("real output locator {0:?} resolved to an unexpected output")]
    RealOutputIdentityMismatch(OutputLocator),

    #[error("selected wallet inputs contain a duplicate real output public key")]
    DuplicateRealPublicKey,

    #[error("ring allocation size overflow for {input_count} inputs at ring size {ring_size}")]
    RingAllocationSizeOverflow {
        input_count: usize,
        ring_size: usize,
    },

    #[error("ring allocation produced {got} rings for {expected} selected inputs")]
    RingCountMismatch { expected: usize, got: usize },

    #[error("ring allocation uses ring size {got}; transaction expects {expected}")]
    RingSizeMismatch { expected: usize, got: usize },

    #[error("ring allocation was produced for different wallet inputs")]
    RingInputMismatch,
}

impl From<DecoySelectionError> for WalletError {
    fn from(error: DecoySelectionError) -> Self {
        let message = error.to_string();
        match error {
            DecoySelectionError::InvalidRingSize { got } => WalletError::InvalidRingSize {
                expected: 2,
                got,
            },
            DecoySelectionError::InsufficientDecoys { available, needed } => {
                WalletError::InsufficientDecoys { available, needed }
            },
            DecoySelectionError::MissingRealOutputs
            | DecoySelectionError::DuplicateRealLocator(_)
            | DecoySelectionError::CoveredLookupSizeOverflow { .. }
            | DecoySelectionError::CoveredLookupCapacityExceeded { .. } => {
                WalletError::InvalidParams(message)
            },
            _ => WalletError::InvalidState(format!("decoy selection failed: {message}")),
        }
    }
}
