//! # Send-path value types
//!
//! Defines the request/context/prepared-transaction types shared across the
//! send module, plus the transfer-shape classifier and the wallet↔consensus
//! ring-size parity guard.
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `Payment` (subaddress flag)** — INVARIANT: `is_subaddress` is stored faithfully;
//!   `new` defaults to a main address, `new_subaddress` sets the flag.
//!   THREAT: a mis-set flag makes a subaddress payment undetectable/unspendable.
//!   TESTS: `payment_new_subaddress_sets_flag_and_keys`.
//! - **§2 `SpendContext::with_ring_size`** — INVARIANT: rejects a ring size below 2 and derives
//!   `min_output_age` from the target height.
//!   THREAT: a degenerate ring (<2) provides no privacy.
//!   TESTS: `spend_context_with_ring_size_rejects_small_ring_and_derives_min_age`.
//! - **§3 ring size == consensus `effective_ring_size`** — INVARIANT: wherever the wallet can
//!   build a ring, its `ring_size_at_height` equals the size consensus requires.
//!   THREAT: 1d27d3c8-class fork surface — wallet emits a tx the validator rejects on ring size.
//!   TESTS: `wallet_ring_size_matches_consensus_effective_ring_size_wherever_buildable`,
//!   `ring_size_bootstrap_boundary_is_consistent`.
//! - **§4 `TransferShape::classify`** — INVARIANT: classifies pre-activation sends as `Legacy`,
//!   a same-destination pair as `UniformDripPair`, and a single recipient as `UniformStandard`.
//!   THREAT: mis-classification → wrong output shape → rejection or de-anonymisation.
//!   TESTS: `prepare_uniform_standard_satisfies_inputs_equal_payments_plus_change_plus_fee`,
//!   `build_prepared_uniform_drip_pair_emits_two_outputs_no_change`,
//!   `build_prepared_legacy_shape_adds_change_and_up_to_two_dummies`.
//! - **§5 `SendRequest` builder** — INVARIANT: defaults to a neutral 1.0 fee multiplier, no memo
//!   and empty extra; builder setters only override what is set.
//!   THREAT: a bad default (e.g. zero fee) silently mis-fees every send.
//!   TESTS: (gap — no test pins the builder defaults directly).
//! - **§6 prepared-transaction accessors** — INVARIANT: `real_outputs`, `ring_size`, and
//!   `input_count` on `Prepared{Privacy,Vesting}Transaction` reflect the selected inputs/context.
//!   THREAT: a stale accessor feeds the wrong rings/size into assembly.
//!   TESTS: `build_prepared_uniform_drip_pair_emits_two_outputs_no_change`,
//!   `prepare_vesting_stamps_unlock_height_onto_output_lock_height`.

use super::super::decoy_selection::RealOutputIdentity;
use crate::constants::{
    min_output_age_at_height, ring_size_at_height, STANDARD_OUTPUT_COUNT,
    UNIFORM_TX_SHAPE_HEIGHT,
};
use crate::error::{Error, Result};
use crate::primitives::{Amount, Hash, PublicKey};
use crate::transaction::SpendableInput;

#[derive(Clone, Copy)]
pub struct Payment {
    pub spend_public: PublicKey,
    pub view_public: PublicKey,
    pub amount: Amount,
    /// Whether the destination is a subaddress. Subaddress outputs use tx
    /// pubkey R = r*D_i so the recipient can detect them against their published
    /// view key C_i = a*D_i. MUST be `true` for a subaddress destination or the
    /// funds are undetectable/unspendable by the recipient. Defaults to `false`
    /// (main address) via `new`/`From`; set from `Address.address_type ==
    /// Subaddress` at the send entry point (see `new_subaddress`/`with_subaddress`).
    pub is_subaddress: bool,
}

impl Payment {
    pub fn new(spend_public: PublicKey, view_public: PublicKey, amount: Amount) -> Self {
        Self {
            spend_public,
            view_public,
            amount,
            is_subaddress: false,
        }
    }

    /// Construct a payment to a SUBADDRESS destination (uses R = r*D_i).
    pub fn new_subaddress(
        spend_public: PublicKey,
        view_public: PublicKey,
        amount: Amount,
    ) -> Self {
        Self {
            spend_public,
            view_public,
            amount,
            is_subaddress: true,
        }
    }

    /// Set the subaddress flag from `Address.address_type == Subaddress`.
    pub fn with_subaddress(mut self, is_subaddress: bool) -> Self {
        self.is_subaddress = is_subaddress;
        self
    }

    pub(super) fn has_same_destination(self, other: Self) -> bool {
        self.spend_public.as_bytes() == other.spend_public.as_bytes()
            && self.view_public.as_bytes() == other.view_public.as_bytes()
    }
}

impl From<(PublicKey, PublicKey, Amount)> for Payment {
    fn from((spend_public, view_public, amount): (PublicKey, PublicKey, Amount)) -> Self {
        Self::new(spend_public, view_public, amount)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendContext {
    target_height: u64,
    ring_size: usize,
    min_output_age: u64,
}

impl SpendContext {
    pub fn for_target_height(target_height: u64) -> Self {
        Self {
            target_height,
            ring_size: ring_size_at_height(target_height),
            min_output_age: min_output_age_at_height(target_height),
        }
    }

    pub fn with_ring_size(target_height: u64, ring_size: usize) -> Result<Self> {
        if ring_size < 2 {
            return Err(Error::InvalidRingSize {
                expected: 2,
                got: ring_size,
            });
        }

        Ok(Self {
            target_height,
            ring_size,
            min_output_age: min_output_age_at_height(target_height),
        })
    }

    pub fn target_height(self) -> u64 {
        self.target_height
    }

    pub fn ring_size(self) -> usize {
        self.ring_size
    }

    pub fn min_output_age(self) -> u64 {
        self.min_output_age
    }
}

#[derive(Clone)]
pub struct SendRequest {
    pub(super) payments: Vec<Payment>,
    pub(super) context: SpendContext,
    pub(super) fee_multiplier: f64,
    pub(super) memo: Option<Vec<u8>>,
    pub(super) extra: Vec<u8>,
}

impl SendRequest {
    pub fn new(payments: Vec<Payment>, context: SpendContext) -> Self {
        Self {
            payments,
            context,
            fee_multiplier: 1.0,
            memo: None,
            extra: Vec::new(),
        }
    }

    pub fn with_fee_multiplier(mut self, fee_multiplier: f64) -> Self {
        self.fee_multiplier = fee_multiplier;
        self
    }

    pub fn with_memo(mut self, memo: Option<Vec<u8>>) -> Self {
        self.memo = memo;
        self
    }

    pub fn with_extra(mut self, extra: Vec<u8>) -> Self {
        self.extra = extra;
        self
    }

    pub fn payments(&self) -> &[Payment] {
        &self.payments
    }

    pub fn context(&self) -> SpendContext {
        self.context
    }
}

#[derive(Clone, Copy)]
pub struct VestingRequest {
    pub payment: Payment,
    pub unlock_height: u64,
    pub context: SpendContext,
}

impl VestingRequest {
    pub fn new(payment: Payment, unlock_height: u64, context: SpendContext) -> Self {
        Self {
            payment,
            unlock_height,
            context,
        }
    }
}

#[derive(Clone)]
pub(super) struct PreparedInput {
    pub(super) input: SpendableInput,
    pub(super) real_output: RealOutputIdentity,
}

impl PreparedInput {
    fn wallet_output_key(&self) -> (Hash, u8) {
        (self.input.tx_hash, self.input.output_index)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TransferShape {
    Legacy,
    UniformStandard,
    UniformDripPair,
}

impl TransferShape {
    pub(super) fn classify(payments: &[Payment], target_height: u64) -> Result<Self> {
        if target_height < UNIFORM_TX_SHAPE_HEIGHT {
            return Ok(Self::Legacy);
        }

        let is_drip_pair = payments.len() == STANDARD_OUTPUT_COUNT
            && payments
                .windows(2)
                .all(|pair| pair[0].has_same_destination(pair[1]));
        if is_drip_pair {
            return Ok(Self::UniformDripPair);
        }
        if payments.len() <= 1 {
            return Ok(Self::UniformStandard);
        }

        Err(Error::InvalidState(
            "Post-activation transfers must have one recipient or a same-address drip pair".into(),
        ))
    }

    pub(super) fn is_uniform(self) -> bool {
        !matches!(self, Self::Legacy)
    }
}

pub struct PreparedPrivacyTransaction {
    pub(super) inputs: Vec<PreparedInput>,
    pub(super) payments: Vec<Payment>,
    pub(super) change_amount: u64,
    pub(super) estimated_fee: Amount,
    pub(super) context: SpendContext,
    pub(super) shape: TransferShape,
    pub(super) spend_public: PublicKey,
    pub(super) view_public: PublicKey,
    pub(super) memo: Option<Vec<u8>>,
    pub(super) extra: Vec<u8>,
}

impl PreparedPrivacyTransaction {
    pub fn real_outputs(&self) -> Vec<RealOutputIdentity> {
        self.inputs.iter().map(|input| input.real_output).collect()
    }

    pub(crate) fn selected_output_keys(&self) -> Vec<(Hash, u8)> {
        self.inputs
            .iter()
            .map(PreparedInput::wallet_output_key)
            .collect()
    }

    pub fn ring_size(&self) -> usize {
        self.context.ring_size()
    }

    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }
}

pub struct PreparedVestingTransaction {
    pub(super) inputs: Vec<PreparedInput>,
    pub(super) request: VestingRequest,
    pub(super) change_amount: u64,
    pub(super) estimated_fee: Amount,
    pub(super) spend_public: PublicKey,
    pub(super) view_public: PublicKey,
}

impl PreparedVestingTransaction {
    pub fn real_outputs(&self) -> Vec<RealOutputIdentity> {
        self.inputs.iter().map(|input| input.real_output).collect()
    }

    pub fn ring_size(&self) -> usize {
        self.request.context.ring_size()
    }

    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }
}

#[derive(Clone, Copy, Debug, Default)]
#[allow(dead_code)]
pub enum CoinSelection {
    #[default]
    OldestFirst,
    NewestFirst,
    LargestFirst,
    SmallestFirst,
    Random,
}

#[cfg(test)]
mod ring_size_parity_tests {
    use crate::constants::{
        effective_ring_size, ring_size_at_height, BOOTSTRAP_MIN_RING_SIZE, DEFAULT_RING_SIZE,
    };

    /// AUDIT (wallet C3, 1d27d3c8-class fork surface): the wallet builds every
    /// ring at `ring_size_at_height(h)`, but consensus REQUIRES exactly
    /// `effective_ring_size(h, available)` (validation.rs rejects on `!=`). This
    /// pins the exact boundary and proves the two can never DISAGREE on an
    /// accepted tx. Wherever the wallet can actually build its ring
    /// (available >= requested size), consensus demands the SAME size. The only
    /// mismatch is young-AND-sparse, where the wallet over-requests and decoy
    /// selection fails safe (`InsufficientDecoys`) — it never emits a tx a
    /// validator would reject, so there is no fork surface, only a bounded
    /// early-chain liveness edge.
    #[test]
    fn wallet_ring_size_matches_consensus_effective_ring_size_wherever_buildable() {
        for &h in &[0u64, 1, 100, 9_999, 10_000, 10_001, 50_000] {
            let wallet = ring_size_at_height(h);
            for &available in &[0usize, 1, 2, 5, 10, 11, 15, 16, 100] {
                let consensus = effective_ring_size(h, available);
                if available >= wallet {
                    // Buildable: consensus must demand exactly the wallet's size.
                    assert_eq!(
                        wallet, consensus,
                        "buildable case must agree (h={h}, available={available})"
                    );
                } else if h >= 10_000 {
                    // Post-bootstrap enforces the full target on both sides; the
                    // wallet then fails to build (correct — a mature chain should
                    // not be this sparse), never emitting a divergent tx.
                    assert_eq!(wallet, consensus, "post-bootstrap agrees (h={h})");
                } else {
                    // Young + sparse: consensus would accept a SMALLER ring, but
                    // the wallet over-requests (> available) → decoy selection
                    // returns InsufficientDecoys. Bounded liveness edge, not a
                    // fork. Pin the exact relationship.
                    assert!(
                        consensus <= wallet,
                        "consensus never demands MORE than the wallet requests (h={h}, available={available})"
                    );
                    assert!(consensus >= 2, "consensus keeps a 2-min ring for any privacy");
                    assert!(available < wallet, "wallet cannot build this ring — it fails safe");
                }
            }
        }
    }

    /// The bootstrap→mature pivot at height 10_000 is where both functions turn.
    #[test]
    fn ring_size_bootstrap_boundary_is_consistent() {
        assert_eq!(ring_size_at_height(9_999), BOOTSTRAP_MIN_RING_SIZE);
        assert_eq!(ring_size_at_height(10_000), DEFAULT_RING_SIZE);
        assert_eq!(effective_ring_size(9_999, 1_000), BOOTSTRAP_MIN_RING_SIZE);
        assert_eq!(effective_ring_size(10_000, 1_000), DEFAULT_RING_SIZE);
    }
}
