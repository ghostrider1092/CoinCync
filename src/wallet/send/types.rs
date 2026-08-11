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
}

impl Payment {
    pub fn new(spend_public: PublicKey, view_public: PublicKey, amount: Amount) -> Self {
        Self {
            spend_public,
            view_public,
            amount,
        }
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
