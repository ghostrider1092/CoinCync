//! # Transaction Creation for CoinCync 1.0
//!
//! Transaction construction is split into two privacy-critical phases:
//! input/fee preparation, followed by final assembly with rings allocated from
//! one snapshot-bound covered locator response.

use super::{Balance, KeyEpoch, UTXO};
use crate::constants::{
    min_output_age_at_height, ring_size_at_height, MIN_FEE_PER_BYTE, MIN_OUTPUT_AMOUNT,
    STANDARD_INPUT_COUNT, STANDARD_OUTPUT_COUNT, UNIFORM_TX_SHAPE_HEIGHT,
};
use crate::crypto::{
    compute_one_time_secret, BlindingFactor, PedersenCommitment, StealthAddress,
};
use crate::error::{Error, Result};
use crate::primitives::{Address, Amount, PublicKey};
use crate::transaction::{
    Recipient, SpendableInput, Transaction, TransactionBuilder, TxType,
};
use crate::wallet::decoy_selection::{AllocatedRing, RealOutputIdentity};
use rand::{seq::SliceRandom, CryptoRng, Rng, RngCore};
use std::collections::HashSet;

#[derive(Clone)]
struct PreparedInput {
    input: SpendableInput,
    real_output: RealOutputIdentity,
}

pub struct PreparedPrivacyTransaction {
    inputs: Vec<PreparedInput>,
    recipients: Vec<(PublicKey, PublicKey, Amount)>,
    change_amount: u64,
    estimated_fee: Amount,
    current_height: u64,
    uniform: bool,
    drip_pair: bool,
    spend_public: PublicKey,
    view_public: PublicKey,
    memo: Option<Vec<u8>>,
    extra: Vec<u8>,
    ring_size: usize,
}

impl PreparedPrivacyTransaction {
    pub fn real_outputs(&self) -> Vec<RealOutputIdentity> {
        self.inputs.iter().map(|input| input.real_output).collect()
    }

    pub fn ring_size(&self) -> usize {
        self.ring_size
    }

    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }
}

pub struct PreparedVestingTransaction {
    inputs: Vec<PreparedInput>,
    recipient_spend: PublicKey,
    recipient_view: PublicKey,
    amount: Amount,
    unlock_height: u64,
    change_amount: u64,
    estimated_fee: Amount,
    current_height: u64,
    spend_public: PublicKey,
    view_public: PublicKey,
    ring_size: usize,
}

impl PreparedVestingTransaction {
    pub fn real_outputs(&self) -> Vec<RealOutputIdentity> {
        self.inputs.iter().map(|input| input.real_output).collect()
    }

    pub fn ring_size(&self) -> usize {
        self.ring_size
    }

    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }
}

/// Coin selection strategy.
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


// The transaction builder is split into textual implementation fragments so
// preparation and final signing keep one module-private contract without
// exposing internal input material across public module boundaries.
include!("send/transactions.rs");
include!("send/vesting_and_inputs.rs");
include!("send/selection_and_tests.rs");
