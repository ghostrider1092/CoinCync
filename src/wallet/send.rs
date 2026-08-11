//! # Transaction Creation for CoinCync 1.0
//!
//! Transaction construction is split into explicit preparation and assembly
//! phases. Preparation selects wallet inputs and computes fees. Assembly only
//! accepts rings allocated from one snapshot-bound covered locator response.

mod assembly;
mod fee;
mod inputs;
mod legacy;
mod prepare;
mod selection;
mod types;
mod vesting;

pub use assembly::build_prepared_privacy_transaction;
pub use fee::{calculate_fee, estimate_fee_with_multiplier, estimate_tx_size};
#[allow(deprecated)]
pub use legacy::create_transaction;
pub use prepare::{prepare_privacy_transaction, prepare_privacy_transaction_with_options};
pub use types::{
    CoinSelection, Payment, PreparedPrivacyTransaction, PreparedVestingTransaction, SendRequest,
    SpendContext, VestingRequest,
};
pub use vesting::{
    build_prepared_vesting_transaction, prepare_vesting, prepare_vesting_transaction,
};

#[cfg(test)]
mod tests;
