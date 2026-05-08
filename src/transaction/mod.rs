//! # Transaction Module for CoinCync 1.0
//!
//! Privacy-preserving transactions with:
//! - Ring signatures (CLSAG) for sender privacy
//! - Stealth addresses for receiver privacy
//! - Bulletproofs+ for amount privacy
//! - Transaction fragmentation for large payments

mod types;
mod builder;
mod validator;
pub mod recovery;

pub use types::{Transaction, TxInput, TxOutput, TxType, RingMemberRef, SigningInputView};
#[allow(deprecated)] // SimpleTransactionBuilder is itself deprecated; re-export kept for the deprecated send.rs path
pub use builder::{
    TransactionBuilder, SimpleTransactionBuilder,
    SpendableInput, Recipient, DecoyOutput,
    decrypt_amount,
};
pub use validator::validate_transaction;
pub use recovery::{RecoveryMeta, validate_recovery_extra};
