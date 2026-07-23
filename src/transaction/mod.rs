//! # Transaction Module for CoinCync 1.0
//!
//! Privacy-preserving transactions with:
//! - Ring signatures (CLSAG) for sender privacy
//! - Stealth addresses for receiver privacy
//! - Bulletproofs+ for amount privacy
//! - Transaction fragmentation for large payments

mod builder;
pub mod recovery;
mod types;
mod validator;

#[allow(deprecated)]
// SimpleTransactionBuilder is itself deprecated; re-export kept for the deprecated send.rs path
pub use builder::{
    decrypt_amount, DecoyOutput, Recipient, SimpleTransactionBuilder, SpendableInput,
    TransactionBuilder,
};
pub use recovery::{validate_recovery_extra, RecoveryMeta};
pub use types::{RingMemberRef, SigningInputView, Transaction, TxInput, TxOutput, TxType};
pub use validator::validate_transaction;
