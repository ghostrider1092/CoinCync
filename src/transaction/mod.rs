//! # Transaction Module for CoinCync 1.0
//!
//! Privacy-preserving transactions with:
//! - Ring signatures (CLSAG) for sender privacy
//! - Stealth addresses for receiver privacy
//! - Bulletproofs+ for amount privacy
//! - Transaction fragmentation for large payments

mod builder;
pub mod payment_id;
pub mod recovery;
pub mod signer;
mod types;
mod validator;

#[allow(deprecated)]
// SimpleTransactionBuilder is itself deprecated; re-export kept for the deprecated send.rs path
pub use builder::{
    decrypt_amount, DecoyOutput, Recipient, SimpleTransactionBuilder, SpendableInput,
    TransactionBuilder,
};
/// Value-revealing (zero-blinding, public-amount) output builder — used by the
/// unshield assembly to materialize pool-exit value on the transparent side.
#[cfg(feature = "libspark-ffi")]
pub use builder::build_revealed_output;
pub use recovery::{validate_recovery_extra, RecoveryMeta};
pub use signer::{ClsagSignRequest, OneTimeKeyRef, SoftwareSigner, TxSigner};
pub use types::{RingMemberRef, SigningInputView, Transaction, TxInput, TxOutput, TxType};
pub use validator::validate_transaction;
