//! Fuzz target for transaction parsing
//!
//! Tests that transaction deserialization handles malformed inputs without panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use coincync::transaction::Transaction;

    // Try to parse transaction from bytes
    // This should not panic regardless of input
    if let Ok(tx) = borsh::from_slice::<Transaction>(data) {
        // If parsing succeeds, verify basic properties don't panic
        let _ = tx.hash();
        let _ = tx.signing_hash();
        let _ = tx.is_coinbase();
        let _ = tx.inputs.len();
        let _ = tx.outputs.len();
        let _ = tx.fee.as_atomic();

        // Try to serialize back
        let _ = borsh::to_vec(&tx);
    }
});
