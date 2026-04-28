//! Fuzz target for block parsing
//!
//! Tests that block deserialization handles malformed inputs without panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use coincync::consensus::Block;

    // Try to parse block from bytes
    // This should not panic regardless of input
    if let Ok(block) = borsh::from_slice::<Block>(data) {
        // If parsing succeeds, verify basic properties don't panic
        let _ = block.hash();
        let _ = block.height();
        let _ = block.size();
        let _ = block.header.timestamp;
        let _ = block.header.version;
        let _ = block.transactions.len();

        // Verify transaction hashes
        for tx in &block.transactions {
            let _ = tx.hash();
        }

        // Try to serialize back
        let _ = borsh::to_vec(&block);
    }
});
