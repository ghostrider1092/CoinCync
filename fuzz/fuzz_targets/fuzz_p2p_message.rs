//! Fuzz target for P2P message parsing
//!
//! Tests that P2P message deserialization handles malformed inputs without panicking.
//! This is critical for DoS resistance — a malformed message from a peer must not
//! crash the node.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use coincync::network::protocol::{Message, MessageType};

    // Try to parse as a raw P2P message
    if data.len() >= 12 {
        // Try message type parsing
        let _ = MessageType::try_from(data[0]);

        // Try full message parsing
        let _ = Message::from_bytes(data);
    }

    // Try CLSAG signature parsing (common attack vector)
    let _ = coincync::crypto::ClsagSignature::from_bytes(data);

    // Try block deserialization
    let _ = borsh::from_slice::<coincync::consensus::Block>(data);

    // Try range proof parsing
    let _ = coincync::crypto::RangeProof::from_bytes(data);
});
