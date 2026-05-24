//! Fuzz target for P2P message parsing
//!
//! Tests that P2P message deserialization handles malformed inputs without
//! panicking. This is critical for DoS resistance — a malformed message from
//! a peer must not crash the node.
//!
//! API drift note (2026-05-17): `Message::from_bytes` and
//! `ClsagSignature::from_bytes` / `RangeProof::from_bytes` were removed when
//! the IBD-wedge fix unified everything through `Message::new` +
//! `Message::to_bytes` (commit 03fb1af). The real parse surface is now
//! `borsh::from_slice::<TypedMessage>(payload)` for each typed message
//! variant downstream of `framing::read_message`. This target reflects the
//! current production attack surface.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use coincync::network::protocol::{
        AddrMessage, BlocksMessage, GetBlocksMessage, GetHeadersMessage,
        HeadersMessage, InvMessage, Message, MessageType, PingPongMessage,
        TxsMessage, VersionMessage,
    };

    // ── 1. MessageType discriminant parsing ──
    if !data.is_empty() {
        let _ = MessageType::try_from(data[0]);
    }

    // ── 2. Message constructor on arbitrary bytes (must not panic) ──
    // Production code never builds Messages from peer bytes via Message::new;
    // it constructs typed payloads + wraps. But fuzzing the constructor on
    // crafted lengths catches bound checks.
    if data.len() >= 4 {
        let magic = [data[0], data[1], data[2], data[3]];
        if let Ok(mt) = MessageType::try_from(data.get(4).copied().unwrap_or(0)) {
            let _ = Message::new(magic, mt, data.to_vec());
        }
    }

    // ── 3. Typed-payload borsh decoders — the REAL attacker surface ──
    // Every one of these is reachable from a peer-controlled payload byte
    // sequence (see src/network/node.rs ~2430..3488). A panic in any of them
    // is a remote-DoS vector.
    let _ = borsh::from_slice::<VersionMessage>(data);
    let _ = borsh::from_slice::<PingPongMessage>(data);
    let _ = borsh::from_slice::<GetHeadersMessage>(data);
    let _ = borsh::from_slice::<HeadersMessage>(data);
    let _ = borsh::from_slice::<GetBlocksMessage>(data);
    let _ = borsh::from_slice::<BlocksMessage>(data);
    let _ = borsh::from_slice::<InvMessage>(data);
    let _ = borsh::from_slice::<TxsMessage>(data);
    let _ = borsh::from_slice::<AddrMessage>(data);

    // ── 4. Block + key-image vec (also reachable from peer payloads) ──
    let _ = borsh::from_slice::<coincync::consensus::Block>(data);
    let _ = borsh::from_slice::<Vec<[u8; 32]>>(data);
});
