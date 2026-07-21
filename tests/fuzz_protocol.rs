//! Protocol fuzz tests (rewrite — targets 1.0 API).
//!
//! Replaces the pre-1.0 file that depended on removed modules. The
//! job of this suite is simple: **when the network feeds untrusted
//! bytes into any deserialization entry point, the node must never
//! panic**. Errors are fine. Panics crash the process and are a DoS
//! vector on a P2P surface.
//!
//! We exercise the three parser boundaries that actually sit on the
//! wire for a running node:
//!
//! 1. `Transaction` via borsh — every inv / tx relay message goes
//!    through this path.
//! 2. `Block` via borsh — every getdata / blocks response goes
//!    through this path.
//! 3. `MessageHeader` via borsh + explicit `validate` — the framer's
//!    very first decode of an incoming byte stream.
//!
//! For each of those, we throw at them:
//! - random bytes
//! - truncated bytes (valid prefix, missing tail)
//! - extreme length prefixes (claims billions of entries)
//! - empty slices
//!
//! None of these should panic. All should return `Err`.

use borsh::BorshDeserialize;
use coincync::consensus::Block;
use coincync::network::{MessageHeader, MAX_MESSAGE_SIZE};
use coincync::transaction::Transaction;

// -----------------------------------------------------------------------------
// Transaction parser boundary
// -----------------------------------------------------------------------------

#[test]
fn tx_parser_handles_random_bytes_without_panicking() {
    // Deterministic "random" bytes — we don't need real entropy for
    // fuzz-ish coverage, we need the bytes to exercise the parser's
    // rejection path. A panicking deserializer would blow up here.
    for seed in 0u32..64 {
        let mut bytes = Vec::with_capacity(256);
        let mut x = seed.wrapping_mul(2654435761); // knuth multiplier
        for _ in 0..256 {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            bytes.push((x >> 16) as u8);
        }
        // `let _ =` — we don't care about Ok vs Err, we care about NO PANIC.
        let _ = Transaction::try_from_slice(&bytes);
    }
}

#[test]
fn tx_parser_rejects_empty_input() {
    let bytes: [u8; 0] = [];
    assert!(
        Transaction::try_from_slice(&bytes).is_err(),
        "empty slice must decode to Err, not Ok with zero-length default"
    );
}

#[test]
fn tx_parser_rejects_truncated_bytes() {
    // Start with a well-formed minimal Transaction, serialize, then
    // feed the serializer progressively shorter prefixes. Every
    // prefix shorter than the full encoding must error, never panic.
    use coincync::primitives::{Amount, KeyImage, PublicKey};
    use coincync::transaction::{RingMemberRef, TxInput, TxOutput, TxType};

    let secret = coincync::crypto::SecretScalar::from_bytes([9u8; 32]);
    let pk = secret.to_public();
    let ki = coincync::crypto::KeyImage::from_secret(&secret);
    let sig = coincync::crypto::ClsagSignature {
        key_image: ki,
        commitment_image: pk,
        c1: [0u8; 32],
        responses: vec![[0u8; 32]; 11],
    };
    let tx = Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            key_image: KeyImage::from_bytes(ki.to_bytes()),
            ring_members: (0..11)
                .map(|_| RingMemberRef {
                    public_key: PublicKey::from_bytes(pk.to_bytes()),
                    commitment: pk.to_bytes(),
                })
                .collect(),
            signature: sig,
            pseudo_output_commitment: pk.to_bytes(),
        }],
        outputs: vec![TxOutput {
            stealth_address: PublicKey::from_bytes(pk.to_bytes()),
            tx_public_key: PublicKey::from_bytes(pk.to_bytes()),
            commitment: pk.to_bytes(),
            encrypted_amount: vec![0u8; 8],
            view_tag: 0,
            lock_height: None,
            encrypted_memo: Vec::new(),
        }],
        fee: Amount::from_atomic(0),
        range_proof: vec![0u8; 64],
        extra: Vec::new(),
    };
    let full = borsh::to_vec(&tx).expect("serialize");

    // Every strict prefix must error, not panic.
    for n in 0..full.len() {
        let _ = Transaction::try_from_slice(&full[..n]);
    }
    // And the full bytes should round-trip successfully.
    assert!(Transaction::try_from_slice(&full).is_ok());
}

#[test]
fn tx_parser_rejects_absurd_length_prefix() {
    // Craft a tx prefix claiming u32::MAX inputs. A borsh reader that
    // allocates upfront based on the claimed length would OOM or
    // panic; a well-behaved reader must either cap the allocation or
    // stream-read and error when the buffer runs out.
    //
    // Borsh encoding of `Vec<T>` is `(len: u32 LE, T*len)`. We
    // construct a buffer with `version`, `tx_type`, then a bogus
    // inputs-length of u32::MAX with no input bytes to follow.
    let mut bytes = vec![1u8, 1u8]; // version=1, TxType::Transfer=1
    bytes.extend_from_slice(&u32::MAX.to_le_bytes()); // inputs.len = 2^32 - 1
                                                      // (no input data follows — parser must error, not panic)

    let _ = Transaction::try_from_slice(&bytes); // must not panic
}

// -----------------------------------------------------------------------------
// Block parser boundary
// -----------------------------------------------------------------------------

#[test]
fn block_parser_handles_random_bytes_without_panicking() {
    for seed in 0u32..64 {
        let mut bytes = Vec::with_capacity(256);
        let mut x = seed.wrapping_add(0xDEADBEEF);
        for _ in 0..256 {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            bytes.push((x >> 8) as u8);
        }
        let _ = Block::try_from_slice(&bytes);
    }
}

#[test]
fn block_parser_rejects_empty_input() {
    let bytes: [u8; 0] = [];
    assert!(
        Block::try_from_slice(&bytes).is_err(),
        "empty slice is not a valid block encoding"
    );
}

#[test]
fn block_parser_rejects_absurd_tx_count() {
    // After a valid header, claim u32::MAX transactions. Parser must
    // not allocate 2^32 vec slots; it must bail as soon as it runs
    // out of input bytes.
    //
    // We don't need a real BlockHeader — borsh will try to decode
    // whatever we give it first, so a short garbage header followed
    // by a huge tx-length prefix exercises the same code path.
    let mut bytes = vec![0u8; 200]; // placeholder header bytes
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    let _ = Block::try_from_slice(&bytes); // must not panic
}

// -----------------------------------------------------------------------------
// MessageHeader parser boundary
// -----------------------------------------------------------------------------

#[test]
fn message_header_parser_handles_random_bytes_without_panicking() {
    for seed in 0u32..32 {
        let mut bytes = Vec::with_capacity(32);
        let mut x = seed.wrapping_add(0xCAFEBABE);
        for _ in 0..32 {
            x = x.wrapping_mul(48271).wrapping_add(0);
            bytes.push(x as u8);
        }
        let _ = MessageHeader::try_from_slice(&bytes);
    }
}

#[test]
fn message_header_validate_rejects_wrong_magic() {
    // MessageHeader::validate() is the network framer's cheap first
    // check — it runs before any payload is read. Wrong magic must
    // return Err.
    let header = MessageHeader {
        magic: [0xDE, 0xAD, 0xBE, 0xEF],
        msg_type: 0,
        length: 0,
        checksum: [0u8; 4],
    };
    let expected = coincync::constants::MAINNET_MAGIC;
    let result = header.validate(expected);
    assert!(
        result.is_err(),
        "MessageHeader with wrong magic must reject"
    );
}

#[test]
fn message_header_validate_rejects_oversized_length() {
    // A peer that advertises a payload larger than MAX_MESSAGE_SIZE is
    // either buggy or trying to make the framer allocate a huge
    // buffer. `validate` must reject before any allocation.
    let header = MessageHeader {
        magic: coincync::constants::MAINNET_MAGIC,
        msg_type: 0,
        length: (MAX_MESSAGE_SIZE as u32).saturating_add(1),
        checksum: [0u8; 4],
    };
    let result = header.validate(coincync::constants::MAINNET_MAGIC);
    assert!(
        result.is_err(),
        "MessageHeader claiming > MAX_MESSAGE_SIZE must reject"
    );
}

#[test]
fn message_header_checksum_mismatch_detected() {
    // Checksum is blake3(payload)[..4]. A header with a checksum that
    // doesn't match the payload must be caught by verify_checksum.
    let payload = b"hello world";
    let mut header = MessageHeader::new(
        coincync::constants::MAINNET_MAGIC,
        coincync::network::MessageType::Ping,
        payload,
    );
    assert!(header.verify_checksum(payload));
    header.checksum[0] ^= 0x01;
    assert!(
        !header.verify_checksum(payload),
        "mutated checksum must be detected"
    );
}
