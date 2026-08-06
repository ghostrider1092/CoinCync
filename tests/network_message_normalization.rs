use std::sync::Arc;

use coincync::colony::stick_insect::SIZE_BUCKETS;
use coincync::network::framing::{MessageFramer, HEADER_SIZE};
use coincync::network::protocol::{MessageType, TxsMessage};
use coincync::network::TrafficShaper;
use coincync::primitives::Amount;
use coincync::transaction::{Transaction, TxType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn real_transaction_round_trip_uses_bucket_sized_frame() {
    let magic = [0x43, 0x59, 0x4e, 0x43];
    let transaction = Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        inputs: vec![],
        outputs: vec![],
        fee: Amount::ZERO,
        range_proof: vec![0x41; 192],
        extra: b"normalized transaction".to_vec(),
    };
    let message = TxsMessage {
        transactions: vec![transaction],
    };
    let payload = borsh::to_vec(&message).unwrap();
    let shaper = Arc::new(TrafficShaper::default_enabled());

    let (sender_stream, mut wire_reader) = tokio::io::duplex(4096);
    let (sender_reader, sender_writer) = tokio::io::split(sender_stream);
    let mut sender =
        MessageFramer::new_normalized(sender_reader, sender_writer, magic, Arc::clone(&shaper));
    sender
        .write_message(MessageType::Txs as u8, &payload)
        .await
        .unwrap();

    let mut header = [0u8; HEADER_SIZE];
    wire_reader.read_exact(&mut header).await.unwrap();
    let wire_payload_len = u32::from_le_bytes(header[5..9].try_into().unwrap()) as usize;
    let mut wire_payload = vec![0u8; wire_payload_len];
    wire_reader.read_exact(&mut wire_payload).await.unwrap();
    let mut wire = header.to_vec();
    wire.extend_from_slice(&wire_payload);
    assert!(
        SIZE_BUCKETS.contains(&wire.len())
            || wire.len() % SIZE_BUCKETS[SIZE_BUCKETS.len() - 1] == 0
    );

    let (receiver_stream, mut wire_writer) = tokio::io::duplex(4096);
    let (receiver_reader, receiver_writer) = tokio::io::split(receiver_stream);
    let mut receiver =
        MessageFramer::new_normalized(receiver_reader, receiver_writer, magic, shaper);
    wire_writer.write_all(&wire).await.unwrap();
    let (msg_type, recovered) = receiver.read_message_timeout().await.unwrap();

    assert_eq!(msg_type, MessageType::Txs as u8);
    assert_eq!(recovered, payload);
    let decoded: TxsMessage = borsh::from_slice(&recovered).unwrap();
    assert_eq!(decoded.transactions.len(), 1);
    assert_eq!(decoded.transactions[0].extra, b"normalized transaction");
}
