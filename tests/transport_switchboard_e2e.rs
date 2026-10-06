//! E2E: the REAL message-framing layer carries protocol frames over a
//! Switchboard-wired `NetStream` pair — no sockets. This proves the E2 transport
//! seam + the F2 switchboard together carry actual framed traffic through the
//! production `MessageFramer`, which is the mechanism the full-node DST
//! scenarios will rely on.

use std::net::SocketAddr;

use coincync::network::framing::MessageFramer;
use coincync::network::switchboard::{DialError, Switchboard};
use tokio::io::split;

fn addr(n: u16) -> SocketAddr {
    SocketAddr::from(([10, 0, 0, 1], n))
}

const MAGIC: [u8; 4] = [0xC0, 0x1C, 0x9C, 0x01];

#[tokio::test]
async fn framed_messages_flow_both_ways_over_the_switchboard() {
    let sb = Switchboard::new();
    let a = addr(1);
    let b = addr(2);
    let mut b_inbox = sb.listen(b);

    // a dials b; b accepts.
    let dialer = sb.connect(a, b).expect("dial a->b");
    let accepted = b_inbox.recv().await.expect("b accepts");

    // Wrap each end in the real production framer.
    let (ar, aw) = split(dialer);
    let (br, bw) = split(accepted);
    let mut fa = MessageFramer::new(ar, aw, MAGIC);
    let mut fb = MessageFramer::new(br, bw, MAGIC);

    // a -> b (Ping = 2; the framer validates the type, so use a real one)
    const PING: u8 = 2;
    const PONG: u8 = 3;
    let payload = b"hello-consensus".to_vec();
    fa.write_message(PING, &payload).await.expect("a writes");
    let (ty, got) = fb.read_message().await.expect("b reads");
    assert_eq!(ty, PING);
    assert_eq!(got, payload);

    // b -> a (Pong = 3)
    fb.write_message(PONG, b"ack").await.expect("b writes");
    let (ty2, got2) = fa.read_message().await.expect("a reads");
    assert_eq!(ty2, PONG);
    assert_eq!(got2, b"ack");
}

#[tokio::test]
async fn a_partitioned_edge_cannot_carry_frames() {
    let sb = Switchboard::new();
    let a = addr(1);
    let b = addr(2);
    let _b_inbox = sb.listen(b);

    sb.partition(a, b);
    // The dial itself fails — there is no stream to frame over. (NetStream has
    // no PartialEq/Debug, so match the variant rather than assert_eq.)
    assert!(matches!(sb.connect(a, b), Err(DialError::Partitioned)));

    // Healing restores delivery.
    sb.heal(a, b);
    assert!(sb.connect(a, b).is_ok());
}
