//! F2 multi-node scenario: a sender reaches its peers over the Switchboard and
//! exchanges framed protocol messages through the REAL `MessageFramer`; a
//! partition makes one peer unreachable (the dial fails), and healing restores
//! it. This is the three-node, partition-aware step up from the two-node e2e
//! test — the transport-level groundwork the full-node DST scenarios build on
//! (those add the real node + E1-driven timeouts).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use coincync::network::framing::MessageFramer;
use coincync::network::switchboard::{DialError, SimConnector, SimListener, Switchboard};
use tokio::io::split;

fn addr(n: u8) -> SocketAddr {
    SocketAddr::from(([10, 0, 0, n], 29080))
}

const MAGIC: [u8; 4] = [0xC0, 0x1C, 0x9C, 0x02];
const PING: u8 = 2; // MessageType::Ping

#[tokio::test]
async fn partition_isolates_a_peer_then_heal_restores_delivery() {
    let sb = Arc::new(Switchboard::new());
    let (a, b, c) = (addr(1), addr(2), addr(3));

    let mut b_in = SimListener::bind(&sb, b);
    let mut c_in = SimListener::bind(&sb, c);
    let a_conn = SimConnector::new(Arc::clone(&sb), a);

    // A<->C partitioned from the start: A reaches B, not C.
    sb.partition(a, c);

    // ── A → B delivers a framed message ──────────────────────────────
    let a_side = a_conn.connect(b).expect("A dials B");
    let (b_side, peer) = b_in.accept().await.expect("B accepts");
    assert_eq!(peer, a, "B sees the connection as coming from A");

    let (ar, aw) = split(a_side);
    let (br, bw) = split(b_side);
    let mut a_framer = MessageFramer::new(ar, aw, MAGIC);
    let mut b_framer = MessageFramer::new(br, bw, MAGIC);

    a_framer.write_message(PING, b"block-ann").await.expect("A writes");
    let (ty, payload) = b_framer.read_message().await.expect("B reads");
    assert_eq!(ty, PING);
    assert_eq!(payload, b"block-ann");

    // ── A ✗ C while partitioned ──────────────────────────────────────
    assert!(
        matches!(a_conn.connect(c), Err(DialError::Partitioned)),
        "A must not reach C across the partition"
    );
    // C received no inbound connection (bounded wait, so the test can't hang).
    let got = tokio::time::timeout(Duration::from_millis(50), c_in.accept()).await;
    assert!(got.is_err(), "C must see no connection while partitioned");

    // ── heal → A reaches C ───────────────────────────────────────────
    sb.heal(a, c);
    let a_to_c = a_conn.connect(c).expect("A dials C after heal");
    let (c_side, cpeer) = c_in.accept().await.expect("C accepts after heal");
    assert_eq!(cpeer, a);

    let (acr, acw) = split(a_to_c);
    let (ccr, ccw) = split(c_side);
    let mut a_c_framer = MessageFramer::new(acr, acw, MAGIC);
    let mut c_framer = MessageFramer::new(ccr, ccw, MAGIC);
    a_c_framer.write_message(PING, b"catch-up").await.expect("A writes C");
    let (ty2, p2) = c_framer.read_message().await.expect("C reads");
    assert_eq!(ty2, PING);
    assert_eq!(p2, b"catch-up");
}
