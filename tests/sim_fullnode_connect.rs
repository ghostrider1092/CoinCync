//! F2 full-node DST — first scenario: two REAL `P2PNode`s connect to each other
//! over the in-memory Switchboard, with NO sockets. This proves the whole node
//! stack (peer_manager accept + dial, the Noise handshake, message framing) runs
//! on the simulation transport — the capstone of the E2/F2 wiring.
//!
//! The deterministic partition / clock-poison / reorg-strand scenarios build on
//! this; they additionally need E1's `advance_sim_mono` to drive the node's
//! internal timeouts (still real-`Instant` here), so this scenario asserts
//! connectivity under a real-time bound rather than virtual-time determinism.

use std::sync::Arc;
use std::time::Duration;

use coincync::chain::Blockchain;
use coincync::mempool::SharedMempool;
use coincync::network::node::{NodeConfig, NodeEvent, P2PNode};
use coincync::network::switchboard::Switchboard;

fn sim_node(sb: &Arc<Switchboard>, addr: &str) -> (P2PNode, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::default();
    config.listen_addr = addr.parse().unwrap();
    config.data_dir = dir.path().to_path_buf();
    config.upnp = false;

    let chain = Arc::new(Blockchain::new());
    chain.init_genesis().expect("genesis");

    let mut node = P2PNode::new(config, chain, SharedMempool::new());
    node.set_switchboard(Arc::clone(sb));
    (node, dir)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_real_nodes_connect_over_the_switchboard() {
    // Distinct synthetic addresses (non-loopback, distinct ports → never a
    // self-dial); both nodes live on the same Switchboard, no real sockets.
    let sb = Arc::new(Switchboard::new());
    let (node_a, _da) = sim_node(&sb, "10.0.0.1:29081");
    let (node_b, _db) = sim_node(&sb, "10.0.0.2:29082");

    // A knows B's address, so A's outbound connector will dial B.
    node_a
        .add_seed_address("10.0.0.2:29082".parse().unwrap())
        .await;
    let mut a_events = node_a.subscribe();

    // B listens first (registers its Switchboard accept queue), then A dials.
    node_b.start().await.expect("B starts");
    node_a.start().await.expect("A starts");

    // A's connector ticks immediately; the Noise handshake runs over the
    // in-memory pipe. Bound the wait so a failure can't hang CI.
    let connected = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match a_events.recv().await {
                Ok(NodeEvent::PeerConnected(_)) => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    })
    .await;

    node_a.stop().await;
    node_b.stop().await;

    assert!(
        matches!(connected, Ok(true)),
        "A must connect to B over the Switchboard with no sockets"
    );
}
