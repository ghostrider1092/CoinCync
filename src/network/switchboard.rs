//! In-memory connection switchboard for deterministic simulation (F2, built on
//! the E2 transport seam). It is the sim-side counterpart to TCP: virtual nodes
//! "listen" on synthetic [`SocketAddr`]s and "dial" each other, and the
//! switchboard wires each dial into a connected [`NetStream`] pair — unless a
//! partition forbids that edge, which is how a network split is expressed.
//!
//! This lets the real node's connection path (which now speaks `NetStream`, not
//! `TcpStream`) run with no sockets at all. Delivery ordering across the pipe is
//! deterministic; pair with the clock (E1) and RNG (E3) seams to make an entire
//! multi-node scenario replay identically.
//!
//! SCOPE: this is the wiring primitive. Threading a `Switchboard` into node
//! startup (so `peer_manager` dials and `node` accepts through it instead of
//! `TcpStream::connect` / `TcpListener`) and the full-node DST scenarios
//! (partition-stall, reorg-strand, clock-poison) are the follow-up — they also
//! need E1's `advance_sim_mono` to drive timeouts, so they land once E1+E2 are
//! merged.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Mutex;

use tokio::sync::mpsc;

use super::transport::NetStream;

/// Error dialing through the switchboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialError {
    /// The `(from, to)` edge is partitioned.
    Partitioned,
    /// No node is listening on `to`.
    NoListener,
}

impl std::fmt::Display for DialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DialError::Partitioned => write!(f, "edge is partitioned"),
            DialError::NoListener => write!(f, "no listener at destination"),
        }
    }
}
impl std::error::Error for DialError {}

/// Per-direction pipe capacity for a simulated connection.
const DEFAULT_PIPE_BYTES: usize = 256 * 1024;

struct Inner {
    /// Each listening node's inbound-connection queue, keyed by its address.
    listeners: HashMap<SocketAddr, mpsc::UnboundedSender<NetStream>>,
    /// Unordered blocked edges; an edge `{a,b}` blocks dials BOTH ways.
    partitions: HashSet<(SocketAddr, SocketAddr)>,
    pipe_bytes: usize,
}

/// A deterministic in-memory replacement for TCP dial/accept. Cloneable-by-`Arc`
/// at the call sites; internally `Mutex`-guarded (sim setup is low-frequency).
pub struct Switchboard {
    inner: Mutex<Inner>,
}

/// Normalize an edge so `{a,b}` and `{b,a}` hash the same.
fn edge(a: SocketAddr, b: SocketAddr) -> (SocketAddr, SocketAddr) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

impl Switchboard {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                listeners: HashMap::new(),
                partitions: HashSet::new(),
                pipe_bytes: DEFAULT_PIPE_BYTES,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Register `addr` as listening; returns the receiver its accept-loop awaits
    /// for inbound `NetStream`s. Re-listening on the same addr replaces the queue.
    pub fn listen(&self, addr: SocketAddr) -> mpsc::UnboundedReceiver<NetStream> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.lock().listeners.insert(addr, tx);
        rx
    }

    /// Stop listening on `addr` (its accept queue closes).
    pub fn unlisten(&self, addr: SocketAddr) {
        self.lock().listeners.remove(&addr);
    }

    /// Dial from `from` to `to`. On success the dialer gets its `NetStream`
    /// endpoint and the listener at `to` receives the other end on its accept
    /// queue. Fails if the edge is partitioned or nothing listens at `to`.
    pub fn connect(&self, from: SocketAddr, to: SocketAddr) -> Result<NetStream, DialError> {
        let inner = self.lock();
        if inner.partitions.contains(&edge(from, to)) {
            return Err(DialError::Partitioned);
        }
        let pipe = inner.pipe_bytes;
        let listener = inner.listeners.get(&to).ok_or(DialError::NoListener)?.clone();
        // dialer_end.peer_addr() == to; listener_end.peer_addr() == from.
        let (dialer_end, listener_end) = NetStream::mem_pair(from, to, pipe);
        if listener.send(listener_end).is_err() {
            // The listener was dropped between the lookup and the send.
            return Err(DialError::NoListener);
        }
        Ok(dialer_end)
    }

    /// Block the `{a,b}` edge in both directions (a network partition).
    pub fn partition(&self, a: SocketAddr, b: SocketAddr) {
        self.lock().partitions.insert(edge(a, b));
    }

    /// Heal a previously-partitioned edge.
    pub fn heal(&self, a: SocketAddr, b: SocketAddr) {
        self.lock().partitions.remove(&edge(a, b));
    }

    /// Whether the `{a,b}` edge is currently partitioned.
    pub fn is_partitioned(&self, a: SocketAddr, b: SocketAddr) -> bool {
        self.lock().partitions.contains(&edge(a, b))
    }
}

impl Default for Switchboard {
    fn default() -> Self {
        Self::new()
    }
}

/// The node's inbound-connection source: a real `TcpListener` in production, or
/// a [`SimListener`] under simulation. `spawn_listener_acceptor` holds one of
/// these and awaits `accept()` without caring which — so the real accept loop
/// runs over the Switchboard with no sockets (F2 node-wiring, accept side).
pub enum Acceptor {
    /// Production: a bound TCP listener.
    Tcp(tokio::net::TcpListener),
    /// Simulation: this node's Switchboard inbound queue.
    Sim(SimListener),
}

impl Acceptor {
    /// Await the next inbound connection as a [`NetStream`] + peer address.
    /// The TCP arm wraps the accepted socket (byte-identical to the prior direct
    /// `TcpListener::accept` + `NetStream::tcp`); the sim arm surfaces a closed
    /// accept queue as a `BrokenPipe` error so the caller's loop ends cleanly.
    pub async fn accept(&mut self) -> std::io::Result<(NetStream, SocketAddr)> {
        match self {
            Acceptor::Tcp(l) => l.accept().await.map(|(s, a)| (NetStream::tcp(s), a)),
            Acceptor::Sim(l) => l.accept().await.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "switchboard accept queue closed",
                )
            }),
        }
    }
}

/// Sim-side dial handle for one node: dials always originate from `local`, so
/// this mirrors "a node's outbound connector" (the prod analogue being
/// `TcpStream::connect` via the proxy). Cheap to clone (shares the `Arc`).
#[derive(Clone)]
pub struct SimConnector {
    switchboard: std::sync::Arc<Switchboard>,
    local: SocketAddr,
}

impl SimConnector {
    pub fn new(switchboard: std::sync::Arc<Switchboard>, local: SocketAddr) -> Self {
        Self { switchboard, local }
    }

    /// Dial `to`, yielding a connected [`NetStream`] (or a [`DialError`] if the
    /// edge is partitioned / nothing listens). Mirrors an outbound TCP connect.
    pub fn connect(&self, to: SocketAddr) -> Result<NetStream, DialError> {
        self.switchboard.connect(self.local, to)
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

/// The node's outbound dialer: real TCP (via the proxy layer) in production, or
/// a [`SimConnector`] under simulation. The outbound connector holds one of these
/// and calls `connect()` without caring which — the dial half of running the real
/// node over the Switchboard (symmetric with [`Acceptor`]).
pub enum Connector {
    /// Production: dial over TCP (honoring the configured proxy), the exact path
    /// `proxy::connect_peer` + `NetStream::tcp` took before.
    Tcp {
        proxy: Option<crate::config::ProxyConfig>,
        timeout: std::time::Duration,
    },
    /// Simulation: dial through the Switchboard.
    Sim(SimConnector),
}

impl Connector {
    /// Dial `addr`, yielding a connected [`NetStream`].
    pub async fn connect(&self, addr: SocketAddr) -> crate::error::Result<NetStream> {
        match self {
            Connector::Tcp { proxy, timeout } => {
                crate::network::proxy::connect_peer(addr, proxy.as_ref(), *timeout)
                    .await
                    .map(NetStream::tcp)
            }
            Connector::Sim(c) => c
                .connect(addr)
                .map_err(|e| crate::error::Error::ConnectionFailed(e.to_string())),
        }
    }
}

/// Sim-side accept handle for one node: awaits inbound connections the way a
/// `TcpListener` does, returning `(stream, peer_addr)`. The prod analogue is
/// `TcpListener::accept`.
pub struct SimListener {
    addr: SocketAddr,
    rx: mpsc::UnboundedReceiver<NetStream>,
}

impl SimListener {
    /// Begin listening on `addr` through `switchboard`.
    pub fn bind(switchboard: &Switchboard, addr: SocketAddr) -> Self {
        Self {
            addr,
            rx: switchboard.listen(addr),
        }
    }

    /// Await the next inbound connection. Returns `None` once the switchboard
    /// stops listening on this address (the accept queue closed).
    pub async fn accept(&mut self) -> Option<(NetStream, SocketAddr)> {
        let stream = self.rx.recv().await?;
        let peer = stream.peer_addr().unwrap_or(self.addr);
        Some((stream, peer))
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn addr(n: u16) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, 1], n))
    }

    #[tokio::test]
    async fn dial_wires_a_connected_pair_with_correct_peer_addrs() {
        let sb = Switchboard::new();
        let a = addr(1);
        let b = addr(2);
        let mut b_inbox = sb.listen(b);

        let mut dialer = sb.connect(a, b).expect("dial");
        let mut accepted = b_inbox.try_recv().expect("b received the inbound conn");

        // Addresses: the dialer's peer is b; the accepted conn's peer is a.
        assert_eq!(dialer.peer_addr().unwrap(), b);
        assert_eq!(accepted.peer_addr().unwrap(), a);

        // Bytes flow both ways.
        dialer.write_all(b"ping").await.unwrap();
        dialer.flush().await.unwrap();
        let mut buf = [0u8; 4];
        accepted.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        accepted.write_all(b"pong").await.unwrap();
        accepted.flush().await.unwrap();
        let mut buf2 = [0u8; 4];
        dialer.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"pong");
    }

    #[test]
    fn partition_blocks_the_edge_both_ways_until_healed() {
        let sb = Switchboard::new();
        let a = addr(1);
        let b = addr(2);
        let _a_inbox = sb.listen(a);
        let _b_inbox = sb.listen(b);

        sb.partition(a, b);
        assert!(sb.is_partitioned(a, b) && sb.is_partitioned(b, a));
        // NetStream has no PartialEq/Debug, so match the error variant rather
        // than assert_eq on the Result.
        assert!(matches!(sb.connect(a, b), Err(DialError::Partitioned)));
        assert!(matches!(sb.connect(b, a), Err(DialError::Partitioned))); // both ways

        sb.heal(a, b);
        assert!(!sb.is_partitioned(a, b));
        assert!(sb.connect(a, b).is_ok());
    }

    #[test]
    fn dialing_a_non_listener_fails() {
        let sb = Switchboard::new();
        assert!(matches!(
            sb.connect(addr(1), addr(9)),
            Err(DialError::NoListener)
        ));
    }

    #[tokio::test]
    async fn connector_and_listener_mirror_tcp_connect_accept() {
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let sb = Arc::new(Switchboard::new());
        let a = addr(1);
        let b = addr(2);

        // b listens; a has a connector bound to its own address.
        let mut b_listener = SimListener::bind(&sb, b);
        let a_conn = SimConnector::new(Arc::clone(&sb), a);
        assert_eq!(a_conn.local_addr(), a);
        assert_eq!(b_listener.local_addr(), b);

        // a dials b; b accepts — just like TcpStream::connect / TcpListener::accept.
        let mut dialer = a_conn.connect(b).expect("connect");
        let (mut accepted, peer) = b_listener.accept().await.expect("accept");
        assert_eq!(peer, a, "accept reports the dialer's address");

        dialer.write_all(b"frame").await.unwrap();
        dialer.flush().await.unwrap();
        let mut buf = [0u8; 5];
        accepted.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"frame");
    }
}
