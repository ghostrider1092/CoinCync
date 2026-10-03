//! Transport seam (correctness-program enabler **E2**): the one type peer
//! byte-streams flow through, so the deterministic-simulation harness can
//! substitute an in-memory pipe for a real socket and run the REAL node with no
//! network at all. Pairs with the clock (E1, [`crate::clock`]) and non-security
//! RNG (E3, [`crate::rng`]) seams — together they let a failing full-node
//! scenario (partition stall, reorg strand) replay deterministically.
//!
//! `NetStream` is a thin enum over a production [`TcpStream`] and a simulation
//! [`DuplexStream`]; both implement `AsyncRead`/`AsyncWrite`, so any code holding
//! a `NetStream` is oblivious to which it has.
//!
//! SCOPE: this increment adds ONLY the type and its in-memory constructor. The
//! call-site rewiring (`peer.rs` / `node/connection.rs` and the dial & accept
//! paths from `TcpStream` → `NetStream`) is a follow-up, so this lands isolated
//! and the live testnet path is byte-for-byte unchanged.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::net::TcpStream;

/// A peer byte-stream: a real TCP socket in production, or an in-memory duplex
/// pipe under simulation. The address is carried explicitly because a simulated
/// pipe has no OS-level `peer_addr()`.
pub enum NetStream {
    /// Production: a real connected socket.
    Tcp(TcpStream),
    /// Simulation: one end of an in-memory pipe, plus the synthetic address of
    /// the peer on the other end.
    Mem(DuplexStream, SocketAddr),
}

impl NetStream {
    /// Wrap a real connected socket (production path).
    pub fn tcp(stream: TcpStream) -> Self {
        NetStream::Tcp(stream)
    }

    /// Create a connected in-memory pair for the harness. `a` reads exactly what
    /// `b` writes and vice-versa; each end is tagged with the address of the
    /// peer it is talking to, so `peer_addr()` is meaningful on both. `buf` is
    /// the per-direction pipe capacity in bytes.
    pub fn mem_pair(
        a_addr: SocketAddr,
        b_addr: SocketAddr,
        buf: usize,
    ) -> (NetStream, NetStream) {
        let (a, b) = tokio::io::duplex(buf);
        // `a`'s peer lives at `b_addr`; `b`'s peer lives at `a_addr`.
        (NetStream::Mem(a, b_addr), NetStream::Mem(b, a_addr))
    }

    /// The peer's address. Real sockets query the OS; simulated pipes return the
    /// synthetic address assigned at creation.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self {
            NetStream::Tcp(s) => s.peer_addr(),
            NetStream::Mem(_, addr) => Ok(*addr),
        }
    }

    /// Whether this is a simulated stream. For assertions/metrics only — MUST
    /// NOT gate any consensus or validation decision.
    pub fn is_simulated(&self) -> bool {
        matches!(self, NetStream::Mem(..))
    }

    /// Set `TCP_NODELAY` (disable Nagle) on a real socket. A no-op for an
    /// in-memory sim pipe, which has no Nagle buffering to disable — so callers
    /// on the connection path can treat both uniformly.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match self {
            NetStream::Tcp(s) => s.set_nodelay(nodelay),
            NetStream::Mem(..) => Ok(()),
        }
    }
}

impl AsyncRead for NetStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            NetStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            NetStream::Mem(s, _) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for NetStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            NetStream::Tcp(s) => Pin::new(s).poll_write(cx, data),
            NetStream::Mem(s, _) => Pin::new(s).poll_write(cx, data),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            NetStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            NetStream::Mem(s, _) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            NetStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            NetStream::Mem(s, _) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn addr(n: u8) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, n], 29080))
    }

    #[tokio::test]
    async fn mem_pair_round_trips_both_directions_and_reports_synthetic_addr() {
        let (mut a, mut b) = NetStream::mem_pair(addr(1), addr(2), 64 * 1024);
        assert!(a.is_simulated() && b.is_simulated());
        // Each end knows the peer it is talking to.
        assert_eq!(a.peer_addr().unwrap(), addr(2));
        assert_eq!(b.peer_addr().unwrap(), addr(1));

        // a -> b
        a.write_all(b"hello").await.unwrap();
        a.flush().await.unwrap();
        let mut buf = [0u8; 5];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        // b -> a
        b.write_all(b"world").await.unwrap();
        b.flush().await.unwrap();
        let mut buf2 = [0u8; 5];
        a.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"world");
    }

    #[tokio::test]
    async fn shutdown_closes_the_peer_read() {
        let (mut a, mut b) = NetStream::mem_pair(addr(1), addr(2), 1024);
        a.write_all(b"last").await.unwrap();
        a.shutdown().await.unwrap();
        drop(a);
        // After the writer shuts down and drops, the reader drains then sees EOF.
        let mut out = Vec::new();
        b.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"last");
    }
}
