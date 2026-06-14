//! TCP keepalive for P2P connections — Cycle 02 Finding #1 fix.
//!
//! **The bug:** outbound TCP connections to peers behind residential
//! NATs (consumer routers, CGNAT) silently died after the router's
//! idle state timeout (typically 60-300s) expired. With CoinCync's
//! P2P traffic pattern of "GetHeaders every ~500ms during IBD + bursts
//! during block relay + long quiet periods otherwise," the gaps between
//! traffic could exceed the router's idle threshold, the router would
//! drop its NAT entry, the next packet would be unrouteable, and the
//! Noise stream would close with "EOF" — the operator-visible flap.
//!
//! Cycle 02 measured ~75s average flap interval on a stable operator-
//! to-barns IPv6 link. Loopback IPv6 test with the same binaries
//! produced 0 disconnects in 145+ seconds, confirming the cause is
//! NAT/router state expiration, not application-layer.
//!
//! **The fix:** set `TCP_KEEPIDLE` on every P2P socket (both
//! outbound and inbound) so the OS sends keepalive probes before the
//! NAT timeout fires, refreshing the router's state and preventing
//! the silent close.
//!
//! See `docs/crucible/cycle-02/finding-01-peer-flap.md` for the full
//! investigation.

use std::time::Duration;
use tokio::net::TcpStream;

/// Idle threshold before the OS starts sending keepalive probes.
///
/// **Calibration history:**
///   - 45s initial fix: Cycle 02 empirical test showed ~4x
///     improvement (75s pre-fix flap → 320s before first
///     disconnect for the protected side) but did not fully
///     eliminate flaps.
///   - 25s retighten attempt: did not show measurable
///     improvement over 45s within a single 6-min window;
///     possibly slight regression on the per-peer numbers.
///     Reverted to 45s as the cleaner baseline.
///
/// **Why this isn't 0 flaps:**
/// The keepalive helps only the side that has the fix. A peer
/// running an older binary still flaps from their own NAT
/// expiration; we can't fix that from our side. The proper
/// full fix is application-layer Ping/Pong — traffic the peer
/// will route as P2P messages, not keepalive frames — which
/// both sides exchange and which both routers see as "real
/// traffic." Tracked as a v1.0.15 follow-up.
pub const P2P_KEEPALIVE_IDLE_SECS: u64 = 45;

/// Time between keepalive probes after the first one fires.
///
/// Unix-only — on Windows the OS picks its own probe interval. 15s
/// means four probes inside a minute of unresponsiveness before TCP
/// gives up; matches a reasonable "the peer is really gone, drop
/// them" detection rate.
pub const P2P_KEEPALIVE_INTERVAL_SECS: u64 = 15;

/// Apply P2P keepalive sockopts to a TCP stream.
///
/// Idempotent and safe to call on both outbound (post-`connect`) and
/// inbound (post-`accept`) streams. Returns `io::Error` if the
/// underlying `setsockopt` fails — caller should log + continue
/// rather than reject the connection, since a missing keepalive
/// degrades the connection to "may flap" rather than breaking it
/// outright.
pub fn apply_p2p_keepalive(stream: &TcpStream) -> std::io::Result<()> {
    let sock = socket2::SockRef::from(stream);

    // The `with_interval` builder is supported on Linux + FreeBSD +
    // Windows but not on all platforms; setting it on platforms that
    // don't support it is a no-op via the underlying socket2 crate,
    // so we set it unconditionally.
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(P2P_KEEPALIVE_IDLE_SECS))
        .with_interval(Duration::from_secs(P2P_KEEPALIVE_INTERVAL_SECS));

    sock.set_tcp_keepalive(&ka)
}
