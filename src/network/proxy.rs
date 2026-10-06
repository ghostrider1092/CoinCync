//! # SOCKS5 Proxy Support
//!
//! Enables CoinCync to route P2P traffic through a SOCKS5 proxy.
//! This is commonly used for Tor (.onion) or I2P connectivity.
//!
//! **Important**: CoinCync does NOT bundle or manage Tor/I2P.
//! Users must install and run their own proxy software.
//!
//! ## Example: Using with Tor
//!
//! 1. Install Tor from https://www.torproject.org/
//! 2. Start the Tor service (default SOCKS5 port: 9050)
//! 3. Configure CoinCync to use the proxy:
//!    ```toml
//!    [p2p.proxy]
//!    enabled = true
//!    address = "127.0.0.1"
//!    port = 9050
//!    ```
//!
//! ## Privacy Note
//!
//! Using Tor provides IP-level anonymity but does NOT hide:
//! - Transaction graph analysis
//! - Timing correlations
//! - Amount patterns (mitigated by Bulletproofs)
//!
//! For maximum privacy, combine with subaddresses and careful OPSEC.
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `connect_peer` onion-only kill switch** — INVARIANT: when
//!   `proxy.onion_only` is set but the proxy is not active, ALL connection
//!   attempts are refused — there is no fallback branch that reaches direct
//!   `TcpStream::connect`. THREAT: CRIT-8 (clearnet fallback silently
//!   deanonymizing a Tor-only user by leaking their real IP to a peer).
//!   TESTS: (gap — no test in this module drives `connect_peer` with
//!   `onion_only: true` and an inactive proxy to assert the refusal; the
//!   branch is currently exercised only by code inspection).
//! - **§2 `connect_peer` direct-connection fallthrough (non-onion-only path)**
//!   — INVARIANT: direct `TcpStream::connect` is only reached when the
//!   proxy is absent/inactive AND `onion_only` is false, i.e. the user has
//!   not opted into Tor-only mode. THREAT: unintended clearnet connections
//!   for a user who believes proxy routing is mandatory. TESTS: (gap — no
//!   unit test in this module covers `connect_peer`'s direct-connect
//!   branch; would require a live/mock TCP listener).
//! - **§3 `connect_via_proxy`** — INVARIANT: only `ProxyType::Socks5` is
//!   accepted; SOCKS4/HTTP are rejected with `ConfigError` before any
//!   connection attempt. THREAT: silently downgrading to an unauthenticated
//!   or unsupported proxy protocol that doesn't provide the expected
//!   anonymity properties. TESTS: `test_socks5_config` (config-shape only;
//!   gap — no test exercises `connect_via_proxy` itself with a non-SOCKS5
//!   `ProxyType` to assert the rejection).
//! - **§4 `connect_onion`** — INVARIANT: connecting to a `.onion` address
//!   requires both an active proxy and `ProxyType::Socks5`, and the address
//!   must literally end in `.onion` before being forwarded. THREAT:
//!   attempting onion routing over a non-Tor-capable proxy, or forwarding a
//!   non-onion hostname through the onion-only code path (DNS-leak /
//!   protocol-confusion risk). TESTS: `test_is_onion_address` (validates the
//!   suffix-matching helper `connect_onion` relies on); (gap — no test
//!   drives `connect_onion` end-to-end against a live/mock proxy).
//! - **§5 `is_onion_address`** — INVARIANT: the `.onion` suffix check
//!   operates on the hostname portion only (after stripping a trailing
//!   `:port`), so `notreal.onion.example.com` style strings are not
//!   misclassified as onion addresses. THREAT: routing decisions (onion
//!   vs. clearnet) being spoofed by a crafted hostname, potentially
//!   sending onion-destined traffic clearnet or vice versa. TESTS:
//!   `test_is_onion_address`.
//! - **§6 `PeerTarget::parse`** — INVARIANT: `.onion` addresses are parsed
//!   via `rsplitn` on the LAST colon (correct for `<56-char-onion>.onion:port`,
//!   which contains no other colons), and non-onion input is parsed as a
//!   strict `SocketAddr`, with malformed input rejected rather than
//!   silently defaulting. THREAT: a malformed peer-address string being
//!   misinterpreted as a different (possibly attacker-chosen) host/port.
//!   TESTS: `test_peer_target_parse`.
//! - **§7 `ProxyConfig::url` / `credentials` (credential-leak prevention)**
//!   — INVARIANT: `url()` never includes the username/password even when
//!   set; credentials are only obtainable via the separate `credentials()`
//!   accessor. THREAT: proxy password leaking into logs or diagnostics that
//!   print the proxy URL. TESTS: `test_proxy_url`.

use crate::config::ProxyConfig;
use crate::error::{Error, Result};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

/// Connect to a peer, optionally through a SOCKS5 proxy
pub async fn connect_peer(
    target: SocketAddr,
    proxy: Option<&ProxyConfig>,
    timeout: std::time::Duration,
) -> Result<TcpStream> {
    match proxy {
        Some(cfg) if cfg.is_active() => connect_via_proxy(target, cfg, timeout).await,
        // SECURITY (CRIT-8): Kill switch - if onion_only is set but proxy is not active,
        // refuse ALL connections to prevent clearnet fallback that would leak the user's IP.
        // This is critical for users who depend on Tor for anonymity.
        Some(cfg) if cfg.onion_only => Err(Error::ConnectionFailed(
            "onion_only mode is enabled but proxy is not active — refusing clearnet connection \
                 to prevent IP leak. Start your Tor/SOCKS5 proxy or disable onion_only mode."
                .into(),
        )),
        _ => {
            // Direct connection (proxy not configured or not onion_only)
            tokio::time::timeout(timeout, TcpStream::connect(target))
                .await
                .map_err(|_| Error::ConnectionFailed("connection timed out".into()))?
                .map_err(|e| Error::ConnectionFailed(e.to_string()))
        }
    }
}

/// Connect to a peer through a SOCKS5 proxy
async fn connect_via_proxy(
    target: SocketAddr,
    proxy: &ProxyConfig,
    timeout: std::time::Duration,
) -> Result<TcpStream> {
    let proxy_addr = format!("{}:{}", proxy.address, proxy.port);

    tracing::debug!(
        "Connecting to {} via {} proxy at {}",
        target,
        match proxy.proxy_type {
            crate::config::ProxyType::Socks5 => "SOCKS5",
            crate::config::ProxyType::Socks4 => "SOCKS4",
            crate::config::ProxyType::Http => "HTTP",
        },
        proxy_addr
    );

    // For now, only SOCKS5 is implemented
    if proxy.proxy_type != crate::config::ProxyType::Socks5 {
        return Err(Error::ConfigError(
            "Only SOCKS5 proxy is currently supported".into(),
        ));
    }

    let connect_future = async {
        match (&proxy.username, &proxy.password) {
            (Some(user), Some(pass)) => {
                // Authenticated connection
                Socks5Stream::connect_with_password(
                    proxy_addr.as_str(),
                    target,
                    user.as_str(),
                    pass.as_str(),
                )
                .await
            }
            _ => {
                // Unauthenticated connection
                Socks5Stream::connect(proxy_addr.as_str(), target).await
            }
        }
    };

    let stream = tokio::time::timeout(timeout, connect_future)
        .await
        .map_err(|_| Error::ConnectionFailed("proxy connection timed out".into()))?
        .map_err(|e| Error::ConnectionFailed(format!("SOCKS5 error: {}", e)))?;

    Ok(stream.into_inner())
}

/// Connect to an .onion address through Tor
///
/// This requires Tor to be running and configured as a SOCKS5 proxy.
/// CoinCync does NOT bundle Tor - you must install it separately.
pub async fn connect_onion(
    onion_addr: &str,
    port: u16,
    proxy: &ProxyConfig,
    timeout: std::time::Duration,
) -> Result<TcpStream> {
    if !proxy.is_active() {
        return Err(Error::ConfigError(
            "Proxy must be enabled to connect to .onion addresses".into(),
        ));
    }

    if proxy.proxy_type != crate::config::ProxyType::Socks5 {
        return Err(Error::ConfigError(
            "Only SOCKS5 (Tor) can connect to .onion addresses".into(),
        ));
    }

    // Validate .onion address format
    if !onion_addr.ends_with(".onion") {
        return Err(Error::InvalidState("Not a valid .onion address".into()));
    }

    let proxy_addr = format!("{}:{}", proxy.address, proxy.port);
    let target = format!("{}:{}", onion_addr, port);

    tracing::debug!("Connecting to {} via Tor proxy at {}", target, proxy_addr);

    let connect_future = async {
        match (&proxy.username, &proxy.password) {
            (Some(user), Some(pass)) => {
                Socks5Stream::connect_with_password(
                    proxy_addr.as_str(),
                    target.as_str(),
                    user.as_str(),
                    pass.as_str(),
                )
                .await
            }
            _ => Socks5Stream::connect(proxy_addr.as_str(), target.as_str()).await,
        }
    };

    let stream = tokio::time::timeout(timeout, connect_future)
        .await
        .map_err(|_| Error::ConnectionFailed("Tor connection timed out".into()))?
        .map_err(|e| Error::ConnectionFailed(format!("Tor SOCKS5 error: {}", e)))?;

    Ok(stream.into_inner())
}

/// Connect to a peer by hostname through a SOCKS5 proxy (DNS-safe)
///
/// Unlike `connect_peer` which takes a `SocketAddr` (already resolved),
/// this sends the hostname to the proxy so DNS resolution happens on the
/// proxy side (e.g., through Tor), preventing DNS leaks.
#[allow(dead_code)]
pub async fn connect_peer_hostname(
    hostname: &str,
    port: u16,
    proxy: &ProxyConfig,
    timeout: std::time::Duration,
) -> Result<TcpStream> {
    if !proxy.is_active() {
        return Err(Error::ConfigError(
            "Proxy must be enabled for hostname-based connections".into(),
        ));
    }

    let proxy_addr = format!("{}:{}", proxy.address, proxy.port);
    let target = format!("{}:{}", hostname, port);

    tracing::debug!(
        "Connecting to {} via proxy at {} (DNS-safe)",
        target,
        proxy_addr
    );

    let connect_future = async {
        match (&proxy.username, &proxy.password) {
            (Some(user), Some(pass)) => {
                Socks5Stream::connect_with_password(
                    proxy_addr.as_str(),
                    target.as_str(),
                    user.as_str(),
                    pass.as_str(),
                )
                .await
            }
            _ => Socks5Stream::connect(proxy_addr.as_str(), target.as_str()).await,
        }
    };

    let stream = tokio::time::timeout(timeout, connect_future)
        .await
        .map_err(|_| Error::ConnectionFailed("proxy connection timed out".into()))?
        .map_err(|e| Error::ConnectionFailed(format!("SOCKS5 error: {}", e)))?;

    Ok(stream.into_inner())
}

/// Check if the proxy is reachable
pub async fn check_proxy(proxy: &ProxyConfig) -> Result<bool> {
    if !proxy.is_active() {
        return Ok(false);
    }

    let proxy_addr = format!("{}:{}", proxy.address, proxy.port);

    // Try to connect to the proxy itself
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        TcpStream::connect(&proxy_addr),
    )
    .await
    {
        Ok(Ok(_)) => {
            tracing::info!("Proxy at {} is reachable", proxy_addr);
            Ok(true)
        }
        Ok(Err(e)) => {
            tracing::warn!("Proxy at {} connection failed: {}", proxy_addr, e);
            Ok(false)
        }
        Err(_) => {
            tracing::warn!("Proxy at {} connection timed out", proxy_addr);
            Ok(false)
        }
    }
}

/// Helper to detect if an address is a .onion address
///
/// Checks that the hostname portion ends with ".onion" to avoid false positives
/// from strings like "notreal.onion.example.com".
pub fn is_onion_address(addr: &str) -> bool {
    // Strip port if present (addr could be "host:port" or just "host")
    let host = addr.split(':').next().unwrap_or(addr);
    host.ends_with(".onion")
}

/// Parse a peer address that might be .onion or regular IP
pub enum PeerTarget {
    /// Regular IP:port
    SocketAddr(SocketAddr),
    /// .onion address with port
    Onion { host: String, port: u16 },
}

impl PeerTarget {
    /// Parse a peer address string
    pub fn parse(addr: &str) -> Result<Self> {
        if is_onion_address(addr) {
            // Parse .onion:port
            let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
            if parts.len() != 2 {
                return Err(Error::InvalidState("Invalid .onion address format".into()));
            }
            let port: u16 = parts[0]
                .parse()
                .map_err(|_| Error::InvalidState("Invalid port in .onion address".into()))?;
            let host = parts[1].to_string();
            Ok(PeerTarget::Onion { host, port })
        } else {
            // Regular socket address
            let socket_addr: SocketAddr = addr
                .parse()
                .map_err(|_| Error::InvalidState("Invalid peer address".into()))?;
            Ok(PeerTarget::SocketAddr(socket_addr))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_onion_address() {
        assert!(is_onion_address("abcdef1234567890.onion:18080"));
        assert!(is_onion_address("xyz.onion"));
        assert!(!is_onion_address("192.168.1.1:8080"));
        assert!(!is_onion_address("example.com:8080"));
    }

    #[test]
    fn test_peer_target_parse() {
        // Regular address
        match PeerTarget::parse("127.0.0.1:8080").unwrap() {
            PeerTarget::SocketAddr(addr) => {
                assert_eq!(addr.port(), 8080);
            }
            _ => panic!("Expected SocketAddr"),
        }

        // Onion address
        match PeerTarget::parse("abcdef.onion:18080").unwrap() {
            PeerTarget::Onion { host, port } => {
                assert_eq!(host, "abcdef.onion");
                assert_eq!(port, 18080);
            }
            _ => panic!("Expected Onion"),
        }
    }

    #[test]
    fn test_proxy_url() {
        let proxy = ProxyConfig::tor();
        // SECURITY: URL no longer includes credentials to prevent password leakage
        assert_eq!(proxy.url(), "socks5://127.0.0.1:9050");

        let proxy_with_auth = ProxyConfig {
            enabled: true,
            address: "localhost".to_string(),
            port: 9050,
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            onion_only: false,
            proxy_type: crate::config::ProxyType::Socks5,
        };
        // URL is safe to log (no credentials)
        assert_eq!(proxy_with_auth.url(), "socks5://localhost:9050");
        // Credentials available separately
        assert_eq!(proxy_with_auth.credentials(), Some(("user", "pass")));
    }

    #[test]
    fn test_socks5_config() {
        let proxy = ProxyConfig::tor();
        assert!(proxy.enabled);
        assert_eq!(proxy.address, "127.0.0.1");
        assert_eq!(proxy.port, 9050);
        assert!(!proxy.onion_only);
        assert!(proxy.username.is_none());
        assert!(proxy.password.is_none());
    }
}
