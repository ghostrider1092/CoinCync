//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `to_socket_addr`** — INVARIANT: port `0` and unspecified IPv6 are
//!   never converted to a dialable address; IPv4-mapped IPv6 is unwrapped to
//!   plain IPv4.
//!   THREAT: an undialable address occupying an address-book slot and
//!   padding an attacker's per-/16 quota with entries that can never become
//!   a useful outbound peer (H7 dial-starvation/eclipse).
//!   TESTS: `converts_wire_addresses`.
//! - **§2 `is_routable` (IPv4 rejection)** — INVARIANT: loopback, multicast,
//!   unspecified, RFC1918 private ranges, link-local, CGNAT (100.64/10),
//!   documentation/benchmark ranges, and the broadcast address are all
//!   rejected as non-gossip-worthy.
//!   THREAT: gossiping private/reserved addresses lets a peer waste other
//!   nodes' outbound slots on unreachable targets, or probe internal networks.
//!   TESTS: `rejects_unroutable_ipv4`.
//! - **§3 `is_routable` (IPv4 acceptance)** — INVARIANT: ordinary public
//!   IPv4 addresses are accepted for gossip.
//!   THREAT: an overly broad reject list would starve the address book of
//!   legitimate peers, indirectly aiding eclipse by shrinking peer diversity.
//!   TESTS: `accepts_routable_ipv4`.
//! - **§4 `is_routable` (IPv6 rejection)** — INVARIANT: unique-local
//!   (`fc00::/7`), link-local (`fe80::/10`), documentation (`2001:db8::/32`),
//!   and IPv4-compatible (but not IPv4-mapped) IPv6 are all rejected.
//!   THREAT: same as §2 for the IPv6 address space — non-routable ranges
//!   gossiped as public peers waste dial attempts and probe local networks.
//!   TESTS: `rejects_unroutable_ipv6`.
//! - **§5 `is_routable` (IPv6 acceptance)** — INVARIANT: ordinary global
//!   unicast IPv6 addresses are accepted for gossip.
//!   THREAT: as §3, an overly broad IPv6 reject list would shrink peer
//!   diversity and aid eclipse attempts.
//!   TESTS: `accepts_routable_ipv6`.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use super::super::protocol::NetAddr;

/// Convert a wire address to a socket address, rejecting unspecified IPv6.
pub(super) fn to_socket_addr(net_addr: &NetAddr) -> Option<SocketAddr> {
    // H7 (dial starvation / eclipse): reject port 0 — it is undialable, so it
    // would occupy a book slot and pad an attacker's per-/16 netgroup quota
    // with entries that can never become a useful outbound peer.
    if net_addr.port == 0 {
        return None;
    }
    let ip = Ipv6Addr::from(net_addr.ip);

    if let Some(v4) = ip.to_ipv4_mapped() {
        Some(SocketAddr::new(IpAddr::V4(v4), net_addr.port))
    } else if ip.is_unspecified() {
        None
    } else {
        Some(SocketAddr::new(IpAddr::V6(ip), net_addr.port))
    }
}

/// Accept only addresses that are useful for public peer gossip.
pub(super) fn is_routable(ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }

    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            if octets[0] == 10 {
                return false;
            }
            if octets[0] == 172 && (octets[1] & 0xf0) == 16 {
                return false;
            }
            if octets[0] == 192 && octets[1] == 168 {
                return false;
            }
            if octets[0] == 169 && octets[1] == 254 {
                return false;
            }
            if octets[0] == 100 && (octets[1] & 0xc0) == 64 {
                return false;
            }
            if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
                return false;
            }
            if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
                return false;
            }
            if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
                return false;
            }
            if octets[0] == 198 && (octets[1] & 0xfe) == 18 {
                return false;
            }
            if octets == [255, 255, 255, 255] || octets[0] == 0 {
                return false;
            }
            true
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            if (segments[0] & 0xfe00) == 0xfc00 {
                return false;
            }
            if (segments[0] & 0xffc0) == 0xfe80 {
                return false;
            }
            if segments[0] == 0x2001 && segments[1] == 0x0db8 {
                return false;
            }
            if v6.to_ipv4().is_some() && v6.to_ipv4_mapped().is_none() {
                return false;
            }
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn rejects_unroutable_ipv4() {
        let rejected = [
            "0.0.0.0",
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.1.2",
            "100.64.0.1",
            "100.127.255.255",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "198.18.0.1",
            "198.19.255.255",
            "255.255.255.255",
            "224.0.0.1",
            "239.255.255.255",
        ];

        for value in rejected {
            let ip = IpAddr::V4(value.parse::<Ipv4Addr>().unwrap());
            assert!(!is_routable(ip), "expected NOT routable: {value}");
        }
    }

    #[test]
    fn accepts_routable_ipv4() {
        for value in ["1.1.1.1", "8.8.8.8", "66.135.23.193", "203.0.114.1"] {
            let ip = IpAddr::V4(value.parse::<Ipv4Addr>().unwrap());
            assert!(is_routable(ip), "expected routable: {value}");
        }
    }

    #[test]
    fn rejects_unroutable_ipv6() {
        for value in [
            "::",
            "::1",
            "fe80::1",
            "fc00::1",
            "fd00::1",
            "ff00::1",
            "ff02::1",
            "2001:db8::1",
        ] {
            let ip = IpAddr::V6(value.parse::<Ipv6Addr>().unwrap());
            assert!(!is_routable(ip), "expected NOT routable: {value}");
        }
    }

    #[test]
    fn accepts_routable_ipv6() {
        for value in ["2001:4860:4860::8888", "2a01:e0a:c53:63d0::1"] {
            let ip = IpAddr::V6(value.parse::<Ipv6Addr>().unwrap());
            assert!(is_routable(ip), "expected routable: {value}");
        }
    }

    #[test]
    fn converts_wire_addresses() {
        let v4 = NetAddr {
            services: 0,
            ip: Ipv4Addr::new(8, 8, 8, 8).to_ipv6_mapped().octets(),
            port: 18080,
            timestamp: 0,
        };
        let v6 = NetAddr {
            services: 0,
            ip: "2001:4860:4860::8888".parse::<Ipv6Addr>().unwrap().octets(),
            port: 18081,
            timestamp: 0,
        };
        let unspecified = NetAddr {
            services: 0,
            ip: Ipv6Addr::UNSPECIFIED.octets(),
            port: 18082,
            timestamp: 0,
        };

        assert_eq!(
            to_socket_addr(&v4),
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                18080
            ))
        );
        assert_eq!(
            to_socket_addr(&v6),
            Some(SocketAddr::new(
                IpAddr::V6("2001:4860:4860::8888".parse().unwrap()),
                18081,
            ))
        );
        assert_eq!(to_socket_addr(&unspecified), None);
    }
}
