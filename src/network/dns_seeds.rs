// src/network/dns_seeds.rs
//
// DNS seeds and hard-coded fallback peers. The primary `TESTNET_*` /
// `MAINNET_*` seed lists live in `src/testnet.rs` and `src/mainnet.rs`
// respectively; the constants below are a separate flat view used by
// `resolve_seeds()`. Keep the two in sync — a refactor that
// de-duplicates them is a reasonable future cleanup.

use std::net::SocketAddr;
use crate::config::Network;

pub const MAINNET_DNS_SEEDS: &[&str] = &[
    "seed1.coincync.network",
    "seed2.coincync.network",
    "seed3.coincync.network",
];

// Must match `TESTNET_DNS_SEEDS` in `src/testnet.rs` (Bootstrapper default).
pub const TESTNET_DNS_SEEDS: &[&str] = &[
    "seed1.coincync.network",
    "seed2.coincync.network",
    "seed3.coincync.network",
];

/// Hardcoded fallback IPs — used when DNS is unavailable. Ports match
/// `MAINNET_P2P_PORT` (19080) and `TESTNET_P2P_PORT` (28080) from
/// `src/constants.rs`. The previous values (18333 / 28333) were Bitcoin
/// testnet leftovers that never resolved to a real CoinCync peer.
pub const MAINNET_FALLBACK: &[&str] = &[
    "45.55.32.13:19080",       // NYC
    "165.245.161.62:19080",    // RIC
    "143.110.218.99:19080",    // Toronto
    "165.245.140.113:19080",   // ATL
    "64.227.49.44:19080",      // SFO
    "138.68.172.80:19080",     // LON
];

pub const TESTNET_FALLBACK: &[&str] = &[
    "45.55.32.13:28080",       // NYC
    "165.245.161.62:28080",    // RIC
    "143.110.218.99:28080",    // Toronto
    "165.245.140.113:28080",   // ATL
    "64.227.49.44:28080",      // SFO
    "138.68.172.80:28080",     // LON
];

/// Resolve DNS seeds and return a deduplicated list of socket addresses.
/// Falls back to hardcoded IPs if all DNS lookups fail.
pub async fn resolve_seeds(network: Network) -> Vec<SocketAddr> {
    let (seeds, fallback) = match network {
        Network::Mainnet => (MAINNET_DNS_SEEDS, MAINNET_FALLBACK),
        Network::Testnet => (TESTNET_DNS_SEEDS, TESTNET_FALLBACK),
        Network::Regtest => return vec![],
    };

    let mut addrs: Vec<SocketAddr> = Vec::new();

    for seed in seeds {
        let host = format!("{}:{}", seed, network.p2p_port());
        let host_owned = host.clone();
        match tokio::net::lookup_host(host_owned).await {
            Ok(resolved) => {
                let new: Vec<_> = resolved.collect();
                tracing::debug!("DNS seed {} resolved {} addr(s)", seed, new.len());
                addrs.extend(new);
            }
            Err(e) => {
                tracing::warn!("DNS seed {} failed: {}", seed, e);
            }
        }
    }

    // Deduplicate
    addrs.sort_unstable();
    addrs.dedup();

    if addrs.is_empty() {
        tracing::warn!("All DNS seeds failed — using hardcoded fallback nodes");
        for addr_str in fallback {
            if let Ok(addr) = addr_str.parse::<SocketAddr>() {
                addrs.push(addr);
            }
        }
    }

    tracing::info!("Resolved {} seed addresses for {}", addrs.len(), network);
    addrs
}
