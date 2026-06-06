// src/network/dns_seeds.rs
//
// DNS seeds and hard-coded fallback peers. The primary `TESTNET_*` /
// `MAINNET_*` seed lists live in `src/testnet.rs` and `src/mainnet.rs`
// respectively; the constants below are a separate flat view used by
// `resolve_seeds()`. Keep the two in sync — a refactor that
// de-duplicates them is a reasonable future cleanup.

use std::net::SocketAddr;
use std::time::Duration;
use crate::config::{Network, ProxyConfig};
use crate::network::socks_dns;

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
    // Pure-seed hosts only — must stay in sync with TESTNET_SEED_NODES
    // in src/testnet.rs. App hosts (NYC3 landing/docs, LON explorer,
    // TOR api.coincync.network) are intentionally NOT in this list:
    // the bootstrap layer must stay isolated from public-facing app
    // surface so a DDoS or TOS event on the apps doesn't blackhole
    // new-user IBD.
    //
    // 2026-06-03 sync with TESTNET_SEED_NODES (Bug #4 follow-up,
    // commit d4d93e9): the previous DigitalOcean IPs (192.34.59.42,
    // 46.101.138.120, 165.245.161.62, 165.245.140.113, 164.92.153.24,
    // 170.64.142.146) were the legacy 2.0 fleet and have been
    // unreachable since the migration to Vultr. A fresh node whose
    // DNS lookups failed would dial dead IPs forever instead of
    // reaching the live network. `TESTNET_SEED_NODES` in src/testnet.rs
    // was updated to the current Vultr fleet but this parallel
    // fallback list was missed — same bug class, second instance.
    // `95.179.165.225` (former api node) is intentionally excluded
    // for the same reason as testnet.rs.
    "66.135.23.193:28080",    // Vultr — seed (US)
    "140.82.57.168:28080",    // Vultr — seed (US, Atlanta)
    "207.148.111.76:28080",   // Vultr — seed (US)
    "207.148.6.50:28080",     // Vultr — seed (US)
    // 2026-06-05: Vultr London (192.248.151.16) decommissioned. It missed the
    // 2026-06-04 testnet wipe, stayed stuck on the pre-wipe chain advertising
    // h=12,201 to the api-box's nginx backend (which was pointing at it). With
    // the api box repointed to its own local node and London destroyed in
    // Vultr, this entry was dialing a dead IP. Add it back only with a fresh
    // node included in the next wipe cycle.
];

/// Resolve DNS seeds and return a deduplicated list of socket addresses.
/// Falls back to hardcoded IPs if all DNS lookups fail.
///
/// This is the clearnet path — uses the OS resolver (which bypasses any
/// SOCKS5 proxy). When a proxy is active, prefer
/// [`resolve_seeds_with_proxy`] to avoid the DNS leak documented in
/// [`crate::network::socks_dns`].
pub async fn resolve_seeds(network: Network) -> Vec<SocketAddr> {
    resolve_seeds_inner(network, None).await
}

/// Resolve DNS seeds, routing queries through `proxy` via DNS-over-TCP
/// when the proxy is active. Falls back to hardcoded IPs when every
/// SOCKS5 lookup fails.
pub async fn resolve_seeds_with_proxy(
    network: Network,
    proxy: Option<&ProxyConfig>,
) -> Vec<SocketAddr> {
    resolve_seeds_inner(network, proxy).await
}

async fn resolve_seeds_inner(
    network: Network,
    proxy: Option<&ProxyConfig>,
) -> Vec<SocketAddr> {
    let (seeds, fallback) = match network {
        Network::Mainnet => (MAINNET_DNS_SEEDS, MAINNET_FALLBACK),
        Network::Testnet => (TESTNET_DNS_SEEDS, TESTNET_FALLBACK),
        Network::Regtest => return vec![],
    };

    let mut addrs: Vec<SocketAddr> = Vec::new();
    let port = network.p2p_port();
    let socks_timeout = Duration::from_secs(8);
    let use_proxy_dns = proxy.map(|p| p.is_active()).unwrap_or(false);

    for seed in seeds {
        if use_proxy_dns {
            let proxy = proxy.expect("use_proxy_dns implies Some(proxy)");
            match socks_dns::resolve_via_socks5(seed, proxy, socks_timeout).await {
                Ok(ips) => {
                    tracing::debug!(
                        "DNS seed {} resolved {} addr(s) via SOCKS5",
                        seed,
                        ips.len()
                    );
                    for ip in ips {
                        addrs.push(SocketAddr::new(ip, port));
                    }
                }
                Err(e) => {
                    tracing::warn!("SOCKS5 DNS seed {} failed: {}", seed, e);
                }
            }
        } else {
            let host = format!("{}:{}", seed, port);
            match tokio::net::lookup_host(host).await {
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
    }

    // Deduplicate
    addrs.sort_unstable();
    addrs.dedup();

    if addrs.is_empty() {
        tracing::warn!("All DNS seeds failed — using hardcoded fallback nodes");
        for addr_str in fallback {
            match addr_str.parse::<SocketAddr>() {
                Ok(addr) => addrs.push(addr),
                Err(e) => tracing::warn!(
                    fallback_entry = %addr_str,
                    error = %e,
                    "dns_seeds: hardcoded fallback entry failed to parse — operator should fix",
                ),
            }
        }
    }

    tracing::info!(
        "Resolved {} seed addresses for {} ({} DNS path)",
        addrs.len(),
        network,
        if use_proxy_dns { "SOCKS5" } else { "OS" }
    );
    addrs
}
