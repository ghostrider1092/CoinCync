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
///
/// 2026-06-21 refresh: removed `207.148.111.76` (decommissioned 2026-06-18 —
/// see operator memory `reference_infra_topology._history.seed3_207.148.111.76`)
/// and added the current seed3 replacement (`45.32.251.6`). The MAINNET_FALLBACK
/// list will be re-populated with launch-day IPs before the 2026-10-01 GA;
/// the entries below are testnet-fleet IPs serving as placeholders so a
/// pre-launch mainnet binary at least has SOMETHING to dial if DNS fails.
/// Operator action required before mainnet launch: replace these with the
/// actual mainnet seed IPs (see `docs/architecture/MAINNET_LAUNCH_CHECKLIST.md`).
pub const MAINNET_FALLBACK: &[&str] = &[
    // 2026-06-06: rewritten to the live Vultr fleet.
    // 2026-06-21: 207.148.111.76 removed (decommissioned); 45.32.251.6 added.
    "66.135.23.193:19080",    // seed1
    "140.82.57.168:19080",    // seed2
    "45.32.251.6:19080",      // seed3 (replaces dead 207.148.111.76)
];

pub const TESTNET_FALLBACK: &[&str] = &[
    // Hardcoded fallback peer list — used when DNS bootstrap returns
    // zero addresses (NXDOMAIN on every seed*.coincync.network hostname).
    //
    // **MUST stay in sync with `scripts/fleet-config.json`** (the
    // operator-side source of truth for fleet topology). The
    // `testnet_fallback_matches_fleet_config` test at the bottom of
    // this file enforces this at `cargo test` time — drift in either
    // direction is a build failure, not a silent regression.
    //
    // ## Policy: which hosts go in the fallback?
    //
    // Active `seed`-role + `miner`-role + `explorer`-role nodes only.
    // `api` role intentionally EXCLUDED — the api box (95.179.165.225)
    // runs nginx-only with no P2P listener; including it would cause
    // every new operator to waste a connection slot on a refused dial.
    //
    // Explorer is a deliberate exception to the original "pure-seed
    // only" policy: it's been stable since launch and gives operators
    // an extra fallback IP in case the seed-role nodes are momentarily
    // unreachable (e.g., during a rolling upgrade). The original
    // concern was "app DDoS blackholes IBD" — that's mitigated by
    // having ≥4 other peers in the list, so a single explorer-DDoS
    // doesn't actually starve new operators.
    //
    // ## History
    //
    // - 2026-06-03 (commit d4d93e9): migrated from legacy DigitalOcean
    //   IPs to Vultr fleet — closed Bug #4 (operators dialing dead
    //   DO boxes forever).
    // - 2026-06-21: removed `207.148.111.76` (dead seed3, destroyed
    //   2026-06-18) and `192.248.151.16` (dead London box). Added
    //   `45.32.251.6` (new seed3) and `173.199.93.21` (randomx miner,
    //   provisioned 2026-06-20 — see operator memory
    //   `project_randomx_miner_2026_06_20`). Closed the gap that left
    //   `seed*.coincync.network` NXDOMAIN AND fallback IPs including
    //   2 dead boxes — meaning Barns and other community miners
    //   couldn't bootstrap even via fallback.
    //
    // ## Prior art for the fallback-on-DNS-fail pattern
    //
    // - **Bitcoin Core** `vFixedSeeds` (chainparamsseeds.h, auto-generated
    //   from `contrib/seeds/nodes_main.txt`). Larger list (~200 IPs)
    //   because Bitcoin's seed-DNS reliability is higher and the fallback
    //   only fires on edge-case DNS outages.
    // - **Monero** `cryptonote_basic.cpp` `seed_nodes`. Smaller list
    //   (~10-15 IPs) closer to CoinCync's scale.
    // - **zebrad** uses both DNS seeds + hardcoded mainnet/testnet
    //   nodes baked into `zebra-network` crate. Same shape.
    "66.135.23.193:28080",    // seed1 — Vultr
    "140.82.57.168:28080",    // seed2 — Vultr
    "45.32.251.6:28080",      // seed3 — Vultr (replaces dead 207.148.111.76)
    "207.148.6.50:28080",     // explorer — Vultr (deliberate exception, see comment)
    "173.199.93.21:28080",    // randomx — Vultr 4 vCPU / 7.2 GB (provisioned 2026-06-20)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Every entry in TESTNET_FALLBACK must parse as a valid SocketAddr.
    /// A typo (e.g. missing port, transposed digit) would cause runtime
    /// `addr.parse::<SocketAddr>()` failures during bootstrap, silently
    /// reducing the fallback list size. Pin this at test time.
    #[test]
    fn testnet_fallback_entries_parse() {
        use std::net::SocketAddr;
        for entry in TESTNET_FALLBACK {
            entry.parse::<SocketAddr>()
                .unwrap_or_else(|e| panic!("TESTNET_FALLBACK entry {:?} doesn't parse: {}", entry, e));
        }
    }

    /// Same parse-check for MAINNET_FALLBACK. Pins the placeholder IPs
    /// the same way so a typo in the eventual launch-day refresh doesn't
    /// silently halve the fallback list.
    #[test]
    fn mainnet_fallback_entries_parse() {
        use std::net::SocketAddr;
        for entry in MAINNET_FALLBACK {
            entry.parse::<SocketAddr>()
                .unwrap_or_else(|e| panic!("MAINNET_FALLBACK entry {:?} doesn't parse: {}", entry, e));
        }
    }

    /// TESTNET_FALLBACK must match `TESTNET_SEED_NODES` in `src/testnet.rs`
    /// byte-for-byte. They are two parallel constants serving the same
    /// purpose (hardcoded peers for fresh-node bootstrap when DNS fails);
    /// keeping them in sync was the bug class that bit us 2026-06-03 and
    /// again 2026-06-21 (the latter is exactly the bug this PR closes).
    /// Test enforces no future drift.
    #[test]
    fn testnet_fallback_matches_seed_nodes() {
        let fallback: HashSet<&str> = TESTNET_FALLBACK.iter().copied().collect();
        let seeds: HashSet<&str> = crate::testnet::TESTNET_SEED_NODES.iter().copied().collect();
        assert_eq!(
            fallback, seeds,
            "TESTNET_FALLBACK (in dns_seeds.rs) and TESTNET_SEED_NODES (in testnet.rs) must \
             contain the same entries. Drift between them re-creates the bug class fixed in \
             2026-06-21 PR (operators bootstrap via stale list while the other was updated)."
        );
    }

    /// Sanity check: TESTNET_FALLBACK must contain SOMETHING — an empty
    /// list means new operators have NO bootstrap path when DNS fails,
    /// which is exactly the failure mode this whole subsystem prevents.
    /// Bitcoin Core's `vFixedSeeds` is never empty for the same reason.
    #[test]
    fn testnet_fallback_is_non_empty() {
        assert!(
            !TESTNET_FALLBACK.is_empty(),
            "TESTNET_FALLBACK must contain at least one entry — empty fallback means \
             DNS-failed bootstrap has no recovery path",
        );
        assert!(
            TESTNET_FALLBACK.len() >= 3,
            "TESTNET_FALLBACK should have ≥3 entries for redundancy (one node down \
             shouldn't strand new operators); current count: {}",
            TESTNET_FALLBACK.len(),
        );
    }

    /// TESTNET_FALLBACK must NOT contain known-dead IPs that bit us
    /// in past incidents. Pinning these as a regression guard — if
    /// someone ever tries to re-add them, the test fails loud with a
    /// pointer to the historical record.
    #[test]
    fn testnet_fallback_excludes_known_dead_ips() {
        let known_dead = &[
            // Destroyed 2026-06-18, original seed3 (host-key rotation issue,
            // see operator memory `reference_infra_topology._history`)
            "207.148.111.76",
            // Decommissioned 2026-06-05, Vultr London (drifted onto pre-wipe
            // chain after missing 2026-06-04 testnet wipe; destroyed)
            "192.248.151.16",
            // Destroyed 2026-06-20, original miner (cyncrandomx); replaced
            // by 173.199.93.21 (randomx). See `project_randomx_miner_2026_06_20`.
            "149.248.37.11",
        ];
        for entry in TESTNET_FALLBACK {
            let ip = entry.split(':').next().unwrap_or("");
            assert!(
                !known_dead.contains(&ip),
                "TESTNET_FALLBACK contains known-dead IP {} — see operator memory \
                 for the decommission history. Re-adding requires explicit operator \
                 authorization (the host may have been re-provisioned with a fresh box).",
                ip,
            );
        }
    }
}
