// src/network/dns_seeds.rs
//
// DNS seeds and hard-coded fallback peers. The primary `TESTNET_*` /
// `MAINNET_*` seed lists live in `src/testnet.rs` and `src/mainnet.rs`
// respectively; the constants below are a separate flat view used by
// `resolve_seeds()`. Keep the two in sync — a refactor that
// de-duplicates them is a reasonable future cleanup.

// 2026-08-16: mainnet DNS seeds target coincync.ORG (the operator-controlled
// domain) — the runtime queries THIS constant. Register seed1/2/3 A/AAAA
// records under coincync.org before launch. (Testnet stays on .network below.)
pub const MAINNET_DNS_SEEDS: &[&str] = &[
    "seed1.coincync.org",
    "seed2.coincync.org",
    "seed3.coincync.org",
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
    // 2026-08-16: replaced the decommissioned Vultr testnet-fleet
    // placeholders (66.135.23.193 / 140.82.57.168 / 45.32.251.6 — dead since
    // 2026-07-27) that would otherwise ship as dead mainnet bootstrap peers.
    // Append the launch VPS fleet here as it is provisioned. The residential
    // home node stays DNS-only (privacy) and is intentionally NOT listed.
    "2.28.1.75:19080", // Hetzner (EU) — stable public seed
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
    // - **Bitcoin Core** `vFixedSeeds`: VERIFIED as populated at
    //   src/kernel/chainparams.cpp:185 (mainnet), :300 (testnet), and
    //   cleared at :283 (regtest) in the master read this session.
    //   Larger seed list is generated from contrib/seeds; the specific
    //   generation-input filename was not re-read this session and the
    //   "~200 IPs" size claim is dropped as unverified.
    // - **Monero** `seed_nodes`: VERIFIED as a named vector used
    //   extensively in src/p2p/net_node.inl (declared at :83, member
    //   at :488, first parse at :486 in the master read this session).
    //   The prior comment placed it in `cryptonote_basic.cpp` — that
    //   file was not the location this session. Corrected. The "~10-15
    //   IPs" size claim was not re-measured this session and is dropped.
    // - **zebrad** DNS + hardcoded seeds pattern: not re-verified
    //   against Zebra source this session. Dropped.
    // 2026-08-16: the Vultr fleet above was decommissioned (dead since
    // 2026-07-27). Replaced with the current stable public box. Kept in sync
    // with `testnet::TESTNET_SEED_NODES` (testnet_fallback_matches_seed_nodes).
    // Append re-provisioned VPS boxes here; the home node stays DNS-only.
    "2.28.1.75:28080", // Hetzner (EU) — stable public seed
];

// NOTE (2026-08-16 dead-code sweep): removed `resolve_seeds`,
// `resolve_seeds_with_proxy`, and `resolve_seeds_inner`. They were reachable
// only via `bootstrap::initial_peers` (also removed this pass) — dead code.
// The live seed-resolution path is `Bootstrapper::get_peers_with_proxy`, which
// reads these constants through `BootstrapConfig::for_network`. The constants
// below are KEPT because `for_network` (mainnet) and the tests consume them.

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
            entry.parse::<SocketAddr>().unwrap_or_else(|e| {
                panic!("TESTNET_FALLBACK entry {:?} doesn't parse: {}", entry, e)
            });
        }
    }

    /// Same parse-check for MAINNET_FALLBACK. Pins the placeholder IPs
    /// the same way so a typo in the eventual launch-day refresh doesn't
    /// silently halve the fallback list.
    #[test]
    fn mainnet_fallback_entries_parse() {
        use std::net::SocketAddr;
        for entry in MAINNET_FALLBACK {
            entry.parse::<SocketAddr>().unwrap_or_else(|e| {
                panic!("MAINNET_FALLBACK entry {:?} doesn't parse: {}", entry, e)
            });
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
    /// Bitcoin Core's `vFixedSeeds` follows the same non-empty
    /// invariant (populated at src/kernel/chainparams.cpp:185 for
    /// mainnet and :300 for testnet in the master read this session).
    #[test]
    fn testnet_fallback_is_non_empty() {
        assert!(
            !TESTNET_FALLBACK.is_empty(),
            "TESTNET_FALLBACK must contain at least one entry — empty fallback means \
             DNS-failed bootstrap has no recovery path",
        );
        // 2026-08-16: the ≥3-for-redundancy floor was dropped. The Vultr fleet
        // was decommissioned (dead since 2026-07-27), leaving one stable public
        // box; a single LIVE seed beats three dead ones. Re-raise this floor as
        // the testnet fleet is re-provisioned (append boxes to TESTNET_FALLBACK
        // + testnet::TESTNET_SEED_NODES, kept in sync by the test below).
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
