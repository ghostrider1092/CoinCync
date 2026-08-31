//! # Network Bootstrap
//!
//! DNS seeds, peer discovery, and network bootstrapping.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::time::timeout;
use tracing::{info, warn};

use crate::error::{Error, Result};
use crate::network::socks_dns;
use crate::testnet::{TESTNET_DNS_SEEDS, TESTNET_P2P_PORT, TESTNET_SEED_NODES};

/// Bootstrap configuration
#[derive(Clone, Debug)]
pub struct BootstrapConfig {
    /// DNS seeds to query
    pub dns_seeds: Vec<String>,
    /// Hardcoded seed nodes
    pub seed_nodes: Vec<SocketAddr>,
    /// DNS query timeout
    pub dns_timeout: Duration,
    /// Maximum addresses to return
    pub max_addresses: usize,
    /// P2P port to assume for DNS-resolved seed IPs (which return just
    /// the address, not the port). Previously hardcoded as
    /// `TESTNET_P2P_PORT` at every call site; lifting it onto the
    /// config makes the bootstrapper reusable for mainnet without
    /// editing the resolver code paths.
    pub p2p_port: u16,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        BootstrapConfig {
            dns_seeds: TESTNET_DNS_SEEDS.iter().map(|s| s.to_string()).collect(),
            seed_nodes: TESTNET_SEED_NODES
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect(),
            dns_timeout: Duration::from_secs(5),
            max_addresses: 100,
            p2p_port: TESTNET_P2P_PORT,
        }
    }
}

impl BootstrapConfig {
    /// Build the bootstrap config for a specific network.
    ///
    /// CORRECTNESS (mainnet launch-blocker): `Default` yields the TESTNET
    /// seeds on the TESTNET port (28080). The node runtime MUST call this so a
    /// `--network mainnet` node dials MAINNET seeds on the mainnet P2P port
    /// (19080). Without it a mainnet node bootstraps against dead testnet
    /// seed IPs on the wrong port (and would reject any that answer on a magic
    /// mismatch), finding zero mainnet peers. Regtest gets an empty set (the
    /// node clears bootstrap for regtest anyway).
    pub fn for_network(network: crate::config::Network) -> Self {
        use crate::config::Network;
        use crate::network::dns_seeds::{MAINNET_DNS_SEEDS, MAINNET_FALLBACK};
        let (dns_seeds, seed_nodes): (&[&str], &[&str]) = match network {
            Network::Mainnet => (MAINNET_DNS_SEEDS, MAINNET_FALLBACK),
            Network::Testnet => (TESTNET_DNS_SEEDS, TESTNET_SEED_NODES),
            Network::Regtest => (&[], &[]),
        };
        BootstrapConfig {
            dns_seeds: dns_seeds.iter().map(|s| s.to_string()).collect(),
            seed_nodes: seed_nodes.iter().filter_map(|s| s.parse().ok()).collect(),
            dns_timeout: Duration::from_secs(5),
            max_addresses: 100,
            p2p_port: network.p2p_port(),
        }
    }
}

/// Network bootstrapper
pub struct Bootstrapper {
    config: BootstrapConfig,
}

impl Bootstrapper {
    /// Create a new bootstrapper
    pub fn new(config: BootstrapConfig) -> Self {
        Bootstrapper { config }
    }

    /// Get initial peer addresses.
    ///
    /// SECURITY (CRIT-7 + M1 audit fix): DNS queries use the OS resolver which
    /// bypasses SOCKS5 / Tor entirely, leaking the user's real IP to whoever
    /// runs their ISP's DNS resolver. To prevent that:
    ///
    ///   - `onion_only=true`           → skip OS DNS; if `proxy` is also
    ///                                   supplied (the supported case), route
    ///                                   DNS queries *through* the proxy via
    ///                                   DNS-over-TCP — see [`socks_dns`].
    ///                                   Without a proxy the only safe move
    ///                                   is to skip DNS entirely.
    ///   - `proxy_active=true`         → ALSO skip OS DNS, but use proxy-DNS
    ///                                   when `proxy` is available. The
    ///                                   trade-off the old code accepted —
    ///                                   "bootstrap relies entirely on
    ///                                   hardcoded seed nodes + peer
    ///                                   exchange" — is no longer the only
    ///                                   option; the SOCKS DNS path
    ///                                   preserves anonymity AND
    ///                                   reachability.
    ///   - both false (clearnet)       → OS DNS proceeds as usual.
    ///
    /// Roadmap item #9 (SOCKS5 UDP-ASSOCIATE DNS) was originally framed as
    /// UDP-ASSOCIATE, but Tor doesn't implement that command — see the
    /// design note in [`socks_dns`]. The shipped fix is DNS-over-TCP via
    /// SOCKS5 CONNECT to a configurable resolver (default 1.1.1.1:53,
    /// override via `COINCYNC_SOCKS_DNS_RESOLVER`).
    pub async fn get_peers(&self, onion_only: bool, proxy_active: bool) -> Vec<SocketAddr> {
        self.get_peers_with_proxy(onion_only, proxy_active, None)
            .await
    }

    /// Same as [`get_peers`] but with an optional proxy. When supplied
    /// AND the caller is in proxied or onion-only mode, DNS queries are
    /// routed through the proxy via DNS-over-TCP rather than skipped.
    pub async fn get_peers_with_proxy(
        &self,
        onion_only: bool,
        proxy_active: bool,
        proxy: Option<&crate::config::ProxyConfig>,
    ) -> Vec<SocketAddr> {
        let mut peers = HashSet::new();
        let force_disable_dns = env_bool("COINCYNC_BOOTSTRAP_DISABLE_DNS");
        let allowlist = seed_allowlist();

        // Add hardcoded seeds first
        for addr in &self.config.seed_nodes {
            peers.insert(*addr);
        }

        // DNS routing decision tree:
        //
        //   force_disable_dns       → no DNS at all (kill switch).
        //   proxy supplied + active → DNS-over-TCP through the proxy.
        //                             Preserves IP anonymity AND
        //                             keeps bootstrap reachability.
        //   onion_only without proxy→ skip DNS (no safe path exists).
        //   proxy_active without
        //     a proxy reference     → skip DNS (legacy callers; same
        //                             posture as before #9 fix).
        //   plain clearnet          → OS resolver (hickory).
        let use_proxy_dns = proxy.map(|p| p.is_active()).unwrap_or(false) && !force_disable_dns;

        if force_disable_dns {
            info!("Bootstrap DNS disabled via COINCYNC_BOOTSTRAP_DISABLE_DNS=1");
        } else if use_proxy_dns {
            let proxy = proxy.expect("use_proxy_dns implies Some(proxy)");
            info!(
                "Proxy active: routing {} DNS seed queries through SOCKS5 (DNS-over-TCP)",
                self.config.dns_seeds.len()
            );
            for seed in &self.config.dns_seeds {
                match socks_dns::resolve_via_socks5(seed, proxy, self.config.dns_timeout).await {
                    Ok(ips) => {
                        info!(
                            "Got {} addresses from DNS seed {} (via SOCKS5)",
                            ips.len(),
                            seed
                        );
                        for ip in ips {
                            peers.insert(SocketAddr::new(ip, self.config.p2p_port));
                        }
                    }
                    Err(e) => {
                        warn!("SOCKS5 DNS failed for seed {}: {}", seed, e);
                    }
                }
            }
        } else if onion_only || proxy_active {
            if onion_only {
                info!("Onion-only mode without proxy reference: skipping DNS seed queries to prevent IP leak");
            } else {
                info!(
                    "Proxy active but no proxy reference threaded through: skipping DNS to prevent IP leak. \
                     Pass the proxy to get_peers_with_proxy() to enable DNS-over-SOCKS5."
                );
            }
        } else {
            // Plain clearnet — OS resolver.
            for seed in &self.config.dns_seeds {
                match self.query_dns_seed(seed).await {
                    Ok(addrs) => {
                        info!("Got {} addresses from DNS seed {}", addrs.len(), seed);
                        for addr in addrs {
                            peers.insert(addr);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to query DNS seed {}: {}", seed, e);
                    }
                }
            }
        }

        let mut result: Vec<SocketAddr> =
            peers.into_iter().take(self.config.max_addresses).collect();

        if let Some(allowed) = allowlist {
            result.retain(|p| allowed.contains(p));
        }

        info!("Bootstrap found {} peer addresses", result.len());
        result
    }

    /// Query a DNS seed
    async fn query_dns_seed(&self, seed: &str) -> Result<Vec<SocketAddr>> {
        use hickory_resolver::TokioResolver;

        let resolver = TokioResolver::builder_tokio()
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?
            .build()
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

        let lookup = timeout(self.config.dns_timeout, resolver.lookup_ip(seed))
            .await
            .map_err(|_| Error::ConnectionFailed("DNS timeout".into()))?
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

        let addrs: Vec<SocketAddr> = lookup
            .iter()
            .map(|ip| SocketAddr::new(ip, self.config.p2p_port))
            .collect();

        Ok(addrs)
    }
}

/// Peer exchange protocol messages
#[derive(Clone, Debug)]
pub struct PeerExchangeRequest {
    /// Our known peers
    pub peers: Vec<PeerAddress>,
    /// Maximum peers we want in response
    pub max_response: u32,
}

#[derive(Clone, Debug)]
pub struct PeerExchangeResponse {
    /// Peers we're sharing
    pub peers: Vec<PeerAddress>,
}

/// Peer address with metadata
#[derive(Clone, Debug)]
pub struct PeerAddress {
    /// IP address
    pub addr: SocketAddr,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Peer services/capabilities
    pub services: u64,
}

impl PeerAddress {
    pub fn new(addr: SocketAddr) -> Self {
        PeerAddress {
            addr,
            last_seen: chrono::Utc::now().timestamp() as u64,
            services: 0,
        }
    }
}

/// Serializable form for disk persistence
#[derive(serde::Serialize, serde::Deserialize)]
struct PeerAddressSerde {
    addr: String,
    last_seen: u64,
    services: u64,
}

/// Peer-aging: after this many consecutive failed dial attempts with no
/// intervening success, an address is purged from the in-memory pool.
///
/// Without this, dead IPs (e.g., destroyed fleet hosts that other peers
/// still gossip) sit in `addresses` forever, get repeatedly retried,
/// fail again, and eat outbound dial slots via the eclipse-defense
/// subnet counter (`MAX_OUTBOUND_PER_SUBNET`) — observed 2026-06-26 when
/// 4 destroyed IPs across the fleet (66.135.23.193, 104.207.140.83,
/// 149.248.37.11, 207.148.111.76) collectively starved real fleet peers
/// out of the outbound rotation. See [[project_chain_partition_2026_06_22]].
///
/// 5 failures × 15s dial timeout ≈ 75s to purge a dead address. Other
/// fleet members may re-gossip it back in, but they too will purge after
/// 5 attempts, so the network self-cleans within minutes instead of the
/// pre-fix "forever."
///
/// Reset to 0 on every `mark_success`. Purge does NOT permanently
/// blacklist — re-gossip via `add()` adds the address back fresh
/// (could be a host that came back after maintenance).
const FAILURE_PURGE_THRESHOLD: u32 = 5;

/// Maximum number of failed addresses retained in one retry cycle.
const MAX_TRIED: usize = 5_000;

/// SECURITY (H-3, eclipse resistance): the address book is bounded so that any
/// single netgroup may occupy at most `max_addresses / NETGROUP_BOOK_DENOM`
/// slots. A flood of thousands of IPs from one /16 therefore competes for a
/// bounded slice of the book instead of crowding out honest peers from other
/// ranges — the precondition an eclipse (→ double-spend on a low-hashrate
/// chain) needs. `connection_tracker.rs` enforces a complementary per-/16 cap
/// on live OUTBOUND connections; this bounds the BOOK the dialer selects from.
const NETGROUP_BOOK_DENOM: usize = 8;

/// Netgroup key for eclipse-resistance bucketing: groups addresses by the range
/// an attacker most cheaply controls (IPv4 /16, IPv6 /32). Mirrors Bitcoin
/// Core's `GetGroup()` intent.
fn netgroup_key(ip: std::net::IpAddr) -> [u8; 5] {
    let mut k = [0u8; 5];
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            k[0] = 4;
            k[1] = o[0];
            k[2] = o[1]; // /16 — the attacker-cost boundary for IPv4
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.octets();
            k[0] = 6;
            k[1..5].copy_from_slice(&s[0..4]); // /32 for IPv6
        }
    }
    k
}

/// Address manager for peer discovery
pub struct AddressManager {
    /// Known addresses
    addresses: Vec<PeerAddress>,
    /// SECURITY (L6): Fast dedup set to prevent duplicate address insertions
    known_addrs: HashSet<SocketAddr>,
    /// Tried addresses (failed connections)
    tried: HashSet<SocketAddr>,
    /// Tried addresses ordered from least to most recently failed.
    tried_order: VecDeque<SocketAddr>,
    /// Self-addresses (detected via nonce match) — never connect to these
    self_addresses: HashSet<SocketAddr>,
    /// ANCHORS (Bitcoin Core model): our known-good outbound peers from the
    /// previous session, persisted to disk and dialed FIRST on restart.
    /// Reconnecting to proven-reachable peers avoids the cold-start dial
    /// churn (self-dials, dead/non-p2p hosts, repeated broken-pipe/reset)
    /// that stalled sync after every restart during the 2026-07-08/09
    /// incident. See docs/architecture (peer-mgmt) + Bitcoin Core PR #17428.
    anchors: Vec<SocketAddr>,
    /// Per-address consecutive-failure count. Resets on `mark_success`;
    /// purges address from pool when it crosses `FAILURE_PURGE_THRESHOLD`.
    failures: HashMap<SocketAddr, u32>,
    /// MANUAL peers (operator --addnode). Dialed with PRIORITY in `get_next`
    /// — ahead of anchors and the discovered book — and NEVER purged by the
    /// failure-count logic. Without this, a large or stale seed set crowds
    /// the last_seen sort and starves the operator's explicit peer out of the
    /// outbound dialer (observed 2026-08-16: 0 outbound for 90s+ against an up
    /// --addnode peer). Mirrors Bitcoin Core's -addnode/-connect priority.
    manual: HashSet<SocketAddr>,
    /// Maximum addresses to store
    max_addresses: usize,
}

impl AddressManager {
    pub fn new(max_addresses: usize) -> Self {
        AddressManager {
            addresses: Vec::new(),
            known_addrs: HashSet::new(),
            tried: HashSet::new(),
            tried_order: VecDeque::new(),
            self_addresses: HashSet::new(),
            anchors: Vec::new(),
            failures: HashMap::new(),
            manual: HashSet::new(),
            max_addresses,
        }
    }

    /// Register a manually-configured (--addnode) peer. Manual peers are
    /// dialed with priority in `get_next` and are exempt from failure-count
    /// purging — the operator explicitly wants a connection to this address,
    /// so we keep trying it across the tried/backoff cycle rather than letting
    /// discovered seeds crowd it out.
    pub fn add_manual(&mut self, addr: SocketAddr) {
        self.manual.insert(addr);
        self.add(PeerAddress::new(addr));
    }

    /// Install the persisted anchor peers (loaded from `anchors.json` on
    /// startup). They are also seeded into the general address pool so
    /// mark_tried/mark_success + the address book treat them normally; the
    /// `anchors` list only controls dial PRIORITY (see `get_next`). Self- and
    /// already-known addresses are filtered by `add`.
    pub fn set_anchors(&mut self, anchors: Vec<SocketAddr>) {
        for a in &anchors {
            self.add(PeerAddress::new(*a));
        }
        self.anchors = anchors;
    }

    /// Add a new address
    pub fn add(&mut self, addr: PeerAddress) {
        // Never (re-)admit a known self-address. mark_self_address()
        // removes our own IP once, but without this guard the next
        // AddrGossip that echoes our IP back to us re-inserts it and we
        // dial ourselves again — wasting an outbound slot and slowing
        // mesh re-formation after a restart (2026-07-08 incident).
        if self.self_addresses.contains(&addr.addr) {
            return;
        }

        // SECURITY (L-12): dedup / tried guards run BEFORE any capacity eviction.
        // Previously the eviction below ran first, so a duplicate or already-
        // tried address evicted a real entry and then inserted nothing —
        // shrinking the book by one honest peer per repeated/tried gossip entry
        // (an eclipse assist). Guard first; only evict when actually inserting.
        if self.tried.contains(&addr.addr) {
            return;
        }
        if self.known_addrs.contains(&addr.addr) {
            return;
        }

        let privileged =
            self.manual.contains(&addr.addr) || self.anchors.contains(&addr.addr);

        // SECURITY (H-3, eclipse): bound any single netgroup's share of the book
        // so a flood of many IPs from one /16 (v4) or /32 (v6) can't crowd out
        // honest peers from other ranges. Manual/anchor peers are operator-
        // chosen and exempt.
        if !privileged {
            let cap = (self.max_addresses / NETGROUP_BOOK_DENOM).max(2);
            let ng = netgroup_key(addr.addr.ip());
            let group_count = self
                .addresses
                .iter()
                .filter(|a| netgroup_key(a.addr.ip()) == ng)
                .count();
            if group_count >= cap {
                return;
            }
        }

        // Capacity eviction — only now that we know we're actually inserting,
        // and from the MOST over-represented netgroup (never a manual/anchor
        // address) so a flood evicts its OWN kind, not an honest peer.
        if self.addresses.len() >= self.max_addresses {
            match self.pick_eviction_index() {
                Some(idx) => {
                    let evicted = self.addresses.swap_remove(idx);
                    self.known_addrs.remove(&evicted.addr);
                }
                None => return, // book is full of only privileged addrs
            }
        }

        self.known_addrs.insert(addr.addr);
        self.addresses.push(addr);
    }

    /// Choose an address to evict when the book is full: the oldest entry within
    /// the MOST over-represented netgroup, never a manual/anchor address. Makes
    /// a single-netgroup flood evict its own entries rather than honest peers
    /// from other ranges (H-3 eclipse resistance).
    fn pick_eviction_index(&self) -> Option<usize> {
        let mut counts: HashMap<[u8; 5], usize> = HashMap::new();
        for a in &self.addresses {
            *counts.entry(netgroup_key(a.addr.ip())).or_insert(0) += 1;
        }
        let mut best: Option<(usize, usize, u64)> = None; // (idx, group_size, last_seen)
        for (i, a) in self.addresses.iter().enumerate() {
            if self.manual.contains(&a.addr) || self.anchors.contains(&a.addr) {
                continue;
            }
            let gsize = counts.get(&netgroup_key(a.addr.ip())).copied().unwrap_or(0);
            let better = match best {
                None => true,
                Some((_, bg, bls)) => gsize > bg || (gsize == bg && a.last_seen < bls),
            };
            if better {
                best = Some((i, gsize, a.last_seen));
            }
        }
        best.map(|(i, _, _)| i)
    }

    /// Add multiple addresses
    pub fn add_many(&mut self, addrs: Vec<PeerAddress>) {
        for addr in addrs {
            self.add(addr);
        }
    }

    /// Get addresses for peer exchange
    pub fn get_for_exchange(&self, max: usize) -> Vec<PeerAddress> {
        self.addresses.iter().take(max).cloned().collect()
    }

    /// Mark an address as our own (detected via self-connection nonce match).
    /// These addresses are permanently skipped by get_next().
    pub fn mark_self_address(&mut self, addr: SocketAddr) {
        self.self_addresses.insert(addr);
        // Also remove from the address list entirely
        self.addresses.retain(|a| a.addr != addr);
        self.known_addrs.remove(&addr);
    }

    /// Get next address to try connecting
    pub fn get_next(&mut self) -> Option<SocketAddr> {
        // MANUAL PEERS FIRST: operator --addnode peers are dialed ahead of
        // anchors and the discovered book. Without this, a large or stale seed
        // set crowds the last_seen sort and the manual peer never gets its turn
        // (observed 2026-08-16: 0 outbound for 90s+ against an up peer). Skipped
        // once tried this cycle; re-prioritized when the tried set clears.
        for a in &self.manual {
            if !self.tried.contains(a) && !self.self_addresses.contains(a) {
                return Some(*a);
            }
        }
        // ANCHORS NEXT: dial our persisted known-good outbound peers before
        // the general book. They were reachable last session, so reconnecting to
        // them re-establishes a working mesh immediately after a restart
        // instead of cold-dialing the whole address book (which churns on
        // self-dials and dead/non-p2p hosts). Skipped once tried this cycle;
        // when the tried set is cleared below they are re-prioritized.
        for a in &self.anchors {
            if !self.tried.contains(a) && !self.self_addresses.contains(a) {
                return Some(*a);
            }
        }
        // Sort by last_seen (most recent first)
        self.addresses
            .sort_by_key(|a| std::cmp::Reverse(a.last_seen));

        // Find first address not in tried set and not a self-address
        for addr in &self.addresses {
            if !self.tried.contains(&addr.addr) && !self.self_addresses.contains(&addr.addr) {
                return Some(addr.addr);
            }
        }

        // All addresses have been tried. Clear the tried set so we retry them.
        // This implements the "exponential backoff + retry" pattern from Bitcoin Core
        // where addresses are periodically retried instead of permanently blacklisted.
        // The outbound connector's per-address backoff (in node.rs) handles rate limiting.
        if !self.tried.is_empty() && !self.addresses.is_empty() {
            tracing::debug!(
                "All {} addresses tried, clearing tried set to retry",
                self.tried.len()
            );
            self.clear_tried();
            // Return first address after clearing
            return self.addresses.first().map(|a| a.addr);
        }

        None
    }

    /// Mark an address as tried (failed)
    ///
    /// SECURITY (M-8): Bounded to MAX_TRIED to prevent unbounded memory growth
    /// and eventual permanent outbound isolation (get_next returns None).
    ///
    /// Peer-aging (2026-06-26): each call increments a per-address failure
    /// counter. Once that crosses `FAILURE_PURGE_THRESHOLD`, the address is
    /// PURGED from `addresses` + `known_addrs` entirely so it stops eating
    /// outbound dial slots via the eclipse-defense subnet counter. The
    /// address can be re-added via gossip later (could be a host coming back
    /// after maintenance), at which point the failure count starts fresh.
    pub fn mark_tried(&mut self, addr: SocketAddr) {
        if !self.tried.insert(addr) {
            self.tried_order.retain(|candidate| *candidate != addr);
        }
        self.tried_order.push_back(addr);

        if self.tried.len() > MAX_TRIED {
            let oldest = self
                .tried_order
                .pop_front()
                .expect("tried order contains every tried address");
            self.tried.remove(&oldest);
        }

        // Bump per-address failure count; purge if we've crossed the threshold.
        let count = self
            .failures
            .entry(addr)
            .and_modify(|c| *c += 1)
            .or_insert(1);
        // Manual (--addnode) peers are never purged: the operator explicitly
        // wants this address, so a temporarily-down manual peer must remain
        // dialable when it comes back rather than being dropped from the pool.
        if *count >= FAILURE_PURGE_THRESHOLD && !self.manual.contains(&addr) {
            tracing::debug!(
                "AddressManager: purging {} after {} consecutive failures",
                addr,
                count
            );
            self.addresses.retain(|a| a.addr != addr);
            self.known_addrs.remove(&addr);
            self.tried.remove(&addr);
            self.tried_order.retain(|candidate| *candidate != addr);
            self.failures.remove(&addr);
        }
    }

    /// Mark an address as successful
    pub fn mark_success(&mut self, addr: SocketAddr) {
        self.tried.remove(&addr);
        self.tried_order.retain(|candidate| *candidate != addr);
        // Reset failure count — a successful connect proves the address is alive.
        self.failures.remove(&addr);

        // Update last_seen
        if let Some(peer) = self.addresses.iter_mut().find(|a| a.addr == addr) {
            peer.last_seen = chrono::Utc::now().timestamp() as u64;
        }
    }

    /// Clear tried addresses (for retry)
    pub fn clear_tried(&mut self) {
        self.tried.clear();
        self.tried_order.clear();
    }

    /// Firework / Veil: mark an address as Noise-capable (SERVICES_NOISE).
    /// Called when a Noise-encrypted connection to `addr` is confirmed so
    /// future GetAddr responses from Veil-capable peers include it.
    pub fn mark_noise_capable(&mut self, addr: SocketAddr, noise_service_bit: u64) {
        for pa in self.addresses.iter_mut() {
            if pa.addr == addr {
                pa.services |= noise_service_bit;
                return;
            }
        }
        // Address not yet in book (e.g. inbound connections) — add it now
        let mut pa = PeerAddress::new(addr);
        pa.services |= noise_service_bit;
        self.add(pa);
    }

    /// Get total address count
    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// Save address book to disk for persistence across restarts
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<()> {
        let entries: Vec<PeerAddressSerde> = self
            .addresses
            .iter()
            .map(|a| PeerAddressSerde {
                addr: a.addr.to_string(),
                last_seen: a.last_seen,
                services: a.services,
            })
            .collect();

        let json = serde_json::to_string_pretty(&entries)
            .map_err(|e| Error::InvalidState(format!("serialize addresses: {}", e)))?;
        std::fs::write(path, json)
            .map_err(|e| Error::InvalidState(format!("write address book: {}", e)))?;
        Ok(())
    }

    /// Load address book from disk
    pub fn load_from_file(&mut self, path: &std::path::Path) -> Result<usize> {
        if !path.exists() {
            return Ok(0);
        }

        // DoS-on-startup defense: bound the read at MAX_ADDRBOOK_BYTES
        // before fs::read_to_string allocates, AND cap the parsed Vec
        // length post-decode. Same OOM-on-startup risk class as
        // Mempool::load_from_disk: any actor with filesystem access
        // (other local user, container neighbor, exfiltrator, leftover
        // file from a crashed peer process) can drop a multi-GB or
        // N-billion-entry JSON file into the data dir.
        //
        // Honest address books with max_addresses=100 entries serialize
        // to a few KB. 1 MiB is ~10K entries — generous over the
        // in-memory cap, narrow enough to make a crafted-file DoS
        // impractical. Hard-coded vs a public const because no other
        // call site needs to reason about this number.
        //
        // Prior art: Bitcoin Core's `CAddrMan::Unserialize` caps the
        // peers.dat file at MAX_ADDRMAN_SIZE and rejects oversized
        // serializations before allocating; Monero's
        // `node_server::store_peerlist` does the same with explicit
        // bucket counts.
        const MAX_ADDRBOOK_BYTES: u64 = 1024 * 1024; // 1 MiB
        const MAX_ADDRBOOK_ENTRIES: usize = 10_000;

        let metadata = std::fs::metadata(path)
            .map_err(|e| Error::InvalidState(format!("stat address book: {}", e)))?;
        if metadata.len() > MAX_ADDRBOOK_BYTES {
            // Remove the oversized file so the node isn't bricked across restarts.
            let _ = std::fs::remove_file(path);
            return Err(Error::InvalidState(format!(
                "address book file too large: {} bytes (max {})",
                metadata.len(),
                MAX_ADDRBOOK_BYTES
            )));
        }

        let data = std::fs::read_to_string(path)
            .map_err(|e| Error::InvalidState(format!("read address book: {}", e)))?;
        let entries: Vec<PeerAddressSerde> = serde_json::from_str(&data)
            .map_err(|e| Error::InvalidState(format!("parse address book: {}", e)))?;

        if entries.len() > MAX_ADDRBOOK_ENTRIES {
            return Err(Error::InvalidState(format!(
                "address book file has {} entries (max {})",
                entries.len(),
                MAX_ADDRBOOK_ENTRIES
            )));
        }

        let mut loaded = 0;
        for entry in entries {
            if let Ok(addr) = entry.addr.parse::<SocketAddr>() {
                let pa = PeerAddress {
                    addr,
                    last_seen: entry.last_seen,
                    services: entry.services,
                };
                self.add(pa);
                loaded += 1;
            }
        }
        Ok(loaded)
    }
}

/// UPnP port forwarding (optional)
pub async fn setup_upnp(internal_port: u16, external_port: u16) -> Result<()> {
    use igd::aio::search_gateway;
    use igd::PortMappingProtocol;

    info!("Attempting UPnP port mapping...");

    let gateway = search_gateway(Default::default())
        .await
        .map_err(|e| Error::ConnectionFailed(format!("UPnP gateway not found: {}", e)))?;

    // Get local address
    let _local_addr = gateway
        .get_external_ip()
        .await
        .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

    // Add port mapping
    gateway
        .add_port(
            PortMappingProtocol::TCP,
            external_port,
            SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), internal_port),
            3600, // 1 hour lease
            "CoinCync",
        )
        .await
        .map_err(|e| Error::ConnectionFailed(format!("UPnP port mapping failed: {}", e)))?;

    info!(
        "UPnP port mapping successful: {} -> {}",
        external_port, internal_port
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_config_is_network_aware() {
        use crate::config::Network;
        // Mainnet must NOT inherit the testnet default (seeds on :28080).
        let m = BootstrapConfig::for_network(Network::Mainnet);
        assert_eq!(
            m.p2p_port, 19080,
            "mainnet bootstrap must use the mainnet P2P port"
        );
        assert!(!m.dns_seeds.is_empty(), "mainnet must have DNS seeds");
        // Decommissioned Vultr IPs must never ship as mainnet seeds, and every
        // hardcoded seed must be on the mainnet port.
        let dead = ["66.135.23.193", "140.82.57.168", "207.148.111.76", "45.32.251.6"];
        for s in &m.seed_nodes {
            assert!(
                !dead.contains(&s.ip().to_string().as_str()),
                "dead Vultr IP {s} must not be a mainnet seed"
            );
            assert_eq!(s.port(), 19080, "mainnet seed {s} must be on :19080");
        }
        // Testnet path is unchanged from the historical default.
        let t = BootstrapConfig::for_network(Network::Testnet);
        assert_eq!(t.p2p_port, crate::testnet::TESTNET_P2P_PORT);
        assert!(!t.seed_nodes.is_empty());
        // Regtest does no seed bootstrap.
        let r = BootstrapConfig::for_network(Network::Regtest);
        assert!(r.dns_seeds.is_empty() && r.seed_nodes.is_empty());
    }

    #[test]
    fn test_bootstrap_config() {
        // Assert ranges, not exact counts, so seed churn doesn't break the
        // test. 2026-08-16: floor lowered from 3 to 1 — the Vultr testnet fleet
        // was decommissioned (dead since 2026-07-27), leaving one stable public
        // box until the fleet is re-provisioned. One live seed beats five dead.
        let config = BootstrapConfig::default();
        assert!(
            config.dns_seeds.len() >= 1,
            "must have at least one DNS seed"
        );
        assert!(
            !config.seed_nodes.is_empty(),
            "must have at least one seed node"
        );
        assert!(
            config.seed_nodes.len() <= 32,
            "more than 32 seed nodes suggests a config bug"
        );
        assert_eq!(config.dns_timeout, Duration::from_secs(5));
        assert_eq!(config.max_addresses, 100);
        // Sanity: every seed must use a non-zero port and a non-loopback IP.
        for seed in &config.seed_nodes {
            assert!(seed.port() != 0, "seed {} has zero port", seed);
            assert!(
                !seed.ip().is_unspecified(),
                "seed {} has unspecified IP",
                seed
            );
        }
    }

    #[test]
    fn test_address_manager() {
        let mut mgr = AddressManager::new(10);
        assert!(mgr.is_empty());

        let addr = PeerAddress::new("127.0.0.1:8080".parse().unwrap());
        mgr.add(addr);
        assert_eq!(mgr.len(), 1);

        let next = mgr.get_next();
        assert!(next.is_some());
    }

    #[test]
    fn manual_peer_is_dialed_before_discovered_addresses() {
        let mut mgr = AddressManager::new(100);
        // A pile of discovered addresses with recent last_seen — they would
        // otherwise sort to the front of get_next's last_seen ordering.
        for i in 1..=10u8 {
            let mut pa = PeerAddress::new(format!("198.51.100.{i}:29999").parse().unwrap());
            pa.last_seen = 1_000_000 + i as u64;
            mgr.add(pa);
        }
        let manual: SocketAddr = "203.0.113.7:29105".parse().unwrap();
        mgr.add_manual(manual);
        // The first address handed to the dialer must be the manual peer,
        // regardless of the discovered addresses' recency (P-2 regression).
        assert_eq!(mgr.get_next(), Some(manual));
    }

    #[test]
    fn manual_peer_survives_failure_purge() {
        let mut mgr = AddressManager::new(100);
        let manual: SocketAddr = "203.0.113.7:29105".parse().unwrap();
        mgr.add_manual(manual);
        // Fail it well past the purge threshold that would drop a discovered
        // address from the pool entirely.
        for _ in 0..(FAILURE_PURGE_THRESHOLD + 3) {
            mgr.mark_tried(manual);
        }
        assert_eq!(mgr.len(), 1, "manual peer must never be purged");
        // Once the tried set clears, it is dialable again.
        mgr.clear_tried();
        assert_eq!(mgr.get_next(), Some(manual));
    }

    #[test]
    fn discovered_peer_is_purged_after_threshold() {
        // Control for the test above: a NON-manual address IS purged, proving
        // the exemption is what keeps the manual one alive.
        let mut mgr = AddressManager::new(100);
        let discovered: SocketAddr = "198.51.100.9:29999".parse().unwrap();
        mgr.add(PeerAddress::new(discovered));
        for _ in 0..FAILURE_PURGE_THRESHOLD {
            mgr.mark_tried(discovered);
        }
        assert_eq!(mgr.len(), 0, "discovered peer should be purged at threshold");
    }

    #[test]
    fn test_address_manager_max() {
        // Capacity (max_addresses) test. Uses DISTINCT netgroups — one IP per
        // /16 — so the per-netgroup eclipse cap (H-3) doesn't bound the count
        // first; this proves max_addresses is enforced. The netgroup cap itself
        // is covered by addr_book_resists_single_netgroup_flood.
        let mut mgr = AddressManager::new(5);

        for i in 0..10u8 {
            let addr =
                PeerAddress::new(format!("{}.{}.0.1:8080", 11 + i, 20 + i).parse().unwrap());
            mgr.add(addr);
        }

        assert_eq!(mgr.len(), 5);
    }

    #[test]
    fn tried_eviction_follows_recent_failure_order() {
        let mut mgr = AddressManager::new(MAX_TRIED + 1);
        let max_port = u16::try_from(MAX_TRIED).expect("MAX_TRIED fits in a port number");
        let addr = |port| SocketAddr::from(([192, 0, 2, 1], port));

        for port in 1..=max_port {
            mgr.mark_tried(addr(port));
        }

        let first = addr(1);
        let second = addr(2);
        mgr.mark_tried(first);
        assert_eq!(mgr.tried.len(), MAX_TRIED);

        let newest = addr(max_port + 1);
        mgr.mark_tried(newest);

        assert!(mgr.tried.contains(&first));
        assert!(!mgr.tried.contains(&second));
        assert!(mgr.tried.contains(&newest));
        assert_eq!(mgr.tried.len(), MAX_TRIED);

        mgr.mark_success(first);
        assert!(!mgr.tried_order.contains(&first));

        mgr.clear_tried();
        assert!(mgr.tried.is_empty());
        assert!(mgr.tried_order.is_empty());
    }

    /// Self-address guard (2026-07-08 self-dial incident): once an address
    /// is marked as our own, it must never be dialed AND never be
    /// re-admitted by a later `add()` (which is how peer AddrGossip
    /// re-injects our own IP). Without the `add()` guard, gossip re-adds
    /// our IP and we self-dial again on the next maintenance tick.
    #[test]
    fn self_address_is_never_dialed_or_readded() {
        let mut mgr = AddressManager::new(100);
        let me: SocketAddr = "45.32.79.234:28080".parse().unwrap();
        let peer: SocketAddr = "192.0.2.1:28080".parse().unwrap();

        mgr.add(PeerAddress::new(me));
        mgr.add(PeerAddress::new(peer));
        mgr.mark_self_address(me);
        // Our own address is gone; the real peer remains.
        assert_eq!(mgr.len(), 1);

        // Simulate a peer gossiping our own IP back to us.
        mgr.add(PeerAddress::new(me));
        assert_eq!(
            mgr.len(),
            1,
            "self-address must not be re-admitted via gossip"
        );

        // get_next() must never hand back our own address.
        for _ in 0..5 {
            if let Some(next) = mgr.get_next() {
                assert_ne!(next, me, "get_next() returned our own self-address");
                mgr.mark_tried(next);
            }
        }
    }

    /// ANCHORS (2026-07-09): persisted known-good outbound peers are dialed
    /// FIRST on restart, before the general address book — the Bitcoin Core
    /// anchor model that avoids cold-start dial churn.
    #[test]
    fn anchors_are_dialed_before_general_pool() {
        let mut mgr = AddressManager::new(100);
        let general: SocketAddr = "192.0.2.50:28080".parse().unwrap();
        mgr.add(PeerAddress::new(general));
        let anchor1: SocketAddr = "192.0.2.1:28080".parse().unwrap();
        let anchor2: SocketAddr = "192.0.2.2:28080".parse().unwrap();
        mgr.set_anchors(vec![anchor1, anchor2]);

        let first = mgr.get_next().unwrap();
        assert!(
            first == anchor1 || first == anchor2,
            "anchor dialed first, got {}",
            first
        );
        mgr.mark_tried(first);
        let second = mgr.get_next().unwrap();
        assert!(
            (second == anchor1 || second == anchor2) && second != first,
            "second anchor dialed next, got {}",
            second
        );
        mgr.mark_tried(second);
        // Both anchors tried this cycle → fall through to the general pool.
        assert_eq!(
            mgr.get_next().unwrap(),
            general,
            "general pool used only after anchors are exhausted"
        );
    }

    /// An anchor that turns out to be a self-address (stale anchors file) is
    /// still never dialed.
    #[test]
    fn self_address_anchor_is_skipped() {
        let mut mgr = AddressManager::new(100);
        let me: SocketAddr = "192.0.2.9:28080".parse().unwrap();
        let good: SocketAddr = "192.0.2.1:28080".parse().unwrap();
        mgr.mark_self_address(me);
        mgr.set_anchors(vec![me, good]);
        assert_eq!(
            mgr.get_next().unwrap(),
            good,
            "self anchor skipped, good anchor dialed"
        );
    }

    /// Peer-aging (2026-06-26): after FAILURE_PURGE_THRESHOLD consecutive
    /// mark_tried calls with no intervening mark_success, the address is
    /// purged from the in-memory pool. Prevents the "dead IP gossiped
    /// forever" pattern that starved fleet outbound slots on 2026-06-26.
    #[test]
    fn peer_aging_purges_after_consecutive_failures() {
        let mut mgr = AddressManager::new(100);
        let live: SocketAddr = "192.0.2.1:28080".parse().unwrap();
        let dead: SocketAddr = "192.0.2.99:28080".parse().unwrap();

        mgr.add(PeerAddress::new(live));
        mgr.add(PeerAddress::new(dead));
        assert_eq!(mgr.len(), 2, "both addresses present pre-failures");

        // 4 failures on dead: still present (threshold is 5)
        for _ in 0..4 {
            mgr.mark_tried(dead);
        }
        assert!(
            mgr.addresses.iter().any(|a| a.addr == dead),
            "address must persist until threshold reached"
        );

        // 5th failure on dead: purged
        mgr.mark_tried(dead);
        assert!(
            !mgr.addresses.iter().any(|a| a.addr == dead),
            "address must be purged after FAILURE_PURGE_THRESHOLD consecutive failures"
        );
        assert!(
            mgr.addresses.iter().any(|a| a.addr == live),
            "other addresses must not be affected"
        );
    }

    /// mark_success resets the failure counter — a healthy peer that
    /// occasionally trips a dial timeout shouldn't get purged after a
    /// long uptime.
    #[test]
    fn peer_aging_success_resets_failure_count() {
        let mut mgr = AddressManager::new(100);
        let addr: SocketAddr = "192.0.2.7:28080".parse().unwrap();
        mgr.add(PeerAddress::new(addr));

        // 4 failures, then a success — count resets
        for _ in 0..4 {
            mgr.mark_tried(addr);
        }
        mgr.mark_success(addr);

        // 4 more failures — still under threshold (count was reset, so we're at 4)
        for _ in 0..4 {
            mgr.mark_tried(addr);
        }
        assert!(
            mgr.addresses.iter().any(|a| a.addr == addr),
            "mark_success must reset the failure counter so a flaky-then-healthy peer isn't purged"
        );

        // 5th failure pushes us over
        mgr.mark_tried(addr);
        assert!(
            !mgr.addresses.iter().any(|a| a.addr == addr),
            "5 consecutive failures after the reset must purge"
        );
    }

    /// A purged address can be re-added via gossip — purge is not a
    /// permanent ban (could be a fleet host coming back after maintenance).
    /// Failure count starts fresh on re-add.
    #[test]
    fn peer_aging_purged_address_can_be_readded() {
        let mut mgr = AddressManager::new(100);
        let addr: SocketAddr = "192.0.2.42:28080".parse().unwrap();

        mgr.add(PeerAddress::new(addr));
        for _ in 0..5 {
            mgr.mark_tried(addr);
        }
        assert!(!mgr.addresses.iter().any(|a| a.addr == addr), "purged");

        // Re-add via gossip
        mgr.add(PeerAddress::new(addr));
        assert!(
            mgr.addresses.iter().any(|a| a.addr == addr),
            "re-add via gossip must succeed (purge is not a permanent ban)"
        );

        // Failure count starts fresh — takes another 5 failures to purge again
        for _ in 0..4 {
            mgr.mark_tried(addr);
        }
        assert!(
            mgr.addresses.iter().any(|a| a.addr == addr),
            "after re-add, counter is fresh — 4 failures must not yet purge"
        );
    }

    /// DoS-on-startup defense: an address-book file larger than 1 MiB
    /// must be rejected at the stat() stage before any read or decode.
    /// The oversized file is removed so the node doesn't fail-loop on
    /// every restart.
    #[test]
    fn load_from_file_rejects_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("addrbook.json");

        // 1 MiB + 1 byte — just past the cap. set_len gives us a sparse
        // file on most filesystems, which is fine for the metadata().len()
        // check we're testing.
        let oversize = 1024 * 1024 + 1;
        let f = std::fs::File::create(&path).unwrap();
        f.set_len(oversize).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), oversize);

        let mut mgr = AddressManager::new(100);
        let result = mgr.load_from_file(&path);

        assert!(result.is_err(), "oversized address book must be rejected");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("too large") || err_msg.contains("max"),
            "error must surface size-cap reason, got: {}",
            err_msg
        );
        assert!(
            !path.exists(),
            "oversized address book must be removed after rejection"
        );
    }

    /// Empty-vec roundtrip: a valid empty JSON `[]` must load cleanly
    /// (zero entries, no error).
    #[test]
    fn load_from_file_accepts_empty_array() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("addrbook.json");
        std::fs::write(&path, "[]").unwrap();

        let mut mgr = AddressManager::new(100);
        let loaded = mgr.load_from_file(&path).unwrap();
        assert_eq!(loaded, 0, "empty address book must load zero entries");
        // The non-oversized path does NOT remove the file (only the
        // oversized branch removes), so the file should still be there.
        assert!(path.exists(), "valid file must not be deleted on success");
    }

    /// Entry-count cap: a JSON array with > MAX_ADDRBOOK_ENTRIES (10k)
    /// must be rejected post-decode. Test via 10,001 minimal entries
    /// staying well under the 1 MiB byte cap.
    #[test]
    fn load_from_file_rejects_too_many_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("addrbook.json");

        // Build a JSON array with 10,001 minimal entries. Each
        // PeerAddressSerde entry is roughly:
        //   {"addr":"1.2.3.4:1","last_seen":0,"services":0}
        // ~50 bytes serialized; 10,001 × ~50 ≈ 500 KB — well under 1 MiB.
        let mut s = String::from("[");
        for i in 0..10_001 {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&format!(
                r#"{{"addr":"1.2.3.4:1","last_seen":0,"services":0}}"#
            ));
        }
        s.push(']');
        std::fs::write(&path, &s).unwrap();
        assert!(std::fs::metadata(&path).unwrap().len() < 1024 * 1024,
            "test fixture must fit under the byte cap so we exercise the entry cap, not the byte cap");

        let mut mgr = AddressManager::new(100);
        let result = mgr.load_from_file(&path);
        assert!(result.is_err(), "10,001 entries must be rejected");
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("entries") || err.contains("max"),
            "error must surface entry-cap reason, got: {}",
            err
        );
    }

    #[test]
    fn test_seed_node_parsing() {
        // Valid socket address should be parseable
        let addr: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let peer = PeerAddress::new(addr);
        assert_eq!(peer.addr.port(), 8080);

        // Seed nodes from default config are now strongly typed as SocketAddr
        // already, so the test now verifies they are non-zero ports and
        // non-loopback IPs (a loopback seed would be a deployment misconfig).
        // Phase A5 (audit fix): the previous code called `.parse::<SocketAddr>()`
        // on `&SocketAddr`, which is a type error since SocketAddr doesn't
        // implement FromStr<&SocketAddr>. seed_nodes is `Vec<SocketAddr>`.
        let config = BootstrapConfig::default();
        for seed in &config.seed_nodes {
            assert!(seed.port() != 0, "seed {} has zero port", seed);
            assert!(
                !seed.ip().is_unspecified(),
                "seed {} has unspecified IP (0.0.0.0/::)",
                seed
            );
        }
    }

    #[test]
    fn addr_book_resists_single_netgroup_flood() {
        // H-3 (eclipse): a flood of many IPs from ONE netgroup (203.0.0.0/16)
        // must not crowd out honest peers from other ranges.
        let mut mgr = AddressManager::new(100);
        let cap = (100 / NETGROUP_BOOK_DENOM).max(2); // per-netgroup slot cap

        for i in 0..10_000u32 {
            let a: std::net::SocketAddr =
                format!("203.0.113.{}:{}", i % 256, 30_000 + (i % 20_000))
                    .parse()
                    .unwrap();
            mgr.add(PeerAddress::new(a));
        }
        let flood_ng = netgroup_key("203.0.113.1".parse().unwrap());
        let flood_count = mgr
            .addresses
            .iter()
            .filter(|p| netgroup_key(p.addr.ip()) == flood_ng)
            .count();
        assert!(
            flood_count <= cap,
            "single netgroup occupied {flood_count} slots, cap is {cap}"
        );

        // Honest peers from DISTINCT netgroups are admitted and survive.
        let honest: Vec<std::net::SocketAddr> = vec![
            "198.51.100.7:28333".parse().unwrap(),
            "192.0.2.9:28333".parse().unwrap(),
            "8.8.8.8:28333".parse().unwrap(),
        ];
        for h in &honest {
            mgr.add(PeerAddress::new(*h));
        }
        for h in &honest {
            assert!(
                mgr.addresses.iter().any(|p| p.addr == *h),
                "honest peer {h} was evicted by the single-netgroup flood"
            );
        }
    }
}

// ── Bootstrap env helpers ─────────────────────────────────────────
// Shared by `Bootstrapper::get_peers_with_proxy` above.
//
// NOTE (2026-08-16 dead-code sweep): removed the second, unused bootstrap
// path that lived here — `initial_peers` (+ `load_signed_manifest_peers`,
// `hex_to_32`, `load_signature`, `SignedSeedManifest`,
// `BOOTSTRAP_MANIFEST_DOMAIN`, and the `MAINNET_NODES` / `TESTNET_NODES`
// hardcoded lists). Nothing called `initial_peers` at runtime; the live
// bootstrap path is `Bootstrapper::get_peers`. The signed-manifest tooling
// still lives in `src/bin/bootstrap_manifest_tool.rs`.

fn env_bool(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| {
            let t = v.trim();
            t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
        })
        .unwrap_or(false)
}

fn seed_allowlist() -> Option<HashSet<SocketAddr>> {
    let raw = std::env::var("COINCYNC_BOOTSTRAP_SEED_ALLOWLIST").ok()?;
    let mut set = HashSet::new();
    for token in raw.split(',') {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(addr) = trimmed.parse::<SocketAddr>() {
            set.insert(addr);
        } else {
            tracing::warn!("Ignoring invalid allowlist seed '{}'", trimmed);
        }
    }
    if set.is_empty() {
        None
    } else {
        Some(set)
    }
}
