//! # Network Bootstrap
//!
//! DNS seeds, peer discovery, and network bootstrapping.

use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};
use std::time::Duration;
use std::collections::HashSet;
use std::path::PathBuf;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use tokio::time::timeout;
use tracing::{info, warn};

use crate::error::{Error, Result};
use crate::testnet::{TESTNET_DNS_SEEDS, TESTNET_SEED_NODES, TESTNET_P2P_PORT};
use crate::network::socks_dns;

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
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        BootstrapConfig {
            dns_seeds: TESTNET_DNS_SEEDS.iter().map(|s| s.to_string()).collect(),
            seed_nodes: TESTNET_SEED_NODES.iter()
                .filter_map(|s| s.parse().ok())
                .collect(),
            dns_timeout: Duration::from_secs(5),
            max_addresses: 100,
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
        self.get_peers_with_proxy(onion_only, proxy_active, None).await
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
        let use_proxy_dns = proxy
            .map(|p| p.is_active())
            .unwrap_or(false)
            && !force_disable_dns;

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
                            peers.insert(SocketAddr::new(ip, TESTNET_P2P_PORT));
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

        let mut result: Vec<SocketAddr> = peers.into_iter()
            .take(self.config.max_addresses)
            .collect();

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
            .map(|ip| SocketAddr::new(ip, TESTNET_P2P_PORT))
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

/// Address manager for peer discovery
pub struct AddressManager {
    /// Known addresses
    addresses: Vec<PeerAddress>,
    /// SECURITY (L6): Fast dedup set to prevent duplicate address insertions
    known_addrs: HashSet<SocketAddr>,
    /// Tried addresses (failed connections)
    tried: HashSet<SocketAddr>,
    /// Self-addresses (detected via nonce match) — never connect to these
    self_addresses: HashSet<SocketAddr>,
    /// Maximum addresses to store
    max_addresses: usize,
}

impl AddressManager {
    pub fn new(max_addresses: usize) -> Self {
        AddressManager {
            addresses: Vec::new(),
            known_addrs: HashSet::new(),
            tried: HashSet::new(),
            self_addresses: HashSet::new(),
            max_addresses,
        }
    }

    /// Add a new address
    pub fn add(&mut self, addr: PeerAddress) {
        if self.addresses.len() >= self.max_addresses {
            // Remove oldest
            self.addresses.sort_by_key(|a| std::cmp::Reverse(a.last_seen));
            if let Some(evicted) = self.addresses.pop() {
                self.known_addrs.remove(&evicted.addr);
            }
        }

        // Don't add if already known or tried
        if self.tried.contains(&addr.addr) {
            return;
        }

        // SECURITY (L6): O(1) dedup check via HashSet instead of O(n) linear scan
        if self.known_addrs.insert(addr.addr) {
            self.addresses.push(addr);
        }
    }

    /// Add multiple addresses
    pub fn add_many(&mut self, addrs: Vec<PeerAddress>) {
        for addr in addrs {
            self.add(addr);
        }
    }

    /// Get addresses for peer exchange
    pub fn get_for_exchange(&self, max: usize) -> Vec<PeerAddress> {
        self.addresses.iter()
            .take(max)
            .cloned()
            .collect()
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
        // Sort by last_seen (most recent first)
        self.addresses.sort_by_key(|a| std::cmp::Reverse(a.last_seen));

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
            self.tried.clear();
            // Return first address after clearing
            return self.addresses.first().map(|a| a.addr);
        }

        None
    }

    /// Mark an address as tried (failed)
    ///
    /// SECURITY (M-8): Bounded to MAX_TRIED to prevent unbounded memory growth
    /// and eventual permanent outbound isolation (get_next returns None).
    pub fn mark_tried(&mut self, addr: SocketAddr) {
        const MAX_TRIED: usize = 5_000;
        if self.tried.len() >= MAX_TRIED {
            // Evict an arbitrary entry to make room
            if let Some(&oldest) = self.tried.iter().next() {
                self.tried.remove(&oldest);
            }
        }
        self.tried.insert(addr);
    }

    /// Mark an address as successful
    pub fn mark_success(&mut self, addr: SocketAddr) {
        self.tried.remove(&addr);

        // Update last_seen
        if let Some(peer) = self.addresses.iter_mut().find(|a| a.addr == addr) {
            peer.last_seen = chrono::Utc::now().timestamp() as u64;
        }
    }

    /// Clear tried addresses (for retry)
    pub fn clear_tried(&mut self) {
        self.tried.clear();
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
        let entries: Vec<PeerAddressSerde> = self.addresses.iter().map(|a| PeerAddressSerde {
            addr: a.addr.to_string(),
            last_seen: a.last_seen,
            services: a.services,
        }).collect();

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
        let data = std::fs::read_to_string(path)
            .map_err(|e| Error::InvalidState(format!("read address book: {}", e)))?;
        let entries: Vec<PeerAddressSerde> = serde_json::from_str(&data)
            .map_err(|e| Error::InvalidState(format!("parse address book: {}", e)))?;

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
    let _local_addr = gateway.get_external_ip()
        .await
        .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

    // Add port mapping
    gateway.add_port(
        PortMappingProtocol::TCP,
        external_port,
        SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), internal_port),
        3600, // 1 hour lease
        "CoinCync",
    ).await
        .map_err(|e| Error::ConnectionFailed(format!("UPnP port mapping failed: {}", e)))?;

    info!("UPnP port mapping successful: {} -> {}", external_port, internal_port);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bootstrap_config() {
        // Phase A7-6 (audit fix): the previous version asserted exactly 3 seed
        // nodes. The seed list grew to 5 (NYC, RIC, TOR, ATL, SFO) when more
        // testnet infrastructure came online — the test was stale. Assert
        // ranges instead of exact counts so future seed additions don't
        // require touching this test.
        let config = BootstrapConfig::default();
        assert!(config.dns_seeds.len()  >= 1, "must have at least one DNS seed");
        assert!(config.seed_nodes.len() >= 3, "must have at least 3 seed nodes");
        assert!(config.seed_nodes.len() <= 32,
            "more than 32 seed nodes suggests a config bug");
        assert_eq!(config.dns_timeout, Duration::from_secs(5));
        assert_eq!(config.max_addresses, 100);
        // Sanity: every seed must use a non-zero port and a non-loopback IP.
        for seed in &config.seed_nodes {
            assert!(seed.port() != 0, "seed {} has zero port", seed);
            assert!(!seed.ip().is_unspecified(),
                "seed {} has unspecified IP", seed);
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
    fn test_address_manager_max() {
        let mut mgr = AddressManager::new(5);

        for i in 0..10 {
            let addr = PeerAddress::new(format!("127.0.0.{}:8080", i).parse().unwrap());
            mgr.add(addr);
        }

        assert_eq!(mgr.len(), 5);
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
            assert!(!seed.ip().is_unspecified(),
                "seed {} has unspecified IP (0.0.0.0/::)", seed);
        }
    }
}

// ── CoinCync 1.0 additions ────────────────────────────────────────
// Kept separate from the 2.0 Bootstrapper machinery above. These are
// the plain fallback lists and the `initial_peers` helper that the
// 1.0 CLI (bin/node.rs) calls when starting up.

use crate::config::{Network, NodeConfig};
use super::dns_seeds::resolve_seeds_with_proxy;

const BOOTSTRAP_MANIFEST_DOMAIN: &[u8] = b"coincync/bootstrap-manifest/v1";

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

#[derive(serde::Deserialize)]
struct SignedSeedManifest {
    peers: Vec<String>,
}

fn hex_to_32(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim()).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn load_signature(path: &PathBuf) -> Option<[u8; 64]> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() == 64 {
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        return Some(out);
    }
    let as_text = std::str::from_utf8(&bytes).ok()?.trim();
    let decoded = hex::decode(as_text).ok()?;
    if decoded.len() != 64 {
        return None;
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&decoded);
    Some(out)
}

fn load_signed_manifest_peers(network: Network) -> Vec<SocketAddr> {
    let manifest_path = match std::env::var("COINCYNC_BOOTSTRAP_SIGNED_MANIFEST") {
        Ok(v) if !v.trim().is_empty() => PathBuf::from(v.trim()),
        _ => return Vec::new(),
    };

    let pubkey_hex = match std::env::var("COINCYNC_BOOTSTRAP_SIGNING_PUBKEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            warn!("Signed bootstrap manifest requested but COINCYNC_BOOTSTRAP_SIGNING_PUBKEY is missing");
            return Vec::new();
        }
    };

    let pubkey_bytes = match hex_to_32(&pubkey_hex) {
        Some(v) => v,
        None => {
            warn!("Invalid COINCYNC_BOOTSTRAP_SIGNING_PUBKEY (expected 32-byte hex)");
            return Vec::new();
        }
    };

    let verify_key = match VerifyingKey::from_bytes(&pubkey_bytes) {
        Ok(v) => v,
        Err(e) => {
            warn!("Invalid bootstrap signing key: {}", e);
            return Vec::new();
        }
    };

    let sig_path = std::env::var("COINCYNC_BOOTSTRAP_SIGNED_MANIFEST_SIG")
        .ok()
        .map(|v| PathBuf::from(v.trim()))
        .unwrap_or_else(|| PathBuf::from(format!("{}.sig", manifest_path.display())));
    let signature = match load_signature(&sig_path) {
        Some(v) => Signature::from_bytes(&v),
        None => {
            warn!("Unable to read bootstrap manifest signature at {}", sig_path.display());
            return Vec::new();
        }
    };

    let manifest_bytes = match std::fs::read(&manifest_path) {
        Ok(v) => v,
        Err(e) => {
            warn!("Unable to read bootstrap manifest {}: {}", manifest_path.display(), e);
            return Vec::new();
        }
    };

    let mut msg = Vec::with_capacity(BOOTSTRAP_MANIFEST_DOMAIN.len() + manifest_bytes.len());
    msg.extend_from_slice(BOOTSTRAP_MANIFEST_DOMAIN);
    msg.extend_from_slice(&manifest_bytes);
    if verify_key.verify(&msg, &signature).is_err() {
        warn!(
            "Bootstrap manifest signature verification failed for {}",
            manifest_path.display()
        );
        return Vec::new();
    }

    let parsed: SignedSeedManifest = match serde_json::from_slice(&manifest_bytes) {
        Ok(v) => v,
        Err(e) => {
            warn!("Invalid bootstrap manifest JSON: {}", e);
            return Vec::new();
        }
    };

    let mut out = Vec::new();
    for raw in parsed.peers {
        let with_port = if raw.contains(':') {
            raw
        } else {
            format!("{}:{}", raw, network.p2p_port())
        };
        if let Ok(addr) = with_port.parse::<SocketAddr>() {
            out.push(addr);
        } else {
            warn!("Skipping invalid manifest peer '{}'", with_port);
        }
    }
    out
}

pub const TESTNET_NODES: &[(&str, &str)] = &[
    ("45.55.32.13:28333",      "NYC relay"),
    ("165.245.161.62:28333",   "RIC relay"),
    ("143.110.218.99:28333",   "TOR relay"),
    ("165.245.140.113:28333",  "ATL miner"),
    ("64.227.49.44:28333",     "SFO relay + faucet"),
    ("138.68.172.80:28333",    "LON relay + monitoring"),
];

pub const MAINNET_NODES: &[(&str, &str)] = &[
    // Populated at mainnet launch.
];

/// Build the initial peer list combining CLI addnodes, DNS seeds, and
/// hardcoded fallbacks. Used by `bin/node.rs` when starting the node.
pub async fn initial_peers(config: &NodeConfig) -> Vec<SocketAddr> {
    let mut peers: Vec<SocketAddr> = Vec::new();
    let allowlist = seed_allowlist();
    let force_disable_dns = env_bool("COINCYNC_BOOTSTRAP_DISABLE_DNS");
    let manifest_only = env_bool("COINCYNC_BOOTSTRAP_MANIFEST_ONLY");

    for addr_str in &config.addnodes {
        let with_port = if addr_str.contains(':') {
            addr_str.clone()
        } else {
            format!("{}:{}", addr_str, config.network.p2p_port())
        };
        if let Ok(addr) = with_port.parse::<SocketAddr>() {
            peers.push(addr);
        }
    }

    if config.no_peers {
        return peers;
    }

    let mut signed_manifest_peers = load_signed_manifest_peers(config.network);
    if !signed_manifest_peers.is_empty() {
        tracing::info!(
            "Bootstrap: loaded {} signed manifest peers",
            signed_manifest_peers.len()
        );
        peers.append(&mut signed_manifest_peers);
    }

    if !manifest_only && !force_disable_dns {
        // Pass the proxy reference so resolve_seeds_with_proxy routes DNS
        // through SOCKS5 (DNS-over-TCP) when a proxy is active rather than
        // leaking queries to the user's ISP via the OS resolver. The
        // proxy=None path is identical to the legacy clearnet behaviour.
        let mut seed_peers = resolve_seeds_with_proxy(
            config.network,
            config.p2p.proxy.as_ref(),
        )
        .await;
        peers.append(&mut seed_peers);
    } else if force_disable_dns {
        tracing::warn!("Bootstrap DNS disabled via COINCYNC_BOOTSTRAP_DISABLE_DNS=1");
    } else if manifest_only {
        tracing::info!("Bootstrap manifest-only mode enabled; skipping DNS/hardcoded fallback");
    }

    if peers.is_empty() && !manifest_only {
        let hardcoded = match config.network {
            Network::Mainnet => MAINNET_NODES,
            Network::Testnet => TESTNET_NODES,
            Network::Regtest => &[],
        };
        for (addr_str, label) in hardcoded {
            if let Ok(addr) = addr_str.parse::<SocketAddr>() {
                tracing::debug!("Adding hardcoded peer {} ({})", addr, label);
                peers.push(addr);
            }
        }
    }

    peers.sort_unstable();
    peers.dedup();

    if let Some(ref allowed) = allowlist {
        peers.retain(|p| allowed.contains(p));
    }

    tracing::info!("Bootstrap: {} initial peer candidates", peers.len());
    peers
}
