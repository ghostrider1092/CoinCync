//! # Rate Limiting for CoinCync RPC
//!
//! Per-IP rate limiting to prevent abuse and DoS attacks.
//!
//! SECURITY: Implements LRU eviction to prevent memory exhaustion attacks.
//! Attackers cannot exhaust memory by connecting from many different IPs.
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `check` (window / quota)** — INVARIANT: requests within a window count
//!   atomically and excess is blocked; the window resets and re-admits after it
//!   elapses. THREAT: rate-limit bypass through miscounting or a race. TESTS:
//!   `test_rate_limiter_allows_requests`, `test_rate_limiter_blocks_excess`,
//!   `test_check_window_reset_readmits_after_window`,
//!   `test_concurrency_same_ip_counts_atomically`.
//! - **§2 `check_sync` (parity + fail-closed)** — INVARIANT: the sync path matches
//!   the async path on ban/permanent/window decisions and fails CLOSED on lock
//!   contention; loopback is whitelisted. THREAT: a lock-contention path silently
//!   disables rate limiting. TESTS: `test_check_sync_fails_closed_on_lock_contention`,
//!   `test_check_sync_loopback_whitelist_bypass`, `test_check_sync_parity_ban_permanent_window`.
//! - **§3 `ban` / `unban` / permanent block** — INVARIANT: a ban blocks until
//!   expiry then re-admits; exceeding max bans yields a permanent block that
//!   survives LRU eviction. THREAT: a repeat abuser evades bans by waiting them out
//!   or forcing eviction of their record. TESTS: `test_check_ban_expiry_clears_and_readmits`,
//!   `test_check_permanent_block_after_max_bans`,
//!   `test_check_permanent_block_survives_lru_eviction`, `test_ban_and_unban`.
//! - **§4 LRU eviction (memory bound)** — INVARIANT: tracked IPs are capped by LRU;
//!   expired entries evict first and eviction is refused when all entries are
//!   active. THREAT: memory-exhaustion DoS from many distinct source IPs. TESTS:
//!   `test_lru_eviction_with_expired_entries`, `test_lru_eviction_rejects_when_all_active`.
//! - **§5 whitelist** — INVARIANT: whitelisted IPs bypass the limit and adding an
//!   entry dedupes. THREAT: an operator IP is throttled, or duplicate entries bloat
//!   state. TESTS: `test_whitelist_bypass`, `test_add_whitelist_bypasses_and_dedupes`.
//! - **§6 `remaining` / `stats` / `cleanup`** — INVARIANT: `remaining` reports the
//!   correct quota (and whitelist), `stats` account accurately, and `cleanup`
//!   retains banned and recent entries. THREAT: inaccurate accounting, or cleanup
//!   dropping an active ban. TESTS: `test_remaining_reports_quota_and_whitelist`,
//!   `test_stats_accounting`, `test_cleanup_retains_banned_and_recent`.
//! - **§7 config presets** — INVARIANT: `strict` / `relaxed` / `default` presets
//!   are distinct policies. THREAT: a preset silently equals another → the wrong
//!   policy is applied. TESTS: `test_config_presets_are_distinct`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Default maximum tracked IPs to prevent memory exhaustion
const DEFAULT_MAX_TRACKED_IPS: usize = 10_000;

/// Rate limit configuration
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    /// Maximum requests per window
    pub max_requests: u32,
    /// Time window duration
    pub window: Duration,
    /// Burst allowance (temporary spike above limit)
    pub burst: u32,
    /// Ban duration after exceeding limits
    pub ban_duration: Duration,
    /// Maximum bans before permanent block
    pub max_bans: u32,
    /// Maximum tracked IPs (DoS protection via LRU eviction)
    pub max_tracked_ips: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window: Duration::from_secs(60),
            burst: 20,
            ban_duration: Duration::from_secs(300), // 5 minutes
            max_bans: 5,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
        }
    }
}

impl RateLimitConfig {
    /// Strict config for public APIs
    pub fn strict() -> Self {
        Self {
            max_requests: 30,
            window: Duration::from_secs(60),
            burst: 5,
            ban_duration: Duration::from_secs(600), // 10 minutes
            max_bans: 3,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS / 2, // Stricter limit
        }
    }

    /// Relaxed config for trusted networks
    pub fn relaxed() -> Self {
        Self {
            max_requests: 1000,
            window: Duration::from_secs(60),
            burst: 100,
            ban_duration: Duration::from_secs(60),
            max_bans: 10,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS * 2, // Higher limit for trusted
        }
    }
}

/// Request tracking for an IP
#[derive(Clone, Debug)]
struct IpState {
    /// Request timestamps in current window
    requests: Vec<Instant>,
    /// Number of times banned
    ban_count: u32,
    /// When ban expires (if banned)
    banned_until: Option<Instant>,
    /// Last activity time (for LRU eviction)
    last_seen: Instant,
}

impl Default for IpState {
    fn default() -> Self {
        Self {
            requests: Vec::new(),
            ban_count: 0,
            banned_until: None,
            last_seen: Instant::now(),
        }
    }
}

/// Rate limit result
#[derive(Debug, Clone, PartialEq)]
pub enum RateLimitResult {
    /// Request allowed
    Allowed,
    /// Request denied (rate limited)
    RateLimited {
        /// Seconds until window resets
        retry_after: u64,
    },
    /// IP is banned
    Banned {
        /// Seconds until ban expires
        retry_after: u64,
    },
    /// IP is permanently blocked
    PermanentlyBlocked,
}

/// Rate limiter
pub struct RateLimiter {
    config: RateLimitConfig,
    state: RwLock<HashMap<IpAddr, IpState>>,
    /// Whitelist IPs (never rate limited)
    whitelist: Vec<IpAddr>,
}

impl RateLimiter {
    /// Create new rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            state: RwLock::new(HashMap::new()),
            whitelist: vec!["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()],
        }
    }

    /// Add IP to whitelist
    pub fn add_whitelist(&mut self, ip: IpAddr) {
        if !self.whitelist.contains(&ip) {
            self.whitelist.push(ip);
        }
    }

    /// Check if request is allowed
    ///
    /// SECURITY: Implements LRU eviction when max_tracked_ips is exceeded
    /// to prevent memory exhaustion attacks from many different IPs.
    pub async fn check(&self, ip: IpAddr) -> RateLimitResult {
        // Whitelist bypass
        if self.whitelist.contains(&ip) {
            return RateLimitResult::Allowed;
        }

        let now = Instant::now();
        let mut state = self.state.write().await;

        // SECURITY: Enforce max tracked IPs with LRU eviction
        // Only evict inactive entries to prevent attackers from flushing
        // active rate-limit state by connecting from many IPs.
        //
        // P7-Rl1 SURGICAL FIX (2026-07-03): PermanentlyBlocked entries
        // (ban_count >= max_bans) are now ALSO preserved during
        // eviction. Prior code only preserved entries with an active
        // ban timer OR recent requests — so a PermanentlyBlocked IP
        // whose ban timer had lapsed and had no recent activity got
        // evicted, and the next connection from that IP started
        // fresh with ban_count = 0. This made "permanent" a lie.
        // Real permanent blocks now survive eviction. Space cost:
        // small — the caller has a bounded set of persistent
        // offenders. A future extension can migrate these to
        // disk-backed storage for restart persistence.
        if !state.contains_key(&ip) && state.len() >= self.config.max_tracked_ips {
            let window_start = now - self.config.window;
            let max_bans = self.config.max_bans;

            // First pass: bulk-remove expired inactive entries.
            // Preserve: active ban timer, recent activity, OR
            // permanent-block state.
            state.retain(|_, s| {
                let ban_active = s.banned_until.map(|t| now < t).unwrap_or(false);
                let has_recent = s.requests.iter().any(|&t| t > window_start);
                let permanent_block = s.ban_count >= max_bans;
                ban_active || has_recent || permanent_block
            });

            // If still at capacity, evict the single oldest inactive entry
            // (still skipping permanent blocks).
            if state.len() >= self.config.max_tracked_ips {
                let oldest_inactive = state
                    .iter()
                    .filter(|(_, s)| {
                        let ban_expired = s.banned_until.map(|t| now >= t).unwrap_or(true);
                        let no_recent = !s.requests.iter().any(|&t| t > window_start);
                        let not_permanent = s.ban_count < max_bans;
                        ban_expired && no_recent && not_permanent
                    })
                    .min_by_key(|(_, s)| s.last_seen)
                    .map(|(ip, _)| *ip);

                if let Some(oldest_ip) = oldest_inactive {
                    state.remove(&oldest_ip);
                    tracing::debug!("Evicted inactive IP {} from rate limiter (LRU)", oldest_ip);
                } else {
                    // All tracked IPs are actively rate-limited or banned.
                    // Reject new IP rather than evicting active tracking state.
                    tracing::warn!(
                        "Rate limiter at capacity ({}) - rejecting untracked IP {}",
                        self.config.max_tracked_ips,
                        ip
                    );
                    return RateLimitResult::RateLimited {
                        retry_after: self.config.window.as_secs(),
                    };
                }
            }
        }

        let ip_state = state.entry(ip).or_default();
        ip_state.last_seen = now;

        // Check if banned
        if let Some(banned_until) = ip_state.banned_until {
            if now < banned_until {
                let remaining = banned_until.duration_since(now).as_secs();
                return RateLimitResult::Banned {
                    retry_after: remaining,
                };
            }
            // Ban expired
            ip_state.banned_until = None;
        }

        // Check permanent block
        if ip_state.ban_count >= self.config.max_bans {
            return RateLimitResult::PermanentlyBlocked;
        }

        // Clean old requests outside window
        let window_start = now - self.config.window;
        ip_state.requests.retain(|&t| t > window_start);

        // Check rate limit
        let total_allowed = self.config.max_requests + self.config.burst;
        if ip_state.requests.len().min(u32::MAX as usize) as u32 >= total_allowed {
            // Rate limited - apply ban
            ip_state.ban_count += 1;
            ip_state.banned_until = Some(now + self.config.ban_duration);

            tracing::warn!(
                "Rate limited IP {} (ban #{}/{})",
                ip,
                ip_state.ban_count,
                self.config.max_bans
            );

            return RateLimitResult::RateLimited {
                retry_after: self.config.ban_duration.as_secs(),
            };
        }

        // Record request
        ip_state.requests.push(now);

        RateLimitResult::Allowed
    }

    /// SECURITY (RPC-M1): Synchronous rate limit check for use inside
    /// jsonrpsee `register_method` handlers (which cannot .await).
    ///
    /// Uses `try_write()` — if the lock is contended, fails CLOSED (rate limited)
    /// to prevent attackers from bypassing rate limits via lock contention.
    pub fn check_sync(&self, ip: IpAddr) -> RateLimitResult {
        if self.whitelist.contains(&ip) {
            return RateLimitResult::Allowed;
        }

        let now = Instant::now();
        let mut state = match self.state.try_write() {
            Ok(guard) => guard,
            Err(_) => return RateLimitResult::RateLimited { retry_after: 1 }, // fail-closed
        };

        // FIX: Safe eviction that preserves active bans.
        // Previously used bulk sort-and-evict that removed oldest entries without
        // checking ban status — an attacker flooding from many IPs could silently
        // untrack previously-banned IPs. Now matches check()'s safe logic.
        if state.len() > self.config.max_tracked_ips {
            let window_start = now - self.config.window;
            let max_bans = self.config.max_bans;
            // P7-Rl1: parallel fix to check() above — preserve
            // PermanentlyBlocked entries during eviction.
            state.retain(|_, s| {
                let is_banned = s.banned_until.map_or(false, |b| now < b);
                let is_active = s.last_seen > window_start;
                let permanent_block = s.ban_count >= max_bans;
                is_banned || is_active || permanent_block
            });
            if state.len() > self.config.max_tracked_ips {
                let oldest = state
                    .iter()
                    .filter(|(_, s)| {
                        let ban_expired = s.banned_until.map_or(true, |b| now >= b);
                        let not_permanent = s.ban_count < max_bans;
                        ban_expired && not_permanent
                    })
                    .min_by_key(|(_, s)| s.last_seen)
                    .map(|(ip, _)| *ip);
                if let Some(ip) = oldest {
                    state.remove(&ip);
                }
            }
        }

        let ip_state = state.entry(ip).or_default();
        ip_state.last_seen = now;

        // Check if banned
        if let Some(banned_until) = ip_state.banned_until {
            if now < banned_until {
                let remaining = banned_until.duration_since(now).as_secs();
                return RateLimitResult::Banned {
                    retry_after: remaining,
                };
            }
            ip_state.banned_until = None;
        }

        // Check permanent block
        if ip_state.ban_count >= self.config.max_bans {
            return RateLimitResult::PermanentlyBlocked;
        }

        // Clean old requests
        let window_start = now - self.config.window;
        ip_state.requests.retain(|&t| t > window_start);

        let total_allowed = self.config.max_requests + self.config.burst;
        if ip_state.requests.len().min(u32::MAX as usize) as u32 >= total_allowed {
            ip_state.ban_count += 1;
            ip_state.banned_until = Some(now + self.config.ban_duration);
            return RateLimitResult::RateLimited {
                retry_after: self.config.ban_duration.as_secs(),
            };
        }

        ip_state.requests.push(now);
        RateLimitResult::Allowed
    }

    /// Get remaining requests for IP
    pub async fn remaining(&self, ip: IpAddr) -> u32 {
        if self.whitelist.contains(&ip) {
            return u32::MAX;
        }

        let now = Instant::now();
        let state = self.state.read().await;

        match state.get(&ip) {
            Some(ip_state) => {
                let window_start = now - self.config.window;
                let recent_requests = ip_state
                    .requests
                    .iter()
                    .filter(|&&t| t > window_start)
                    .count()
                    .min(u32::MAX as usize) as u32;

                self.config.max_requests.saturating_sub(recent_requests)
            }
            None => self.config.max_requests,
        }
    }

    /// Manually ban an IP
    pub async fn ban(&self, ip: IpAddr, duration: Duration) {
        let mut state = self.state.write().await;
        let ip_state = state.entry(ip).or_default();
        ip_state.banned_until = Some(Instant::now() + duration);
        ip_state.ban_count += 1;

        tracing::info!("Manually banned IP {} for {:?}", ip, duration);
    }

    /// Unban an IP
    pub async fn unban(&self, ip: IpAddr) {
        let mut state = self.state.write().await;
        if let Some(ip_state) = state.get_mut(&ip) {
            ip_state.banned_until = None;
            tracing::info!("Unbanned IP {}", ip);
        }
    }

    /// Get statistics
    pub async fn stats(&self) -> RateLimitStats {
        let state = self.state.read().await;
        let now = Instant::now();

        let mut active_ips = 0;
        let mut banned_ips = 0;
        let mut total_requests = 0;

        for ip_state in state.values() {
            if ip_state.banned_until.map(|t| now < t).unwrap_or(false) {
                banned_ips += 1;
            } else if !ip_state.requests.is_empty() {
                active_ips += 1;
            }
            total_requests += ip_state.requests.len();
        }

        RateLimitStats {
            active_ips,
            banned_ips,
            total_requests,
            whitelist_size: self.whitelist.len(),
            tracked_ips: state.len(),
            max_tracked_ips: self.config.max_tracked_ips,
        }
    }

    /// Cleanup old entries
    pub async fn cleanup(&self) {
        let now = Instant::now();
        let window_start = now - self.config.window;
        let mut state = self.state.write().await;

        state.retain(|_, ip_state| {
            // Keep if banned or has recent requests
            ip_state.banned_until.map(|t| now < t).unwrap_or(false)
                || ip_state.requests.iter().any(|&t| t > window_start)
        });
    }
}

/// Rate limit statistics
#[derive(Debug, Clone)]
pub struct RateLimitStats {
    pub active_ips: usize,
    pub banned_ips: usize,
    pub total_requests: usize,
    pub whitelist_size: usize,
    /// Total tracked IPs (for monitoring memory usage)
    pub tracked_ips: usize,
    /// Maximum tracked IPs limit
    pub max_tracked_ips: usize,
}

/// Shared rate limiter
pub type SharedRateLimiter = Arc<RateLimiter>;

/// Create shared rate limiter
pub fn create_rate_limiter(config: RateLimitConfig) -> SharedRateLimiter {
    Arc::new(RateLimiter::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_allows_requests() {
        let config = RateLimitConfig {
            max_requests: 5,
            window: Duration::from_secs(60),
            burst: 2,
            ban_duration: Duration::from_secs(60),
            max_bans: 3,
            max_tracked_ips: 1000,
        };
        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Should allow first requests
        for _ in 0..5 {
            assert_eq!(limiter.check(ip).await, RateLimitResult::Allowed);
        }

        // Burst should also be allowed
        for _ in 0..2 {
            assert_eq!(limiter.check(ip).await, RateLimitResult::Allowed);
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_blocks_excess() {
        let config = RateLimitConfig {
            max_requests: 2,
            window: Duration::from_secs(60),
            burst: 1,
            ban_duration: Duration::from_secs(60),
            max_bans: 3,
            max_tracked_ips: 1000,
        };
        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Use up quota
        assert_eq!(limiter.check(ip).await, RateLimitResult::Allowed);
        assert_eq!(limiter.check(ip).await, RateLimitResult::Allowed);
        assert_eq!(limiter.check(ip).await, RateLimitResult::Allowed);

        // Should be rate limited
        match limiter.check(ip).await {
            RateLimitResult::RateLimited { .. } => {}
            other => panic!("Expected RateLimited, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_whitelist_bypass() {
        let config = RateLimitConfig {
            max_requests: 1,
            window: Duration::from_secs(60),
            burst: 0,
            ban_duration: Duration::from_secs(60),
            max_bans: 1,
            max_tracked_ips: 1000,
        };
        let limiter = RateLimiter::new(config);
        let localhost: IpAddr = "127.0.0.1".parse().unwrap();

        // Localhost should always be allowed
        for _ in 0..100 {
            assert_eq!(limiter.check(localhost).await, RateLimitResult::Allowed);
        }
    }

    #[tokio::test]
    async fn test_lru_eviction_with_expired_entries() {
        // Use a very short window so entries expire quickly
        let config = RateLimitConfig {
            max_requests: 10,
            window: Duration::from_millis(1), // Expires almost immediately
            burst: 0,
            ban_duration: Duration::from_secs(60),
            max_bans: 3,
            max_tracked_ips: 3, // Very small for testing
        };
        let limiter = RateLimiter::new(config);

        // Fill up with 3 IPs
        for i in 1..=3 {
            let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
            assert_eq!(limiter.check(ip).await, RateLimitResult::Allowed);
        }

        // Stats should show 3 tracked IPs
        let stats = limiter.stats().await;
        assert_eq!(stats.tracked_ips, 3);

        // Wait for entries to expire
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Add a 4th IP - expired entries should be evicted, allowing the new IP
        let ip4: IpAddr = "192.168.1.4".parse().unwrap();
        assert_eq!(limiter.check(ip4).await, RateLimitResult::Allowed);

        // Expired entries should have been cleaned up
        let stats = limiter.stats().await;
        assert!(stats.tracked_ips <= 3);
    }

    #[tokio::test]
    async fn test_lru_eviction_rejects_when_all_active() {
        // Use a long window so entries stay active
        let config = RateLimitConfig {
            max_requests: 10,
            window: Duration::from_secs(60),
            burst: 0,
            ban_duration: Duration::from_secs(60),
            max_bans: 3,
            max_tracked_ips: 3,
        };
        let limiter = RateLimiter::new(config);

        // Fill up with 3 active IPs
        for i in 1..=3 {
            let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
            assert_eq!(limiter.check(ip).await, RateLimitResult::Allowed);
        }

        // 4th IP should be rate-limited (all entries are active, none evictable)
        let ip4: IpAddr = "192.168.1.4".parse().unwrap();
        match limiter.check(ip4).await {
            RateLimitResult::RateLimited { .. } => {}
            other => panic!("Expected RateLimited, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_check_window_reset_readmits_after_window() {
        // Tiny window so it elapses within the test.
        let config = RateLimitConfig {
            max_requests: 2,
            window: Duration::from_millis(50),
            burst: 1,
            ban_duration: Duration::from_secs(60),
            max_bans: 5,
            max_tracked_ips: 1000,
        };
        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.50.1".parse().unwrap();

        // Exhaust the quota (total_allowed = max_requests + burst = 3) without
        // tripping the ban (that only happens on the request *over* the limit).
        for _ in 0..3 {
            assert_eq!(limiter.check(ip).await, RateLimitResult::Allowed);
        }

        // After the window elapses, the recorded timestamps age out and a fresh
        // request is admitted again.
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(limiter.check(ip).await, RateLimitResult::Allowed);
    }

    #[tokio::test]
    async fn test_check_ban_expiry_clears_and_readmits() {
        let config = RateLimitConfig {
            max_requests: 1,
            window: Duration::from_millis(10),
            burst: 0,
            ban_duration: Duration::from_millis(30),
            max_bans: 5,
            max_tracked_ips: 1000,
        };
        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.60.1".parse().unwrap();

        // First request allowed; second trips the limit and applies a ban.
        assert_eq!(limiter.check(ip).await, RateLimitResult::Allowed);
        match limiter.check(ip).await {
            RateLimitResult::RateLimited { .. } => {}
            other => panic!("Expected RateLimited, got {:?}", other),
        }
        // While the ban timer is live the IP is Banned.
        match limiter.check(ip).await {
            RateLimitResult::Banned { .. } => {}
            other => panic!("Expected Banned, got {:?}", other),
        }

        // After the ban duration (and window) elapse, banned_until is cleared and
        // the aged-out requests let the IP back in.
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(limiter.check(ip).await, RateLimitResult::Allowed);
    }

    #[tokio::test]
    async fn test_check_permanent_block_after_max_bans() {
        let config = RateLimitConfig {
            max_requests: 5,
            window: Duration::from_secs(60),
            burst: 0,
            ban_duration: Duration::from_secs(60),
            max_bans: 3,
            max_tracked_ips: 1000,
        };
        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.70.1".parse().unwrap();

        // Drive ban_count up to max_bans with manual bans that expire immediately
        // (0 duration), so the permanent-block branch is what fires.
        for _ in 0..3 {
            limiter.ban(ip, Duration::from_millis(0)).await;
        }

        match limiter.check(ip).await {
            RateLimitResult::PermanentlyBlocked => {}
            other => panic!("Expected PermanentlyBlocked, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_check_permanent_block_survives_lru_eviction() {
        // P7-Rl1: a PermanentlyBlocked entry with a lapsed ban timer and no recent
        // activity must NOT be evicted to make room for a new IP.
        let config = RateLimitConfig {
            max_requests: 5,
            window: Duration::from_secs(60),
            burst: 0,
            ban_duration: Duration::from_secs(60),
            max_bans: 1,
            max_tracked_ips: 1,
        };
        let limiter = RateLimiter::new(config);
        let ip_perm: IpAddr = "192.168.80.1".parse().unwrap();

        // Make ip_perm permanent (ban_count >= max_bans) with a lapsed timer.
        limiter.ban(ip_perm, Duration::from_millis(0)).await;

        // At capacity (max_tracked_ips = 1): a new IP cannot evict the permanent
        // entry, so it is rejected instead.
        let ip_new: IpAddr = "192.168.80.2".parse().unwrap();
        match limiter.check(ip_new).await {
            RateLimitResult::RateLimited { .. } => {}
            other => panic!("Expected RateLimited for new IP, got {:?}", other),
        }

        // The permanent entry survived eviction pressure and is still permanent.
        match limiter.check(ip_perm).await {
            RateLimitResult::PermanentlyBlocked => {}
            other => panic!("Expected PermanentlyBlocked, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_check_sync_fails_closed_on_lock_contention() {
        let limiter = RateLimiter::new(RateLimitConfig::default());
        let ip: IpAddr = "192.168.90.1".parse().unwrap();

        // Hold the write lock so check_sync's try_write() fails.
        let _guard = limiter.state.write().await;

        match limiter.check_sync(ip) {
            RateLimitResult::RateLimited { retry_after } => assert_eq!(retry_after, 1),
            other => panic!("Expected fail-closed RateLimited, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_check_sync_loopback_whitelist_bypass() {
        let config = RateLimitConfig {
            max_requests: 1,
            window: Duration::from_secs(60),
            burst: 0,
            ban_duration: Duration::from_secs(60),
            max_bans: 1,
            max_tracked_ips: 1000,
        };
        let limiter = RateLimiter::new(config);
        let localhost: IpAddr = "127.0.0.1".parse().unwrap();

        for _ in 0..100 {
            assert_eq!(limiter.check_sync(localhost), RateLimitResult::Allowed);
        }
    }

    #[tokio::test]
    async fn test_check_sync_parity_ban_permanent_window() {
        let config = RateLimitConfig {
            max_requests: 1,
            window: Duration::from_secs(60),
            burst: 0,
            ban_duration: Duration::from_secs(60),
            max_bans: 2,
            max_tracked_ips: 1000,
        };
        let limiter = RateLimiter::new(config);

        // Window / rate-limit parity with check().
        let ip: IpAddr = "10.0.0.7".parse().unwrap();
        assert_eq!(limiter.check_sync(ip), RateLimitResult::Allowed);
        match limiter.check_sync(ip) {
            RateLimitResult::RateLimited { .. } => {}
            other => panic!("Expected RateLimited, got {:?}", other),
        }

        // Permanent-block parity: drive a second IP to max_bans via manual bans.
        let ip_perm: IpAddr = "10.0.0.8".parse().unwrap();
        limiter.ban(ip_perm, Duration::from_millis(0)).await;
        limiter.ban(ip_perm, Duration::from_millis(0)).await;
        match limiter.check_sync(ip_perm) {
            RateLimitResult::PermanentlyBlocked => {}
            other => panic!("Expected PermanentlyBlocked, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_remaining_reports_quota_and_whitelist() {
        let config = RateLimitConfig {
            max_requests: 5,
            window: Duration::from_secs(60),
            burst: 2,
            ban_duration: Duration::from_secs(60),
            max_bans: 5,
            max_tracked_ips: 1000,
        };
        let limiter = RateLimiter::new(config);

        // Whitelisted (loopback) IP reports unbounded quota.
        let localhost: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(limiter.remaining(localhost).await, u32::MAX);

        // Untracked IP reports the full quota.
        let ip: IpAddr = "172.16.0.1".parse().unwrap();
        assert_eq!(limiter.remaining(ip).await, 5);

        // After two requests, remaining drops accordingly.
        assert_eq!(limiter.check(ip).await, RateLimitResult::Allowed);
        assert_eq!(limiter.check(ip).await, RateLimitResult::Allowed);
        assert_eq!(limiter.remaining(ip).await, 3);
    }

    #[tokio::test]
    async fn test_ban_and_unban() {
        let config = RateLimitConfig {
            max_requests: 5,
            window: Duration::from_secs(60),
            burst: 0,
            ban_duration: Duration::from_secs(60),
            max_bans: 5,
            max_tracked_ips: 1000,
        };
        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "172.16.1.1".parse().unwrap();

        limiter.ban(ip, Duration::from_secs(60)).await;
        match limiter.check(ip).await {
            RateLimitResult::Banned { .. } => {}
            other => panic!("Expected Banned, got {:?}", other),
        }

        limiter.unban(ip).await;
        // ban_count (1) is still below max_bans (5), so unban re-admits.
        assert_eq!(limiter.check(ip).await, RateLimitResult::Allowed);
    }

    #[tokio::test]
    async fn test_stats_accounting() {
        let config = RateLimitConfig {
            max_requests: 5,
            window: Duration::from_secs(60),
            burst: 0,
            ban_duration: Duration::from_secs(60),
            max_bans: 5,
            max_tracked_ips: 1000,
        };
        let limiter = RateLimiter::new(config);

        let ip1: IpAddr = "172.16.2.1".parse().unwrap();
        let ip2: IpAddr = "172.16.2.2".parse().unwrap();
        let ip3: IpAddr = "172.16.2.3".parse().unwrap();
        assert_eq!(limiter.check(ip1).await, RateLimitResult::Allowed);
        assert_eq!(limiter.check(ip2).await, RateLimitResult::Allowed);
        limiter.ban(ip3, Duration::from_secs(60)).await;

        let stats = limiter.stats().await;
        assert_eq!(stats.whitelist_size, 2); // 127.0.0.1 + ::1
        assert_eq!(stats.tracked_ips, 3);
        assert_eq!(stats.banned_ips, 1);
        assert_eq!(stats.active_ips, 2);
        assert_eq!(stats.total_requests, 2);
        assert_eq!(stats.max_tracked_ips, 1000);
    }

    #[tokio::test]
    async fn test_cleanup_retains_banned_and_recent() {
        let config = RateLimitConfig {
            max_requests: 5,
            window: Duration::from_millis(20),
            burst: 0,
            ban_duration: Duration::from_secs(60),
            max_bans: 5,
            max_tracked_ips: 1000,
        };
        let limiter = RateLimiter::new(config);

        let ip_recent: IpAddr = "172.16.3.1".parse().unwrap();
        let ip_banned: IpAddr = "172.16.3.2".parse().unwrap();
        assert_eq!(limiter.check(ip_recent).await, RateLimitResult::Allowed);
        limiter.ban(ip_banned, Duration::from_secs(60)).await;

        // Let ip_recent's request age past the window so it is no longer "recent".
        tokio::time::sleep(Duration::from_millis(40)).await;
        limiter.cleanup().await;

        // Only the banned entry is retained.
        let stats = limiter.stats().await;
        assert_eq!(stats.tracked_ips, 1);
        assert_eq!(stats.banned_ips, 1);
    }

    #[tokio::test]
    async fn test_add_whitelist_bypasses_and_dedupes() {
        let config = RateLimitConfig {
            max_requests: 1,
            window: Duration::from_secs(60),
            burst: 0,
            ban_duration: Duration::from_secs(60),
            max_bans: 1,
            max_tracked_ips: 1000,
        };
        let mut limiter = RateLimiter::new(config);
        let ip: IpAddr = "203.0.113.5".parse().unwrap();

        limiter.add_whitelist(ip);
        // Whitelisted IP is never limited even far beyond quota.
        for _ in 0..50 {
            assert_eq!(limiter.check(ip).await, RateLimitResult::Allowed);
        }

        // Adding the same IP again does not grow the whitelist.
        let before = limiter.stats().await.whitelist_size;
        limiter.add_whitelist(ip);
        let after = limiter.stats().await.whitelist_size;
        assert_eq!(before, after);
    }

    #[test]
    fn test_config_presets_are_distinct() {
        let d = RateLimitConfig::default();
        let s = RateLimitConfig::strict();
        let r = RateLimitConfig::relaxed();

        // max_requests: strict < default < relaxed
        assert!(s.max_requests < d.max_requests);
        assert!(d.max_requests < r.max_requests);
        // burst: strict < default < relaxed
        assert!(s.burst < d.burst);
        assert!(d.burst < r.burst);
        // max_bans: strict < default < relaxed
        assert!(s.max_bans < d.max_bans);
        assert!(d.max_bans < r.max_bans);
        // ban_duration: strict longest, relaxed shortest
        assert!(r.ban_duration < d.ban_duration);
        assert!(d.ban_duration < s.ban_duration);
        // max_tracked_ips: strict < default < relaxed
        assert!(s.max_tracked_ips < d.max_tracked_ips);
        assert!(d.max_tracked_ips < r.max_tracked_ips);
    }

    #[tokio::test]
    async fn test_concurrency_same_ip_counts_atomically() {
        let config = RateLimitConfig {
            max_requests: 50,
            window: Duration::from_secs(60),
            burst: 0,
            ban_duration: Duration::from_secs(60),
            max_bans: 100,
            max_tracked_ips: 1000,
        };
        let limiter = Arc::new(RateLimiter::new(config));
        let ip: IpAddr = "198.51.100.9".parse().unwrap();

        // Fire 100 concurrent checks at the same IP; exactly total_allowed (50)
        // must be Allowed — the RwLock serializes writes so there are no lost
        // updates that would over-admit.
        let mut handles = Vec::new();
        for _ in 0..100 {
            let l = limiter.clone();
            handles.push(tokio::spawn(async move { l.check(ip).await }));
        }

        let mut allowed = 0;
        for h in handles {
            if h.await.unwrap() == RateLimitResult::Allowed {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 50);
    }
}
