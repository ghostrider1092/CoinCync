//! # Rate Limiting for CoinCync RPC
//!
//! Per-IP rate limiting to prevent abuse and DoS attacks.
//!
//! SECURITY: Implements LRU eviction to prevent memory exhaustion attacks.
//! Attackers cannot exhaust memory by connecting from many different IPs.

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
}
