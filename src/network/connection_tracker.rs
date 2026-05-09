//! Per-IP connection limiting and P2P buffer memory budget.
//!
//! Extracted from the monolithic `network::node` module as the first
//! concrete step in splitting ~3100 lines of coordinator code into
//! single-responsibility submodules. `ConnectionTracker` has no
//! dependency on `P2PNode` internals — it owns a `DashMap<IpAddr,
//! usize>` for Sybil-limiting and an `AtomicUsize` memory budget for
//! bounding inbound buffer allocation. Anything that touches it goes
//! through its public methods, so moving it here is a pure relocation.
//!
//! ## Responsibilities
//!
//! - **Per-IP connection cap** — prevents a single address from
//!   opening more than `MAX_CONNECTIONS_PER_IP` simultaneous
//!   connections (Bitcoin Core's core Sybil defence).
//! - **TOCTOU-safe admission** — `try_track_connection` atomically
//!   checks AND increments the counter, so two concurrent accept
//!   threads can't both pass a limit check and then each increment.
//! - **Memory budget** — `allocate` / `deallocate` track buffer
//!   reservations against `memory_budget` using a compare-exchange
//!   loop (H-FIX: prevents two concurrent allocates from both seeing
//!   a below-budget snapshot and then both adding).
//! - **Stale-entry cleanup** — `cleanup_stale_entries` is called
//!   from the node maintenance loop to reap zero-count entries that
//!   leaked due to missed untrack calls, and caps total tracked IPs
//!   at 10 000 to prevent unbounded growth under DoS.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use dashmap::DashMap;

use super::node::MAX_CONNECTIONS_PER_IP;

/// Per-IP connection tracking and memory budget for inbound P2P buffers.
///
/// Cheap to clone: internal state is an `Arc`-friendly `DashMap` plus
/// an atomic. The `P2PNode` wraps this in `Arc<ConnectionTracker>` and
/// shares it across the accept loop, the maintenance task, and any
/// message handler that needs to reserve memory for a payload.
/// HARDENING (Layer 4): Maximum outbound connections per /16 subnet.
/// Prevents eclipse attacks where an attacker fills all outbound slots
/// from the same network range. Bitcoin Core uses 1; we use 2 to allow
/// one backup peer in the same datacenter (the CoinCync fleet has
/// 207.148.6.50 and 207.148.111.76 in the same /16, so a hard cap of
/// 1 would force one of them out of the outbound set).
pub const MAX_OUTBOUND_PER_SUBNET: usize = 2;

#[allow(dead_code)]
pub struct ConnectionTracker {
    /// Live connection count per IP address. Zero-count entries are
    /// removed by `untrack_connection` and `cleanup_stale_entries`.
    connections_per_ip: DashMap<IpAddr, usize>,
    /// HARDENING (Layer 4): Outbound connection count per /16 subnet.
    /// Prevents eclipse attacks by ensuring peer diversity.
    outbound_per_subnet: DashMap<u16, usize>,
    /// Current memory usage estimate for P2P buffers.
    memory_used: AtomicUsize,
    /// Memory budget ceiling. `allocate()` refuses requests that would
    /// push `memory_used` over this limit.
    memory_budget: usize,
}

impl ConnectionTracker {
    pub fn new(memory_budget: usize) -> Self {
        ConnectionTracker {
            connections_per_ip: DashMap::new(),
            outbound_per_subnet: DashMap::new(),
            memory_used: AtomicUsize::new(0),
            memory_budget,
        }
    }

    /// HARDENING (Layer 4): Extract /16 subnet key from an IP address.
    /// For IPv4 a.b.c.d, returns (a << 8 | b) — the /16 prefix.
    /// For IPv6, uses the first 16 bits of the address.
    fn subnet_key(ip: &IpAddr) -> u16 {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                (octets[0] as u16) << 8 | octets[1] as u16
            }
            IpAddr::V6(v6) => {
                let segments = v6.segments();
                segments[0]
            }
        }
    }

    /// HARDENING (Layer 4): Check if we can add an outbound connection
    /// to this subnet without exceeding diversity limits.
    ///
    /// Non-atomic — for admission decisions use `try_track_outbound_subnet`
    /// instead. This entry point is kept for read-only inspection (logs,
    /// metrics, "would this be allowed" UI).
    pub fn can_add_outbound_subnet(&self, addr: &SocketAddr) -> bool {
        let subnet = Self::subnet_key(&addr.ip());
        let count = self.outbound_per_subnet.get(&subnet).map(|c| *c).unwrap_or(0);
        count < MAX_OUTBOUND_PER_SUBNET
    }

    /// HARDENING (Layer 4): Atomically check-and-increment the per-/16
    /// outbound counter. Returns `true` if the connection was admitted
    /// (and the counter incremented), `false` if the subnet cap was hit.
    ///
    /// This is the only admission path that's safe against two concurrent
    /// dialers racing each other — a plain `can_add_outbound_subnet` +
    /// `track_outbound_subnet` pair would let both pass the check and
    /// then both increment, exceeding the limit. Mirrors the per-IP
    /// pattern in `try_track_connection`.
    pub fn try_track_outbound_subnet(&self, addr: &SocketAddr) -> bool {
        let subnet = Self::subnet_key(&addr.ip());
        let mut accepted = false;
        self.outbound_per_subnet
            .entry(subnet)
            .and_modify(|c| {
                if *c < MAX_OUTBOUND_PER_SUBNET {
                    *c += 1;
                    accepted = true;
                }
            })
            .or_insert_with(|| {
                accepted = true;
                1
            });
        accepted
    }

    /// HARDENING (Layer 4): Track an outbound connection's subnet
    /// (unconditional increment). Prefer `try_track_outbound_subnet`
    /// for admission paths; this exists for callers that have already
    /// committed to the connection by other means.
    pub fn track_outbound_subnet(&self, addr: &SocketAddr) {
        let subnet = Self::subnet_key(&addr.ip());
        self.outbound_per_subnet
            .entry(subnet)
            .and_modify(|c| *c += 1)
            .or_insert(1);
    }

    /// HARDENING (Layer 4): Untrack an outbound connection's subnet.
    ///
    /// Prefer `try_track_outbound_subnet_owned` over manual `try_track`
    /// + `untrack` pairing — the owned variant returns a Drop-guard
    /// that decrements automatically on every exit path including
    /// panics, making slot leaks structurally impossible.
    pub fn untrack_outbound_subnet(&self, addr: &SocketAddr) {
        let subnet = Self::subnet_key(&addr.ip());
        if let Some(mut entry) = self.outbound_per_subnet.get_mut(&subnet) {
            if *entry > 0 { *entry -= 1; }
            if *entry == 0 {
                drop(entry);
                self.outbound_per_subnet.remove(&subnet);
            }
        }
    }

    /// HARDENING (Layer 4): Atomic admission with RAII Drop-guard semantics.
    ///
    /// Returns `Some(OutboundSubnetSlot)` if the per-/16 counter was
    /// successfully incremented, `None` if the cap was hit. The returned
    /// slot decrements the counter on Drop — including panics, early
    /// returns, and tokio task termination — so an outbound spawn that
    /// holds the slot can never leak it.
    ///
    /// This is the **preferred** admission path for outbound dialers.
    /// The bare `try_track_outbound_subnet` + manual
    /// `untrack_outbound_subnet` pairing is kept for the test suite
    /// and for callers that intentionally want fire-and-forget tracking.
    ///
    /// In production, the connector loop holds the slot for the lifetime
    /// of the spawned tokio task; when handle_connection returns (cleanly
    /// or with error) the spawn body ends, the slot drops, the counter
    /// decrements. That eliminates the entire class of "forgot to call
    /// untrack on this error path" bugs.
    pub fn try_track_outbound_subnet_owned(
        self: &Arc<Self>,
        addr: &SocketAddr,
    ) -> Option<OutboundSubnetSlot> {
        if self.try_track_outbound_subnet(addr) {
            Some(OutboundSubnetSlot {
                tracker: self.clone(),
                addr: *addr,
            })
        } else {
            None
        }
    }

    /// Snapshot of the per-/16 outbound counter map. Used by the periodic
    /// observability log so operators can see the eclipse-defense state
    /// without needing a debugger. Cheap — DashMap iteration is O(n) over
    /// at most a few dozen entries in practice.
    pub fn outbound_subnet_snapshot(&self) -> Vec<(u16, usize)> {
        let mut snap: Vec<(u16, usize)> = self
            .outbound_per_subnet
            .iter()
            .map(|e| (*e.key(), *e.value()))
            .collect();
        snap.sort_by_key(|(k, _)| *k);
        snap
    }

    /// Check if we can accept a connection from this IP without
    /// actually tracking it. Non-atomic — if you need TOCTOU safety,
    /// call `try_track_connection` instead.
    #[allow(dead_code)]
    pub fn can_accept(&self, addr: &SocketAddr) -> bool {
        let ip = addr.ip();
        let count = self
            .connections_per_ip
            .get(&ip)
            .map(|c| *c)
            .unwrap_or(0);
        count < MAX_CONNECTIONS_PER_IP
    }

    /// Atomically check-and-increment the per-IP counter.
    ///
    /// Returns `true` if the connection was accepted (and the counter
    /// has been incremented), `false` if the per-IP cap has been hit.
    /// This is the only admission path that is safe against two accept
    /// threads racing each other — a plain `can_accept` + `track` pair
    /// would allow both to pass the check and then both increment,
    /// exceeding the limit.
    pub fn try_track_connection(&self, addr: &SocketAddr) -> bool {
        let ip = addr.ip();
        let mut accepted = false;
        self.connections_per_ip
            .entry(ip)
            .and_modify(|c| {
                if *c < MAX_CONNECTIONS_PER_IP {
                    *c += 1;
                    accepted = true;
                }
            })
            .or_insert_with(|| {
                accepted = true;
                1
            });
        accepted
    }

    /// Increment the per-IP counter unconditionally. Prefer
    /// `try_track_connection` for admission — this entry point exists
    /// for callers that have already committed to the connection.
    #[allow(dead_code)]
    pub fn track_connection(&self, addr: &SocketAddr) {
        let ip = addr.ip();
        self.connections_per_ip
            .entry(ip)
            .and_modify(|c| *c += 1)
            .or_insert(1);
    }

    /// Decrement the per-IP counter when a connection closes. Removes
    /// the entry entirely when the counter reaches zero so the map
    /// doesn't accumulate dead IPs.
    pub fn untrack_connection(&self, addr: &SocketAddr) {
        let ip = addr.ip();
        if let Some(mut entry) = self.connections_per_ip.get_mut(&ip) {
            *entry = entry.saturating_sub(1);
            if *entry == 0 {
                drop(entry);
                self.connections_per_ip.remove(&ip);
            }
        }
    }

    /// Periodic cleanup of leaked or stale tracking entries.
    ///
    /// Call from the P2P maintenance loop roughly every 60 s. Removes
    /// entries with zero connections, and if the table has grown past
    /// `MAX_TRACKED_IPS` it additionally culls any entry whose IP is
    /// not in the active peer list (defence against leaked-entry
    /// accumulation under sustained DoS).
    ///
    /// Inspired by CKB's `ADDR_TIMEOUT_MS` pattern.
    #[allow(dead_code)]
    pub fn cleanup_stale_entries(&self, active_peer_ips: &[IpAddr]) {
        const MAX_TRACKED_IPS: usize = 10_000;

        // Pass 1: reap zero-count rows.
        self.connections_per_ip.retain(|_ip, count| *count > 0);

        // Pass 2: if still too large, drop anything we can't match
        // against a currently-connected peer.
        if self.connections_per_ip.len() > MAX_TRACKED_IPS {
            let active_set: std::collections::HashSet<&IpAddr> = active_peer_ips.iter().collect();
            self.connections_per_ip.retain(|ip, _| active_set.contains(ip));
        }
    }

    /// Number of distinct IPs currently tracked (monitoring hook).
    #[allow(dead_code)]
    pub fn tracked_ip_count(&self) -> usize {
        self.connections_per_ip.len()
    }

    /// Atomically reserve `bytes` of P2P buffer memory against the
    /// budget. Returns `true` if the reservation succeeded.
    ///
    /// Uses a compare-exchange loop to prevent a TOCTOU race where
    /// two concurrent callers both see `current + bytes <= budget`
    /// based on a stale snapshot and both then commit, exceeding the
    /// budget.
    #[allow(dead_code)]
    pub fn allocate(&self, bytes: usize) -> bool {
        loop {
            let current = self.memory_used.load(Ordering::Acquire);
            if current + bytes > self.memory_budget {
                return false;
            }
            match self.memory_used.compare_exchange_weak(
                current,
                current + bytes,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(_) => continue, // retry on contention
            }
        }
    }

    /// Release a previously-allocated buffer back to the budget.
    #[allow(dead_code)]
    pub fn deallocate(&self, bytes: usize) {
        self.memory_used.fetch_sub(bytes, Ordering::Relaxed);
    }

    /// Current P2P buffer memory usage (monitoring hook).
    pub fn memory_usage(&self) -> usize {
        self.memory_used.load(Ordering::Relaxed)
    }

    /// Current connection count for a specific IP (monitoring hook).
    pub fn connections_from(&self, ip: &IpAddr) -> usize {
        self.connections_per_ip
            .get(ip)
            .map(|c| *c)
            .unwrap_or(0)
    }
}

/// RAII guard that holds an outbound /16 subnet slot in
/// `ConnectionTracker::outbound_per_subnet`. Created by
/// `ConnectionTracker::try_track_outbound_subnet_owned`. On Drop the
/// slot is released — the per-/16 counter decrements automatically,
/// regardless of whether the holder exits cleanly, panics, or is
/// cancelled (in tokio task termination, the captured slot is dropped
/// during stack unwinding).
///
/// **The slot must outlive the connection it represents.** Move the
/// slot into the `tokio::spawn` body that owns the connection lifetime
/// (handle_connection); when that body exits — for any reason — the
/// slot drops and the counter decrements.
///
/// `mem::forget(slot)` will permanently leak the counter — the slot
/// must drop normally for the decrement to fire. This is by design:
/// matches std's RAII guard semantics (e.g. `MutexGuard`).
pub struct OutboundSubnetSlot {
    tracker: Arc<ConnectionTracker>,
    addr: SocketAddr,
}

impl Drop for OutboundSubnetSlot {
    fn drop(&mut self) {
        self.tracker.untrack_outbound_subnet(&self.addr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> SocketAddr {
        format!("127.0.0.{}:1234", n).parse().unwrap()
    }

    #[test]
    fn new_tracker_is_empty() {
        let t = ConnectionTracker::new(1024);
        assert_eq!(t.tracked_ip_count(), 0);
        assert_eq!(t.memory_usage(), 0);
    }

    #[test]
    fn per_ip_limit_enforced_by_try_track() {
        let t = ConnectionTracker::new(1024);
        let a = addr(1);
        // Up to MAX_CONNECTIONS_PER_IP must succeed.
        for _ in 0..MAX_CONNECTIONS_PER_IP {
            assert!(t.try_track_connection(&a));
        }
        // One more must fail.
        assert!(!t.try_track_connection(&a));
    }

    #[test]
    fn untrack_removes_entry_when_count_reaches_zero() {
        let t = ConnectionTracker::new(1024);
        let a = addr(2);
        assert!(t.try_track_connection(&a));
        assert_eq!(t.connections_from(&a.ip()), 1);
        t.untrack_connection(&a);
        assert_eq!(t.connections_from(&a.ip()), 0);
        assert_eq!(t.tracked_ip_count(), 0);
    }

    #[test]
    fn allocate_respects_budget() {
        let t = ConnectionTracker::new(100);
        assert!(t.allocate(60));
        assert!(t.allocate(40));
        // 60 + 40 = 100 (full). One more byte must fail.
        assert!(!t.allocate(1));
        assert_eq!(t.memory_usage(), 100);
        t.deallocate(60);
        assert_eq!(t.memory_usage(), 40);
        // After freeing, we can allocate again.
        assert!(t.allocate(50));
    }

    #[test]
    fn cleanup_removes_zero_count_entries() {
        let t = ConnectionTracker::new(1024);
        let a = addr(3);
        t.try_track_connection(&a);
        t.untrack_connection(&a);
        // `untrack` already removes zero-count entries, but
        // `cleanup_stale_entries` must be idempotent in that case.
        t.cleanup_stale_entries(&[]);
        assert_eq!(t.tracked_ip_count(), 0);
    }

    fn addr_in(a: u8, b: u8, c: u8) -> SocketAddr {
        format!("{}.{}.{}.1:1234", a, b, c).parse().unwrap()
    }

    #[test]
    fn outbound_subnet_cap_admits_up_to_max_then_rejects() {
        let t = ConnectionTracker::new(1024);
        // All in the same /16 (10.0.x.1).
        for i in 0..MAX_OUTBOUND_PER_SUBNET {
            assert!(
                t.try_track_outbound_subnet(&addr_in(10, 0, i as u8)),
                "should admit slot {} (under cap)", i
            );
        }
        // The next one must be rejected.
        assert!(
            !t.try_track_outbound_subnet(&addr_in(10, 0, 99)),
            "should reject beyond cap"
        );
    }

    #[test]
    fn outbound_subnet_cap_is_per_subnet() {
        let t = ConnectionTracker::new(1024);
        // Fill /16 = 10.0.0.0
        for i in 0..MAX_OUTBOUND_PER_SUBNET {
            assert!(t.try_track_outbound_subnet(&addr_in(10, 0, i as u8)));
        }
        // A different /16 (10.1.x.1) must still admit normally.
        assert!(t.try_track_outbound_subnet(&addr_in(10, 1, 0)));
    }

    #[test]
    fn untrack_outbound_subnet_releases_slot() {
        let t = ConnectionTracker::new(1024);
        let peers: Vec<SocketAddr> =
            (0..MAX_OUTBOUND_PER_SUBNET as u8).map(|i| addr_in(10, 0, i)).collect();
        for p in &peers {
            assert!(t.try_track_outbound_subnet(p));
        }
        // Cap reached, new dial rejected.
        assert!(!t.try_track_outbound_subnet(&addr_in(10, 0, 99)));
        // Drop one peer; slot must free up.
        t.untrack_outbound_subnet(&peers[0]);
        assert!(t.try_track_outbound_subnet(&addr_in(10, 0, 99)));
    }

    #[test]
    fn outbound_subnet_concurrent_admission_does_not_exceed_cap() {
        // TOCTOU regression test: spawn many threads that all race
        // to dial peers in the same /16. Total admitted must be
        // exactly MAX_OUTBOUND_PER_SUBNET, not more.
        use std::sync::Arc;
        use std::thread;
        let t = Arc::new(ConnectionTracker::new(1024));
        let total_attempts: usize = 64;
        let mut handles = Vec::with_capacity(total_attempts);
        for i in 0..total_attempts {
            let t = t.clone();
            handles.push(thread::spawn(move || {
                let a = addr_in(10, 0, (i % 250) as u8);
                t.try_track_outbound_subnet(&a)
            }));
        }
        let admitted: usize = handles
            .into_iter()
            .map(|h| if h.join().unwrap() { 1 } else { 0 })
            .sum();
        assert_eq!(
            admitted, MAX_OUTBOUND_PER_SUBNET,
            "exactly MAX_OUTBOUND_PER_SUBNET admissions should win the race"
        );
    }

    // ── OutboundSubnetSlot RAII semantics ─────────────────────────────

    #[test]
    fn slot_increments_on_construct_and_decrements_on_drop() {
        let t = Arc::new(ConnectionTracker::new(1024));
        let a = addr_in(10, 0, 1);
        {
            let _slot = t.try_track_outbound_subnet_owned(&a)
                .expect("under cap, must admit");
            // Inside scope: counter incremented.
            assert_eq!(t.outbound_subnet_snapshot(), vec![(0x0a00, 1)]);
        }
        // After drop: counter back to zero, entry removed.
        assert!(t.outbound_subnet_snapshot().is_empty());
    }

    #[test]
    fn slot_returns_none_when_cap_hit_and_does_not_increment() {
        let t = Arc::new(ConnectionTracker::new(1024));
        let mut held = Vec::new();
        for i in 0..MAX_OUTBOUND_PER_SUBNET {
            let s = t.try_track_outbound_subnet_owned(&addr_in(10, 0, i as u8))
                .expect("under cap");
            held.push(s);
        }
        // Cap hit — next attempt returns None.
        assert!(t.try_track_outbound_subnet_owned(&addr_in(10, 0, 99)).is_none());
        // And the failed attempt did NOT increment.
        let snap = t.outbound_subnet_snapshot();
        assert_eq!(snap, vec![(0x0a00, MAX_OUTBOUND_PER_SUBNET)]);
        // Drop everything: counter goes back to 0.
        drop(held);
        assert!(t.outbound_subnet_snapshot().is_empty());
    }

    #[test]
    fn slot_decrements_through_panic_unwind() {
        let t = Arc::new(ConnectionTracker::new(1024));
        let a = addr_in(10, 0, 1);
        let t2 = t.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _slot = t2.try_track_outbound_subnet_owned(&a)
                .expect("under cap");
            // counter is 1 at this point
            panic!("simulated task crash");
        }));
        assert!(result.is_err(), "panic should propagate");
        // Despite panic, slot's Drop ran during unwind → counter back to 0.
        assert!(t.outbound_subnet_snapshot().is_empty());
    }

    #[test]
    fn slot_mem_forget_leaks_counter_intentionally() {
        // Documented behavior: mem::forget skips Drop, so the counter
        // stays incremented forever. Matches std MutexGuard semantics.
        // Test exists to pin this contract — if a future change moves
        // the decrement out of Drop, this test will silently start
        // passing for the wrong reason, which is why it asserts the
        // exact expected leak.
        let t = Arc::new(ConnectionTracker::new(1024));
        let a = addr_in(10, 0, 1);
        let slot = t.try_track_outbound_subnet_owned(&a).expect("under cap");
        std::mem::forget(slot);
        assert_eq!(t.outbound_subnet_snapshot(), vec![(0x0a00, 1)]);
    }

    #[test]
    fn slot_stacking_for_same_subnet_increments_each() {
        // Cap-agnostic: stack exactly MAX, verify count, drop middle,
        // verify count drops by 1, then drain — exercises both stacking
        // and out-of-order drop without depending on the cap value.
        let t = Arc::new(ConnectionTracker::new(1024));
        let mut slots: Vec<OutboundSubnetSlot> = (0..MAX_OUTBOUND_PER_SUBNET as u8)
            .map(|i| t.try_track_outbound_subnet_owned(&addr_in(10, 0, i)).unwrap())
            .collect();
        assert_eq!(
            t.outbound_subnet_snapshot(),
            vec![(0x0a00, MAX_OUTBOUND_PER_SUBNET)]
        );
        // Drop a middle slot, verify count drops by 1.
        if slots.len() >= 2 {
            slots.remove(slots.len() / 2);
            assert_eq!(
                t.outbound_subnet_snapshot(),
                vec![(0x0a00, MAX_OUTBOUND_PER_SUBNET - 1)]
            );
        }
        drop(slots);
        assert!(t.outbound_subnet_snapshot().is_empty());
    }
}
