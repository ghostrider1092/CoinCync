//! # Persistent Peer Address Book
//!
//! Stores discovered peer addresses across restarts.
//! Seeds are never aged out.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Minimum interval between persistent writes of the address book.
/// FIX #13: previous implementation called `save()` on every peer event
/// (add, record_success, record_failure, add_seeds). With thousands of
/// peers this did a full JSON re-serialize + disk write per event,
/// saturating I/O. Dirty-flag pattern below flushes at most once every
/// `FLUSH_INTERVAL`.
const FLUSH_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddrEntry {
    pub addr:       SocketAddr,
    pub last_seen:  u64,
    pub successes:  u32,
    pub failures:   u32,
    pub is_seed:    bool,
}

impl AddrEntry {
    fn new(addr: SocketAddr, is_seed: bool) -> Self {
        AddrEntry { addr, last_seen: 0, successes: 0, failures: 0, is_seed }
    }

    pub fn score(&self) -> f64 {
        let age_secs = now_secs().saturating_sub(self.last_seen) as f64;
        let age_penalty = (age_secs / 3600.0).min(10.0);
        let reliability = if self.successes + self.failures > 0 {
            self.successes as f64 / (self.successes + self.failures) as f64
        } else {
            0.5
        };
        let seed_bonus = if self.is_seed { 100.0 } else { 0.0 };
        seed_bonus + reliability * 10.0 - age_penalty
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct BookData {
    entries: HashMap<String, AddrEntry>,
}

pub struct IronAddressBook {
    data:        BookData,
    path:        Option<PathBuf>,
    max_age:     Duration,
    max_entries: usize,
    /// FIX #13: dirty-flag pattern to avoid O(n) JSON serialize on every event.
    dirty:       bool,
    last_flush:  Instant,
}

impl IronAddressBook {
    pub fn in_memory() -> Self {
        IronAddressBook {
            data:        BookData::default(),
            path:        None,
            max_age:     Duration::from_secs(7 * 24 * 3600),
            max_entries: 2048,
            dirty:       false,
            last_flush:  Instant::now(),
        }
    }

    pub fn persistent(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        let mut book = IronAddressBook {
            data:        BookData::default(),
            path:        Some(path.clone()),
            max_age:     Duration::from_secs(7 * 24 * 3600),
            max_entries: 2048,
            dirty:       false,
            last_flush:  Instant::now(),
        };
        book.load();
        book
    }

    /// FIX #13: mark the book as dirty without touching disk. The background
    /// flusher (or `flush_if_dirty` called from a periodic task) will write
    /// at most once every `FLUSH_INTERVAL`.
    fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// FIX #13: flush to disk if dirty AND enough time has elapsed.
    /// Call from a background timer every 30s and on shutdown via `flush()`.
    pub fn flush_if_dirty(&mut self) {
        if !self.dirty { return; }
        if self.last_flush.elapsed() < FLUSH_INTERVAL { return; }
        self.save();
        self.dirty = false;
        self.last_flush = Instant::now();
    }

    /// FIX #13: unconditional flush for shutdown paths.
    pub fn flush(&mut self) {
        if self.dirty {
            self.save();
            self.dirty = false;
            self.last_flush = Instant::now();
        }
    }

    pub fn add_seeds(&mut self, seeds: &[SocketAddr]) {
        for &addr in seeds {
            let key = addr.to_string();
            self.data.entries
                .entry(key)
                .or_insert_with(|| AddrEntry::new(addr, true))
                .is_seed = true;
        }
        self.mark_dirty();
    }

    pub fn add(&mut self, addr: SocketAddr) {
        if self.data.entries.len() >= self.max_entries {
            self.evict_worst();
        }
        self.data.entries
            .entry(addr.to_string())
            .or_insert_with(|| AddrEntry::new(addr, false));
        self.mark_dirty();
    }

    pub fn record_success(&mut self, addr: SocketAddr) {
        let key = addr.to_string();
        if let Some(e) = self.data.entries.get_mut(&key) {
            e.last_seen = now_secs();
            e.successes += 1;
        } else {
            let mut e = AddrEntry::new(addr, false);
            e.last_seen = now_secs();
            e.successes = 1;
            self.data.entries.insert(key, e);
        }
        self.mark_dirty();
    }

    pub fn record_failure(&mut self, addr: SocketAddr) {
        let key = addr.to_string();
        if let Some(e) = self.data.entries.get_mut(&key) {
            e.failures += 1;
        }
        self.mark_dirty();
    }

    pub fn candidates(&self, exclude: &[SocketAddr]) -> Vec<SocketAddr> {
        let now = now_secs();
        let max_age_secs = self.max_age.as_secs();
        let exclude_set: std::collections::HashSet<_> = exclude.iter().collect();

        let mut entries: Vec<&AddrEntry> = self.data.entries.values()
            .filter(|e| {
                !exclude_set.contains(&e.addr) &&
                (e.is_seed || e.last_seen == 0 || now.saturating_sub(e.last_seen) < max_age_secs)
            })
            .collect();

        entries.sort_by(|a, b| b.score().partial_cmp(&a.score()).unwrap_or(std::cmp::Ordering::Equal));
        entries.iter().map(|e| e.addr).collect()
    }

    pub fn age_out(&mut self) {
        let now = now_secs();
        let max_age = self.max_age.as_secs();
        let before = self.data.entries.len();
        self.data.entries.retain(|_, e| {
            e.is_seed || e.last_seen == 0 || now.saturating_sub(e.last_seen) < max_age
        });
        let removed = before - self.data.entries.len();
        if removed > 0 {
            debug!("IronAddressBook: aged out {removed} stale peers");
            self.mark_dirty();
        }
    }

    pub fn len(&self) -> usize { self.data.entries.len() }
    pub fn is_empty(&self) -> bool { self.data.entries.is_empty() }

    fn load(&mut self) {
        let Some(path) = &self.path else { return };
        match std::fs::read_to_string(path) {
            Ok(s) => match serde_json::from_str(&s) {
                Ok(data) => {
                    self.data = data;
                    info!("IronAddressBook: loaded {} peers from {:?}", self.data.entries.len(), path);
                }
                Err(e) => warn!("IronAddressBook: parse error: {e} — starting empty"),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!("IronAddressBook: read error: {e}"),
        }
    }

    fn save(&self) {
        let Some(path) = &self.path else { return };
        match serde_json::to_string_pretty(&self.data) {
            Ok(s) => {
                if let Err(e) = std::fs::write(path, s) {
                    warn!("IronAddressBook: write error: {e}");
                }
            }
            Err(e) => warn!("IronAddressBook: serialise error: {e}"),
        }
    }

    fn evict_worst(&mut self) {
        let worst = self.data.entries.iter()
            .filter(|(_, e)| !e.is_seed)
            .min_by(|(_, a), (_, b)| a.score().partial_cmp(&b.score()).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(k, _)| k.clone());
        if let Some(k) = worst { self.data.entries.remove(&k); }
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_never_aged_out() {
        let mut book = IronAddressBook::in_memory();
        let seed: SocketAddr = "1.2.3.4:1234".parse().unwrap();
        book.add_seeds(&[seed]);
        book.age_out();
        assert_eq!(book.len(), 1);
    }

    #[test]
    fn candidates_sorted_by_score() {
        let mut book = IronAddressBook::in_memory();
        let seed:    SocketAddr = "1.1.1.1:1".parse().unwrap();
        let regular: SocketAddr = "2.2.2.2:2".parse().unwrap();
        book.add_seeds(&[seed]);
        book.add(regular);
        book.record_success(seed);
        let candidates = book.candidates(&[]);
        assert_eq!(candidates[0], seed);
    }

    #[test]
    fn max_entries_evicts_worst() {
        let mut book = IronAddressBook::in_memory();
        book.max_entries = 3;
        for i in 0..4u8 {
            book.add(format!("10.0.0.{}:1000", i).parse().unwrap());
        }
        assert!(book.len() <= 3);
    }
}
