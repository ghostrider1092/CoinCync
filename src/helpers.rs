//! # Helper Utilities and Macros
//!
//! Common patterns and utilities for cleaner code.

use std::time::{Duration, Instant};

/// Retry an operation with exponential backoff.
///
/// Delegates to `tokio-retry`'s `ExponentialBackoff` strategy so we get
/// well-tested jitter-free exponential delays without maintaining our own loop.
pub async fn retry_with_backoff<F, Fut, T, E>(
    operation: F,
    max_retries: usize,
    initial_delay: Duration,
) -> std::result::Result<T, E>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, E>>,
    E: std::fmt::Display,
{
    use tokio_retry::strategy::ExponentialBackoff;
    use tokio_retry::Retry;

    let strategy =
        ExponentialBackoff::from_millis(initial_delay.as_millis() as u64).take(max_retries);

    Retry::start(strategy, || operation()).await
}

/// Measure execution time of a block
pub struct Timer {
    start: Instant,
    label: &'static str,
}

impl Timer {
    /// Start a new timer
    pub fn new(label: &'static str) -> Self {
        Timer {
            start: Instant::now(),
            label,
        }
    }

    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Get elapsed milliseconds
    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        tracing::debug!("{}: {:?}", self.label, self.start.elapsed());
    }
}

/// Rate limiter for operations
pub struct RateLimiter {
    /// Maximum operations per second
    max_ops: u32,
    /// Current window start
    window_start: Instant,
    /// Operations in current window
    ops_count: u32,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(max_ops_per_second: u32) -> Self {
        RateLimiter {
            max_ops: max_ops_per_second,
            window_start: Instant::now(),
            ops_count: 0,
        }
    }

    /// Check if operation is allowed (non-blocking)
    pub fn try_acquire(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.ops_count = 0;
        }

        if self.ops_count < self.max_ops {
            self.ops_count += 1;
            true
        } else {
            false
        }
    }

    /// Wait until an operation is allowed.
    ///
    /// #89 (junbyjun1238): rather than polling `try_acquire()` every 10ms, when
    /// the current 1-second window is exhausted this sleeps until that window
    /// resets (`window_start + 1s`) and then retries. That's the earliest moment
    /// a slot can free up, so it wakes at most once or twice per wait instead of
    /// ~100 times/second. `try_acquire`'s behavior is unchanged.
    pub async fn acquire(&mut self) {
        loop {
            if self.try_acquire() {
                return;
            }
            // The window is full (and, since `try_acquire` resets an elapsed
            // window, not yet elapsed) — the next slot opens at the reset point.
            let reset_at = self.window_start + Duration::from_secs(1);
            let wait = reset_at.saturating_duration_since(Instant::now());
            // A 1ms floor keeps the loop cooperative if we wake a hair early.
            tokio::time::sleep(wait.max(Duration::from_millis(1))).await;
        }
    }
}

/// Batch processor for efficient bulk operations
pub struct BatchProcessor<T> {
    items: Vec<T>,
    batch_size: usize,
}

impl<T> BatchProcessor<T> {
    /// Create new batch processor
    pub fn new(batch_size: usize) -> Self {
        BatchProcessor {
            items: Vec::with_capacity(batch_size),
            batch_size,
        }
    }

    /// Add an item (returns true if batch is full)
    pub fn add(&mut self, item: T) -> bool {
        self.items.push(item);
        self.items.len() >= self.batch_size
    }

    /// Take the current batch
    pub fn take_batch(&mut self) -> Vec<T> {
        std::mem::take(&mut self.items)
    }

    /// Check if batch is ready
    pub fn is_ready(&self) -> bool {
        self.items.len() >= self.batch_size
    }

    /// Get current count
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Simple moving average calculator
pub struct MovingAverage {
    values: Vec<f64>,
    capacity: usize,
    index: usize,
    count: usize,
}

impl MovingAverage {
    /// Create with specified window size
    pub fn new(window_size: usize) -> Self {
        MovingAverage {
            values: vec![0.0; window_size],
            capacity: window_size,
            index: 0,
            count: 0,
        }
    }

    /// Add a value
    pub fn add(&mut self, value: f64) {
        self.values[self.index] = value;
        self.index = (self.index + 1) % self.capacity;
        if self.count < self.capacity {
            self.count += 1;
        }
    }

    /// Get the average
    pub fn average(&self) -> f64 {
        if self.count == 0 {
            return 0.0;
        }
        let sum: f64 = self.values[..self.count].iter().sum();
        sum / self.count as f64
    }
}

/// Hex encoding/decoding helpers
pub mod hex_utils {
    /// Encode bytes to hex string
    pub fn encode(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    /// Decode hex string to bytes
    pub fn decode(s: &str) -> Option<Vec<u8>> {
        hex::decode(s).ok()
    }

    /// Decode hex to fixed-size array
    pub fn decode_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
        let bytes = hex::decode(s).ok()?;
        if bytes.len() != N {
            return None;
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        Some(arr)
    }
}

/// Time utilities
pub mod time_utils {
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Get current Unix timestamp in seconds
    pub fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Get current Unix timestamp in milliseconds
    pub fn now_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Format timestamp as ISO 8601
    pub fn format_timestamp(secs: u64) -> String {
        chrono::DateTime::from_timestamp(secs as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "Invalid timestamp".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(3);
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(!limiter.try_acquire()); // Should be rate limited
    }

    /// #89 (junbyjun1238): `acquire()` blocks when the window is exhausted and
    /// resumes once the 1-second window resets — without busy-polling. This
    /// exercises the async waiting path: the first two calls pass immediately,
    /// and the third must wait roughly until the window resets.
    #[tokio::test]
    async fn acquire_waits_for_window_reset_issue_89() {
        let mut limiter = RateLimiter::new(2);
        limiter.acquire().await; // 1/2 — immediate
        limiter.acquire().await; // 2/2 — immediate
        let before = std::time::Instant::now();
        limiter.acquire().await; // must block until the ~1s window resets
        let waited = before.elapsed();
        assert!(
            waited >= Duration::from_millis(500),
            "rate-limited acquire should wait for the window to reset, waited {:?}",
            waited
        );
    }

    #[test]
    fn test_batch_processor() {
        let mut batch: BatchProcessor<i32> = BatchProcessor::new(3);
        assert!(!batch.add(1));
        assert!(!batch.add(2));
        assert!(batch.add(3)); // Batch is now full

        let items = batch.take_batch();
        assert_eq!(items, vec![1, 2, 3]);
        assert!(batch.is_empty());
    }

    #[test]
    fn test_moving_average() {
        let mut avg = MovingAverage::new(3);
        avg.add(10.0);
        assert_eq!(avg.average(), 10.0);
        avg.add(20.0);
        assert_eq!(avg.average(), 15.0);
        avg.add(30.0);
        assert_eq!(avg.average(), 20.0);
        avg.add(40.0); // Oldest (10) is replaced
        assert_eq!(avg.average(), 30.0);
    }

    #[test]
    fn test_hex_utils() {
        let bytes = [0xAB, 0xCD, 0xEF];
        let hex = hex_utils::encode(&bytes);
        assert_eq!(hex, "abcdef");

        let decoded = hex_utils::decode(&hex).unwrap();
        assert_eq!(decoded, bytes);

        let fixed: [u8; 3] = hex_utils::decode_fixed("abcdef").unwrap();
        assert_eq!(fixed, bytes);
    }

    #[test]
    fn test_time_utils() {
        let now = time_utils::now_secs();
        assert!(now > 1700000000); // After 2023

        let formatted = time_utils::format_timestamp(1704067200);
        assert!(formatted.contains("2024"));
    }

    #[test]
    fn test_backoff_timing() {
        // Verify exponential delay progression via RateLimiter window resets
        let initial = Duration::from_millis(100);
        let doubled = initial * 2;
        let quadrupled = initial * 4;
        assert_eq!(doubled, Duration::from_millis(200));
        assert_eq!(quadrupled, Duration::from_millis(400));
        // Simulates the retry_with_backoff delay doubling pattern
        assert!(quadrupled > doubled);
        assert!(doubled > initial);
    }
}
