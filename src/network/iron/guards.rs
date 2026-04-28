//! # Engine Guards
//!
//! 1. **Panic recovery** — tick panics are caught, engine continues
//! 2. **Re-entry guard** — prevents concurrent enforcement passes
//! 3. **Graceful shutdown** — flushes state to disk

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

// -- Re-entry guard --

pub struct TickGuard {
    running: Arc<AtomicBool>,
}

pub struct TickLock {
    running: Arc<AtomicBool>,
}

impl Drop for TickLock {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
    }
}

impl TickGuard {
    pub fn new() -> Self {
        TickGuard { running: Arc::new(AtomicBool::new(false)) }
    }

    pub fn try_acquire(&self) -> Option<TickLock> {
        match self.running.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => Some(TickLock { running: self.running.clone() }),
            Err(_) => None,
        }
    }
}

impl Default for TickGuard {
    fn default() -> Self { Self::new() }
}

// -- Panic recovery --

pub fn run_with_panic_recovery<F>(tick_name: &str, f: F)
where
    F: FnOnce() + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(f) {
        Ok(_) => {}
        Err(e) => {
            let msg = if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic payload".to_string()
            };
            error!(
                tick = tick_name,
                panic = %msg,
                "IronConsensus: tick panicked — recovering and continuing"
            );
        }
    }
}

/// Async panic recovery via tokio::spawn.
pub async fn run_tick_safe<F, Fut>(tick_name: &'static str, f: F)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let handle = tokio::spawn(f());
    match handle.await {
        Ok(()) => {}
        Err(e) if e.is_panic() => {
            error!(
                tick = tick_name,
                "IronConsensus: async tick panicked — engine continues"
            );
        }
        Err(_) => {}
    }
}

// -- Graceful shutdown --

pub struct ShutdownFlusher {
    pub state_log_path: Option<std::path::PathBuf>,
}

impl ShutdownFlusher {
    pub fn new() -> Self {
        ShutdownFlusher {
            state_log_path: Some("iron_consensus_state.jsonl".into()),
        }
    }

    pub fn flush_state_log(&self, jsonl: &str) {
        use std::io::Write;
        let Some(path) = &self.state_log_path else { return };
        // FIX #12: atomic write via tmp file + rename. Previous `std::fs::write`
        // wrote in-place and is NOT atomic on any platform — a crash mid-write
        // leaves a corrupt JSONL file that readers see as partially-truncated.
        // On POSIX `rename` is atomic: readers see either the old file or the
        // fully-flushed new one. `sync_all()` forces the kernel to flush the
        // buffer before the rename so power-loss doesn't leave a zero-length
        // file behind the rename.
        let tmp = path.with_extension("jsonl.tmp");
        let result: std::io::Result<()> = (|| {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(jsonl.as_bytes())?;
            f.sync_all()?;
            std::fs::rename(&tmp, path)?;
            Ok(())
        })();
        match result {
            Ok(_)  => info!("IronConsensus: state log flushed to {:?}", path),
            Err(e) => error!("IronConsensus: state log flush failed: {e}"),
        }
    }
}

impl Default for ShutdownFlusher { fn default() -> Self { Self::new() } }

// -- Slow tick detector --

pub struct SlowTickDetector {
    threshold: Duration,
    started:   Instant,
}

impl SlowTickDetector {
    pub fn start(threshold: Duration) -> Self {
        SlowTickDetector { threshold, started: Instant::now() }
    }

    pub fn finish(self, tick_name: &str) -> Duration {
        let elapsed = self.started.elapsed();
        if elapsed > self.threshold {
            warn!(
                tick = tick_name,
                elapsed_ms = elapsed.as_millis(),
                threshold_ms = self.threshold.as_millis(),
                "IronConsensus: slow tick detected"
            );
        }
        elapsed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_guard_prevents_reentry() {
        let guard = TickGuard::new();
        let lock1 = guard.try_acquire();
        assert!(lock1.is_some());
        let lock2 = guard.try_acquire();
        assert!(lock2.is_none());
        drop(lock1);
        let lock3 = guard.try_acquire();
        assert!(lock3.is_some());
    }

    #[test]
    fn panic_recovery_does_not_propagate() {
        run_with_panic_recovery("test_tick", || {
            panic!("intentional test panic");
        });
    }

    #[test]
    fn slow_tick_detector_returns_elapsed() {
        let d = SlowTickDetector::start(Duration::from_secs(10));
        let elapsed = d.finish("test");
        assert!(elapsed < Duration::from_secs(1));
    }
}
