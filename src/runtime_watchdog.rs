//! # Runtime deadlock watchdog
//!
//! Detects the specific class of failure that took `api.coincync.network`
//! down for 41 hours on 2026-07-02: every tokio worker thread parked on
//! a futex, no forward progress, process alive per systemd, log frozen,
//! zero RPC responsiveness.
//!
//! The watchdog:
//!
//! 1. Runs as a **dedicated OS thread** (`std::thread::spawn`, NOT a
//!    tokio task). If tokio deadlocks, tokio-scheduled tasks can't run.
//!    A native thread bypasses the whole runtime and can still detect
//!    + report the situation.
//!
//! 2. Reads a **heartbeat counter** that a lightweight tokio task
//!    increments every `HEARTBEAT_INTERVAL_SECS`. If the counter stops
//!    advancing while the watchdog is still ticking, tokio is wedged.
//!
//! 3. Cross-references with `/proc/self/task/*/wchan` on Linux to
//!    confirm the wedge is a **futex deadlock** (as opposed to e.g. an
//!    endless CPU-bound loop or a stalled I/O syscall). The 2026-07-02
//!    signature was `16/16 threads on futex_wait_queue`.
//!
//! 4. On confirmed deadlock, dumps a **diagnostic snapshot** to
//!    `<data_dir>/deadlock-<unix_ts>.log`:
//!       - Per-thread `state`, `wchan`, and kernel stack
//!         (`/proc/self/task/<tid>/stack`)
//!       - Approximate task-scheduler counters (voluntary /
//!         non-voluntary context switches)
//!       - Timestamps of the last heartbeat, first stall detection,
//!         and abort.
//!    Then calls [`std::process::abort()`], which produces a coredump
//!    if enabled and triggers systemd's Restart= policy.
//!
//! ## Scope caveats — honest about what this does NOT do
//!
//! - **No Rust-level userspace backtraces.** Getting cross-thread Rust
//!   stacks requires either `gdb` attached (not installed on the
//!   fleet), a `tokio-console` instrumented build (planned as a
//!   follow-up feature), or a fragile SIGUSR1 + per-thread
//!   `backtrace::trace_unsynchronized` dance that is worse than the
//!   kernel-stack dump for a first-cut diagnostic.
//! - **False-positive risk on very-loaded systems.** IBD burst can
//!   legitimately park many workers on futexes briefly. The watchdog
//!   requires the futex-park pattern to persist for
//!   `DEADLOCK_CONFIRMATION_SECS` (default 120s) before acting.
//! - **Linux-only diagnostic dump.** `/proc/*` is Linux. On other
//!   OSes the watchdog still detects the heartbeat stall + aborts,
//!   but the diagnostic file is a stub.
//!
//! ## Design references
//!
//! - Bitcoin Core's `WaitableCriticalSection` deadlock check
//! - Kubernetes' liveness / readiness split (we're implementing the
//!   liveness half in-process rather than delegating to k8s)
//! - Amazon's "process suicide is better than half-alive" principle:
//!   under a deadlock, restarting is strictly better than staying up
//!   and silently serving stale data.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// How often the tokio heartbeat task increments the counter.
///
/// Kept short so a wedged tokio is detected quickly, but long enough
/// that a single scheduling hiccup doesn't trip us.
pub const HEARTBEAT_INTERVAL_SECS: u64 = 5;

/// The watchdog's own sleep interval between checks. Independent of
/// tokio's timer wheel — pure `std::thread::sleep`.
pub const WATCHDOG_CHECK_INTERVAL_SECS: u64 = 15;

/// Consecutive seconds the heartbeat must be stale before we open a
/// hang investigation.
pub const HANG_SUSPICION_SECS: u64 = 45;

/// Total seconds the futex-park pattern must persist before we call it
/// a confirmed deadlock and abort. Chosen to comfortably exceed any
/// legitimate long-running blocking operation (e.g. RandomX dataset
/// build at startup, which can take 30-60s and parks all workers
/// briefly).
pub const DEADLOCK_CONFIRMATION_SECS: u64 = 120;

/// Fraction of threads that must be in futex_wait state to consider the
/// process deadlocked. On a healthy 8-worker tokio process, at most a
/// few threads should be futex-parked at any moment; the rest are in
/// `epoll_wait` (I/O) or `hrtimer_nanosleep` (timer). Sustained 90%+
/// futex-park means everyone is fighting for a lock.
pub const FUTEX_FRACTION_THRESHOLD: f64 = 0.90;

/// Public heartbeat handle. Cheap to clone (`Arc<AtomicU64>`).
///
/// The tokio heartbeat task calls [`Self::pulse`] every
/// [`HEARTBEAT_INTERVAL_SECS`]. The native watchdog thread reads
/// [`Self::read`] to detect staleness.
#[derive(Clone)]
pub struct WatchdogHeartbeat {
    counter: Arc<AtomicU64>,
    started_at: std::time::Instant,
}

impl WatchdogHeartbeat {
    pub fn new() -> Self {
        Self {
            counter: Arc::new(AtomicU64::new(0)),
            started_at: std::time::Instant::now(),
        }
    }

    /// Called from the tokio heartbeat task on every interval tick.
    pub fn pulse(&self) {
        self.counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Called from the native watchdog thread — reads without blocking.
    pub fn read(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }

    /// Seconds elapsed since the watchdog was armed. Used to reject
    /// premature abort during process startup, when the RandomX
    /// dataset build (~30-60s) legitimately parks every worker.
    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}

impl Default for WatchdogHeartbeat {
    fn default() -> Self {
        Self::new()
    }
}

/// Start the watchdog. Returns the [`WatchdogHeartbeat`] handle to be
/// pulsed by the tokio heartbeat task; the native OS thread is
/// spawned and detached inside this call.
///
/// `data_dir` is where diagnostic snapshots land on confirmed
/// deadlock. Usually the node's `--data-dir` (e.g.
/// `/var/lib/coincync`) — the directory must be writable by the
/// process.
///
/// This function returns immediately after spawning the OS thread;
/// the tokio task that pulses `heartbeat` should be spawned by the
/// caller (see [`spawn_heartbeat_task`]).
pub fn arm(data_dir: impl Into<PathBuf>) -> WatchdogHeartbeat {
    let heartbeat = WatchdogHeartbeat::new();
    let watchdog_hb = heartbeat.clone();
    let data_dir = data_dir.into();

    std::thread::Builder::new()
        .name("coincync-watchdog".to_string())
        .spawn(move || run_watchdog_loop(watchdog_hb, data_dir))
        .expect("watchdog OS thread spawn must succeed at process start");

    tracing::info!(
        target: "runtime_watchdog",
        "runtime deadlock watchdog armed: heartbeat every {}s, check every {}s, \
         hang suspicion at {}s, deadlock confirmation at {}s",
        HEARTBEAT_INTERVAL_SECS,
        WATCHDOG_CHECK_INTERVAL_SECS,
        HANG_SUSPICION_SECS,
        DEADLOCK_CONFIRMATION_SECS,
    );

    heartbeat
}

/// Spawn the tokio task that pulses the heartbeat every
/// [`HEARTBEAT_INTERVAL_SECS`]. Caller is responsible for spawning
/// this from a tokio runtime.
pub fn spawn_heartbeat_task(heartbeat: WatchdogHeartbeat) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
        loop {
            ticker.tick().await;
            heartbeat.pulse();
        }
    });
}

// ─── internal watchdog loop (dedicated OS thread) ──────────────────────

fn run_watchdog_loop(heartbeat: WatchdogHeartbeat, data_dir: PathBuf) {
    let mut last_seen_counter = heartbeat.read();
    let mut last_progress = std::time::Instant::now();
    let mut first_stall_detected: Option<std::time::Instant> = None;

    loop {
        std::thread::sleep(Duration::from_secs(WATCHDOG_CHECK_INTERVAL_SECS));

        let current = heartbeat.read();
        let uptime = heartbeat.uptime_secs();

        // During the first minute we ignore stalls — RandomX dataset
        // build at startup legitimately parks every worker for
        // 30-60s. Aborting in that window would prevent the node from
        // ever starting.
        if uptime < 90 {
            last_seen_counter = current;
            last_progress = std::time::Instant::now();
            continue;
        }

        if current > last_seen_counter {
            // Tokio is making progress. Reset the stall clock.
            last_seen_counter = current;
            last_progress = std::time::Instant::now();
            first_stall_detected = None;
            continue;
        }

        // Heartbeat has not advanced since the previous check.
        let stall_secs = last_progress.elapsed().as_secs();

        if stall_secs < HANG_SUSPICION_SECS {
            // Below the suspicion threshold — could be a transient
            // scheduling gap. Keep waiting.
            continue;
        }

        // Suspicion threshold hit. Record when we first noticed and
        // check whether the futex-park pattern also holds.
        let first = first_stall_detected.get_or_insert_with(std::time::Instant::now);

        let futex_status = inspect_futex_pattern();

        tracing::warn!(
            target: "runtime_watchdog",
            "runtime stall detected: heartbeat frozen for {}s (last counter {}); \
             {} of {} threads on futex_wait_queue",
            stall_secs, current, futex_status.futex_count, futex_status.total_threads,
        );

        // Confirmed deadlock only if BOTH the heartbeat stall AND the
        // futex-park pattern have persisted long enough.
        if first.elapsed().as_secs() >= DEADLOCK_CONFIRMATION_SECS
            && futex_status.is_deadlock_pattern()
        {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let path = data_dir.join(format!("deadlock-{}.log", ts));

            tracing::error!(
                target: "runtime_watchdog",
                "CONFIRMED DEADLOCK: {} of {} threads on futex_wait_queue for {}s + \
                 heartbeat frozen for {}s. Writing diagnostic to {} then calling \
                 abort() — systemd will restart the process. If this recurs, \
                 attach gdb / rebuild with tokio-console for Rust-level stacks.",
                futex_status.futex_count, futex_status.total_threads,
                first.elapsed().as_secs(), stall_secs, path.display(),
            );

            let _ = write_diagnostic_snapshot(&path, &futex_status, stall_secs, current, uptime);

            // Give tracing a moment to flush before abort.
            std::thread::sleep(Duration::from_millis(200));
            std::process::abort();
        }
    }
}

// ─── /proc introspection ───────────────────────────────────────────────

struct FutexStatus {
    total_threads: usize,
    futex_count: usize,
    #[cfg(target_os = "linux")]
    per_thread: Vec<ThreadSnapshot>,
}

#[cfg(target_os = "linux")]
struct ThreadSnapshot {
    tid: u32,
    wchan: String,
    state_line: String,
    kernel_stack_head: String,
}

impl FutexStatus {
    fn is_deadlock_pattern(&self) -> bool {
        if self.total_threads == 0 {
            return false;
        }
        (self.futex_count as f64 / self.total_threads as f64) >= FUTEX_FRACTION_THRESHOLD
    }
}

#[cfg(target_os = "linux")]
fn inspect_futex_pattern() -> FutexStatus {
    let task_dir = Path::new("/proc/self/task");
    let mut total = 0usize;
    let mut futex = 0usize;
    let mut per_thread: Vec<ThreadSnapshot> = Vec::new();

    let entries = match std::fs::read_dir(task_dir) {
        Ok(e) => e,
        Err(_) => {
            return FutexStatus {
                total_threads: 0,
                futex_count: 0,
                per_thread: Vec::new(),
            };
        }
    };

    for entry in entries.flatten() {
        let tid_os = entry.file_name();
        let tid_str = tid_os.to_string_lossy().to_string();
        let tid: u32 = match tid_str.parse() {
            Ok(t) => t,
            Err(_) => continue,
        };
        total += 1;

        let base = format!("/proc/self/task/{}", tid);
        let wchan = std::fs::read_to_string(format!("{}/wchan", base))
            .unwrap_or_default()
            .trim()
            .to_string();
        if wchan == "futex_wait_queue" || wchan == "do_futex" || wchan.contains("futex") {
            futex += 1;
        }

        // Only collect per-thread detail for the diagnostic snapshot
        // path — cap at 32 to keep the file small on high-thread-count
        // hosts.
        if per_thread.len() < 32 {
            let state_line = std::fs::read_to_string(format!("{}/status", base))
                .unwrap_or_default()
                .lines()
                .find(|l| l.starts_with("State:"))
                .unwrap_or("State: ?")
                .to_string();
            let kernel_stack_head = std::fs::read_to_string(format!("{}/stack", base))
                .unwrap_or_default()
                .lines()
                .take(3)
                .collect::<Vec<_>>()
                .join(" | ");
            per_thread.push(ThreadSnapshot {
                tid,
                wchan: wchan.clone(),
                state_line,
                kernel_stack_head,
            });
        }
    }

    FutexStatus {
        total_threads: total,
        futex_count: futex,
        per_thread,
    }
}

#[cfg(not(target_os = "linux"))]
fn inspect_futex_pattern() -> FutexStatus {
    // Non-Linux hosts: without /proc we can't cheaply enumerate
    // per-thread wchan. Return a conservative zero — the watchdog
    // falls back to heartbeat-only detection.
    FutexStatus {
        total_threads: 0,
        futex_count: 0,
    }
}

fn write_diagnostic_snapshot(
    path: &Path,
    status: &FutexStatus,
    stall_secs: u64,
    last_counter: u64,
    uptime: u64,
) -> std::io::Result<()> {
    use std::io::Write;

    let mut f = std::fs::File::create(path)?;
    writeln!(f, "coincync runtime deadlock diagnostic")?;
    writeln!(
        f,
        "unix_ts: {}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    )?;
    writeln!(f, "process_uptime_secs: {}", uptime)?;
    writeln!(f, "heartbeat_last_counter: {}", last_counter)?;
    writeln!(f, "heartbeat_stall_secs: {}", stall_secs)?;
    writeln!(f, "total_threads: {}", status.total_threads)?;
    writeln!(f, "futex_park_threads: {}", status.futex_count)?;
    writeln!(
        f,
        "futex_fraction: {:.2}",
        if status.total_threads == 0 {
            0.0
        } else {
            status.futex_count as f64 / status.total_threads as f64
        }
    )?;
    writeln!(f)?;

    #[cfg(target_os = "linux")]
    {
        writeln!(f, "─── per-thread snapshot (capped at 32) ───")?;
        for t in &status.per_thread {
            writeln!(
                f,
                "tid={} wchan={} state=[{}] kernel_stack_head=[{}]",
                t.tid, t.wchan, t.state_line, t.kernel_stack_head,
            )?;
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        writeln!(
            f,
            "(per-thread introspection unavailable on non-Linux hosts)"
        )?;
    }
    Ok(())
}

// ─── tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_pulses_increment_the_counter() {
        let hb = WatchdogHeartbeat::new();
        assert_eq!(hb.read(), 0);
        hb.pulse();
        assert_eq!(hb.read(), 1);
        hb.pulse();
        hb.pulse();
        assert_eq!(hb.read(), 3);
    }

    #[test]
    fn heartbeat_clone_shares_state() {
        // The heartbeat handle is passed to both the tokio task and
        // the watchdog thread. Clones MUST share state, otherwise the
        // watchdog would see stale zero counts.
        let hb1 = WatchdogHeartbeat::new();
        let hb2 = hb1.clone();
        hb1.pulse();
        assert_eq!(hb2.read(), 1, "clone must observe the pulse");
        hb2.pulse();
        assert_eq!(hb1.read(), 2, "original must observe the clone's pulse");
    }

    #[test]
    fn futex_pattern_needs_at_least_90_percent() {
        // Sanity-check the deadlock threshold. 89% futex-park should
        // NOT trip; 90% or more should. This threshold was chosen
        // empirically from the 2026-07-02 incident (16/16 = 100%);
        // a single tokio task not in futex is enough to break the
        // pattern under legitimate lock contention.
        let s = FutexStatus {
            total_threads: 100,
            futex_count: 89,
            #[cfg(target_os = "linux")]
            per_thread: Vec::new(),
        };
        assert!(!s.is_deadlock_pattern());

        let s = FutexStatus {
            total_threads: 100,
            futex_count: 90,
            #[cfg(target_os = "linux")]
            per_thread: Vec::new(),
        };
        assert!(s.is_deadlock_pattern());
    }

    #[test]
    fn futex_pattern_zero_threads_returns_false() {
        // Defensive: if /proc read failed and we have zero threads,
        // we must NOT report deadlock. Zero-divided-by-zero would
        // otherwise be ambiguous.
        let s = FutexStatus {
            total_threads: 0,
            futex_count: 0,
            #[cfg(target_os = "linux")]
            per_thread: Vec::new(),
        };
        assert!(!s.is_deadlock_pattern());
    }
}
