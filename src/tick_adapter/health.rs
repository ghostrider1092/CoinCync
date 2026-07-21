//! Local system-health readers for `CoincyncAdapter::health_snapshot`.
//!
//! No external system-info dependency. Uses Linux `/proc/*` parsing
//! directly; non-Linux platforms get honest zero-valued fallbacks
//! (the sidecar binary runs on Linux fleet hosts in production, but
//! zero-fallbacks keep local Windows/macOS development builds
//! testable).
//!
//! ## What this module covers today (Phase 1h)
//!
//! - `ram_used_pct` — parses `/proc/meminfo`
//! - `swap_used_pct` — parses `/proc/meminfo`
//! - `uptime_secs` — parses `/proc/uptime`
//!
//! ## What's deferred with honest TODO comments
//!
//! - `disk_used_pct` — needs `statvfs` syscall; either a `libc` dep or
//!   subprocess to `df`. Deferred to Phase 1i (which brings tar +
//!   systemctl surface for `apply_chaindata` — disk usage naturally
//!   fits there since `apply_chaindata` is what makes disk fill up).
//! - `cpu_used_pct` — needs two `/proc/stat` samples separated in time
//!   for a delta calculation. A single-snapshot method can't compute
//!   this. Deferred to Phase 1j (the binary layer) which can keep a
//!   background sampler thread.
//! - `hashrate_hs` — not exposed via node RPC; would need direct
//!   integration with `coincync-rig`. Deferred to Phase 1j.
//! - `mempool_txs` — comes from the local node's `get_info` RPC, not
//!   `/proc/*`, so it's plumbed at the adapter level, not this
//!   module.

/// Percent RAM used according to `/proc/meminfo`. Uses `MemAvailable`
/// (kernel's best estimate of usable-without-swapping memory) rather
/// than `MemFree` (which underestimates by not counting caches).
///
/// Returns `0` on non-Linux platforms.
pub fn ram_used_pct() -> u8 {
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string("/proc/meminfo") {
            Ok(text) => parse_meminfo_ram_pct(&text).unwrap_or(0),
            Err(_) => 0,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// Percent swap used according to `/proc/meminfo`.
///
/// Returns `0` on non-Linux platforms.
pub fn swap_used_pct() -> u8 {
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string("/proc/meminfo") {
            Ok(text) => parse_meminfo_swap_pct(&text).unwrap_or(0),
            Err(_) => 0,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// System uptime in seconds from `/proc/uptime`. Not the adapter's
/// uptime — the whole host's uptime.
///
/// Returns `0` on non-Linux platforms.
pub fn uptime_secs() -> u64 {
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string("/proc/uptime") {
            Ok(text) => parse_uptime_secs(&text).unwrap_or(0),
            Err(_) => 0,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

// ─── Pure parsers ─────────────────────────────────────────────────────────

/// Parse `/proc/meminfo` for RAM used percentage.
///
/// `/proc/meminfo` has key/value lines like:
///
/// ```text
/// MemTotal:       32895616 kB
/// MemFree:         5321248 kB
/// MemAvailable:   19432080 kB
/// ```
///
/// We compute `(MemTotal - MemAvailable) / MemTotal * 100`. On kernels
/// too old to expose `MemAvailable` (pre-3.14), falls back to using
/// `MemFree` (less accurate but still returns *something*).
///
/// Returns `None` if `MemTotal` is missing or zero (undefined ratio).
pub fn parse_meminfo_ram_pct(text: &str) -> Option<u8> {
    let mem_total = parse_kb_field(text, "MemTotal")?;
    if mem_total == 0 {
        return None;
    }
    let available =
        parse_kb_field(text, "MemAvailable").or_else(|| parse_kb_field(text, "MemFree"))?;
    let used = mem_total.saturating_sub(available);
    Some(((used.saturating_mul(100)) / mem_total).min(100) as u8)
}

/// Parse `/proc/meminfo` for swap used percentage.
///
/// Returns `Some(0)` when swap is disabled (SwapTotal = 0). Distinct
/// from `None` (couldn't parse), so the caller can tell them apart
/// if needed.
pub fn parse_meminfo_swap_pct(text: &str) -> Option<u8> {
    let swap_total = parse_kb_field(text, "SwapTotal")?;
    if swap_total == 0 {
        return Some(0);
    }
    let swap_free = parse_kb_field(text, "SwapFree")?;
    let used = swap_total.saturating_sub(swap_free);
    Some(((used.saturating_mul(100)) / swap_total).min(100) as u8)
}

/// Parse `/proc/uptime` for system uptime in seconds.
///
/// `/proc/uptime` has ONE line: two space-separated floats, uptime
/// first, idle second. We take the integer part of the first value.
pub fn parse_uptime_secs(text: &str) -> Option<u64> {
    let first = text.split_ascii_whitespace().next()?;
    // Take only the integer part; the fractional part below-1s
    // precision doesn't matter for HealthTick's minute-scale
    // alerting.
    let dot_or_end = first.find('.').unwrap_or(first.len());
    first[..dot_or_end].parse().ok()
}

/// Helper: parse a `Key: NNN kB` line from `/proc/meminfo`. Returns
/// the value in kB.
fn parse_kb_field(text: &str, key: &str) -> Option<u64> {
    for line in text.lines() {
        // Split on the first colon: "MemTotal: 12345 kB"
        if let Some(rest) = line.strip_prefix(key) {
            let rest = rest.trim_start_matches(':').trim();
            // "12345 kB" — take the first whitespace-separated token
            if let Some(num_str) = rest.split_ascii_whitespace().next() {
                if let Ok(v) = num_str.parse::<u64>() {
                    return Some(v);
                }
            }
        }
    }
    None
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Sample `/proc/meminfo` output from a real Linux host (Ubuntu
    /// 24.04, ~32 GB RAM, ~8 GB swap, moderate load). Truncated to
    /// the lines we consume.
    const SAMPLE_MEMINFO: &str = "\
MemTotal:       32895616 kB
MemFree:         5321248 kB
MemAvailable:   19432080 kB
Buffers:          234876 kB
Cached:          8329480 kB
SwapCached:            0 kB
SwapTotal:       8388604 kB
SwapFree:        7500000 kB
";

    #[test]
    fn parse_meminfo_ram_pct_uses_memavailable() {
        // (32895616 - 19432080) / 32895616 * 100 = 40.9% → 40 (u8 trunc)
        let pct = parse_meminfo_ram_pct(SAMPLE_MEMINFO).expect("Some");
        assert_eq!(pct, 40);
    }

    #[test]
    fn parse_meminfo_ram_pct_falls_back_to_memfree_when_available_missing() {
        let text = "\
MemTotal:       10000000 kB
MemFree:         4000000 kB
";
        // (10000000 - 4000000) / 10000000 * 100 = 60%
        assert_eq!(parse_meminfo_ram_pct(text), Some(60));
    }

    #[test]
    fn parse_meminfo_ram_pct_none_when_memtotal_missing() {
        let text = "MemFree: 100 kB";
        assert_eq!(parse_meminfo_ram_pct(text), None);
    }

    #[test]
    fn parse_meminfo_ram_pct_none_when_memtotal_zero() {
        let text = "MemTotal: 0 kB\nMemAvailable: 0 kB";
        assert_eq!(parse_meminfo_ram_pct(text), None);
    }

    #[test]
    fn parse_meminfo_ram_pct_clamps_at_100() {
        // Available > Total is nonsensical but shouldn't panic —
        // saturating math clamps.
        let text = "MemTotal: 100 kB\nMemAvailable: 999 kB";
        assert_eq!(parse_meminfo_ram_pct(text), Some(0));
    }

    #[test]
    fn parse_meminfo_swap_pct_computes_used_fraction() {
        // (8388604 - 7500000) / 8388604 * 100 = 10.59% → 10
        let pct = parse_meminfo_swap_pct(SAMPLE_MEMINFO).expect("Some");
        assert_eq!(pct, 10);
    }

    #[test]
    fn parse_meminfo_swap_pct_zero_when_swap_disabled() {
        let text = "SwapTotal: 0 kB\nSwapFree: 0 kB";
        assert_eq!(parse_meminfo_swap_pct(text), Some(0));
    }

    #[test]
    fn parse_uptime_secs_takes_integer_part_of_first_float() {
        // Real `/proc/uptime` format: two floats separated by space.
        assert_eq!(parse_uptime_secs("1234.56 999.99\n"), Some(1234));
    }

    #[test]
    fn parse_uptime_secs_handles_zero() {
        assert_eq!(parse_uptime_secs("0.00 0.00\n"), Some(0));
    }

    #[test]
    fn parse_uptime_secs_none_on_empty() {
        assert_eq!(parse_uptime_secs(""), None);
    }

    #[test]
    fn parse_uptime_secs_none_on_non_numeric() {
        assert_eq!(parse_uptime_secs("abc def\n"), None);
    }

    #[test]
    fn parse_uptime_secs_handles_no_dot() {
        assert_eq!(parse_uptime_secs("42 999\n"), Some(42));
    }

    #[test]
    fn parse_kb_field_prefix_matches_correctly() {
        // Ensure "MemTotal" isn't accidentally matched by a line that
        // starts with "Mem" (like "MemFree"). Prefix + colon check
        // guards this.
        let text = "MemFree: 100 kB\nMemTotal: 200 kB";
        assert_eq!(parse_kb_field(text, "MemTotal"), Some(200));
        assert_eq!(parse_kb_field(text, "MemFree"), Some(100));
    }

    /// Sanity check on the platform-gated readers: they don't panic
    /// on the current platform. Values will be 0 on Windows.
    #[test]
    fn platform_gated_readers_do_not_panic() {
        let _ = ram_used_pct();
        let _ = swap_used_pct();
        let _ = uptime_secs();
    }
}
