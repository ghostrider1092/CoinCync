//! CPU affinity + thread-count helpers — miner-side only, zero consensus impact.
//!
//! RandomX full-mem is memory-latency bound, so two cheap, well-documented
//! wins (both standard in mature miners like XMRig):
//!
//!   - **Pin** each mining thread to a distinct core. Left unpinned, the
//!     scheduler migrates hashing threads between cores; every migration
//!     cold-starts L1/L2, and on a multi-node box can bounce a thread onto
//!     memory it no longer sits near. Pinning holds each worker on one core.
//!   - **Default the thread count to PHYSICAL cores**, not logical. SMT
//!     siblings share execution ports and the memory port, so a second thread
//!     per physical core rarely adds RandomX throughput and often steals it.
//!
//! Both are pure performance: the per-nonce hash goes through the unchanged,
//! hash-locked `compute_pow_hash`, so results stay byte-identical and the
//! validator still accepts the blocks. NUMA-local dataset placement and
//! physical-first core ordering build on this (next step); this module keeps
//! a simple round-robin pin so it is correct and safe on every platform.

use std::sync::OnceLock;

/// Schedulable core ids ordered **physical-first**: one logical CPU per
/// physical core, then the SMT siblings. Detected once. Empty when the
/// platform can't report cores (then we mine unpinned rather than fail).
///
/// Why the ordering matters: with the physical-core thread default, pinning
/// the first N workers to this order lands them on N distinct physical cores
/// instead of doubling up on one core's SMT siblings — which is where the
/// RandomX throughput actually lives. On Linux the order comes from
/// `/sys` topology; anywhere else (or on any read failure) it falls back to
/// the raw enumeration order, which still pins, just without the reordering.
fn ordered_core_ids() -> &'static Vec<core_affinity::CoreId> {
    static IDS: OnceLock<Vec<core_affinity::CoreId>> = OnceLock::new();
    IDS.get_or_init(|| {
        let raw = core_affinity::get_core_ids().unwrap_or_default();
        #[cfg(target_os = "linux")]
        if let Some(ordered) = linux_physical_first(&raw) {
            return ordered;
        }
        raw
    })
}

/// Group `(physical_core, [logical cpu ids])` from Linux `/sys` topology and
/// emit a physical-first ordering. Returns `None` on any missing/unparseable
/// file so the caller falls back to the raw order.
#[cfg(target_os = "linux")]
fn linux_physical_first(
    raw: &[core_affinity::CoreId],
) -> Option<Vec<core_affinity::CoreId>> {
    use std::collections::BTreeMap;
    // Key each logical cpu by its (package, physical core) so SMT siblings
    // share a group. BTreeMap keeps the group order stable + deterministic.
    let mut groups: BTreeMap<(u32, u32), Vec<core_affinity::CoreId>> = BTreeMap::new();
    for id in raw {
        let base = format!("/sys/devices/system/cpu/cpu{}/topology", id.id);
        let pkg: u32 = std::fs::read_to_string(format!("{base}/physical_package_id"))
            .ok()?
            .trim()
            .parse()
            .ok()?;
        let core: u32 = std::fs::read_to_string(format!("{base}/core_id"))
            .ok()?
            .trim()
            .parse()
            .ok()?;
        groups.entry((pkg, core)).or_default().push(*id);
    }
    if groups.is_empty() {
        return None;
    }
    Some(interleave_groups(groups.into_values().collect()))
}

/// Round-robin across groups: take the 1st of every group, then the 2nd of
/// every group, and so on. One logical CPU per physical core comes out first,
/// siblings last. Pure + deterministic, so it is unit-tested directly.
fn interleave_groups<T: Clone>(groups: Vec<Vec<T>>) -> Vec<T> {
    let widest = groups.iter().map(Vec::len).max().unwrap_or(0);
    let mut out = Vec::new();
    for lane in 0..widest {
        for g in &groups {
            if let Some(item) = g.get(lane) {
                out.push(item.clone());
            }
        }
    }
    out
}

/// Pin the CURRENT thread to one core, chosen by `worker_index` over the
/// physical-first core order. Call once at the top of a mining thread, before
/// it builds its VM, so the VM's scratchpad is allocated local to the pinned
/// core. Best-effort: on any platform that can't pin, it logs and returns so
/// mining still runs.
pub fn pin_current_thread(worker_index: usize) {
    let ids = ordered_core_ids();
    if ids.is_empty() {
        tracing::debug!(
            worker_index,
            "core affinity unavailable on this platform; running unpinned"
        );
        return;
    }
    let core = ids[worker_index % ids.len()];
    if core_affinity::set_for_current(core) {
        tracing::debug!(worker_index, core_id = core.id, "pinned mining thread to core");
    } else {
        tracing::debug!(
            worker_index,
            core_id = core.id,
            "could not pin mining thread (continuing unpinned)"
        );
    }
}

/// Resolve the mining thread count.
///
/// - `requested != 0` is honored verbatim (always clamped to >= 1), so the
///   fleet's explicit `--threads 1` is unchanged.
/// - `requested == 0` (auto) resolves to the **physical** core count, which is
///   the better default for memory-bound RandomX than the logical count the
///   rig used before. `COINCYNC_RIG_THREADS` overrides the auto value for
///   per-box tuning without a rebuild.
pub fn resolve_thread_count(requested: usize) -> usize {
    if requested != 0 {
        return requested.max(1);
    }
    if let Ok(v) = std::env::var("COINCYNC_RIG_THREADS") {
        if let Ok(n) = v.trim().parse::<usize>() {
            if n >= 1 {
                tracing::info!(threads = n, "thread count from COINCYNC_RIG_THREADS");
                return n;
            }
        }
    }
    let physical = num_cpus::get_physical().max(1);
    let logical = num_cpus::get();
    tracing::info!(
        physical,
        logical,
        chosen = physical,
        "auto thread count = physical cores (override with --threads N or COINCYNC_RIG_THREADS)"
    );
    physical
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_honors_explicit_request() {
        assert_eq!(resolve_thread_count(4), 4);
        assert_eq!(resolve_thread_count(1), 1);
    }

    #[test]
    fn resolve_clamps_nonzero_to_at_least_one() {
        // 0 is the "auto" sentinel; any explicit value stays >= 1.
        assert!(resolve_thread_count(7) >= 1);
    }

    #[test]
    fn resolve_auto_is_at_least_one() {
        // Auto path (env may or may not be set in CI) must never yield 0.
        assert!(resolve_thread_count(0) >= 1);
    }

    #[test]
    fn pin_is_safe_to_call() {
        // Must never panic, whatever the platform reports.
        pin_current_thread(0);
        pin_current_thread(99999);
    }

    #[test]
    fn interleave_is_physical_first() {
        // 4 physical cores, 2 SMT siblings each (logical ids grouped by core).
        let groups = vec![vec![0, 4], vec![1, 5], vec![2, 6], vec![3, 7]];
        // One logical per physical core first (0..3), then the siblings (4..7).
        assert_eq!(interleave_groups(groups), vec![0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn interleave_handles_no_smt_and_ragged_groups() {
        // No SMT: each group has one cpu → order is just the cores in order.
        assert_eq!(
            interleave_groups(vec![vec![0], vec![1], vec![2]]),
            vec![0, 1, 2]
        );
        // Ragged (some cores expose a sibling, some don't): still physical-first,
        // and never drops or duplicates a cpu.
        let mut out = interleave_groups(vec![vec![0, 2], vec![1]]);
        out.sort();
        assert_eq!(out, vec![0, 1, 2]);
    }
}
