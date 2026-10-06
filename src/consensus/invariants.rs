//! Policy and enforcement glue over the diagnostic `CATALOG` — the single
//! registry of consensus invariants (see [`crate::diagnostics`]).
//!
//! The catalog already names each invariant: a stable `CYNC-*` code, the
//! statement that MUST hold, a severity, and the code location that enforces it.
//! This module adds the thin layer the catalog does not:
//!
//! 1. [`fail_closed`] — the policy, derived from severity, of whether a breach
//!    must reject/halt (consensus) or merely be surfaced (observability).
//! 2. [`check`] — a uniform helper so every enforcement site turns a breached
//!    condition into the SAME coded, compiler-style [`Report`], instead of each
//!    site inventing an ad-hoc error string.
//! 3. [`consensus_catalog`] — the consensus-critical view the deterministic
//!    simulation harness runs after every event.
//!
//! One registry, one policy, consumed by block validation, the runtime guards
//! and the simulator — the single-source discipline of #173 applied to the
//! invariants themselves rather than re-listing them per consumer.

use crate::diagnostics::{self, Diagnostic, Domain, Report, Severity};

/// Whether a breach of an invariant of this severity must FAIL CLOSED — reject
/// the object or refuse to advance — rather than be logged and tolerated.
/// `Error` invariants protect chain validity; `Warning` ones are
/// degraded-but-safe observations.
pub const fn fail_closed(severity: Severity) -> bool {
    matches!(severity, Severity::Error)
}

/// The consensus-critical domains: the invariants the validator enforces and the
/// simulator checks, as opposed to wallet- or network-UX diagnostics.
pub const fn is_consensus_domain(domain: Domain) -> bool {
    matches!(
        domain,
        Domain::Consensus | Domain::Pow | Domain::Emission | Domain::Transaction | Domain::Storage
    )
}

/// The consensus-critical catalog entries, in catalog order.
pub fn consensus_catalog() -> impl Iterator<Item = &'static Diagnostic> {
    diagnostics::CATALOG
        .iter()
        .filter(|d| is_consensus_domain(d.domain))
}

/// Enforce one invariant at a check site.
///
/// Returns `Ok(())` when `holds`; otherwise `Err` carrying the invariant's coded
/// [`Report`] anchored at `at` (e.g. `"height 10000, block ac4e…"`), ready to log
/// or map into a validation error. `code` MUST be a `CYNC_*` catalog constant —
/// an unknown code panics (a programming error, per [`Report::new`]).
#[must_use = "a breached invariant that is neither propagated nor logged defeats the check"]
pub fn check(code: &'static str, holds: bool, at: impl Into<String>) -> Result<(), Report> {
    if holds {
        Ok(())
    } else {
        Err(Report::new(code).at(at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostics::{
        CYNC_CONS_001, CYNC_CONS_002, CYNC_EMIT_001, CYNC_NET_001, CYNC_POW_001, CYNC_SHLD_001,
        CYNC_STOR_001,
    };

    #[test]
    fn fail_closed_tracks_severity() {
        assert!(fail_closed(Severity::Error));
        assert!(!fail_closed(Severity::Warning));
    }

    #[test]
    fn check_ok_when_holds_and_reports_code_when_breached() {
        assert!(check(CYNC_EMIT_001, true, "height 1").is_ok());
        let err = check(CYNC_EMIT_001, false, "height 10000, block ac4e…").unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.starts_with("error[CYNC-EMIT-001]"), "got: {rendered}");
        assert!(rendered.contains("height 10000, block ac4e…"));
    }

    #[test]
    fn consensus_view_is_nonempty_and_only_consensus_domains() {
        let mut n = 0;
        for d in consensus_catalog() {
            assert!(
                is_consensus_domain(d.domain),
                "{} is not a consensus domain",
                d.code
            );
            n += 1;
        }
        assert!(n > 0, "the consensus view must not be empty");
        // Network- and wallet-domain diagnostics are excluded.
        assert!(!consensus_catalog().any(|d| matches!(d.domain, Domain::Network | Domain::Wallet)));
    }

    #[test]
    fn critical_invariants_are_present_and_fail_closed() {
        // Anti-regression: these core consensus invariants must stay in the
        // registry. Deleting an entry would silently drop its coded enforcement.
        for code in [CYNC_CONS_001, CYNC_CONS_002, CYNC_EMIT_001] {
            let d = diagnostics::lookup(code)
                .unwrap_or_else(|| panic!("critical invariant {code} missing from CATALOG"));
            assert!(is_consensus_domain(d.domain));
            assert!(fail_closed(d.severity), "{code} must be fail-closed (Error)");
        }
    }

    #[test]
    fn every_defined_code_resolves() {
        // No `CYNC_*` const may exist without a CATALOG entry (orphan code).
        for code in [
            CYNC_CONS_001,
            CYNC_CONS_002,
            CYNC_EMIT_001,
            CYNC_POW_001,
            CYNC_STOR_001,
            CYNC_NET_001,
            CYNC_SHLD_001,
        ] {
            assert!(diagnostics::lookup(code).is_some(), "orphan code const: {code}");
        }
    }
}
