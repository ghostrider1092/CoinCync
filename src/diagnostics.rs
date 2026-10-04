//! # Diagnostics — stable codes for runtime & consensus failures
//!
//! `rustc` gives compile errors a stable code and `--explain` text so you jump
//! straight to the cause. This module does the same for CoinCync's **runtime**
//! failures — consensus rejects, broken invariants, soak/test panics — so that
//! in a large codebase a bug is *located and understood by its code*, not by
//! grepping.
//!
//! Each failure class has a stable [`Diagnostic`] in the [`CATALOG`]: a code
//! (`CYNC-<DOMAIN>-<NNN>`), a one-line title, the invariant it guards, the code
//! location that enforces it, the spec/CIP that defines it, and fix guidance.
//! When a failure actually occurs, a [`Report`] pairs that catalog entry with
//! the concrete context (where on the chain, expected vs. got, how to reproduce)
//! and renders it compiler-style:
//!
//! ```text
//! error[CYNC-SHLD-001]: shielded pool value went negative
//!   --> height 142, block 3af9c1…
//!    = invariant : ShieldedPoolValue ≥ 0 (running Σ value_balance)
//!    = expected  : >= 0
//!    = got       : -500
//!    = where     : src/chain.rs::verify_block_shielded_spends
//!    = spec      : docs/design/cip-shielded-anonset.md (pool turnstile)
//!    = reproduce : SHIELDED_SOAK_SEED=828927513140
//!    = help      : a spend's value_balance exceeded the pool — check
//!                  crypto/spark_turnstile.rs::crossing
//! ```
//!
//! `CATALOG` is the single source of truth: it drives the runtime message, the
//! `coincync-diag explain <code>` CLI, and the generated `DIAGNOSTICS.md`. A
//! test enforces that every code is well-formed and unique, so the catalog can't
//! rot as the tree grows.

use std::fmt;

/// Subsystem a diagnostic belongs to. The `as_str` token is the `<DOMAIN>`
/// segment of the code (`CYNC-<DOMAIN>-<NNN>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    /// Block/transaction validation + chain state.
    Consensus,
    /// Proof-of-work + difficulty retargeting.
    Pow,
    /// Emission schedule + supply accounting.
    Emission,
    /// Peer-to-peer networking + sync.
    Network,
    /// Mempool + transaction admission.
    Transaction,
    /// Shielded (Lelantus-Spark) path.
    Shielded,
    /// Persistent stores + reorg handling.
    Storage,
    /// Wallet.
    Wallet,
}

impl Domain {
    /// The `<DOMAIN>` token used in codes.
    pub const fn as_str(self) -> &'static str {
        match self {
            Domain::Consensus => "CONS",
            Domain::Pow => "POW",
            Domain::Emission => "EMIT",
            Domain::Network => "NET",
            Domain::Transaction => "TX",
            Domain::Shielded => "SHLD",
            Domain::Storage => "STOR",
            Domain::Wallet => "WALL",
        }
    }
}

/// How serious a diagnostic is when it fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// A broken invariant / rejected object — the chain protected itself.
    Error,
    /// A degraded-but-safe condition worth surfacing.
    Warning,
}

impl Severity {
    const fn label(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
        }
    }
}

/// A stable catalog entry for one class of runtime/consensus failure.
///
/// All fields are `&'static str` so the whole catalog is a compile-time
/// constant with zero runtime cost until a failure is actually reported.
#[derive(Debug, Clone, Copy)]
pub struct Diagnostic {
    /// Stable identifier, `CYNC-<DOMAIN>-<NNN>` (e.g. `CYNC-SHLD-001`).
    pub code: &'static str,
    /// Subsystem this belongs to.
    pub domain: Domain,
    /// Default severity.
    pub severity: Severity,
    /// One-line human title.
    pub title: &'static str,
    /// The invariant this guards — what MUST hold.
    pub invariant: &'static str,
    /// Code location that enforces it (`file.rs::fn`).
    pub location: &'static str,
    /// Spec / CIP / doc that defines the rule.
    pub spec: &'static str,
    /// Guidance: where to look / likely cause when it fires.
    pub help: &'static str,
}

impl Diagnostic {
    /// Render the static catalog entry as `coincync-diag explain <code>` shows
    /// it (no per-occurrence context — see [`Report`] for that).
    pub fn explain(&self) -> String {
        format!(
            "{sev}[{code}]: {title}\n\
             \x20  domain    : {domain}\n\
             \x20  invariant : {inv}\n\
             \x20  where     : {loc}\n\
             \x20  spec      : {spec}\n\
             \x20  help      : {help}",
            sev = self.severity.label(),
            code = self.code,
            title = self.title,
            domain = self.domain.as_str(),
            inv = self.invariant,
            loc = self.location,
            spec = self.spec,
            help = self.help,
        )
    }
}

/// A concrete occurrence of a [`Diagnostic`] with runtime context, rendered
/// compiler-style. Build with [`Report::new`] and the `at`/`expected`/`got`/
/// `reproduce` setters, then `to_string()` / log it.
#[derive(Debug, Clone)]
pub struct Report {
    diagnostic: &'static Diagnostic,
    /// Where on the chain (e.g. "height 142, block 3af9c1…").
    at: Option<String>,
    expected: Option<String>,
    got: Option<String>,
    /// How to reproduce (e.g. a soak seed, a block hash to replay).
    reproduce: Option<String>,
}

impl Report {
    /// Start a report for `code`. Panics only if `code` is not in the catalog —
    /// a programming error caught by the catalog-consistency test, never a
    /// runtime path (reporters use the `CYNC_*` consts, not raw strings).
    pub fn new(code: &str) -> Self {
        let diagnostic = lookup(code)
            .unwrap_or_else(|| panic!("diagnostics: unknown code {code:?} (not in CATALOG)"));
        Report { diagnostic, at: None, expected: None, got: None, reproduce: None }
    }

    /// Where on the chain the failure occurred.
    pub fn at(mut self, location: impl Into<String>) -> Self {
        self.at = Some(location.into());
        self
    }

    /// The value the invariant required.
    pub fn expected(mut self, v: impl fmt::Display) -> Self {
        self.expected = Some(v.to_string());
        self
    }

    /// The value actually observed.
    pub fn got(mut self, v: impl fmt::Display) -> Self {
        self.got = Some(v.to_string());
        self
    }

    /// A handle that reproduces the failure (seed, block hash, …).
    pub fn reproduce(mut self, v: impl Into<String>) -> Self {
        self.reproduce = Some(v.into());
        self
    }

    /// The underlying catalog entry.
    pub fn diagnostic(&self) -> &'static Diagnostic {
        self.diagnostic
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d = self.diagnostic;
        writeln!(f, "{}[{}]: {}", d.severity.label(), d.code, d.title)?;
        if let Some(at) = &self.at {
            writeln!(f, "  --> {at}")?;
        }
        writeln!(f, "   = invariant : {}", d.invariant)?;
        if let Some(e) = &self.expected {
            writeln!(f, "   = expected  : {e}")?;
        }
        if let Some(g) = &self.got {
            writeln!(f, "   = got       : {g}")?;
        }
        writeln!(f, "   = where     : {}", d.location)?;
        writeln!(f, "   = spec      : {}", d.spec)?;
        if let Some(r) = &self.reproduce {
            writeln!(f, "   = reproduce : {r}")?;
        }
        write!(f, "   = help      : {}", d.help)
    }
}

/// Look up a catalog entry by its code. Returns a `'static` reference so
/// reporters and the CLI share the one compile-time catalog.
pub fn lookup(code: &str) -> Option<&'static Diagnostic> {
    CATALOG.iter().find(|d| d.code == code)
}

// ============================================================================
// Code constants — reporters reference these, never raw strings, so a typo is a
// compile error and `grep CYNC_` finds every emission site.
// ============================================================================

/// Block header fails its PoW target.
pub const CYNC_CONS_001: &str = "CYNC-CONS-001";
/// A transaction double-spends an already-spent output (key image reused).
pub const CYNC_CONS_002: &str = "CYNC-CONS-002";
/// Consensus safety: two honest nodes hold different blocks at a height at or
/// below the finality floor (a fork that should be impossible became visible).
pub const CYNC_CONS_003: &str = "CYNC-CONS-003";
/// Block timestamp exceeds the future-drift cap (now + MAX_TIMESTAMP_DRIFT).
pub const CYNC_CONS_004: &str = "CYNC-CONS-004";
/// Block timestamp is not strictly greater than the parent's (monotonicity).
pub const CYNC_CONS_005: &str = "CYNC-CONS-005";
/// Coinbase output exceeds the scheduled block reward + fees.
pub const CYNC_EMIT_001: &str = "CYNC-EMIT-001";
/// Difficulty retarget stepped outside the permitted per-block bounds.
pub const CYNC_POW_001: &str = "CYNC-POW-001";
/// A reorg left the UTXO set and a Phase-2 store out of lock-step.
pub const CYNC_STOR_001: &str = "CYNC-STOR-001";
/// Node is isolated (0 outbound) with an exhausted address book.
pub const CYNC_NET_001: &str = "CYNC-NET-001";
/// Shielded pool value went negative (value created across the veil).
pub const CYNC_SHLD_001: &str = "CYNC-SHLD-001";
/// Unsupported transaction version.
pub const CYNC_CONS_006: &str = "CYNC-CONS-006";
/// Output encrypted_amount wrong size.
pub const CYNC_CONS_007: &str = "CYNC-CONS-007";
/// Output encrypted_memo exceeds cap (structural).
pub const CYNC_CONS_008: &str = "CYNC-CONS-008";
/// Input:output ratio exceeds cap.
pub const CYNC_CONS_009: &str = "CYNC-CONS-009";
/// Output:input ratio exceeds cap.
pub const CYNC_CONS_010: &str = "CYNC-CONS-010";
/// Transfer/churn input count mismatch.
pub const CYNC_CONS_011: &str = "CYNC-CONS-011";
/// Transfer/churn output count mismatch.
pub const CYNC_CONS_012: &str = "CYNC-CONS-012";
/// Churn output count mismatch.
pub const CYNC_CONS_013: &str = "CYNC-CONS-013";
/// Duplicate key image within block.
pub const CYNC_CONS_014: &str = "CYNC-CONS-014";
/// Duplicate output stealth address.
pub const CYNC_CONS_015: &str = "CYNC-CONS-015";
/// Output stealth collides with on-chain output.
pub const CYNC_CONS_016: &str = "CYNC-CONS-016";
/// Ring member commitment mismatch (live UTXO).
pub const CYNC_CONS_017: &str = "CYNC-CONS-017";
/// Ring member commitment mismatch (spent record).
pub const CYNC_CONS_018: &str = "CYNC-CONS-018";
/// Ring member references non-existent output.
pub const CYNC_CONS_019: &str = "CYNC-CONS-019";
/// Ring member references immature coinbase.
pub const CYNC_CONS_020: &str = "CYNC-CONS-020";
/// Ring member references time-locked output.
pub const CYNC_CONS_021: &str = "CYNC-CONS-021";
/// Duplicate ring member within input.
pub const CYNC_CONS_022: &str = "CYNC-CONS-022";
/// Ring signature (CLSAG) verification failed.
pub const CYNC_CONS_023: &str = "CYNC-CONS-023";
/// Transaction validation failed.
pub const CYNC_CONS_024: &str = "CYNC-CONS-024";
/// Output stealth address is zero.
pub const CYNC_CONS_025: &str = "CYNC-CONS-025";
/// Output stealth address not a valid point.
pub const CYNC_CONS_026: &str = "CYNC-CONS-026";
/// Output tx_public_key is identity.
pub const CYNC_CONS_027: &str = "CYNC-CONS-027";
/// Output tx_public_key not a valid point.
pub const CYNC_CONS_028: &str = "CYNC-CONS-028";
/// Output commitment is identity.
pub const CYNC_CONS_029: &str = "CYNC-CONS-029";
/// Output commitment not a valid point.
pub const CYNC_CONS_030: &str = "CYNC-CONS-030";
/// Transaction has no inputs.
pub const CYNC_CONS_031: &str = "CYNC-CONS-031";
/// Transaction has no outputs.
pub const CYNC_CONS_032: &str = "CYNC-CONS-032";
/// Ring size below minimum.
pub const CYNC_CONS_033: &str = "CYNC-CONS-033";
/// Missing range proof.
pub const CYNC_CONS_034: &str = "CYNC-CONS-034";
/// Duplicate key image within transaction.
pub const CYNC_CONS_035: &str = "CYNC-CONS-035";
/// Encrypted_amount exceeds cap.
pub const CYNC_CONS_036: &str = "CYNC-CONS-036";
/// Encrypted_memo exceeds cap.
pub const CYNC_CONS_037: &str = "CYNC-CONS-037";
/// Input key image is zero.
pub const CYNC_CONS_038: &str = "CYNC-CONS-038";
/// Input key image not a valid point.
pub const CYNC_CONS_039: &str = "CYNC-CONS-039";
/// RandomX anchor mismatch.
pub const CYNC_POW_002: &str = "CYNC-POW-002";
/// PoW algorithm mismatch.
pub const CYNC_POW_003: &str = "CYNC-POW-003";

/// The canonical diagnostic catalog — the single source of truth for runtime
/// messages, `explain`, and the generated `DIAGNOSTICS.md`.
pub const CATALOG: &[Diagnostic] = &[
    Diagnostic {
        code: CYNC_CONS_001,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "block does not meet its proof-of-work target",
        invariant: "blake3_pow(header) <= header.target",
        location: "src/consensus/pow.rs::verify_pow",
        spec: "docs/design (PoW) — RandomX/target check",
        help: "the submitted block's hash exceeds its declared target; reject. \
               Check the miner's target selection and the header fields fed to PoW.",
    },
    Diagnostic {
        code: CYNC_CONS_002,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "double-spend: key image already spent",
        invariant: "each key image appears at most once across the chain",
        location: "src/consensus/validation.rs (key-image set check)",
        spec: "docs/design (CLSAG / key images)",
        help: "a tx re-used a key image already in the spent set — reject. \
               If this fires in a reorg, check the spent-set rewind path.",
    },
    Diagnostic {
        code: CYNC_CONS_003,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "consensus safety violation: honest nodes diverged below finality",
        invariant: "no two honest nodes hold different blocks at or below the finality floor",
        location: "tests/common/sim (check_safety) + consensus fork-choice",
        spec: "docs/testing/L3-byzantine-simulator.md (SAFETY)",
        help: "two honest nodes finalized conflicting history — a deep safety break. \
               Reproduce with the simulator's printed seed; inspect fork-choice and \
               the configured finality depth.",
    },
    Diagnostic {
        code: CYNC_CONS_004,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "block timestamp too far in the future",
        invariant: "header.timestamp <= now + MAX_TIMESTAMP_DRIFT",
        location: "src/consensus/validation.rs::check_header_future_timestamp",
        spec: "docs/design (future-block timestamp cap)",
        help: "a block's timestamp is beyond the allowed future drift — reject. \
               A flood of these from one source may be clock-poisoning; check net_time.",
    },
    Diagnostic {
        code: CYNC_CONS_005,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "block timestamp not greater than its parent",
        invariant: "header.timestamp > prev.timestamp",
        location: "src/consensus/validation.rs (timestamp monotonicity check)",
        spec: "docs/design (block timestamp rules)",
        help: "a block's timestamp is <= its parent's — reject. The chain's \
               timestamps must strictly increase.",
    },
    Diagnostic {
        code: CYNC_EMIT_001,
        domain: Domain::Emission,
        severity: Severity::Error,
        title: "coinbase exceeds the scheduled block reward",
        invariant: "coinbase_out <= emission(height) + fees_in_block",
        location: "src/emission/mod.rs + src/consensus/validation.rs (coinbase check)",
        spec: "src/emission/curve.rs (emission schedule)",
        help: "a block minted more than the schedule allows — reject. \
               Verify emission(height) and the fee summation for the block.",
    },
    Diagnostic {
        code: CYNC_POW_001,
        domain: Domain::Pow,
        severity: Severity::Error,
        title: "difficulty retarget outside permitted bounds",
        invariant: "next_target within [tip/MAX_ADJ, tip*MAX_ADJ] and the MIN_DIFFICULTY cap",
        location: "src/consensus/difficulty.rs::calculate_difficulty",
        spec: "src/consensus/difficulty.rs (ASERT clamps)",
        help: "the computed next target jumped more than the per-step clamp allows. \
               Check the timestamp window and the ASERT clamp bounds.",
    },
    Diagnostic {
        code: CYNC_STOR_001,
        domain: Domain::Storage,
        severity: Severity::Error,
        title: "reorg could not roll back a Phase-2 store (state stranded)",
        invariant: "every disconnected block's Phase-2 state rewinds in lock-step with the UTXO set",
        location: "src/chain.rs::rewind_phase2_stores (+ src/storage/phase2.rs)",
        spec: "src/storage/phase2.rs (Phase2Store lock-step contract)",
        help: "a store's in-memory checkpoint stack was empty (e.g. a reorg reaching \
               past a node restart), so elements are stranded above the new tip. \
               shielded/spark/MW MUST NOT activate until rewind checkpoints are \
               restart-durable (phase-2-reorg-rewind).",
    },
    Diagnostic {
        code: CYNC_NET_001,
        domain: Domain::Network,
        severity: Severity::Warning,
        title: "node isolated with an exhausted address book",
        invariant: "a reachable node maintains >= 1 outbound peer or re-bootstraps",
        location: "src/network/node/peer_manager.rs::spawn_outbound_connector",
        spec: "docs/design/runtime-mesh-floor.md (re-bootstrap on isolation)",
        help: "0 outbound peers and no dialable addresses; the connector re-resolves \
               the DNS seeds (rate-limited). Persistent firing means the seeds are down.",
    },
    Diagnostic {
        code: CYNC_SHLD_001,
        domain: Domain::Shielded,
        severity: Severity::Error,
        title: "shielded pool value went negative",
        invariant: "ShieldedPoolValue >= 0 (running sum of value_balance)",
        location: "src/chain.rs::verify_block_shielded_spends",
        spec: "docs/design/cip-shielded-anonset.md (pool turnstile)",
        help: "a spend's value_balance exceeded the pool — value was created across \
               the veil. Check the balance/turnstile in crypto/spark_turnstile.rs.",
    },
    Diagnostic {
        code: CYNC_CONS_006,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "unsupported transaction version",
        invariant: "tx.version is an accepted protocol version",
        location: "src/consensus/validation.rs",
        spec: "docs/design (transaction format)",
        help: "a tx declared an unknown version; check the version gate.",
    },
    Diagnostic {
        code: CYNC_CONS_007,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "output encrypted_amount wrong size",
        invariant: "each output's encrypted_amount is exactly 8 bytes",
        location: "src/consensus/validation.rs",
        spec: "docs/design (output format)",
        help: "an output's encrypted_amount was not 8 bytes.",
    },
    Diagnostic {
        code: CYNC_CONS_008,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "output encrypted_memo exceeds cap (structural)",
        invariant: "each output's encrypted_memo is within the size cap",
        location: "src/consensus/validation.rs",
        spec: "docs/design (output format)",
        help: "an output memo exceeded the per-output byte cap.",
    },
    Diagnostic {
        code: CYNC_CONS_009,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "input:output ratio exceeds cap",
        invariant: "the input:output count ratio is within the anti-bloat cap",
        location: "src/consensus/validation.rs",
        spec: "docs/design (anti-bloat limits)",
        help: "too many inputs per output; likely a bloat/DoS shape.",
    },
    Diagnostic {
        code: CYNC_CONS_010,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "output:input ratio exceeds cap",
        invariant: "the output:input count ratio is within the anti-bloat cap",
        location: "src/consensus/validation.rs",
        spec: "docs/design (anti-bloat limits)",
        help: "too many outputs per input; likely a bloat/DoS shape.",
    },
    Diagnostic {
        code: CYNC_CONS_011,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "transfer/churn input count mismatch",
        invariant: "a post-activation Transfer/Churn has the fixed input count",
        location: "src/consensus/validation.rs",
        spec: "docs/design (CYNC tx shape)",
        help: "the tx did not have the required number of inputs for its type.",
    },
    Diagnostic {
        code: CYNC_CONS_012,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "transfer/churn output count mismatch",
        invariant: "a post-activation Transfer/Churn has the fixed output count",
        location: "src/consensus/validation.rs",
        spec: "docs/design (CYNC tx shape)",
        help: "the tx did not have the required number of outputs for its type.",
    },
    Diagnostic {
        code: CYNC_CONS_013,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "churn output count mismatch",
        invariant: "a Churn has the fixed CYNC output count",
        location: "src/consensus/validation.rs",
        spec: "docs/design (CYNC tx shape)",
        help: "a Churn tx had the wrong number of outputs.",
    },
    Diagnostic {
        code: CYNC_CONS_014,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "duplicate key image within block",
        invariant: "a key image appears at most once across the block's txs",
        location: "src/consensus/validation.rs",
        spec: "docs/design (CLSAG / key images)",
        help: "two txs in the block spent the same key image.",
    },
    Diagnostic {
        code: CYNC_CONS_015,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "duplicate output stealth address",
        invariant: "output stealth addresses are unique within a transaction",
        location: "src/consensus/validation.rs",
        spec: "docs/design (stealth addresses)",
        help: "a tx reused a stealth address across its outputs.",
    },
    Diagnostic {
        code: CYNC_CONS_016,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "output stealth collides with on-chain output",
        invariant: "a new output stealth address does not collide with an existing on-chain one",
        location: "src/consensus/validation.rs",
        spec: "docs/design (stealth addresses)",
        help: "an output stealth address already exists on-chain (forced-reuse / burn risk).",
    },
    Diagnostic {
        code: CYNC_CONS_017,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "ring member commitment mismatch (live UTXO)",
        invariant: "a ring member's commitment equals the live UTXO's commitment",
        location: "src/consensus/validation.rs",
        spec: "docs/design (CLSAG rings)",
        help: "a ring member's commitment did not match the live UTXO (inflation vector).",
    },
    Diagnostic {
        code: CYNC_CONS_018,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "ring member commitment mismatch (spent record)",
        invariant: "a ring member's commitment equals the on-chain spent-output record",
        location: "src/consensus/validation.rs",
        spec: "docs/design (CLSAG rings)",
        help: "a ring member's commitment did not match the on-chain spent record.",
    },
    Diagnostic {
        code: CYNC_CONS_019,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "ring member references non-existent output",
        invariant: "every ring member exists in the UTXO set or the output index",
        location: "src/consensus/validation.rs",
        spec: "issue #219 (fabricated ring members)",
        help: "a ring member was never created on this chain (fabricated/inflation).",
    },
    Diagnostic {
        code: CYNC_CONS_020,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "ring member references immature coinbase",
        invariant: "coinbase ring members satisfy the coinbase-maturity floor",
        location: "src/consensus/validation.rs",
        spec: "docs/design (coinbase maturity)",
        help: "a ring member spent a coinbase before it matured.",
    },
    Diagnostic {
        code: CYNC_CONS_021,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "ring member references time-locked output",
        invariant: "ring members are past their unlock height",
        location: "src/consensus/validation.rs",
        spec: "docs/design (time locks)",
        help: "a ring member referenced a still-time-locked output.",
    },
    Diagnostic {
        code: CYNC_CONS_022,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "duplicate ring member within input",
        invariant: "an input's ring members are distinct",
        location: "src/consensus/validation.rs",
        spec: "docs/design (CLSAG rings)",
        help: "an input listed the same ring member twice.",
    },
    Diagnostic {
        code: CYNC_CONS_023,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "ring signature (CLSAG) verification failed",
        invariant: "each input's CLSAG signature verifies against its ring",
        location: "src/consensus/validation.rs",
        spec: "docs/design (CLSAG)",
        help: "an input's ring signature did not verify.",
    },
    Diagnostic {
        code: CYNC_CONS_024,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "transaction validation failed",
        invariant: "each referenced transaction passes full validation",
        location: "src/consensus/validation.rs",
        spec: "docs/design (transaction validation)",
        help: "a contained transaction failed full validation (see wrapped reason).",
    },
    Diagnostic {
        code: CYNC_CONS_025,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "output stealth address is zero",
        invariant: "an output stealth address is not the zero/identity point",
        location: "src/consensus/validation.rs",
        spec: "docs/design (output soundness)",
        help: "a zero stealth address makes the output unspendable (burn).",
    },
    Diagnostic {
        code: CYNC_CONS_026,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "output stealth address not a valid point",
        invariant: "an output stealth address is a valid Ristretto point",
        location: "src/consensus/validation.rs",
        spec: "docs/design (output soundness)",
        help: "the stealth address was not a valid Ristretto point (unspendable).",
    },
    Diagnostic {
        code: CYNC_CONS_027,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "output tx_public_key is identity",
        invariant: "an output tx_public_key is not the identity point",
        location: "src/consensus/validation.rs",
        spec: "docs/design (stealth ECDH)",
        help: "an identity tx_public_key breaks stealth ECDH (deanon).",
    },
    Diagnostic {
        code: CYNC_CONS_028,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "output tx_public_key not a valid point",
        invariant: "an output tx_public_key is a valid Ristretto point",
        location: "src/consensus/validation.rs",
        spec: "docs/design (stealth ECDH)",
        help: "the tx_public_key was not a valid Ristretto point (unspendable).",
    },
    Diagnostic {
        code: CYNC_CONS_029,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "output commitment is identity",
        invariant: "an output commitment is not the identity point",
        location: "src/consensus/validation.rs",
        spec: "docs/design (Pedersen commitments)",
        help: "an identity commitment makes the balance equation breakable.",
    },
    Diagnostic {
        code: CYNC_CONS_030,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "output commitment not a valid point",
        invariant: "an output commitment is a valid Ristretto point",
        location: "src/consensus/validation.rs",
        spec: "docs/design (Pedersen commitments)",
        help: "the commitment was not a valid Ristretto point.",
    },
    Diagnostic {
        code: CYNC_CONS_031,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "transaction has no inputs",
        invariant: "a non-coinbase transaction has at least one input",
        location: "src/consensus/validation.rs",
        spec: "docs/design (transaction format)",
        help: "a non-coinbase tx carried zero inputs.",
    },
    Diagnostic {
        code: CYNC_CONS_032,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "transaction has no outputs",
        invariant: "a transaction has at least one output",
        location: "src/consensus/validation.rs",
        spec: "docs/design (transaction format)",
        help: "a tx carried zero outputs.",
    },
    Diagnostic {
        code: CYNC_CONS_033,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "ring size below minimum",
        invariant: "each input's ring size is at least the mandatory minimum",
        location: "src/consensus/validation.rs",
        spec: "docs/BILL_OF_RIGHTS.md (mandatory privacy)",
        help: "an input's ring was smaller than the mandatory minimum.",
    },
    Diagnostic {
        code: CYNC_CONS_034,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "missing range proof",
        invariant: "a transaction with outputs carries a Bulletproofs range proof",
        location: "src/consensus/validation.rs",
        spec: "docs/BILL_OF_RIGHTS.md (range proofs required)",
        help: "a tx lacked its mandatory range proof.",
    },
    Diagnostic {
        code: CYNC_CONS_035,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "duplicate key image within transaction",
        invariant: "a transaction's inputs have distinct key images",
        location: "src/consensus/validation.rs",
        spec: "docs/design (CLSAG / key images)",
        help: "a tx spent the same key image twice within itself.",
    },
    Diagnostic {
        code: CYNC_CONS_036,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "encrypted_amount exceeds cap",
        invariant: "encrypted_amount is within the 64-byte cap",
        location: "src/consensus/validation.rs",
        spec: "docs/design (output format)",
        help: "encrypted_amount exceeded the 64-byte cap.",
    },
    Diagnostic {
        code: CYNC_CONS_037,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "encrypted_memo exceeds cap",
        invariant: "encrypted_memo is within the 256-byte cap",
        location: "src/consensus/validation.rs",
        spec: "docs/design (output format)",
        help: "encrypted_memo exceeded the 256-byte cap.",
    },
    Diagnostic {
        code: CYNC_CONS_038,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "input key image is zero",
        invariant: "an input key image is not zero",
        location: "src/consensus/validation.rs",
        spec: "docs/design (CLSAG / key images)",
        help: "a zero key image bypasses double-spend detection.",
    },
    Diagnostic {
        code: CYNC_CONS_039,
        domain: Domain::Consensus,
        severity: Severity::Error,
        title: "input key image not a valid point",
        invariant: "an input key image is a valid curve point",
        location: "src/consensus/validation.rs",
        spec: "docs/design (CLSAG / key images)",
        help: "the key image was not a valid curve point.",
    },
    Diagnostic {
        code: CYNC_POW_002,
        domain: Domain::Pow,
        severity: Severity::Error,
        title: "RandomX anchor mismatch",
        invariant: "the claimed PoW anchor equals the recomputed anchor",
        location: "src/consensus/pow_cache.rs::pow_hash_cached",
        spec: "docs/design (PoW anchor)",
        help: "the block's claimed RandomX anchor did not match the recomputed one.",
    },
    Diagnostic {
        code: CYNC_POW_003,
        domain: Domain::Pow,
        severity: Severity::Error,
        title: "PoW algorithm mismatch",
        invariant: "the claimed PoW algorithm equals the computed one",
        location: "src/consensus/pow_cache.rs::pow_hash_cached",
        spec: "docs/design (PoW algorithm)",
        help: "the block's claimed PoW algorithm did not match the computed one.",
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn catalog_codes_are_wellformed_and_unique() {
        let mut seen = HashSet::new();
        for d in CATALOG {
            assert!(seen.insert(d.code), "duplicate diagnostic code {}", d.code);
            // CYNC-<DOMAIN>-<NNN>
            let parts: Vec<&str> = d.code.split('-').collect();
            assert_eq!(parts.len(), 3, "code {} must be CYNC-<DOMAIN>-<NNN>", d.code);
            assert_eq!(parts[0], "CYNC", "code {} must start with CYNC", d.code);
            assert_eq!(
                parts[1],
                d.domain.as_str(),
                "code {} domain token must match its Domain ({})",
                d.code,
                d.domain.as_str()
            );
            assert_eq!(parts[2].len(), 3, "code {} must end in a 3-digit number", d.code);
            assert!(
                parts[2].chars().all(|c| c.is_ascii_digit()),
                "code {} must end in digits",
                d.code
            );
            // No empty descriptive fields — the catalog must stay useful.
            for (name, field) in [
                ("title", d.title),
                ("invariant", d.invariant),
                ("location", d.location),
                ("spec", d.spec),
                ("help", d.help),
            ] {
                assert!(!field.trim().is_empty(), "code {} has empty {name}", d.code);
            }
        }
    }

    #[test]
    fn lookup_finds_and_misses() {
        assert!(lookup(CYNC_SHLD_001).is_some());
        assert_eq!(lookup(CYNC_SHLD_001).unwrap().domain, Domain::Shielded);
        assert!(lookup("CYNC-NOPE-999").is_none());
    }

    #[test]
    fn report_renders_compiler_style() {
        let out = Report::new(CYNC_SHLD_001)
            .at("height 142, block 3af9c1…")
            .expected(">= 0")
            .got(-500)
            .reproduce("SHIELDED_SOAK_SEED=828927513140")
            .to_string();
        // Header + anchors present and readable.
        assert!(out.starts_with("error[CYNC-SHLD-001]: shielded pool value went negative"));
        assert!(out.contains("--> height 142, block 3af9c1…"));
        assert!(out.contains("= got       : -500"));
        assert!(out.contains("= where     : src/chain.rs::verify_block_shielded_spends"));
        assert!(out.contains("= reproduce : SHIELDED_SOAK_SEED=828927513140"));
        assert!(out.contains("= help      :"));
    }

    #[test]
    fn report_omits_absent_optional_fields() {
        let out = Report::new(CYNC_NET_001).to_string();
        assert!(out.starts_with("warning[CYNC-NET-001]:"));
        assert!(!out.contains("expected"));
        assert!(!out.contains("reproduce"));
        assert!(out.contains("= invariant :"));
    }

    #[test]
    fn explain_is_nonempty_for_every_code() {
        for d in CATALOG {
            let e = d.explain();
            assert!(e.contains(d.code));
            assert!(e.contains(d.title));
        }
    }
}
