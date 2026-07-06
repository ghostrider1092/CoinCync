//! # tick — passive network agents that quest, latch, and feed
//!
//! Designed for privacy blockchains. See `docs/architecture/tick.md` in
//! the coincync repo for the full design document, including:
//!
//! - The three tick modes (RescueTick, HealthTick, PropagationTick)
//! - Privacy considerations (Dandelion++ preservation, aggregate-only
//!   metrics, no fleet-topology leaks, no wallet access, Poisson-
//!   distributed poll intervals)
//! - Cross-blockchain portability contract
//! - Phased implementation plan
//!
//! # This crate — Phase 1a
//!
//! Ships the traits + types + a MockAdapter for testing. Concrete tick
//! implementations (RescueTick etc.) land in subsequent phases.
//!
//! ```
//! # #[cfg(feature = "mock")] {
//! use tick::{ChainAdapter, TickBehavior, MockAdapter};
//!
//! // In real code, downstream chains supply their own ChainAdapter
//! // impl (e.g. `CoincyncAdapter` in the coincync repo). Here we
//! // use the MockAdapter to exercise the trait shape.
//! let adapter = MockAdapter::new();
//! assert_eq!(adapter.fleet_peers().len(), 0);
//! # }
//! ```
//!
//! # Privacy contract (summary)
//!
//! Every `ChainAdapter` implementation MUST:
//!
//! 1. Never expose per-host identifiers via `aggregate_fleet_health` —
//!    the return type is aggregate-only by construction (no `Vec<Host>`).
//! 2. Return `false` from `is_stem_phase` ONLY for txs that are fully
//!    fluffed. When in doubt, return `true` — refusing to re-broadcast
//!    is always safer than accidentally leaking a stem tx.
//! 3. Return `stem_relay_peers` accurately — PropagationTick uses this
//!    to blacklist those peers from re-broadcast, so a bug here becomes
//!    a privacy break.
//! 4. Report `deployment_mode` truthfully. `Personal` mode is the safer
//!    default; adapters should return `Personal` unless the runtime
//!    configuration explicitly opts into `Fleet`.
//!
//! # Non-goals for this crate
//!
//! - No wallet access, ever. `ChainAdapter` has no methods that touch
//!   wallet files, balances, or key material.
//! - No consensus rule changes. Ticks are off-chain agents.
//! - No block signing. Ticks don't produce blocks; they observe and
//!   react to the chain's state.
//! - No UI. Ticks are headless daemons; observability is via alert
//!   channels + local logs.

#![warn(missing_docs)]
#![deny(unsafe_code)]

pub mod adapter;
pub mod rescue;
pub mod tick;
pub mod types;

#[cfg(feature = "mock")]
pub mod mock;

pub use adapter::ChainAdapter;
pub use rescue::{recovery_priority, RescueConfig, RescueTick};
pub use tick::{TickBehavior, TickPhase};
pub use types::{
    AggregateFleetHealth, ChainTipState, DeploymentMode, FleetPeer,
    HealthSnapshot, Severity, Snapshot, TickError, TickNotice, TickNoticeKind,
    TickResult,
};

#[cfg(feature = "mock")]
pub use mock::MockAdapter;
