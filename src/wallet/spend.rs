//! Wallet spend orchestration.
//!
//! The public surface is intentionally small: callers create an intent, begin
//! one snapshot-bound session, build a submission-ready spend and then submit
//! it through the typed coordinator. Internal modules keep construction,
//! submission and state-carrying types separate so reservation invariants do
//! not leak into CLI or churn callers.
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `begin`** — INVARIANT: every session is bound to exactly one freshly
//!   validated decoy snapshot, with target height and maturity floor derived
//!   from that snapshot so later build/submit steps cannot recombine across
//!   snapshots. THREAT: cross-snapshot decoy mixing or a stale maturity floor
//!   that deanonymizes the real input. TESTS: `validated_snapshot_rejects_unsupported_policy`,
//!   `validated_snapshot_rejects_invalid_height_buckets`,
//!   `regression_finding_01_spend_context_preserves_target_height_min_age`.
//! - **§2 `new` / `for_node` (construction)** — INVARIANT: a coordinator wraps
//!   exactly one typed `NodeRpcClient`, so all node I/O flows through the typed
//!   transport. THREAT: an untyped or duplicate transport path that bypasses
//!   submission classification. TESTS: (gap — thin constructors, exercised only
//!   indirectly by the `submit_reserved` tests).
//! - **§3 `rpc`** — INVARIANT: exposes a shared read-only borrow of the client
//!   for diagnostics, never a second mutable transport. THREAT: an aliased
//!   client that could submit outside the reservation path.
//!   TESTS: (gap — trivial accessor).

mod build;
mod submission;
mod types;

use super::decoy_selection::ValidatedDecoySnapshot;
use super::node_rpc::NodeRpcClient;
use super::send::SpendContext;
use crate::error::Result;

pub use types::{BuiltSpend, SpendIntent, SpendSession, SpendSubmission};

/// Coordinates snapshot-bound transaction construction and submission.
#[derive(Clone)]
pub struct SpendCoordinator {
    pub(super) rpc: NodeRpcClient,
}

impl SpendCoordinator {
    /// Construct from an existing typed RPC client.
    pub fn new(rpc: NodeRpcClient) -> Self {
        Self { rpc }
    }

    /// Construct with the wallet's standard transport policy.
    pub fn for_node(endpoint: impl Into<String>) -> Result<Self> {
        Ok(Self::new(NodeRpcClient::new(endpoint)?))
    }

    /// Borrow the shared client, primarily for diagnostics.
    pub fn rpc(&self) -> &NodeRpcClient {
        &self.rpc
    }

    /// Start one validated, snapshot-bound build attempt.
    pub async fn begin(&self) -> Result<SpendSession> {
        let snapshot = ValidatedDecoySnapshot::try_from(self.rpc.decoy_distribution().await?)?;
        let context = SpendContext::for_target_height(snapshot.spend_height());

        Ok(SpendSession::new(snapshot, context))
    }
}
