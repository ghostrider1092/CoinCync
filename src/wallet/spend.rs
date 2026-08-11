//! Wallet spend orchestration.
//!
//! The public surface is intentionally small: callers create an intent, begin
//! one snapshot-bound session, build a submission-ready spend and then submit
//! it through the typed coordinator. Internal modules keep construction,
//! submission and state-carrying types separate so reservation invariants do
//! not leak into CLI or churn callers.

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
