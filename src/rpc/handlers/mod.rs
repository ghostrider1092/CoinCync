//! Internal RPC context and assembly of the method groups.
//!
//! Startup policy stays in `server`; handlers depend only on this context
//! and the chain, mempool, and network APIs they already use.

mod audit;
mod chain;
mod mining;
mod node;
mod privacy;
mod transactions;

use std::sync::Arc;

use jsonrpsee::RpcModule;

use crate::chain::SharedBlockchain;
use crate::error::Result;
use crate::mempool::SharedMempool;
use crate::network::P2PNode;

pub use audit::MAX_RPC_AUDIT_BLOCK_SPAN;

/// Shared state passed to every RPC method handler.
#[derive(Clone)]
pub(super) struct RpcState {
    pub(super) chain: SharedBlockchain,
    pub(super) mempool: SharedMempool,
    pub(super) p2p: Option<Arc<P2PNode>>,
    pub(super) network_name: String,
    pub(super) auth_enabled: bool,
    pub(super) minimize_metadata: bool,
    pub(super) stratum_public_bind_requested: bool,
    pub(super) stratum_public_bind_ack: bool,
    pub(super) stratum_native_tls_enabled: bool,
    pub(super) stratum_tls_proxy_ack: bool,
    pub(super) stratum_transport_hardened: bool,
}

pub(super) fn create_rpc_module(state: RpcState) -> Result<RpcModule<RpcState>> {
    let mut module = RpcModule::new(state);
    node::register(&mut module)?;
    chain::register(&mut module)?;
    mining::register(&mut module)?;
    transactions::register(&mut module)?;
    privacy::register(&mut module)?;
    audit::register(&mut module)?;
    Ok(module)
}

/// JSON numbers cannot portably carry all u128 values. Aggregate atomic supply
/// values therefore use canonical base-10 strings at every RPC boundary.
#[inline]
fn supply_atomic_decimal(value: u128) -> String {
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_supply_decimal_preserves_values_above_u64() {
        assert_eq!(
            supply_atomic_decimal((u64::MAX as u128) + 1),
            "18446744073709551616"
        );
        assert_eq!(
            supply_atomic_decimal(crate::constants::MAX_SUPPLY),
            "100000000000000000000"
        );
    }
}
