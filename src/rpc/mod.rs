//! # RPC Module for CoinCync 1.0
//!
//! JSON-RPC 2.0 API for node and wallet interaction.
//!
//! P0 scope: just enough to let a node speak JSON-RPC and the TUIs
//! show live data. The `rest`, `explorer`, `openapi`, `node_api`, and
//! `wallet_api` submodules stay out of the compile graph until P1 —
//! they pull in heavy wallet/asset/compliance surface that isn't wired
//! yet, and the minimal method set for a live node lives directly in
//! `server::start_rpc_server`.

mod ratelimit;
mod server;
pub mod tls;
pub mod types;
mod websocket;

// Phase 1 RPC surface — wired in. `wallet_api` is a deliberate placeholder
// stub that will be fleshed out once the wallet modules stabilise; the
// other two (`node_api`, `openapi`) are self-contained.
pub mod explorer;
pub mod lightwallet;
pub mod node_api;
pub mod openapi;
pub mod rest;
pub mod wallet_api;

pub use ratelimit::{
    create_rate_limiter, RateLimitConfig, RateLimitResult, RateLimitStats, RateLimiter,
    SharedRateLimiter,
};
pub use server::{start_rpc_server, RpcConfig, RpcServer, MAX_RPC_AUDIT_BLOCK_SPAN};
pub use types::*;
pub use websocket::{
    create_subscription_manager, Event, EventType, SharedSubscriptionManager, SubscriptionManager,
    WsMessage, WsResponse,
};
