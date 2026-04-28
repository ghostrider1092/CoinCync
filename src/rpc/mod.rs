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

mod server;
pub mod types;
mod websocket;
mod ratelimit;
pub mod tls;

// Phase 1 RPC surface — wired in. `wallet_api` is a deliberate placeholder
// stub that will be fleshed out once the wallet modules stabilise; the
// other two (`node_api`, `openapi`) are self-contained.
pub mod node_api;
pub mod wallet_api;
pub mod openapi;
pub mod explorer;
pub mod rest;
pub mod lightwallet;

pub use server::{RpcServer, RpcConfig, start_rpc_server, MAX_RPC_AUDIT_BLOCK_SPAN};
pub use types::*;
pub use websocket::{
    SubscriptionManager, SharedSubscriptionManager, create_subscription_manager,
    Event, EventType, WsMessage, WsResponse,
};
pub use ratelimit::{
    RateLimiter, SharedRateLimiter, create_rate_limiter,
    RateLimitConfig, RateLimitResult, RateLimitStats,
};
