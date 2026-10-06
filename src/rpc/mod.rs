//! # RPC Module for CoinCync 1.0
//!
//! JSON-RPC 2.0 API for node and wallet interaction. `server` owns listener
//! configuration and HTTP middleware; private `handlers` modules own method
//! registration, response serialization, and method-specific policy.

mod handlers;
mod ratelimit;
mod server;
pub mod tls;
pub mod types;
mod websocket;

// Phase 1 RPC surface — wired in.
// (Removed 2026-08-22) `node_api` (a duplicate of the live node RPC methods)
// and `wallet_api` (a `NotImplemented` placeholder) had no callers and were deleted.
// `openapi` is retained as a self-contained doc generator.
pub mod explorer;
pub mod lightwallet;
pub mod openapi;
pub mod rest;

pub use handlers::MAX_RPC_AUDIT_BLOCK_SPAN;
pub use ratelimit::{
    create_rate_limiter, RateLimitConfig, RateLimitResult, RateLimitStats, RateLimiter,
    SharedRateLimiter,
};
pub use server::{start_rpc_server, RpcConfig, RpcServer};
pub use types::*;
pub use websocket::{
    create_subscription_manager, Event, EventType, SharedSubscriptionManager, SubscriptionManager,
    WsMessage, WsResponse,
};
