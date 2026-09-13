//! RPC method handlers, extracted from `start_rpc_server` (issue #107).
//!
//! Each submodule groups related JSON-RPC methods as free functions over the
//! shared [`crate::rpc::server::RpcState`]. `start_rpc_server` stays responsible
//! for configuration, shared state, middleware, and server startup; it wires
//! each method name to the handler here via `register_method` /
//! `register_blocking_method`. This lets an RPC handler be changed without
//! editing the server-startup implementation.
//!
//! Behavior is preserved exactly: method names, parameter parsing, response
//! fields, error codes, and the blocking-vs-async execution model are unchanged
//! from the previous inline closures.

pub(crate) mod audit;
pub(crate) mod chain;
