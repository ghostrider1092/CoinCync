//! # Wallet RPC (P0 stub — every method fails loudly).
//!
//! The real wallet-side RPC surface (balance, send, export-ivk, subaddress
//! management, compliance proofs) depends on wallet modules that are still
//! in the P1 wire-up phase: `wallet::scanner`, `wallet::send`,
//! `wallet::persistence`, `wallet::balance`, `wallet::history`,
//! `wallet::SharedWallet`, `wallet::SubaddressManager`.
//!
//! Until P1 wires them through, every method on this stub returns an
//! explicit `Error::NotImplemented` carrying a method name. This is
//! deliberate — a placeholder that silently succeeds is the worst kind of
//! stub because callers think the operation worked. A placeholder that
//! returns a labelled error fails CI loudly, fails monitoring loudly, and
//! cannot be confused with success.

use crate::error::{Error, Result};
use serde_json::Value;

/// Wallet RPC stub. Every method returns `Error::NotImplemented` with the
/// caller-facing method name. Replace with real handlers in P1 — do not
/// remove the stub, just add real bodies behind each method.
pub struct WalletRpc;

impl WalletRpc {
    pub fn new() -> Self { Self }

    fn not_yet(method: &'static str) -> Error {
        Error::NotImplemented(format!(
            "wallet RPC method `{}` is not wired in P0 \
             (depends on wallet::scanner / wallet::send / wallet::balance \
             — lands in the P1 wallet-wiring pass)",
            method
        ))
    }

    pub fn get_balance(&self) -> Result<Value> {
        Err(Self::not_yet("get_balance"))
    }

    pub fn get_address(&self) -> Result<Value> {
        Err(Self::not_yet("get_address"))
    }

    pub fn get_history(&self) -> Result<Value> {
        Err(Self::not_yet("get_history"))
    }

    pub fn send_transaction(&self, _params: Value) -> Result<Value> {
        Err(Self::not_yet("send_transaction"))
    }

    pub fn export_ivk(&self) -> Result<Value> {
        Err(Self::not_yet("export_ivk"))
    }

    pub fn create_subaddress(&self) -> Result<Value> {
        Err(Self::not_yet("create_subaddress"))
    }

    pub fn list_subaddresses(&self) -> Result<Value> {
        Err(Self::not_yet("list_subaddresses"))
    }

    pub fn rescan(&self, _params: Value) -> Result<Value> {
        Err(Self::not_yet("rescan"))
    }
}

impl Default for WalletRpc {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_method_fails_loudly_with_method_name_in_message() {
        let w = WalletRpc::new();
        // Each handler must produce a NotImplemented error whose message
        // includes the method name — so a future caller (or a CI dashboard)
        // can tell which RPC method is missing without guessing.
        let cases: Vec<(&str, Result<Value>)> = vec![
            ("get_balance",       w.get_balance()),
            ("get_address",       w.get_address()),
            ("get_history",       w.get_history()),
            ("send_transaction",  w.send_transaction(Value::Null)),
            ("export_ivk",        w.export_ivk()),
            ("create_subaddress", w.create_subaddress()),
            ("list_subaddresses", w.list_subaddresses()),
            ("rescan",            w.rescan(Value::Null)),
        ];
        for (name, result) in cases {
            match result {
                Err(Error::NotImplemented(msg)) => {
                    assert!(msg.contains(name),
                        "NotImplemented for `{}` must mention method name; got: {}",
                        name, msg);
                }
                other => panic!("`{}` did not return NotImplemented: {:?}", name, other),
            }
        }
    }
}
