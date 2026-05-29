//! CLOB (central-limit order book) state machine, per CIP-002
//! §"Order Book Model".
//!
//! ## Status: SKELETON
//!
//! ## Design summary
//!
//! - **Single pair in V1:** CYNC/BTC.
//! - **Matching rule:** price-time priority. Best bid (highest price)
//!   matches against best ask (lowest price) when bid_price >= ask_price.
//! - **Spread:** the matching CyncHub miner takes the spread on top of
//!   the 0.1% per-side fee.
//! - **Block size:** max 100 KB body (~500 orders per block at ~200 bytes
//!   each).
//! - **Match latency:** orderbook update + match inclusion happens in
//!   the next CyncHub block (60s avg).
//!
//! Per-order state transitions:
//!
//! ```text
//!     Open ──Match──▶ Matched ──claim observed──▶ Settled
//!      │
//!      └──expiry─▶ Expired ──refund tx on native chain──▶ Refunded
//! ```
//!
//! `Refunded` is a wallet-side state inferred from the native chain;
//! the orderbook itself only tracks `Open / Matched / Settled / Expired`.

use serde::{Deserialize, Serialize};

use crate::tx::{LockRef, Order};
use crate::Error;

/// State of an order from the orderbook's perspective.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum OrderState {
    /// Order is on the book and matchable.
    Open,
    /// Order has been matched by a [`crate::tx::Match`] tx.
    Matched,
    /// Both sides' claims observed on their native chains; trade complete.
    Settled,
    /// Order passed its `expiry_block` without being matched. The
    /// underlying lock will (or has) refunded on its native chain.
    Expired,
}

/// One entry in the orderbook: the order itself plus current state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrderbookEntry {
    /// The order placed by the user.
    pub order: Order,
    /// Current state.
    pub state: OrderState,
    /// CyncHub block height at which this entry was last updated.
    pub last_updated_height: u64,
}

/// The full orderbook for a single pair (CYNC/BTC in V1).
///
/// Internal storage is a placeholder for the skeleton; the eventual
/// implementation will use a sorted structure for O(log n) match
/// queries on best-bid / best-ask.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OrderBook {
    /// Bids (buy CYNC) — should be sorted by price descending, time
    /// ascending in the eventual impl.
    pub bids: Vec<OrderbookEntry>,
    /// Asks (sell CYNC) — should be sorted by price ascending, time
    /// ascending in the eventual impl.
    pub asks: Vec<OrderbookEntry>,
}

impl OrderBook {
    /// Construct an empty orderbook.
    pub const fn new() -> Self {
        OrderBook {
            bids: Vec::new(),
            asks: Vec::new(),
        }
    }
}

/// Insert a new order into the book. Validates the order's lock_ref
/// against the chain state (skeleton stub).
///
/// **Stub:** returns [`Error::NotImplemented`].
pub fn insert(_book: &mut OrderBook, _order: Order, _at_height: u64) -> Result<(), Error> {
    Err(Error::NotImplemented { stage: "orderbook.insert" })
}

/// Find the best matchable pair (top bid + top ask where bid ≥ ask).
/// Returns the two `LockRef`s that a [`crate::tx::Match`] would reference.
///
/// **Stub:** returns [`Error::NotImplemented`].
pub fn next_match(_book: &OrderBook) -> Result<Option<(LockRef, LockRef)>, Error> {
    Err(Error::NotImplemented { stage: "orderbook.next_match" })
}

/// Transition an order from `Open` → `Matched`.
///
/// **Stub:** returns [`Error::NotImplemented`].
pub fn mark_matched(_book: &mut OrderBook, _lock_ref: &LockRef, _at_height: u64) -> Result<(), Error> {
    Err(Error::NotImplemented { stage: "orderbook.mark_matched" })
}

/// Remove an order from the book (cancel or expiry).
///
/// **Stub:** returns [`Error::NotImplemented`].
pub fn remove(_book: &mut OrderBook, _lock_ref: &LockRef) -> Result<(), Error> {
    Err(Error::NotImplemented { stage: "orderbook.remove" })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::Side;

    #[test]
    fn new_orderbook_is_empty() {
        let book = OrderBook::new();
        assert!(book.bids.is_empty());
        assert!(book.asks.is_empty());
    }

    #[test]
    fn insert_is_unimplemented_in_skeleton() {
        let mut book = OrderBook::new();
        let order = Order {
            side: Side::Ask,
            amount_cync: 1_000_000,
            price_sat_per_cync: 25,
            lock_ref: LockRef { chain: "cync".to_string(), lock_id: [0u8; 32] },
            expiry_block: 100,
        };
        let err = insert(&mut book, order, 1).unwrap_err();
        assert!(matches!(err, Error::NotImplemented { stage: "orderbook.insert" }));
    }
}
