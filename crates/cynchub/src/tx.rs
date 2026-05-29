//! The five V1 CyncHub transaction types, per CIP-002 §"Mechanism —
//! Transaction Types".
//!
//! ## Status: SKELETON
//!
//! Types are declared; validation and execution return
//! [`Error::NotImplemented`][crate::Error::NotImplemented]. The on-wire
//! representation uses serde for the skeleton; final wire format
//! (likely borsh, matching the parent `coincync` node) is tracked
//! against CIP-002 §"Open Questions" before mainnet ship.
//!
//! ## The five types
//!
//! 1. [`LockBtc`]  — declares a Bitcoin P2WSH HTLC the user has already
//!                   broadcast. Carries the adaptor pubkey-tweak point `T`
//!                   and an SPV proof showing the lock exists on Bitcoin.
//! 2. [`LockCync`] — declares a CYNC stealth-address transaction with
//!                   CLSAG adaptor binding to the same `T`. SPV proof
//!                   shows the tx is included with ≥ H+16 finality.
//! 3. [`Order`]    — places a buy or sell order on the CyncHub order book,
//!                   backed by a previously-declared lock.
//! 4. [`Match`]    — issued by a CyncHub miner observing two compatible
//!                   orders. Includes the fee distribution to the miner.
//! 5. [`Cancel`]   — removes an open order from the book. Signed by the
//!                   lock's refund_pubkey.
//!
//! ## What's NOT a CyncHub tx
//!
//! Refunds happen on the **native chain** (Bitcoin nLockTime, CYNC
//! adaptor refund condition). CyncHub doesn't track refunds because
//! they're enforced by underlying consensus. This is the architectural
//! property that lets CyncHub die without anyone losing money.

use serde::{Deserialize, Serialize};

use crate::Error;

/// Which side of an order book entry: bid (buy) or ask (sell).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Side {
    /// Buy CYNC, pay BTC.
    Bid,
    /// Sell CYNC, receive BTC.
    Ask,
}

/// Reference to a previously-declared lock by chain + lock-id.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LockRef {
    /// Which chain the lock lives on (`"btc"` or `"cync"`).
    pub chain: String,
    /// 32-byte hash identifying the lock (Bitcoin txid for BTC,
    /// CYNC tx hash for CYNC).
    pub lock_id: [u8; 32],
}

/// `LockBtc` — declares a Bitcoin P2WSH HTLC. CyncHub validates the SPV
/// proof + the script-pattern match before accepting the lock as backing
/// for any subsequent [`Order`].
///
/// The 33-byte secp256k1 pubkey fields are `Vec<u8>` in this skeleton
/// because serde 1.x doesn't derive `Deserialize` for `[u8; N]` when
/// N > 32. The eventual wire format (likely borsh, matching the parent
/// `coincync` node) will tighten these to fixed-size arrays; the type
/// signature change is intentionally deferred to the wire-format
/// commitment slice so this skeleton stays serde-derivable today.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LockBtc {
    /// Amount in satoshis.
    pub amount: u64,
    /// Adaptor pubkey-tweak point `T` (33-byte compressed secp256k1).
    /// Whoever learns the corresponding scalar `t` can complete the
    /// Schnorr signature spending the lock.
    pub adaptor_pubkey_t: Vec<u8>,
    /// 33-byte secp256k1 pubkey to which the refund path pays.
    pub refund_pubkey: Vec<u8>,
    /// Refund timeout, expressed as a Bitcoin block height (BIP-65 CLTV).
    pub timeout_block_height: u32,
    /// SPV proof: Bitcoin headers + Merkle path proving this lock tx
    /// is included in a block ≥ 6 confirmations deep.
    pub btc_spv_proof: Vec<u8>,
}

/// `LockCync` — declares a CYNC stealth-address transaction with CLSAG
/// adaptor binding. CyncHub validates the SPV proof + H+16 finality
/// before accepting the lock as backing for any subsequent [`Order`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LockCync {
    /// Amount in atomic CYNC units.
    pub amount: u64,
    /// Adaptor pubkey-tweak point `T` (32-byte Ristretto255 compressed).
    /// Same `T` as the counterpart [`LockBtc`] — that's what makes the
    /// swap atomic.
    pub adaptor_pubkey_t: [u8; 32],
    /// 32-byte ed25519/Ristretto pubkey to which the refund path pays.
    pub refund_pubkey: [u8; 32],
    /// Refund timeout, expressed as a CYNC block height. Must satisfy
    /// the asymmetry rule: `timeout_block_height_cync > timeout_block_height_btc + buffer`.
    pub timeout_block_height: u64,
    /// SPV proof: CYNC headers + Merkle path proving this lock tx is
    /// included with ≥ H+16 finality.
    pub cync_spv_proof: Vec<u8>,
}

/// `Order` — places an order on the CyncHub CLOB.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Order {
    /// Bid (buy CYNC) or Ask (sell CYNC).
    pub side: Side,
    /// Amount in atomic CYNC units (the *base* asset of the V1 pair).
    pub amount_cync: u64,
    /// Price in satoshis per atomic CYNC unit.
    pub price_sat_per_cync: u64,
    /// Lock backing this order. CyncHub rejects orders whose lock
    /// doesn't exist on chain (validated via the lock's SPV proof at
    /// the time the lock was declared).
    pub lock_ref: LockRef,
    /// CyncHub block height after which this order auto-expires
    /// (and the underlying lock refunds via the native-chain timeout).
    pub expiry_block: u64,
}

/// `Match` — issued by a CyncHub miner observing two compatible orders
/// and including a match in their block. Encodes the fee distribution
/// to the miner (paid in both assets).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Match {
    /// First order matched (typically the bid).
    pub order_a: LockRef,
    /// Second order matched (typically the ask).
    pub order_b: LockRef,
    /// Miner-fee BTC address (P2WPKH or P2TR). Encoded as raw script
    /// bytes for skeleton; eventually constrained to specific output types.
    pub miner_fee_btc_script: Vec<u8>,
    /// Miner-fee CYNC stealth address (one-time output target).
    pub miner_fee_cync_address: Vec<u8>,
}

/// `Cancel` — removes an open order from the orderbook. The signature
/// must verify against the lock's `refund_pubkey` so only the order
/// owner can cancel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cancel {
    /// Order to cancel, referenced by the same `LockRef` used in [`Order`].
    pub order_id: LockRef,
    /// Signature by the lock's refund_pubkey over the order_id bytes.
    /// Variable-length because the signature scheme differs by chain
    /// (Schnorr for BTC-side orders, Schnorr-over-Ristretto for CYNC-side).
    pub owner_sig: Vec<u8>,
}

/// Top-level tagged enum for the five V1 transaction types.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Transaction {
    /// See [`LockBtc`].
    LockBtc(LockBtc),
    /// See [`LockCync`].
    LockCync(LockCync),
    /// See [`Order`].
    Order(Order),
    /// See [`Match`].
    Match(Match),
    /// See [`Cancel`].
    Cancel(Cancel),
}

/// Validate a transaction against the current chain state.
///
/// **Stub:** returns [`Error::NotImplemented`].
pub fn validate(_tx: &Transaction) -> Result<(), Error> {
    Err(Error::NotImplemented { stage: "tx.validate" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_round_trips_serde() {
        let tx = Transaction::Order(Order {
            side: Side::Ask,
            amount_cync: 1_000_000,
            price_sat_per_cync: 25,
            lock_ref: LockRef { chain: "cync".to_string(), lock_id: [9u8; 32] },
            expiry_block: 100,
        });
        let json = serde_json::to_vec(&tx).expect("serialize");
        let back: Transaction = serde_json::from_slice(&json).expect("deserialize");
        match back {
            Transaction::Order(o) => assert_eq!(o.amount_cync, 1_000_000),
            _ => panic!("unexpected tx type after round-trip"),
        }
    }

    #[test]
    fn validate_is_unimplemented_in_skeleton() {
        let tx = Transaction::Cancel(Cancel {
            order_id: LockRef { chain: "cync".to_string(), lock_id: [0u8; 32] },
            owner_sig: Vec::new(),
        });
        let err = validate(&tx).unwrap_err();
        assert!(matches!(err, Error::NotImplemented { stage: "tx.validate" }));
    }
}
