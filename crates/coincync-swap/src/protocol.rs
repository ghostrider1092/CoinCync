//! Atomic-swap state machine: roles, states, and legal transitions.
//!
//! The two parties are **Alice** (sells CYNC, buys BTC) and **Bob**
//! (sells BTC, buys CYNC). The asymmetry matters: the protocol is not
//! symmetric in who locks first or how refunds work. See CIP-001 for
//! the full state diagram.
//!
//! ## Status: SKELETON
//!
//! Types and transitions are declared. Bodies return
//! [`Error::not_implemented`] with the stage name.

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// The two roles in any single swap.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Role {
    /// Sells CYNC, buys BTC. Locks CYNC first.
    Alice,
    /// Sells BTC, buys CYNC. Locks BTC after seeing Alice's CYNC lock.
    Bob,
}

/// State of an in-progress swap. The transitions form a directed graph
/// with two terminal states (Completed, Refunded) reachable from any
/// non-terminal state via the appropriate path.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum State {
    /// Both parties have agreed to swap parameters but no on-chain
    /// activity has occurred yet.
    Negotiated,
    /// Alice has broadcast the CYNC-side lock transaction.
    AliceLocked,
    /// Bob has seen Alice's lock confirmed and broadcast his BTC lock.
    BobLocked,
    /// Alice has revealed the secret to claim Bob's BTC; Bob can now
    /// use the same secret to claim Alice's CYNC.
    SecretRevealed,
    /// Both sides claimed; the swap is complete.
    Completed,
    /// At least one side timed out and reclaimed their original funds.
    Refunded,
    /// The state machine entered an invalid configuration (consensus
    /// bug, network issue, manual abort). Recovery via the refund
    /// path; no funds lost — that's the whole point of the design.
    Aborted,
}

impl State {
    /// `true` if the state is terminal — no further transitions occur.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Refunded | Self::Aborted)
    }
}

/// Parameters agreed between Alice and Bob during the negotiation
/// phase. All fields are placeholders; the eventual implementation
/// will replace these `String` types with proper cryptographic types
/// (commitments, public keys, transaction outputs).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwapParameters {
    /// Amount of CYNC Alice will lock, in atomic units.
    pub cync_amount: u64,
    /// Amount of satoshis Bob will lock.
    pub btc_amount_sats: u64,
    /// CYNC-side timelock in blocks.
    pub cync_timeout_blocks: u32,
    /// BTC-side timelock in blocks (must be < cync_timeout to be safe).
    pub btc_timeout_blocks: u32,
    /// Placeholder for the CYNC stealth address Alice spends to.
    pub alice_cync_address: String,
    /// Placeholder for the BTC P2WPKH address Bob spends to.
    pub bob_btc_address: String,
}

/// In-memory representation of an active swap. Persisted between
/// CLI invocations in a JSON state file (see `cyncswap` binary).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Swap {
    /// Stable identifier for this swap session.
    pub id: String,
    /// Which role this node is playing.
    pub role: Role,
    /// Current state in the protocol.
    pub state: State,
    /// Parameters agreed during negotiation.
    pub parameters: SwapParameters,
}

impl Swap {
    /// Begin a new swap as `role`. Persists to disk; the eventual
    /// implementation will also start the coordinator session.
    pub fn negotiate(_role: Role, _params: SwapParameters) -> Result<Self> {
        Err(Error::not_implemented("protocol.negotiate"))
    }

    /// Advance the state machine after observing a chain or peer event.
    /// The eventual implementation will validate the transition is
    /// legal for the current state and role.
    pub fn advance(&mut self, _next: State) -> Result<()> {
        Err(Error::not_implemented("protocol.advance"))
    }

    /// Compute the next legal transitions from the current state +
    /// role. Used by the CLI's `status` subcommand to tell the
    /// operator what to do next.
    pub fn legal_next(&self) -> &'static [State] {
        // Skeleton: empty until implementation.
        &[]
    }
}
