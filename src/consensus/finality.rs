//! # Finality (intentional placeholder)
//!
//! CoinCync does **not** ship a separate voted-checkpoint or BFT-overlay
//! finality layer. Reorg defense is a six-layer system; this module is
//! the stable import path for the BFT/voted-finality work if and when it
//! lands. The authoritative description of the shipped defense lives in
//! [`docs/security/reorg-defense.md`](../../docs/security/reorg-defense.md)
//! (use that for the threat model and parameter justifications). The
//! short version, anchored to the code:
//!
//! 1. **Tier-1 Nakamoto** (≤ 10): unconditional longest-work
//!    (`REORG_UNCONDITIONAL_DEPTH = 10` in [`crate::chain`]).
//! 2. **Tier-2 MESS** (11–100 mainnet / 11–1000 testnet): fork must
//!    carry `2^((depth-10)/20)` more work — defeats single-burst rental
//!    attacks (`MESS_EXPONENT_DIVISOR = 20`,
//!    `evaluate_reorg_acceptability` in [`crate::chain`]).
//! 3. **Tier-3 hard cap** (> mainnet=100, testnet=1000): rejected
//!    outright; operator intervention required for deeper legitimate
//!    forks (`max_reorg_depth()` in [`crate::chain`]).
//! 4. **Per-node rolling checkpoints**: each node refuses to reorg below
//!    its own `last_checkpoint` (`CHECKPOINT_INTERVAL = 144` in
//!    [`crate::constants`]).
//! 5. **Hardcoded consensus checkpoints** (CIP-009 Path B, shipped
//!    2026-05-08): `CONSENSUS_CHECKPOINTS` table in
//!    [`crate::constants`], populated post-launch via the release
//!    process.
//! 6. **Miner-signed rolling finality** (CIP-009.D, queued post-launch):
//!    feature-gated in [`crate::consensus::rolling_finality`]; not
//!    consensus-gating today.
//!
//! A separate finality module will be added pre-mainnet if the
//! post-public-testnet attack-surface review shows the layers above
//! leave residual rental-hashrate risk above what the audit accepts.

// (no public types — this module is an anchor for the docs above and a
// stable import path for future finality additions.)
