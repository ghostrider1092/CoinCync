//! # Finality (intentional placeholder)
//!
//! CoinCync does **not** ship a separate voted-checkpoint or BFT-overlay
//! finality layer. Reorg defense is delivered by the 3-tier hybrid in
//! [`crate::chain`] (search for `MAX_REORG_DEPTH` / `mess_weight`):
//!
//! 1. **Tier 1 — Tip protection** (≤ 10 blocks): unconditional accept,
//!    matches Bitcoin's standard reorg window.
//! 2. **Tier 2 — MESS** (11–100 blocks on mainnet, 11–1000 on testnet):
//!    competitor chain must carry exponentially more accumulated work,
//!    `2^((depth-10)/20)`, to be adopted. Defeats single-burst rental
//!    attacks.
//! 3. **Tier 3 — Hard cutoff** (> mainnet=100, testnet=1000): reorgs are
//!    rejected outright. Operator intervention required if a deeper fork
//!    legitimately occurs.
//!
//! The `CHECKPOINT_INTERVAL` constant in [`crate::constants`] is reserved
//! for a future operator-rolling checkpoint scheme. That scheme is **not
//! enforcement-gating today** — a separate finality module will be added
//! pre-mainnet if the post-public-testnet attack-surface review shows the
//! MESS hybrid alone leaves residual rental-hashrate risk above what the
//! audit accepts.
//!
//! See `docs/src/security/reorg-defense.md` for the threat model.

// (no public types — this module is an anchor for the docs above and a
// stable import path for future finality additions.)
