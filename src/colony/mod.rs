//! colony — biomimetic swarm agents for network resilience.
//!
//! Emergent, no-central-controller network health built from many simple
//! agents (see `docs/architecture/colony.md` and the umbrella
//! `docs/architecture/biomimetic.md`). Hosted by the `coincync-tick`
//! sidecar; **advisory-only** and **non-consensus**.
//!
//! ## Prime Privacy Invariant
//!
//! The colony forages **only on public signals** (block relay, chain tip,
//! peer liveness) and is structurally incapable of observing, scoring, or
//! routing individual transactions or stem-phase traffic. Transaction
//! propagation stays 100% under the node's Dandelion++ logic.
//!
//! ## Status
//!
//! Phase 1: [`forager`] in **observe mode** — scores peers by public
//! block/tip signals and reports the ranking; sends nothing, changes no
//! node behavior. Later phases (advise/act, scouts, termite healing) are
//! designed but not built.

pub mod forager;
pub mod pheromone;
pub mod sensor;
