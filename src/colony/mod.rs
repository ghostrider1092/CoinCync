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
// Timing-privacy caste: prime-interval anti-correlation scheduling for
// node-local housekeeping (never transaction/stem-phase timing). Pure,
// deterministic core; the sidecar layers CSPRNG jitter on top.
pub mod cicada;
// Defensive caste: adversarial tarpit — escalating slow-hold for
// misbehaving peers (DoS asymmetry). Pure decision core; the node applies
// the hold.
pub mod mantis;
// Cover-traffic caste: pulse-coupled (Mirollo-Strogatz) oscillator for
// network-wide cover-traffic synchronization. Pure phase engine; coupling
// is bounded so a pulse flood can't drive our flash timing.
pub mod firefly;
// Relay-resilience caste: netgroup-diverse multipath block-relay leg
// selection (eclipse/reliability). Pure selection core; block relay only,
// never transactions.
pub mod centipede;
// Privacy caste: protocol camouflage — canonical wire-fingerprint
// normalization (uniformity is anonymity). Pure policy core.
pub mod stick_insect;
// Detection caste: sentinel threat classifier — eclipse/flood/partition
// signatures from public connection/topology metrics. Detection only.
pub mod spider;
// Resilience caste: density-adaptive relay mode (solitary<->gregarious)
// with hysteresis. Pure state machine, advisory.
pub mod locust;
// Healing caste: living-bridge partition recovery — netgroup-diverse,
// freshness-weighted reconnection-target selection. Pure selection core.
pub mod army_ant;
