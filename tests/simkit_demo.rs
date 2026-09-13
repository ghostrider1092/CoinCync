//! Demo + smoke tests for the `simkit` multi-node harness.
//!
//! The first test is fast (no mining) — it verifies the harness wiring, the
//! invariant monitors, and the state-diff on genesis nodes. The `#[ignore]`
//! tests run real-PoW multi-node scenarios (partition-heal, equivocation).
//!
//! Run the slow ones: `cargo test --features testnet --test simkit_demo -- --ignored`

#[path = "common/mining.rs"]
mod mining;
#[path = "common/simkit.rs"]
mod simkit;

use simkit::{invariants, Behavior, Sim};

#[test]
fn simkit_wires_up_and_invariants_hold_on_genesis() {
    let sim = Sim::new(3)
        .with_invariant("supply_conservation", invariants::supply_conservation)
        .with_invariant("work_positive", invariants::work_positive);
    sim.check_invariants().expect("genesis invariants must hold");
    sim.assert_converged();
    assert_eq!(sim.first_divergence(0, 1), None, "genesis nodes must agree");
    assert_eq!(sim.height(0), 0);
}

#[test]
#[ignore = "real-PoW mining, slow"]
fn simkit_partition_heals_to_the_heavier_chain() {
    let mut sim =
        Sim::new(2).with_invariant("supply_conservation", invariants::supply_conservation);
    for _ in 0..3 {
        sim.mine_on(0);
    }
    sim.deliver_to_fixpoint(16);
    sim.assert_converged();

    // Partition {0}|{1}; node 1 builds the heavier (taller) fork.
    sim.partition(&[0], &[1]);
    for _ in 0..2 {
        sim.mine_on(0);
    }
    for _ in 0..3 {
        sim.mine_on(1);
    }
    assert!(sim.first_divergence(0, 1).is_some(), "partition must diverge");
    assert!(sim.work(1) > sim.work(0), "node 1's fork must be heavier");

    sim.heal();
    sim.deliver_to_fixpoint(64);
    sim.assert_converged();
    assert!(sim.height(0) > 3, "converged above the fork point");
}

#[test]
#[ignore = "real-PoW mining, slow"]
fn simkit_equivocation_does_not_split_honest_nodes() {
    let mut sim = Sim::new(3);
    sim.set_behavior(0, Behavior::Equivocate);
    for _ in 0..4 {
        sim.mine_equivocating(0);
        sim.deliver_to_fixpoint(16);
    }
    // Deterministic hash-tiebreak + gossip: honest nodes converge to one chain.
    sim.assert_converged();
}
