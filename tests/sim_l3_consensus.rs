//! L3 Byzantine discrete-event consensus scenarios.
//!
//! The reusable simulator lives in `tests/common/sim/` (Stage 3 Phase A). This
//! file is a consumer: it wires `SimConfig`s and asserts the two consensus
//! invariants — SAFETY (honest nodes never disagree below the finality floor)
//! and LIVENESS (the canonical height advances) — for an honest single miner and
//! for an equivocating miner. Partitions, more behaviors, and the
//! invariant-registry hook are added in later phases; see
//! docs/testing/L3-byzantine-simulator.md.
//!
//! Run: `cargo test --features testnet --test sim_l3_consensus -- --ignored`

#[path = "common/sim/mod.rs"]
mod sim;

use sim::{Behavior, Sim, SimConfig};

#[test]
#[ignore = "real-PoW light-mode mining, slow; run with --features testnet -- --ignored"]
fn honest_single_miner_safety_and_liveness() {
    let cfg = SimConfig {
        seed: 0x00C0FFEE,
        n_nodes: 3,
        miners: vec![0],
        behaviors: vec![Behavior::Honest; 3],
        min_delay: 50,
        max_delay: 500,
        drop_prob: 0.0,
        dup_prob: 0.10, // exercises the AlreadyKnown path
        block_spacing_secs: 3600,
        finality_depth: 4,
        rounds: 8,
    };

    let mut sim = Sim::new(cfg);
    let start = sim.max_honest_height();

    // Safety is checked after every accepted block inside run().
    sim.run().expect("no safety violation during the run");

    let end = sim.max_honest_height();
    assert!(
        end >= start + 6,
        "LIVENESS: canonical height must advance (start={start} end={end})"
    );
    sim.check_safety()
        .expect("SAFETY: honest nodes must agree below the finality floor");

    // With bounded delay and no drops, every follower must catch up to the miner.
    let tip = sim.nodes[0].chain.tip_hash();
    let h0 = sim.nodes[0].chain.height();
    for i in 0..sim.nodes.len() {
        assert_eq!(
            sim.nodes[i].chain.tip_hash(),
            tip,
            "node {i} must converge to the miner's tip"
        );
        assert_eq!(sim.nodes[i].chain.height(), h0, "node {i} height must match");
    }

    println!("PASS honest_single_miner_safety_and_liveness: converged 3 nodes to height {h0}");
}

#[test]
#[ignore = "real-PoW light-mode mining, slow; run with --features testnet -- --ignored"]
fn equivocating_miner_does_not_split_honest_nodes() {
    // Node 0 double-signs: at every height it mines two valid twin blocks and
    // sends one to node 1 and the other to node 2. Under the deterministic
    // hash-lex fork-choice, gossip propagates both twins and every honest node
    // converges to the SAME tie-winning chain — equivocation cannot split them.
    let cfg = SimConfig {
        seed: 0x00BADBEE,
        n_nodes: 3,
        miners: vec![0],
        behaviors: vec![Behavior::Equivocate, Behavior::Honest, Behavior::Honest],
        min_delay: 50,
        max_delay: 400,
        drop_prob: 0.0, // no drops: every honest node must fully converge
        dup_prob: 0.05,
        block_spacing_secs: 3600,
        finality_depth: 4,
        rounds: 8,
    };

    let mut sim = Sim::new(cfg);
    let start = sim.max_honest_height();

    // Safety is checked after every accepted block, including the twin forks.
    sim.run().expect("SAFETY must hold under equivocation");

    let end = sim.max_honest_height();
    assert!(
        end >= start + 6,
        "LIVENESS under equivocation: honest height must advance (start={start} end={end})"
    );
    sim.check_safety()
        .expect("SAFETY: equivocation must not split honest nodes below the finality floor");

    // The two honest nodes received DIFFERENT twins directly, yet the
    // deterministic hash tiebreak + gossip converge them to the SAME tip.
    assert_eq!(
        sim.nodes[1].chain.tip_hash(),
        sim.nodes[2].chain.tip_hash(),
        "honest nodes must converge to ONE chain under equivocation (deterministic hash tiebreak)"
    );
    assert_eq!(
        sim.nodes[1].chain.height(),
        sim.nodes[2].chain.height(),
        "honest heights must match after convergence"
    );

    println!(
        "PASS equivocating_miner_does_not_split_honest_nodes: honest nodes converged to height {}",
        sim.nodes[1].chain.height()
    );
}
