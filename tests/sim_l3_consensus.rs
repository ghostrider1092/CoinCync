//! L3 Byzantine discrete-event consensus simulator — minimal deliverable.
//!
//! A seeded, deterministic, replayable event-driven simulator. Each node is an
//! in-process `Blockchain`; a seeded `StdRng` (ChaCha) is the ONLY entropy source
//! (no `SystemTime`/`OsRng` in the driver — block timestamps are kept in the
//! past so validation's future-timestamp bound is never load-bearing). Messages
//! flow through a `(time, seq)`-ordered event queue, giving a total, reproducible
//! delivery order; per-link latency and duplication are drawn from the seed.
//!
//! This first deliverable runs ONE honest miner + validating followers and
//! asserts the two consensus invariants — SAFETY (honest nodes never disagree
//! below the finality floor) and LIVENESS (the canonical height advances). One
//! miner ⇒ a single canonical chain, a stable green foundation that still fully
//! exercises the queue, per-link delay, duplication, and multi-node validation.
//! Byzantine behaviors (equivocation/withholding/spam) + a second miner layer on
//! next — see docs/testing/L3-byzantine-simulator.md.
//!
//! Run: `cargo test --features testnet --test sim_l3_consensus -- --ignored`

#[path = "common/mining.rs"]
mod mining;

use coincync::chain::{BlockStatus, Blockchain};
use coincync::config::NetworkType;
use coincync::consensus::block::Block;
use coincync::crypto::SecretScalar;
use coincync::primitives::{Hash, PublicKey, SecretKey};
use mining::{build_coinbase, mine_block};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::sync::Arc;

type NodeId = usize;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Behavior {
    Honest,
    // Byzantine variants land next session:
    // Equivocate, Withhold { release_after: u64 }, InvalidSpam,
}

struct Node {
    id: NodeId,
    chain: Blockchain,
    spend_pub: PublicKey,
    view_pub: PublicKey,
    behavior: Behavior,
    peers: Vec<NodeId>,
}

enum EventKind {
    MineTick { miner: NodeId },
    DeliverBlock { to: NodeId, block: Arc<Block> },
}

struct Event {
    time: u64,
    seq: u64,
    kind: EventKind,
}

// Total order on (time, seq) — the seq monotonic tiebreak makes same-time events
// deterministically ordered. Wrapped in `Reverse` for a min-heap.
impl PartialEq for Event {
    fn eq(&self, o: &Self) -> bool {
        self.time == o.time && self.seq == o.seq
    }
}
impl Eq for Event {}
impl PartialOrd for Event {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Event {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        self.time.cmp(&o.time).then(self.seq.cmp(&o.seq))
    }
}

struct SimConfig {
    seed: u64,
    n_nodes: usize,
    miners: Vec<NodeId>,
    behaviors: Vec<Behavior>,
    min_delay: u64,
    max_delay: u64,
    drop_prob: f64,
    dup_prob: f64,
    block_spacing_secs: u64,
    finality_depth: u64,
    rounds: u64,
}

struct Sim {
    nodes: Vec<Node>,
    rng: StdRng,
    queue: BinaryHeap<Reverse<Event>>,
    clock: u64,
    seq: u64,
    magic: [u8; 4],
    base_ts: u64,
    cfg: SimConfig,
}

/// Deterministic keypair from (seed, tag) — no OsRng, so runs replay exactly.
fn deterministic_keypair(seed: u64, tag: u8) -> (SecretKey, PublicKey) {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&seed.to_le_bytes());
    b[8] = tag;
    let secret = SecretScalar::from_bytes(b);
    let public = secret.to_public();
    (
        SecretKey::from_bytes(secret.to_bytes()),
        PublicKey::from_bytes(public.to_bytes()),
    )
}

impl Sim {
    fn new(cfg: SimConfig) -> Self {
        std::env::set_var("COINCYNC_RANDOMX_LIGHT_MODE", "1");
        coincync::consensus::bind_randomx_genesis_for_network(NetworkType::Testnet);

        let mut nodes = Vec::with_capacity(cfg.n_nodes);
        let mut base_ts = 0u64;
        for id in 0..cfg.n_nodes {
            let chain = Blockchain::new();
            chain.init_genesis().expect("genesis");
            let genesis = chain.get_block_by_height(0).expect("genesis block");
            chain
                .restore_state(0, genesis.hash(), 1)
                .expect("seed base");
            base_ts = genesis.header.timestamp;
            let (_ss, spend_pub) = deterministic_keypair(cfg.seed, id as u8 + 1);
            let (_vs, view_pub) = deterministic_keypair(cfg.seed, id as u8 + 128);
            let peers = (0..cfg.n_nodes).filter(|&p| p != id).collect();
            nodes.push(Node {
                id,
                chain,
                spend_pub,
                view_pub,
                behavior: cfg.behaviors[id],
                peers,
            });
        }

        let rng = StdRng::seed_from_u64(cfg.seed);
        Sim {
            nodes,
            rng,
            queue: BinaryHeap::new(),
            clock: 0,
            seq: 0,
            magic: NetworkType::Testnet.magic_bytes(),
            base_ts,
            cfg,
        }
    }

    fn schedule(&mut self, time: u64, kind: EventKind) {
        self.seq += 1;
        self.queue.push(Reverse(Event {
            time,
            seq: self.seq,
            kind,
        }));
    }

    fn link_delay(&mut self) -> u64 {
        let span = self.cfg.max_delay.saturating_sub(self.cfg.min_delay);
        self.cfg.min_delay + if span == 0 { 0 } else { self.rng.gen_range(0..=span) }
    }

    fn on_mine(&mut self, miner: NodeId) {
        let cur = self.nodes[miner].chain.height();
        let h = cur + 1;
        let parent = self.nodes[miner]
            .chain
            .get_block_by_height(cur)
            .expect("parent block");
        let target = if h == 1 {
            Hash::from_difficulty(500)
        } else {
            self.nodes[miner].chain.next_target()
        };
        let ts = self.base_ts + h * self.cfg.block_spacing_secs;
        let (cb, _) = build_coinbase(h, &self.nodes[miner].spend_pub, &self.nodes[miner].view_pub, 0);
        let blk = mine_block(
            &parent,
            h,
            ts,
            target,
            vec![cb],
            self.nodes[miner].spend_pub,
            self.magic,
        );
        self.nodes[miner]
            .chain
            .add_block(blk.clone())
            .expect("miner add");
        self.broadcast(miner, Arc::new(blk));
    }

    fn broadcast(&mut self, from: NodeId, block: Arc<Block>) {
        let peers = self.nodes[from].peers.clone();
        for peer in peers {
            if self.rng.gen::<f64>() < self.cfg.drop_prob {
                continue; // link dropped this message
            }
            let d = self.link_delay();
            self.schedule(
                self.clock + d,
                EventKind::DeliverBlock {
                    to: peer,
                    block: Arc::clone(&block),
                },
            );
            if self.rng.gen::<f64>() < self.cfg.dup_prob {
                let d2 = self.link_delay();
                self.schedule(
                    self.clock + d2,
                    EventKind::DeliverBlock {
                        to: peer,
                        block: Arc::clone(&block),
                    },
                );
            }
        }
    }

    fn run(&mut self) -> Result<(), String> {
        // Schedule the mine ticks (round cadence in virtual ms; delays < 1000 so
        // each round's deliveries land before the next tick).
        let miners = self.cfg.miners.clone();
        for r in 0..self.cfg.rounds {
            let t = r * 1000;
            for &m in &miners {
                self.schedule(t, EventKind::MineTick { miner: m });
            }
        }

        while let Some(Reverse(ev)) = self.queue.pop() {
            self.clock = ev.time;
            match ev.kind {
                EventKind::MineTick { miner } => self.on_mine(miner),
                EventKind::DeliverBlock { to, block } => {
                    match self.nodes[to].chain.add_block((*block).clone()) {
                        Ok(BlockStatus::Invalid(e)) => {
                            return Err(format!("honest node {to} received an INVALID block: {e}"))
                        }
                        Err(e) => return Err(format!("add_block error at node {to}: {e}")),
                        Ok(_) => {}
                    }
                }
            }
            self.check_safety()?;
        }
        Ok(())
    }

    fn honest(&self) -> Vec<NodeId> {
        (0..self.nodes.len())
            .filter(|&i| self.nodes[i].behavior == Behavior::Honest)
            .collect()
    }

    fn max_honest_height(&self) -> u64 {
        self.honest()
            .iter()
            .map(|&i| self.nodes[i].chain.height())
            .max()
            .unwrap_or(0)
    }

    /// SAFETY: no two honest nodes disagree on any block at or below the finality
    /// floor (min honest height − finality_depth).
    fn check_safety(&self) -> Result<(), String> {
        let honest = self.honest();
        if honest.len() < 2 {
            return Ok(());
        }
        let min_h = honest
            .iter()
            .map(|&i| self.nodes[i].chain.height())
            .min()
            .unwrap();
        let floor = min_h.saturating_sub(self.cfg.finality_depth);
        for h in 0..=floor {
            let mut reference: Option<Hash> = None;
            for &i in &honest {
                if let Some(b) = self.nodes[i].chain.get_block_by_height(h) {
                    let hh = b.hash();
                    match reference {
                        None => reference = Some(hh),
                        Some(r) if r != hh => {
                            return Err(format!(
                                "SAFETY VIOLATION at height {h}: honest nodes hold different blocks"
                            ))
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }
}

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
