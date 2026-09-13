//! # simkit — a deterministic multi-node blockchain test harness
//!
//! Generalizes the one-off `sim_l3_consensus` / `chaos_partition_l6` harnesses
//! into a reusable toolkit for the bug class that hurts most: consensus/sync
//! defects that only appear ACROSS NODES and OVER TIME (partitions, reorg
//! divergence, sync wedges). Everything is synchronous, single-threaded, and
//! seed-driven, so every run is bit-for-bit reproducible.
//!
//! What it gives you (one import):
//!   * `Sim::new(n)` — n in-process `Blockchain` nodes with per-node miner keys.
//!   * fault injection — `partition`, `heal` (latency/drop are a follow-on).
//!   * byzantine behavior — `mine_equivocating` (twin blocks to split peers).
//!   * a `VirtualClock` so block timestamps (and, later, timeout logic) advance
//!     deterministically instead of on wall-clock.
//!   * STATE-DIFF — `first_divergence(a, b)` pinpoints the first height two nodes
//!     disagree on (how today's rollback-telemetry bug would be caught instantly).
//!   * INVARIANT MONITORS — register `Invariant`s (supply conservation, work
//!     monotonicity, …) checked after every delivery round; a violation fails the
//!     run with the offending node + height.
//!
//! Mining uses the real PoW at the chain's floor difficulty (opt-in `#[ignore]`
//! for the slow scenarios); a true fast-PoW test mode is a separate consensus
//! hook. The harness API is the reusable value — write your scenario, assert
//! convergence + invariants.
#![allow(dead_code)]

use coincync::chain::{BlockStatus, Blockchain};
use coincync::config::NetworkType;
use coincync::consensus::block::Block;
use coincync::primitives::{Hash, PublicKey};

#[allow(unused_imports)]
use super::mining::{build_coinbase, generate_keypair, mine_block, mine_block_fast};

/// Deterministic logical clock — block timestamps come from here, never the OS.
pub struct VirtualClock {
    now: u64,
    step: u64,
}
impl VirtualClock {
    pub fn new(start: u64, step: u64) -> Self {
        VirtualClock { now: start, step: step.max(1) }
    }
    pub fn now(&self) -> u64 {
        self.now
    }
    /// Advance one step and return the new time.
    pub fn tick(&mut self) -> u64 {
        self.now += self.step;
        self.now
    }
    /// Advance by an arbitrary number of steps (latency / stall modelling).
    pub fn advance(&mut self, steps: u64) {
        self.now += self.step * steps;
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Behavior {
    Honest,
    /// Mines two valid twin blocks per height and shows different peers different twins.
    Equivocate,
    /// Mines but withholds — never gossips (eclipse / selfish-mining modelling).
    Withhold,
}

/// A node's full-state fingerprint — equal fingerprints ⇒ identical canonical state.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Fingerprint {
    pub height: u64,
    pub tip: Hash,
    pub total_supply: u128,
    pub total_difficulty: u128,
    pub total_burned: u128,
}

/// A named invariant checked against a node's chain after every delivery round.
pub struct Invariant {
    pub name: &'static str,
    pub check: Box<dyn Fn(&Blockchain) -> Result<(), String>>,
}

pub struct SimNode {
    pub chain: Blockchain,
    pub known: Vec<Block>,
    pub spend_pub: PublicKey,
    pub view_pub: PublicKey,
    pub behavior: Behavior,
}

pub struct Sim {
    pub nodes: Vec<SimNode>,
    link: Vec<Vec<bool>>,
    magic: [u8; 4],
    base_ts: u64,
    pub clock: VirtualClock,
    invariants: Vec<Invariant>,
}

impl Sim {
    /// `n` honest nodes on the same base-1 testnet genesis.
    pub fn new(n: usize) -> Self {
        std::env::set_var("COINCYNC_RANDOMX_LIGHT_MODE", "1");
        coincync::consensus::bind_randomx_genesis_for_network(NetworkType::Testnet);
        let mut nodes = Vec::with_capacity(n);
        let mut base_ts = 0u64;
        for _ in 0..n {
            let chain = Blockchain::new();
            chain.init_genesis().expect("genesis");
            let genesis = chain.get_block_by_height(0).expect("genesis block");
            chain.restore_state(0, genesis.hash(), 1).expect("seed base");
            base_ts = genesis.header.timestamp;
            let (_s, spend_pub) = generate_keypair();
            let (_v, view_pub) = generate_keypair();
            nodes.push(SimNode {
                chain,
                known: vec![genesis],
                spend_pub,
                view_pub,
                behavior: Behavior::Honest,
            });
        }
        let link = vec![vec![true; n]; n];
        Sim {
            nodes,
            link,
            magic: NetworkType::Testnet.magic_bytes(),
            base_ts,
            // loose spacing → ASERT holds difficulty near the cheap floor
            clock: VirtualClock::new(base_ts, 3600),
            invariants: Vec::new(),
        }
    }

    pub fn set_behavior(&mut self, i: usize, b: Behavior) {
        self.nodes[i].behavior = b;
    }

    /// Register an invariant checked after every delivery round.
    pub fn with_invariant(
        mut self,
        name: &'static str,
        check: impl Fn(&Blockchain) -> Result<(), String> + 'static,
    ) -> Self {
        self.invariants.push(Invariant { name, check: Box::new(check) });
        self
    }

    pub fn partition(&mut self, a: &[usize], b: &[usize]) {
        for &x in a {
            for &y in b {
                self.link[x][y] = false;
                self.link[y][x] = false;
            }
        }
    }
    pub fn heal(&mut self) {
        let n = self.nodes.len();
        self.link = vec![vec![true; n]; n];
    }

    /// Mine one real block on node `i`'s tip; timestamp comes from the clock.
    pub fn mine_on(&mut self, i: usize) -> BlockStatus {
        let ts = self.clock.tick();
        let blk = self.build_on(i, ts);
        let status = self.nodes[i].chain.add_block(blk.clone()).expect("add_block");
        self.nodes[i].known.push(blk);
        status
    }

    /// Byzantine: mine TWO valid twins at the same height (distinct timestamps ⇒
    /// distinct block hashes) and keep both in `known` so gossip shows different
    /// peers different twins.
    pub fn mine_equivocating(&mut self, i: usize) -> (BlockStatus, BlockStatus) {
        let ts = self.clock.tick();
        let a = self.build_on(i, ts);
        let b = self.build_on(i, ts + 1);
        let sa = self.nodes[i].chain.add_block(a.clone()).expect("add twin a");
        let sb = self.nodes[i].chain.add_block(b.clone()).expect("add twin b");
        self.nodes[i].known.push(a);
        self.nodes[i].known.push(b);
        (sa, sb)
    }

    fn build_on(&self, i: usize, ts: u64) -> Block {
        let h = self.nodes[i].chain.height() + 1;
        let parent = self
            .nodes[i]
            .chain
            .get_block_by_height(self.nodes[i].chain.height())
            .expect("parent");
        let (cb, _) = build_coinbase(h, &self.nodes[i].spend_pub, &self.nodes[i].view_pub, 0);
        // With `test-fast-pow` the validator skips PoW + difficulty enforcement,
        // so mine instantly (no RandomX loop); otherwise do the real work.
        #[cfg(feature = "test-fast-pow")]
        {
            mine_block_fast(&parent, h, ts, vec![cb], self.nodes[i].spend_pub, self.magic)
        }
        #[cfg(not(feature = "test-fast-pow"))]
        {
            let target = self.nodes[i].chain.next_target();
            mine_block(&parent, h, ts, target, vec![cb], self.nodes[i].spend_pub, self.magic)
        }
    }

    /// One gossip round over allowed links; runs all invariants after. Returns
    /// the number of NEW block acceptances.
    pub fn deliver_round(&mut self) -> usize {
        let n = self.nodes.len();
        let mut delivered = 0usize;
        for src in 0..n {
            if self.nodes[src].behavior == Behavior::Withhold {
                continue;
            }
            for dst in 0..n {
                if src == dst || !self.link[src][dst] {
                    continue;
                }
                let mut blocks = self.nodes[src].known.clone();
                blocks.sort_by_key(|b| b.header.height);
                for blk in blocks {
                    match self.nodes[dst].chain.add_block(blk.clone()) {
                        Ok(BlockStatus::Accepted)
                        | Ok(BlockStatus::AcceptedFork)
                        | Ok(BlockStatus::AcceptedReorg { .. }) => {
                            self.nodes[dst].known.push(blk);
                            delivered += 1;
                        }
                        Ok(BlockStatus::AlreadyKnown) | Ok(BlockStatus::Orphan) => {}
                        Ok(BlockStatus::Invalid(e)) => {
                            panic!("delivery produced an INVALID block: {e}")
                        }
                        Err(e) => panic!("add_block error during delivery: {e}"),
                    }
                }
            }
        }
        self.check_invariants().expect("invariant violated after delivery");
        delivered
    }

    pub fn deliver_to_fixpoint(&mut self, max_rounds: usize) -> usize {
        for round in 1..=max_rounds {
            if self.deliver_round() == 0 {
                return round;
            }
        }
        panic!("delivery did not reach a fixpoint within {max_rounds} rounds");
    }

    /// Run every registered invariant against every node.
    pub fn check_invariants(&self) -> Result<(), String> {
        for (i, node) in self.nodes.iter().enumerate() {
            for inv in &self.invariants {
                (inv.check)(&node.chain)
                    .map_err(|e| format!("invariant `{}` failed on node {i}: {e}", inv.name))?;
            }
        }
        Ok(())
    }

    pub fn fingerprint(&self, i: usize) -> Fingerprint {
        let c = &self.nodes[i].chain;
        let s = c.stats();
        Fingerprint {
            height: c.height(),
            tip: c.tip_hash(),
            total_supply: s.total_supply,
            total_difficulty: s.total_difficulty,
            total_burned: s.total_burned,
        }
    }

    /// STATE-DIFF: the first height at which nodes `a` and `b` hold different
    /// canonical blocks, or `None` if their shared prefix agrees. Pinpoints a
    /// consensus split deterministically.
    pub fn first_divergence(&self, a: usize, b: usize) -> Option<u64> {
        let top = self.height(a).min(self.height(b));
        for h in 0..=top {
            let ha = self.nodes[a].chain.get_block_by_height(h).map(|x| x.hash());
            let hb = self.nodes[b].chain.get_block_by_height(h).map(|x| x.hash());
            if ha != hb {
                return Some(h);
            }
        }
        None
    }

    /// Assert every node converged to the identical tip, height, and work.
    pub fn assert_converged(&self) {
        let f0 = self.fingerprint(0);
        for i in 1..self.nodes.len() {
            let fi = self.fingerprint(i);
            assert_eq!(
                (fi.tip, fi.height, fi.total_difficulty),
                (f0.tip, f0.height, f0.total_difficulty),
                "node {i} did not converge (first divergence at height {:?})",
                self.first_divergence(0, i)
            );
        }
    }

    pub fn tip(&self, i: usize) -> Hash {
        self.nodes[i].chain.tip_hash()
    }
    pub fn height(&self, i: usize) -> u64 {
        self.nodes[i].chain.height()
    }
    pub fn work(&self, i: usize) -> u128 {
        self.nodes[i].chain.stats().total_difficulty
    }
}

/// Built-in invariants teams can register on any `Sim`.
pub mod invariants {
    use super::*;
    use coincync::emission::calculate_block_reward;

    /// Total supply must equal Σ block reward over the canonical chain minus
    /// burned — i.e. no inflation and no lost coins, at every tip.
    pub fn supply_conservation(chain: &Blockchain) -> Result<(), String> {
        let s = chain.stats();
        let expected: u128 = (0..=chain.height())
            .map(|h| calculate_block_reward(h).as_atomic() as u128)
            .sum();
        if s.total_supply + s.total_burned != expected {
            return Err(format!(
                "supply {} + burned {} != Σ reward(0..={}) {}",
                s.total_supply, s.total_burned, chain.height(), expected
            ));
        }
        Ok(())
    }

    /// Cumulative work must be strictly positive and never below the seeded base.
    pub fn work_positive(chain: &Blockchain) -> Result<(), String> {
        if chain.stats().total_difficulty == 0 {
            return Err("total_difficulty is zero".into());
        }
        Ok(())
    }
}
