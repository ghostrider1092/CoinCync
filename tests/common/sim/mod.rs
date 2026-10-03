//! Deterministic-simulation (DST) harness — reusable across scenario tests.
//!
//! A seeded, deterministic, replayable event-driven multi-node simulator. Each
//! node is an in-process [`Blockchain`]; a seeded `StdRng` (ChaCha) is the ONLY
//! entropy source (no `SystemTime`/`OsRng` in the driver — block timestamps are
//! kept in the past so validation's future-timestamp bound is never load-bearing).
//! Messages flow through a `(time, seq)`-ordered event queue, giving a total,
//! reproducible delivery order; per-link latency, drops and duplication are drawn
//! from the seed. A failing run reproduces bit-for-bit from its `seed`.
//!
//! Extracted from `tests/sim_l3_consensus.rs` (Stage 3 Phase A) so every scenario
//! shares one harness. Network partitions, more Byzantine/clock-skew behaviors,
//! and the consensus-invariant-registry hook layer on in later phases
//! (see docs/testing/L3-byzantine-simulator.md).

#[path = "../mining.rs"]
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

pub type NodeId = usize;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Behavior {
    Honest,
    /// Double-signs: mines two valid twin blocks at the same height and sends
    /// different ones to different halves of its peers.
    Equivocate,
    /// Withholds: mines a valid block and adopts it locally, but NEVER broadcasts
    /// it (selfish mining / block withholding). With another honest miner present
    /// the honest majority ignores the withholder and converges on the public
    /// chain. Still relays OTHER nodes' blocks normally — only its own are withheld.
    Withhold,
    // Further Byzantine variants (InvalidSpam / demon-timing) next.
}

pub struct Node {
    pub id: NodeId,
    pub chain: Blockchain,
    pub behavior: Behavior,
    spend_pub: PublicKey,
    view_pub: PublicKey,
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

/// A network partition active over the virtual-time window `[start, end)`.
///
/// While active, a message between two nodes in DIFFERENT `groups` is blocked
/// (eclipse / split-brain). A node listed in no group is fully reachable, so a
/// partition can isolate a subset and leave the rest connected. An empty
/// `partitions` list (the default) is a fully-connected network — the pre-Phase-B
/// behavior. Reordering and latency are already modeled by the seeded event queue.
#[derive(Clone)]
pub struct Partition {
    pub start: u64,
    pub end: u64,
    pub groups: Vec<Vec<NodeId>>,
}

pub struct SimConfig {
    pub seed: u64,
    pub n_nodes: usize,
    pub miners: Vec<NodeId>,
    pub behaviors: Vec<Behavior>,
    pub min_delay: u64,
    pub max_delay: u64,
    pub drop_prob: f64,
    pub dup_prob: f64,
    pub block_spacing_secs: u64,
    pub finality_depth: u64,
    pub rounds: u64,
    /// Network partitions to apply over virtual time (empty = fully connected).
    pub partitions: Vec<Partition>,
}

pub struct Sim {
    pub nodes: Vec<Node>,
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
    pub fn new(cfg: SimConfig) -> Self {
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
        // Always mine at the chain's own next target. At h==1 this maintains the
        // genesis difficulty (cheap); hard-coding `from_difficulty(500)` here is a
        // ~128x jump off genesis (≈4) and trips the per-block sanity-ratio clamp,
        // so the block is rejected before it can propagate.
        let target = self.nodes[miner].chain.next_target();
        let base = self.base_ts + h * self.cfg.block_spacing_secs;
        let miner_pk = self.nodes[miner].spend_pub;
        let (cb, _) = build_coinbase(h, &self.nodes[miner].spend_pub, &self.nodes[miner].view_pub, 0);
        let peers = self.nodes[miner].peers.clone();

        match self.nodes[miner].behavior {
            Behavior::Honest => {
                let blk = mine_block(&parent, h, base, target, vec![cb], miner_pk, self.magic);
                self.nodes[miner]
                    .chain
                    .add_block(blk.clone())
                    .expect("miner add");
                self.broadcast_to(miner, Arc::new(blk), &peers);
            }
            Behavior::Equivocate => {
                // Twin A uses the miner's normal coinbase; twin B pays a DISTINCT
                // coinbase (different view key) so the two twins don't share an
                // identical coinbase tx (which would collide in the tx index).
                let (_vb, view_pub_b) = deterministic_keypair(self.cfg.seed, miner as u8 + 200);
                let (cb_b, _) = build_coinbase(h, &self.nodes[miner].spend_pub, &view_pub_b, 0);

                let a = mine_block(&parent, h, base, target, vec![cb], miner_pk, self.magic);
                let mut b_ts = base + 1;
                let b = loop {
                    let cand =
                        mine_block(&parent, h, b_ts, target, vec![cb_b.clone()], miner_pk, self.magic);
                    if cand.hash() != a.hash() {
                        break cand;
                    }
                    b_ts += 1;
                };
                // Adopt both locally (the node's own tip is the fork-choice winner);
                // under the deterministic hash-tiebreak an equal-work twin is
                // Ok(AcceptedFork) or Ok(AcceptedReorg), never an error.
                self.nodes[miner]
                    .chain
                    .add_block(a.clone())
                    .unwrap_or_else(|e| panic!("equiv add a failed: {e:?}"));
                self.nodes[miner]
                    .chain
                    .add_block(b.clone())
                    .unwrap_or_else(|e| panic!("equiv add b failed: {e:?}"));
                // A to the first half of peers, B to the second half.
                let mid = peers.len() / 2;
                let (pa, pb) = peers.split_at(mid);
                self.broadcast_to(miner, Arc::new(a), pa);
                self.broadcast_to(miner, Arc::new(b), pb);
            }
            Behavior::Withhold => {
                // Mine a valid block and adopt it locally, but NEVER broadcast —
                // the block is withheld from the network (selfish mining).
                let blk = mine_block(&parent, h, base, target, vec![cb], miner_pk, self.magic);
                self.nodes[miner]
                    .chain
                    .add_block(blk)
                    .expect("withhold add");
                let _ = &peers; // deliberately NOT broadcast
            }
        }
    }

    /// Whether a message from `from` to `to` is blocked by an active partition at
    /// virtual time `at`. Nodes in different partition groups cannot reach each
    /// other; a node in no group is always reachable.
    fn blocked(&self, from: NodeId, to: NodeId, at: u64) -> bool {
        self.cfg.partitions.iter().any(|p| {
            if at < p.start || at >= p.end {
                return false;
            }
            let g_from = p.groups.iter().position(|g| g.contains(&from));
            let g_to = p.groups.iter().position(|g| g.contains(&to));
            matches!((g_from, g_to), (Some(a), Some(b)) if a != b)
        })
    }

    fn broadcast_to(&mut self, from: NodeId, block: Arc<Block>, targets: &[NodeId]) {
        for &peer in targets {
            if self.blocked(from, peer, self.clock) {
                continue; // partitioned: no link between these nodes right now
            }
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

    pub fn run(&mut self) -> Result<(), String> {
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
                            return Err(format!("node {to} received an INVALID block: {e}"))
                        }
                        Err(e) => return Err(format!("add_block error at node {to}: {e}")),
                        Ok(BlockStatus::Accepted)
                        | Ok(BlockStatus::AcceptedFork)
                        | Ok(BlockStatus::AcceptedReorg { .. }) => {
                            // Gossip: relay a newly-accepted block onward. Peers
                            // that already have it return AlreadyKnown and do not
                            // re-relay, so the flood terminates.
                            let peers = self.nodes[to].peers.clone();
                            self.broadcast_to(to, Arc::clone(&block), &peers);
                        }
                        Ok(_) => {} // AlreadyKnown / Orphan — no relay
                    }
                }
            }
            self.check_safety()?;
        }
        Ok(())
    }

    pub fn honest(&self) -> Vec<NodeId> {
        (0..self.nodes.len())
            .filter(|&i| self.nodes[i].behavior == Behavior::Honest)
            .collect()
    }

    pub fn max_honest_height(&self) -> u64 {
        self.honest()
            .iter()
            .map(|&i| self.nodes[i].chain.height())
            .max()
            .unwrap_or(0)
    }

    /// SAFETY: no two honest nodes disagree on any block at or below the finality
    /// floor (min honest height − finality_depth).
    pub fn check_safety(&self) -> Result<(), String> {
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
                            // Phase D: emit the SAME coded report the validator and
                            // runtime guards use (CYNC-CONS-003), via the consensus
                            // invariant registry, with a reproduce-from-seed hint —
                            // not a bespoke ad-hoc string.
                            return coincync::consensus::invariants::check(
                                coincync::diagnostics::CYNC_CONS_003,
                                false,
                                format!("height {h} (seed {:#x})", self.cfg.seed),
                            )
                            .map_err(|rep| rep.to_string());
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }
}
