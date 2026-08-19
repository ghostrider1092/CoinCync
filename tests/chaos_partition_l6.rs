//! L6 chaos/partition harness — minimal deliverable.
//!
//! Models each node as an in-process `Blockchain` plus an outbox of every block
//! it ever accepted (needed to relay fork tips, which the main-chain height
//! index hides). A "message" is a `Block`; the "bus" is a boolean adjacency
//! matrix. Delivery = replay `src.known` into `dst.add_block` in height order,
//! looping to a fixpoint so orphans resolve once their parent arrives. Partition
//! = drop links; heal = restore + deliver. Everything is synchronous and
//! single-threaded, so runs are bit-for-bit deterministic.
//!
//! Run: `cargo test --features testnet --test chaos_partition_l6 -- --ignored`

#[path = "common/mining.rs"]
mod mining;

use coincync::chain::{BlockStatus, Blockchain};
use coincync::config::NetworkType;
use coincync::consensus::block::Block;
use coincync::primitives::{Hash, PublicKey};
use mining::{build_coinbase, generate_keypair, mine_block};

struct Node {
    chain: Blockchain,
    known: Vec<Block>,
    spend_pub: PublicKey,
    view_pub: PublicKey,
}

struct Bus {
    nodes: Vec<Node>,
    /// link[a][b] == true => blocks from a may be delivered to b.
    link: Vec<Vec<bool>>,
    magic: [u8; 4],
    base_ts: u64,
    spacing: u64,
}

impl Bus {
    fn new_in_memory(n: usize) -> Self {
        std::env::set_var("COINCYNC_RANDOMX_LIGHT_MODE", "1");
        coincync::consensus::bind_randomx_genesis_for_network(NetworkType::Testnet);

        let mut nodes = Vec::with_capacity(n);
        let mut base_ts = 0u64;
        for _ in 0..n {
            let chain = Blockchain::new();
            chain.init_genesis().expect("genesis");
            let genesis = chain.get_block_by_height(0).expect("genesis block");
            // Base-1 cumulative-work seed so equal-length forks are a true tie
            // (broken by the hash rule), not a spurious reorg.
            chain
                .restore_state(0, genesis.hash(), 1)
                .expect("seed base");
            base_ts = genesis.header.timestamp;
            // Per-node miner keys so two nodes produce DISTINCT blocks at the
            // same height (different coinbase => different tx_root => real fork).
            let (_s, spend_pub) = generate_keypair();
            let (_v, view_pub) = generate_keypair();
            nodes.push(Node {
                chain,
                known: vec![genesis],
                spend_pub,
                view_pub,
            });
        }
        let link = vec![vec![true; n]; n];
        Bus {
            nodes,
            link,
            magic: NetworkType::Testnet.magic_bytes(),
            base_ts,
            spacing: 3600,
        }
    }

    fn partition(&mut self, a: &[usize], b: &[usize]) {
        for &x in a {
            for &y in b {
                self.link[x][y] = false;
                self.link[y][x] = false;
            }
        }
    }

    fn heal(&mut self) {
        let n = self.nodes.len();
        self.link = vec![vec![true; n]; n];
    }

    /// Mine one real block on node `i`'s current tip and add it locally.
    fn mine_on(&mut self, i: usize) -> BlockStatus {
        let h = self.nodes[i].chain.height() + 1;
        let parent = self.nodes[i]
            .chain
            .get_block_by_height(self.nodes[i].chain.height())
            .expect("parent block");
        let target = if h == 1 {
            Hash::from_difficulty(500)
        } else {
            self.nodes[i].chain.next_target()
        };
        let ts = self.base_ts + h * self.spacing;
        let (cb, _) = build_coinbase(h, &self.nodes[i].spend_pub, &self.nodes[i].view_pub, 0);
        let blk = mine_block(
            &parent,
            h,
            ts,
            target,
            vec![cb],
            self.nodes[i].spend_pub,
            self.magic,
        );
        let status = self.nodes[i].chain.add_block(blk.clone()).expect("add_block");
        self.nodes[i].known.push(blk);
        status
    }

    /// One gossip round: for every allowed ordered pair, replay src's known
    /// blocks (height-ordered) into dst. Returns the count of NEW acceptances.
    fn deliver_round(&mut self) -> usize {
        let n = self.nodes.len();
        let mut delivered = 0usize;
        for src in 0..n {
            for dst in 0..n {
                if src == dst || !self.link[src][dst] {
                    continue;
                }
                // Clone src's outbox first to release the borrow before mutating dst.
                let mut blocks: Vec<Block> = self.nodes[src].known.clone();
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
                            panic!("honest partition produced an INVALID block: {e}")
                        }
                        Err(e) => panic!("add_block error during delivery: {e}"),
                    }
                }
            }
        }
        delivered
    }

    /// Deliver until a fixpoint (no new acceptances) or the round cap. Returns
    /// the number of rounds run.
    fn deliver_to_fixpoint(&mut self, max_rounds: usize) -> usize {
        for round in 1..=max_rounds {
            if self.deliver_round() == 0 {
                return round;
            }
        }
        panic!("delivery did not reach a fixpoint within {max_rounds} rounds");
    }

    fn tip(&self, i: usize) -> Hash {
        self.nodes[i].chain.tip_hash()
    }
    fn height(&self, i: usize) -> u64 {
        self.nodes[i].chain.height()
    }
    fn work(&self, i: usize) -> u128 {
        self.nodes[i].chain.stats().total_difficulty
    }
}

#[test]
#[ignore = "real-PoW mining, slow; run with --features testnet -- --ignored"]
fn two_node_partition_heals_to_heavier_chain() {
    let mut bus = Bus::new_in_memory(2);

    // ── Shared prefix: mine 3 blocks on node 0, gossip to node 1 ─────────────
    for _ in 0..3 {
        assert!(matches!(bus.mine_on(0), BlockStatus::Accepted));
    }
    bus.deliver_to_fixpoint(16);
    assert_eq!(bus.tip(0), bus.tip(1), "prefix must sync across both nodes");
    assert_eq!(bus.height(0), 3, "prefix height");
    assert_eq!(bus.height(1), 3, "prefix height (node 1)");

    // ── Partition {0} | {1}: each side extends its own fork ──────────────────
    bus.partition(&[0], &[1]);
    for _ in 0..2 {
        bus.mine_on(0); // node 0 -> height 5 (2-block fork)
    }
    for _ in 0..3 {
        bus.mine_on(1); // node 1 -> height 6 (3-block fork, strictly heavier)
    }
    assert_ne!(bus.tip(0), bus.tip(1), "the two sides must have diverged");
    assert_eq!(bus.height(0), 5);
    assert_eq!(bus.height(1), 6);
    assert!(
        bus.work(1) > bus.work(0),
        "node 1's longer fork must carry strictly more work: w1={} w0={}",
        bus.work(1),
        bus.work(0)
    );

    // ── Heal → the network must converge on node 1's heavier chain ───────────
    bus.heal();
    let rounds = bus.deliver_to_fixpoint(64);

    // Three-way agreement (tip AND height AND total_difficulty) rules out the
    // false-convergence class (identical tip, divergent work).
    let (t, h, w) = (bus.tip(1), bus.height(1), bus.work(1));
    for i in 0..2 {
        assert_eq!(bus.tip(i), t, "node {i} tip must converge to the heavier chain");
        assert_eq!(bus.height(i), h, "node {i} height must converge");
        assert_eq!(bus.work(i), w, "node {i} total_difficulty must converge");
    }
    assert!(h > 3, "converged chain must be above the fork point");

    println!("PASS two_node_partition_heals_to_heavier_chain: converged to height {h} in {rounds} rounds");
}
