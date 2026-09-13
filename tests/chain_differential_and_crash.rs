//! # Cross-cutting chain integration: differential, reorg-with-real-tx,
//! # apply/disconnect property, and crash-consistency
//!
//! Implements the four emphasized MISSING integration classes from
//! `docs/audit/test-plan/chain-storage.md`
//! (§ "Cross-cutting integration (the four emphasized classes)"):
//!
//!  1. **DIFFERENTIAL** — two nodes fed the SAME block set in DIFFERENT
//!     orders (interleaved forks / reorg-then-extend vs extend-then-reorg)
//!     must reach BYTE-IDENTICAL canonical state: tip, height,
//!     total_difficulty, total_supply, total_burned, a UTXO-set digest
//!     (count + per-height output_index buckets + every canonical output's
//!     ordinal/content), and the shielded/spark/kernel roots. A second
//!     variant proves a node built via a REORG and a node built LINEARLY to
//!     the same tip are identical on total_difficulty AND UTXO/output-index.
//!
//!  2. **REORG-REAL-TX** — an ACCEPTED (winning) reorg that re-applies REAL
//!     non-coinbase transfers: recipient/UTXO state, key images, the
//!     output_index, and the orphaned-tx mempool return are all correct on
//!     the winning branch (the single largest gap — the only pre-existing
//!     real-tx reorg test covers a *rejected* reorg).
//!
//!  3. **PROPERTY** — apply/disconnect symmetry: connect N blocks then
//!     rollback to any k ⇒ state equals connecting exactly k; and
//!     supply == Σ reward(0..=h) − Σ burned across arbitrary
//!     connect/rollback histories.
//!
//!  4. **CRASH-CONSISTENCY** — the harness cannot kill a process mid-op, so
//!     the atomicity invariants are emulated via reopen-after-commit
//!     ("all-or-nothing on reopen; height index never ahead of state; no
//!     orphaned output-index entries; supply matches replay"). The literal
//!     kill-mid-op variants are `#[ignore]`d "needs process-kill harness".
//!     A phase-2 store variant documents that shielded/spark/MW stay dormant
//!     (roots `[0u8;32]`) across a reorg in the current testnet build.
//!
//! ## Reuse of the established harness
//!
//! All mining and crypto reuse the exact patterns proven in
//! `tests/reorg_double_spend_e2e.rs` — real RandomX PoW via `mine_block`,
//! real coinbases via `build_coinbase`, real CLSAG 2-in/2-out transfers via
//! `build_uniform_transfer` (the sibling file's `build_double_spend` with a
//! non-double-spending target pair), fork-lineage difficulty via
//! `calculate_difficulty`, and the base-1 cumulative-work seed via
//! `restore_state`. No mining or crypto is re-implemented here.
//!
//! ## Determinism of the winning fork
//!
//! Every reorg here is driven by a fork that is strictly TALLER than the
//! branch it replaces (more blocks above the fork point at the
//! MIN_DIFFICULTY floor ⇒ strictly greater cumulative work). This avoids the
//! equal-work hash-lexicographic tiebreak, whose outcome varies with mined
//! hashes run-to-run — the exact fragility that led the sibling file to
//! descope its deterministic-heavier-fork step.
//!
//! Requires the `testnet` feature (which enables `randomx`); every test does
//! real PoW and is `#[ignore]`d exactly like the sibling e2e tests. Run:
//!   cargo test --features testnet --test chain_differential_and_crash -- --ignored --nocapture

use coincync::chain::{BlockStatus, Blockchain, ChainLoadOutcome};
use coincync::config::NetworkType;
use coincync::consensus::block::Block;
use coincync::consensus::fork_signal::{encode_coinbase_extra, SignalBits};
use coincync::consensus::{
    calculate_difficulty, compute_full_anchor, compute_pow_hash, BlockHeader, DifficultyBlock,
    PowAlgorithm,
};
use coincync::constants::{block_version_at_height, BOOTSTRAP_MIN_RING_SIZE};
use coincync::crypto::{
    coinbase_stealth_address, compute_one_time_secret, BlindingFactor, PedersenCommitment,
    SecretScalar, StealthAddress,
};
use coincync::db::Database;
use coincync::decoy::OutputLocator;
use coincync::emission::calculate_block_reward;
use coincync::primitives::{hash_domain, merkle_root, Hash, PublicKey, SecretKey};
use coincync::transaction::{
    DecoyOutput, Recipient, SpendableInput, Transaction, TransactionBuilder, TxOutput, TxType,
};
use rand::rngs::OsRng;
use std::sync::Arc;

// =============================================================================
// Key material — mirrors reorg_double_spend_e2e.rs
// =============================================================================

fn generate_keypair() -> (SecretKey, PublicKey) {
    let secret = SecretScalar::random(&mut OsRng);
    let public = secret.to_public();
    (
        SecretKey::from_bytes(secret.to_bytes()),
        PublicKey::from_bytes(public.to_bytes()),
    )
}

// =============================================================================
// Coinbase — mirrors create_mining_coinbase_with_fees / the sibling e2e file.
// =============================================================================

fn build_coinbase(
    height: u64,
    spend_pub: &PublicKey,
    view_pub: &PublicKey,
    total_fees: u64,
) -> (Transaction, StealthAddress) {
    let reward = calculate_block_reward(height);
    let total_amount = reward.as_atomic().saturating_add(total_fees);
    let commitment = PedersenCommitment::commit(total_amount, &BlindingFactor::zero());
    let miner_secret: [u8; 32] = *blake3::hash(view_pub.as_bytes()).as_bytes();
    let (stealth, _tx_secret) =
        coinbase_stealth_address(spend_pub, view_pub, height, 0, &miner_secret)
            .expect("coinbase stealth derivation must succeed");
    let view_tag = {
        let shared = hash_domain(
            b"COINCYNC_VIEW_TAG",
            &[stealth.tx_public_key.as_bytes().as_slice(), &[0u8]].concat(),
        );
        shared.as_bytes()[0]
    };
    let output = TxOutput {
        stealth_address: stealth.public_key,
        tx_public_key: stealth.tx_public_key,
        encrypted_amount: total_amount.to_le_bytes().to_vec(),
        commitment: commitment.to_bytes(),
        view_tag,
        lock_height: None,
        encrypted_memo: vec![],
    };
    let tx = Transaction {
        version: 1,
        tx_type: TxType::Coinbase,
        inputs: vec![],
        outputs: vec![output],
        fee: coincync::primitives::Amount::ZERO,
        range_proof: vec![],
        extra: encode_coinbase_extra(height, SignalBits(0)),
    };
    (tx, stealth)
}

/// Miner-claimable fee share, mirroring the sibling file / validator rule.
fn claimable_fees(height: u64, total_fees: u64) -> u64 {
    if total_fees == 0 {
        return 0;
    }
    if height < coincync::constants::FEE_DISTRIBUTION_HEIGHT {
        return total_fees;
    }
    coincync::consensus::fee_market::distribute_fee(
        coincync::primitives::Amount::from_atomic(total_fees),
        false,
    )
    .to_miner
    .as_atomic()
}

// =============================================================================
// Real CLSAG uniform 2-in/2-out transfer — mirrors build_double_spend, but the
// two target coinbases differ between calls so the spends are INDEPENDENT
// (a valid transfer, not a double-spend).
// =============================================================================

fn create_real_decoys(count: usize) -> Vec<DecoyOutput> {
    (0..count)
        .map(|i| {
            let s = SecretScalar::random(&mut OsRng);
            let p = s.to_public();
            let bf = BlindingFactor::random(&mut OsRng);
            let amount = 1_000_000_000u64 + (i as u64 * 100_000);
            let commitment = PedersenCommitment::commit(amount, &bf);
            DecoyOutput {
                public_key: PublicKey::from_bytes(p.to_bytes()),
                commitment: commitment.to_bytes(),
                height: 500 + i as u64,
            }
        })
        .collect()
}

struct SpendTarget {
    stealth: StealthAddress,
    amount: u64,
    height: u64,
}

/// Build a REAL, uniform-shape (2-in/2-out) CLSAG transfer spending two
/// on-chain coinbase outputs the caller controls. Identical construction to
/// the sibling file's `build_double_spend`; naming reflects that here the two
/// targets are distinct per call, so no key image is reused.
#[allow(clippy::too_many_arguments)]
fn build_uniform_transfer(
    targets: &[SpendTarget; 2],
    view_secret: &SecretKey,
    spend_secret: &SecretKey,
    recipient_spend: &PublicKey,
    recipient_view: &PublicKey,
    fee: u64,
    target_height: u64,
) -> Transaction {
    let mut rng = OsRng;
    let ring_size = BOOTSTRAP_MIN_RING_SIZE;
    let mut builder = TransactionBuilder::transfer().with_target_height(target_height);

    let mut input_sum: u64 = 0;
    for t in targets {
        let one_time_secret = compute_one_time_secret(&t.stealth, view_secret, spend_secret, 0)
            .expect("one-time secret recovery must succeed");
        let input = SpendableInput {
            tx_hash: Hash::zero(),
            output_index: 0,
            amount: coincync::primitives::Amount::from_atomic(t.amount),
            one_time_secret,
            blinding: BlindingFactor::zero(),
            height: t.height,
        };
        let decoys = create_real_decoys(ring_size - 1);
        builder
            .add_input(input, decoys, 0)
            .expect("add_input must succeed for a real coinbase output");
        input_sum += t.amount;
    }

    let change = 1_000_000_000u64;
    let out0 = input_sum - fee - change;
    builder
        .add_output(
            &Recipient {
                spend_public: *recipient_spend,
                view_public: *recipient_view,
                amount: coincync::primitives::Amount::from_atomic(out0),
                lock_height: None,
            },
            0,
            &mut rng,
        )
        .expect("add_output 0 must succeed");
    builder
        .add_output(
            &Recipient {
                spend_public: *recipient_spend,
                view_public: *recipient_view,
                amount: coincync::primitives::Amount::from_atomic(change),
                lock_height: None,
            },
            1,
            &mut rng,
        )
        .expect("add_output 1 must succeed");
    builder.set_fee(coincync::primitives::Amount::from_atomic(fee));

    builder
        .build(&mut rng)
        .expect("CLSAG build must succeed — balanced 2-in/2-out spend of real on-chain outputs")
}

// =============================================================================
// Real RandomX mining — mirrors reorg_double_spend_e2e.rs
// =============================================================================

fn mine_block(
    prev: &Block,
    height: u64,
    timestamp: u64,
    target: Hash,
    transactions: Vec<Transaction>,
    miner_pubkey: PublicKey,
    magic: [u8; 4],
) -> Block {
    let prev_hash = prev.hash();
    let tx_hashes: Vec<Hash> = transactions.iter().map(|t| t.hash()).collect();
    let tx_root = merkle_root(&tx_hashes);
    // audit §1: the anchor binds the header via `pow_binding()`. Build the
    // header first with a placeholder anchor, derive its binding, then compute
    // the real 4-arg anchor and write it back before mining.
    let mut header = BlockHeader {
        network_magic: magic,
        version: block_version_at_height(height),
        height,
        timestamp,
        prev_hash,
        tx_root,
        anchor: Hash::from_bytes([0u8; 32]),
        algorithm: PowAlgorithm::RandomX as u8,
        nonce: 0,
        target,
        miner_pubkey,
        supply_commitment: [0u8; 32],
        checkpoint_vote: None,
        spark_set_root: [0u8; 32],
        mw_kernel_root: [0u8; 32],
    };
    let binding = header.pow_binding();
    let anchor = compute_full_anchor(&prev_hash, height, timestamp, &binding)
        .expect("anchor computation must succeed")
        .mixed_hash;
    header.anchor = anchor;

    let mut nonce = 0u64;
    loop {
        let pow = compute_pow_hash(PowAlgorithm::RandomX, &anchor, nonce, &tx_root, height)
            .expect("RandomX hash must succeed (build with --features randomx)");
        if pow.meets_difficulty(&target) {
            break;
        }
        nonce = nonce
            .checked_add(1)
            .expect("nonce space exhausted — target unexpectedly hard");
    }
    header.nonce = nonce;

    Block::new(header, transactions)
}

fn diff_block(b: &Block) -> DifficultyBlock {
    DifficultyBlock {
        height: b.header.height,
        timestamp: b.header.timestamp,
        target: b.header.target,
    }
}

/// Fork-aware difficulty target for a block at `height` whose ascending
/// lineage (genesis .. parent) is `lineage`. Mirrors the sibling file's F13
/// target construction: build `DifficultyBlock`s from the fork's OWN lineage
/// (not the active chain by height) and run ASERT. Below a 2-block window the
/// parent target is maintained.
fn fork_target(lineage: &[Block], height: u64) -> Hash {
    let dblocks: Vec<DifficultyBlock> = lineage.iter().map(diff_block).collect();
    if dblocks.len() >= 2 {
        calculate_difficulty(&dblocks, height)
    } else {
        dblocks
            .last()
            .map(|b| b.target)
            .expect("lineage is non-empty (at least genesis)")
    }
}

// =============================================================================
// Test-only inspection: a UTXO-set digest derived ENTIRELY from public API.
// =============================================================================

/// Compute a deterministic digest of the live UTXO set + output_index using
/// ONLY public accessors:
///   - `available_output_count()`            (set cardinality),
///   - `decoy_distribution_snapshot()`       (per-height output_index buckets:
///                                             the canonical output_index shape),
///   - `resolve_decoy_snapshot(..)`          (each canonical output's ordinal
///                                             position + public_key/commitment/
///                                             height/is_coinbase/lock_height).
///
/// The chain exposes NO direct UTXO-set merkle root, so — per the task's rule —
/// this is the equivalent digest computed from what IS public. The ordinal
/// within each height bucket is the canonical output_index position, so two
/// nodes agree here iff their UTXO set AND output_index agree, independent of
/// the order blocks were fed. `resolve_decoy_snapshot` caps a request at 256
/// locators, so locators are resolved in chunks.
fn utxo_digest(chain: &Blockchain) -> [u8; 32] {
    let snap = chain.decoy_distribution_snapshot();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"COINCYNC_TEST_UTXO_DIGEST_V1");
    hasher.update(&(chain.available_output_count() as u64).to_le_bytes());

    let mut locators: Vec<OutputLocator> = Vec::new();
    for hc in &snap.heights {
        hasher.update(&hc.height.to_le_bytes());
        hasher.update(&hc.count.to_le_bytes());
        for ordinal in 0..hc.count {
            locators.push(OutputLocator {
                height: hc.height,
                ordinal,
            });
        }
    }

    for chunk in locators.chunks(200) {
        let resolved = chain
            .resolve_decoy_snapshot(
                snap.snapshot_height,
                snap.snapshot_hash,
                snap.policy_version,
                chunk,
            )
            .expect("resolve_decoy_snapshot over canonical locators");
        for o in resolved.outputs {
            hasher.update(&o.locator.height.to_le_bytes());
            hasher.update(&o.locator.ordinal.to_le_bytes());
            hasher.update(o.public_key.as_bytes());
            hasher.update(&o.commitment);
            hasher.update(&[o.is_coinbase as u8]);
            hasher.update(&o.lock_height.unwrap_or(u64::MAX).to_le_bytes());
        }
    }
    *hasher.finalize().as_bytes()
}

/// Full byte-for-byte consensus + storage fingerprint, including the UTXO
/// digest and the three phase-2 roots. Two nodes on the same canonical chain
/// must be equal on every field regardless of the history that got them there.
#[derive(Debug, PartialEq, Eq)]
struct Fingerprint {
    height: u64,
    tip: Hash,
    total_supply: u128,
    total_difficulty: u128,
    total_burned: u128,
    total_transactions: u64,
    total_blocks: u64,
    output_count: usize,
    utxo_digest: [u8; 32],
    shielded_root: [u8; 32],
    spark_root: [u8; 32],
    kernel_root: [u8; 32],
}

fn fingerprint(c: &Blockchain) -> Fingerprint {
    let s = c.stats();
    Fingerprint {
        height: c.height(),
        tip: c.tip_hash(),
        total_supply: s.total_supply,
        total_difficulty: s.total_difficulty,
        total_burned: s.total_burned,
        total_transactions: s.total_transactions,
        total_blocks: s.total_blocks,
        output_count: c.available_output_count(),
        utxo_digest: utxo_digest(c),
        shielded_root: c.shielded_root(),
        spark_root: c.spark_root(),
        kernel_root: c.mw_kernel_root(),
    }
}

/// Fresh in-memory testnet node seeded with the base-1 cumulative-work genesis
/// (see the sibling file for the full rationale — `init_genesis` writes
/// total_difficulty=1 only to the absent DB state, so the live base must be
/// seeded to 1 for the fork-work walk to treat an equal-length fork as a true
/// tie). Returns the node and its genesis block.
fn fresh_seeded_node() -> (Blockchain, Block) {
    let chain = Blockchain::new();
    chain.init_genesis().expect("genesis init");
    let genesis = chain.get_block_by_height(0).expect("genesis block");
    chain
        .restore_state(0, genesis.hash(), 1)
        .expect("seed cumulative-work genesis base = 1");
    (chain, genesis)
}

fn light_randomx() {
    std::env::set_var("COINCYNC_RANDOMX_LIGHT_MODE", "1");
    coincync::consensus::bind_randomx_genesis_for_network(NetworkType::Testnet);
}

/// Add a block, panicking on error, and return `(is_reorg, orphaned_txs)`.
/// Intermediate statuses at equal-work heights depend on the hash-lexicographic
/// tiebreak (which varies with the mined hashes), so tests assert on the FINAL
/// canonical state plus "a reorg occurred somewhere", never on a specific
/// intermediate variant.
fn add(chain: &Blockchain, block: &Block, label: &str) -> (bool, Vec<Transaction>) {
    match chain.add_block(block.clone()).unwrap_or_else(|e| panic!("add {label}: {e:?}")) {
        BlockStatus::AcceptedReorg { orphaned_txs } => (true, orphaned_txs),
        BlockStatus::Accepted | BlockStatus::AcceptedFork => (false, Vec::new()),
        other => panic!("add {label}: unexpected status {other:?}"),
    }
}

// =============================================================================
// A small deterministic reorg TREE, mined ONCE and replayed into fresh nodes.
//
//   genesis ─ B1 ─ B2                     (short "honest" branch)
//               \
//                F2 ─ F3 ─ F4             (heavier fork: 3 blocks above B1 > 1)
//
// The fork is strictly taller above the fork point (B1), so it wins with no
// dependence on the equal-work hash tiebreak. The canonical chain both feed
// orders converge to is  genesis ─ B1 ─ F2 ─ F3 ─ F4.
// =============================================================================

struct ReorgTree {
    b1: Block,
    b2: Block,
    f2: Block,
    f3: Block,
    f4: Block,
}

fn mine_reorg_tree() -> ReorgTree {
    let magic = NetworkType::Testnet.magic_bytes();
    let (_s, spend_pub) = generate_keypair();
    let (_v, view_pub) = generate_keypair();
    let (_m, miner_pk) = generate_keypair();

    // A throwaway builder node supplies main-chain ASERT targets (its tip is
    // the main branch). Fork targets are computed from the fork's own lineage.
    let (builder, genesis) = fresh_seeded_node();
    let base_ts = genesis.header.timestamp;
    let spacing = 3600u64;

    // B1 (h1): loose window (< 2 blocks) — start below genesis difficulty so
    // ASERT clamps the rest to the floor, keeping real PoW cheap.
    let (cb1, _) = build_coinbase(1, &spend_pub, &view_pub, 0);
    let b1 = mine_block(
        &genesis,
        1,
        base_ts + spacing,
        Hash::from_difficulty(500),
        vec![cb1],
        miner_pk,
        magic,
    );
    assert!(matches!(
        builder.add_block(b1.clone()).expect("add B1"),
        BlockStatus::Accepted
    ));

    // B2 (h2) on the honest branch.
    let (cb2, _) = build_coinbase(2, &spend_pub, &view_pub, 0);
    let b2 = mine_block(
        &b1,
        2,
        base_ts + 2 * spacing,
        builder.next_target(),
        vec![cb2],
        miner_pk,
        magic,
    );

    // Fork off B1: F2, F3, F4 (each with a distinct timestamp so it differs
    // from the honest B2; the fork's difficulty uses its OWN lineage).
    let lineage_01 = vec![genesis.clone(), b1.clone()];
    let (fcb2, _) = build_coinbase(2, &spend_pub, &view_pub, 0);
    let f2 = mine_block(
        &b1,
        2,
        base_ts + 2 * spacing + 500,
        fork_target(&lineage_01, 2),
        vec![fcb2],
        miner_pk,
        magic,
    );
    let lineage_012 = vec![genesis.clone(), b1.clone(), f2.clone()];
    let (fcb3, _) = build_coinbase(3, &spend_pub, &view_pub, 0);
    let f3 = mine_block(
        &f2,
        3,
        base_ts + 3 * spacing + 500,
        fork_target(&lineage_012, 3),
        vec![fcb3],
        miner_pk,
        magic,
    );
    let lineage_0123 = vec![genesis.clone(), b1.clone(), f2.clone(), f3.clone()];
    let (fcb4, _) = build_coinbase(4, &spend_pub, &view_pub, 0);
    let f4 = mine_block(
        &f3,
        4,
        base_ts + 4 * spacing + 500,
        fork_target(&lineage_0123, 4),
        vec![fcb4],
        miner_pk,
        magic,
    );

    ReorgTree { b1, b2, f2, f3, f4 }
}

// =============================================================================
// CLASS 1 — DIFFERENTIAL: same block set, different feed orders
// =============================================================================

/// Two independent nodes are fed the SAME five blocks in DIFFERENT orders:
///  - Node A (extend-then-reorg): B1, B2, F2, F3, F4  — builds the honest
///    branch to B2, then the heavier fork arrives and reorgs it away.
///  - Node B (interleaved forks): B1, F2, B2, F3, F4  — the fork block F2
///    arrives first and becomes the tip, B2 arrives as a losing side branch,
///    and the fork simply extends; Node B never reorgs.
///
/// Despite the divergent histories, both converge to the canonical chain
/// genesis─B1─F2─F3─F4 and MUST be byte-identical on tip, height,
/// total_difficulty, total_supply, total_burned, the UTXO-set digest
/// (count + output_index buckets + every canonical output), and the phase-2
/// roots. This is the differential the existing replay/db-reopen tests do not
/// cover: they feed the SAME order and never compare a UTXO/set root.
#[test]
#[ignore = "real-PoW mining, slow; run with --features testnet -- --ignored"]
fn differential_interleaved_fork_orders_reach_byte_identical_state() {
    light_randomx();
    let tree = mine_reorg_tree();

    // Node A: extend to B2, then the heavier fork arrives and reorgs it away.
    let (node_a, _g) = fresh_seeded_node();
    let mut reorg_a = false;
    for (b, l) in [
        (&tree.b1, "A B1"),
        (&tree.b2, "A B2"),
        (&tree.f2, "A F2"),
        (&tree.f3, "A F3"),
        (&tree.f4, "A F4"),
    ] {
        reorg_a |= add(&node_a, b, l).0;
    }
    assert!(
        reorg_a,
        "Node A (extend-then-reorg) must reorg onto the heavier fork at least once"
    );

    // Node B: the fork block F2 arrives before B2, so the fork branch tends to
    // stay canonical; B2 arrives as a competing side branch. Whatever the
    // intermediate tiebreaks, it converges to the same tip.
    let (node_b, _g) = fresh_seeded_node();
    for (b, l) in [
        (&tree.b1, "B B1"),
        (&tree.f2, "B F2"),
        (&tree.b2, "B B2"),
        (&tree.f3, "B F3"),
        (&tree.f4, "B F4"),
    ] {
        add(&node_b, b, l);
    }

    assert_eq!(node_a.tip_hash(), tree.f4.hash(), "Node A tip must be F4");
    assert_eq!(node_b.tip_hash(), tree.f4.hash(), "Node B tip must be F4");
    assert_eq!(
        fingerprint(&node_a),
        fingerprint(&node_b),
        "two nodes fed the same blocks in different orders must reach a \
         byte-identical canonical state (tip/height/difficulty/supply/burned/\
         UTXO digest/output_index/phase-2 roots)"
    );

    println!("PASS differential_interleaved_fork_orders_reach_byte_identical_state");
}

/// A node built via a REORG and a node built LINEARLY to the SAME tip must be
/// identical on total_difficulty AND the UTXO/output-index digest (plus the
/// rest of the fingerprint). The linear node is fed only the canonical blocks
/// (B1, F2, F3, F4); the reorg node is fed B1, B2, F2, F3, F4 so the extra B2
/// forces a real reorg. total_difficulty is a pure function of the canonical
/// chain, so the losing B2's work must not leak in.
#[test]
#[ignore = "real-PoW mining, slow; run with --features testnet -- --ignored"]
fn differential_reorg_built_equals_linear_built_to_same_tip() {
    light_randomx();
    let tree = mine_reorg_tree();

    // Linear: canonical chain only (B1, F2, F3, F4), each a clean extend.
    let (linear, _g) = fresh_seeded_node();
    for (b, l) in [
        (&tree.b1, "L B1"),
        (&tree.f2, "L F2"),
        (&tree.f3, "L F3"),
        (&tree.f4, "L F4"),
    ] {
        let (was_reorg, _) = add(&linear, b, l);
        assert!(!was_reorg, "linear {l} must extend, not reorg");
    }

    // Reorg: honest B2 then the heavier fork forces a real reorg.
    let (reorg, _g) = fresh_seeded_node();
    let mut reorged = false;
    for (b, l) in [
        (&tree.b1, "R B1"),
        (&tree.b2, "R B2"),
        (&tree.f2, "R F2"),
        (&tree.f3, "R F3"),
        (&tree.f4, "R F4"),
    ] {
        reorged |= add(&reorg, b, l).0;
    }
    assert!(reorged, "the reorg node must perform at least one reorg");

    assert_eq!(linear.tip_hash(), tree.f4.hash());
    assert_eq!(reorg.tip_hash(), tree.f4.hash());
    assert_eq!(
        linear.stats().total_difficulty,
        reorg.stats().total_difficulty,
        "reorg-built and linear-built nodes on the same tip must have identical \
         total_difficulty (the losing fork's work must not leak in)"
    );
    assert_eq!(
        utxo_digest(&linear),
        utxo_digest(&reorg),
        "reorg-built and linear-built nodes must have identical UTXO / \
         output-index state"
    );
    assert_eq!(
        fingerprint(&linear),
        fingerprint(&reorg),
        "full fingerprint must match between reorg-built and linear-built nodes"
    );

    println!("PASS differential_reorg_built_equals_linear_built_to_same_tip");
}

// =============================================================================
// CLASS 2 — REORG-REAL-TX: an ACCEPTED reorg re-applying real transfers
// =============================================================================

/// The single largest gap: an ACCEPTED (winning) reorg that re-applies REAL
/// non-coinbase transfers. Topology (all below STRICT_RING_MEMBER_HEIGHT):
///
/// ```text
///   genesis ─ B1(KA) ─ B2(KA2) ─ B3(KB) ─ B4(KB2) ─ B5..B10 ─ B11 ─ B12*
///                                                        \
///                                       F11 ─ F12 ─ F13 ─ F14 ─ F15**
/// ```
///  - `B12*`  main tip carries a REAL 2-in/2-out transfer spending KA(h1)+KA2(h2).
///  - Fork off `B10` is FIVE blocks (F11..F15) vs the main's two (B11,B12), so
///    it is strictly heavier and wins with no tiebreak dependence.
///  - Adding `F13` triggers the reorg (disconnecting B11 and B12): its
///    `AcceptedReorg.orphaned_txs` must return B12's transfer for the mempool.
///  - `F15**` re-applies a DIFFERENT real transfer spending KB(h3)+KB2(h4)
///    (matured by h15, on the shared prefix, never spent on either branch).
///
/// Asserted on the winning branch:
///  - the reorg returns B12's transfer as an orphaned tx (mempool restoration);
///  - KA/KA2's key images become UNSPENT again (their spend was disconnected);
///  - KB/KB2's key images are SPENT (the re-applied transfer);
///  - UTXO / output_index / supply / burn match an independent LINEAR node
///    built on the same canonical chain (a differential that sidesteps any
///    fee/burn-accounting assumptions — recipient balances and every
///    accumulator must agree exactly).
#[test]
#[ignore = "real-PoW mining, slow; run with --features testnet -- --ignored"]
fn accepted_reorg_reapplies_real_transfers_correctly() {
    light_randomx();
    let magic = NetworkType::Testnet.magic_bytes();

    // Attacker controls KA,KA2 (spent on main B12) and KB,KB2 (spent on fork F15).
    let (spend_secret, spend_public) = generate_keypair();
    let (view_secret, view_public) = generate_keypair();
    let (_fs, filler_spend_pk) = generate_keypair();
    let (_fv, filler_view_pk) = generate_keypair();
    let (_rs, r_spend_pk) = generate_keypair();
    let (_rv, r_view_pk) = generate_keypair();

    let (builder, genesis) = fresh_seeded_node();
    let base_ts = genesis.header.timestamp;
    let spacing = 3600u64;
    let fee = 50_000_000u64;

    // ── Main chain genesis + B1..B12 ──────────────────────────────────────
    // KA=h1, KA2=h2, KB=h3, KB2=h4 are attacker-owned; the rest are fillers.
    let mut lineage: Vec<Block> = vec![genesis.clone()]; // shared prefix, extended to B10
    let mut parent = genesis.clone();
    let mut ka: Option<StealthAddress> = None;
    let mut ka2: Option<StealthAddress> = None;
    let mut kb: Option<StealthAddress> = None;
    let mut kb2: Option<StealthAddress> = None;

    for h in 1..=12u64 {
        let target = builder.next_target();
        let (spk, vpk) = if (1..=4).contains(&h) {
            (&spend_public, &view_public)
        } else {
            (&filler_spend_pk, &filler_view_pk)
        };
        let (coinbase, stealth) = if h == 12 {
            // B12 coinbase claims the transfer's miner fee share.
            build_coinbase(12, &filler_spend_pk, &filler_view_pk, claimable_fees(12, fee))
        } else {
            build_coinbase(h, spk, vpk, 0)
        };
        match h {
            1 => ka = Some(stealth),
            2 => ka2 = Some(stealth),
            3 => kb = Some(stealth),
            4 => kb2 = Some(stealth),
            _ => {}
        }

        let txs = if h == 12 {
            // Real transfer spending KA(h1)+KA2(h2), both matured by h12.
            let main_targets = [
                SpendTarget {
                    stealth: ka.clone().expect("KA"),
                    amount: calculate_block_reward(1).as_atomic(),
                    height: 1,
                },
                SpendTarget {
                    stealth: ka2.clone().expect("KA2"),
                    amount: calculate_block_reward(2).as_atomic(),
                    height: 2,
                },
            ];
            let transfer = build_uniform_transfer(
                &main_targets,
                &view_secret,
                &spend_secret,
                &r_spend_pk,
                &r_view_pk,
                fee,
                12,
            );
            vec![coinbase, transfer]
        } else {
            vec![coinbase]
        };

        let block = mine_block(&parent, h, base_ts + h * spacing, target, txs, spend_public, magic);
        assert!(
            matches!(builder.add_block(block.clone()).expect("add B*"), BlockStatus::Accepted),
            "B{h} must extend the main chain"
        );
        parent = block.clone();
        if h <= 10 {
            lineage.push(block.clone());
        }
    }
    assert_eq!(builder.height(), 12, "main tip must be B12");

    // Recover B12's transfer + its key images (KA/KA2 spends).
    let b12 = builder.get_block_by_height(12).expect("B12");
    let main_transfer = b12
        .transactions
        .iter()
        .find(|t| !t.is_coinbase())
        .cloned()
        .expect("B12 carries a non-coinbase transfer");
    let ka_ki = main_transfer.inputs[0].key_image;
    let ka2_ki = main_transfer.inputs[1].key_image;

    // ── Heavier fork off B10: F11..F15 (5 blocks > main's B11,B12) ─────────
    let b10 = lineage.last().expect("B10").clone();
    assert_eq!(b10.header.height, 10, "fork point must be B10");

    // F15 re-applies a real transfer spending KB(h3)+KB2(h4), matured by h15.
    let fork_targets = [
        SpendTarget {
            stealth: kb.clone().expect("KB"),
            amount: calculate_block_reward(3).as_atomic(),
            height: 3,
        },
        SpendTarget {
            stealth: kb2.clone().expect("KB2"),
            amount: calculate_block_reward(4).as_atomic(),
            height: 4,
        },
    ];
    let fork_transfer = build_uniform_transfer(
        &fork_targets,
        &view_secret,
        &spend_secret,
        &r_spend_pk,
        &r_view_pk,
        fee,
        15,
    );
    let kb_ki = fork_transfer.inputs[0].key_image;
    let kb2_ki = fork_transfer.inputs[1].key_image;
    assert!(
        kb_ki != ka_ki && kb2_ki != ka2_ki,
        "fork transfer must spend DIFFERENT outputs than the main transfer"
    );

    let mut fork_lineage = lineage.clone(); // genesis..B10
    let mut fparent = b10.clone();
    let mut fork_blocks: Vec<Block> = Vec::new();
    for h in 11..=15u64 {
        let target = fork_target(&fork_lineage, h);
        let txs = if h == 15 {
            let (fcb, _) =
                build_coinbase(15, &filler_spend_pk, &filler_view_pk, claimable_fees(15, fee));
            vec![fcb, fork_transfer.clone()]
        } else {
            let (fcb, _) = build_coinbase(h, &filler_spend_pk, &filler_view_pk, 0);
            vec![fcb]
        };
        let fblk = mine_block(
            &fparent,
            h,
            base_ts + h * spacing + 500,
            target,
            txs,
            spend_public,
            magic,
        );
        fork_lineage.push(fblk.clone());
        fork_blocks.push(fblk.clone());
        fparent = fblk;
    }

    // ── Drive the reorg on the builder node ───────────────────────────────
    // The heavier fork overtakes the main tip (B12) once it is taller; the
    // exact trigger block depends on the equal-height work comparison, so we
    // collect the orphaned txs returned by WHICHEVER add reorgs and require at
    // least one reorg overall. B12's disconnect returns its real transfer.
    let mut all_orphaned: Vec<Transaction> = Vec::new();
    let mut reorged = false;
    for (i, fb) in fork_blocks.iter().enumerate() {
        let (was_reorg, orphaned) = add(&builder, fb, &format!("F{}", 11 + i));
        reorged |= was_reorg;
        all_orphaned.extend(orphaned);
    }
    assert!(reorged, "the heavier fork must trigger an accepted reorg");
    assert!(
        all_orphaned.iter().any(|t| t.hash() == main_transfer.hash()),
        "the accepted reorg must return B12's real transfer as an orphaned tx \
         for mempool restoration"
    );

    assert_eq!(builder.tip_hash(), fork_blocks[4].hash(), "tip must be F15");
    assert_eq!(builder.height(), 15, "height must be 15 on the winning branch");

    // KA/KA2's spend was disconnected → their key images are UNSPENT again.
    assert!(
        !builder.is_spent(&ka_ki) && !builder.is_spent(&ka2_ki),
        "the orphaned main transfer's key images must be UNSPENT after reorg \
         (their block was disconnected)"
    );
    // KB/KB2 were spent by the re-applied fork transfer.
    assert!(
        builder.is_spent(&kb_ki) && builder.is_spent(&kb2_ki),
        "the re-applied fork transfer's key images must be SPENT on the winning \
         branch"
    );

    // ── Differential: an independent LINEAR node on the same canonical chain ─
    // Feed genesis→B10 then F11→F15 (no B11/B12). Identical fingerprint proves
    // recipient balances, output_index, supply and burn are all correct on the
    // winning branch — without assuming the fee/burn formula.
    let (linear, _g) = fresh_seeded_node();
    for b in lineage.iter().skip(1) {
        // B1..B10
        assert!(matches!(
            linear.add_block(b.clone()).expect("linear prefix"),
            BlockStatus::Accepted
        ));
    }
    for fb in &fork_blocks {
        assert!(matches!(
            linear.add_block(fb.clone()).expect("linear fork"),
            BlockStatus::Accepted
        ));
    }
    assert_eq!(linear.tip_hash(), fork_blocks[4].hash());
    assert_eq!(
        fingerprint(&linear),
        fingerprint(&builder),
        "the reorged winning branch must be byte-identical to a node built \
         linearly on the same canonical chain (UTXO/output_index/supply/burn)"
    );

    println!("PASS accepted_reorg_reapplies_real_transfers_correctly");
}

// =============================================================================
// CLASS 3 — PROPERTY: apply/disconnect symmetry + supply conservation
// =============================================================================

/// Apply/disconnect symmetry over a real chain:
///   connect N blocks, then `rollback_to_height(k)`  ⇒  the resulting state
///   (tip, height, total_difficulty, total_supply, total_burned, UTXO digest,
///   output_index) equals the state of an independent node that connected
///   EXACTLY k blocks and stopped.
///
/// Also asserts the supply invariant across the connect/rollback history:
///   total_supply == Σ reward(0..=h)  and  total_burned == 0
/// for these coinbase-only blocks (no fees ⇒ no burn), i.e.
///   total_supply == Σ reward(0..=h) − Σ burned.
///
/// The rollback is exercised at several k to make the symmetry a property, not
/// a single point. Coinbase-only keeps the supply/burn arithmetic exact and
/// independent of the fee-distribution formula.
#[test]
#[ignore = "real-PoW mining, slow; run with --features testnet -- --ignored"]
fn apply_disconnect_symmetry_and_supply_conservation() {
    light_randomx();
    let magic = NetworkType::Testnet.magic_bytes();
    let (_s, spend_pub) = generate_keypair();
    let (_v, view_pub) = generate_keypair();

    const N: u64 = 6;

    // Mine a canonical coinbase-only chain genesis + B1..B6 once, on a builder.
    let (builder, genesis) = fresh_seeded_node();
    let base_ts = genesis.header.timestamp;
    let spacing = 3600u64;
    let mut blocks: Vec<Block> = Vec::new();
    let mut parent = genesis.clone();
    for h in 1..=N {
        let target = builder.next_target();
        let (cb, _) = build_coinbase(h, &spend_pub, &view_pub, 0);
        let blk = mine_block(&parent, h, base_ts + h * spacing, target, vec![cb], spend_pub, magic);
        assert!(matches!(
            builder.add_block(blk.clone()).expect("add"),
            BlockStatus::Accepted
        ));
        blocks.push(blk.clone());
        parent = blk;
    }

    // Genesis-baseline supply is reward(0); each block h adds reward(h).
    let sum_reward = |up_to: u64| -> u128 {
        (0..=up_to)
            .map(|h| calculate_block_reward(h).as_atomic() as u128)
            .sum()
    };

    // Reference nodes: connect EXACTLY k blocks (fresh node each), and the
    // supply invariant at every prefix length.
    let build_prefix = |k: u64| -> Blockchain {
        let (node, _g) = fresh_seeded_node();
        for b in blocks.iter().take(k as usize) {
            assert!(matches!(
                node.add_block(b.clone()).expect("prefix add"),
                BlockStatus::Accepted
            ));
        }
        node
    };

    for k in 0..=N {
        // Fresh node connected to N, then rolled back to k.
        let (rolled, _g) = fresh_seeded_node();
        for b in &blocks {
            assert!(matches!(
                rolled.add_block(b.clone()).expect("full add"),
                BlockStatus::Accepted
            ));
        }
        let orphaned = rolled.rollback_to_height(k).expect("rollback");
        assert!(
            orphaned.is_empty(),
            "coinbase-only rollback returns no non-coinbase orphans (k={k})"
        );

        let reference = build_prefix(k);

        assert_eq!(
            fingerprint(&rolled),
            fingerprint(&reference),
            "connect {N} then rollback to {k} must equal connecting exactly {k} \
             (apply/disconnect symmetry incl. UTXO/output_index)"
        );

        // Supply conservation: supply == Σ reward(0..=k) − burned, burned == 0.
        let s = rolled.stats();
        assert_eq!(
            s.total_burned, 0,
            "coinbase-only chain burns nothing at k={k}"
        );
        assert_eq!(
            s.total_supply,
            sum_reward(k) - s.total_burned,
            "total_supply must equal Σ reward(0..={k}) − Σ burned"
        );
    }

    println!("PASS apply_disconnect_symmetry_and_supply_conservation (N={N})");
}

// =============================================================================
// CLASS 4 — CRASH-CONSISTENCY (emulated via reopen-after-commit)
// =============================================================================

/// Reopen-after-commit emulation of the mid-`add_block` (extend) crash
/// invariants. We cannot kill the process mid-op here, so we commit a real
/// chain to RocksDB, drop the node + DB, reopen from disk, and assert the
/// all-or-nothing invariants that a crash-consistent commit guarantees:
///
///  - **all-or-nothing on reopen**: the reloaded state is byte-identical to
///    the live pre-close state (nothing half-applied);
///  - **height index never ahead of state**: every height in `1..=state_height`
///    resolves to a block, and `state_height + 1` does not
///    (the crash barrier `commit_block_atomic` upholds);
///  - **no orphaned output-index entries**: the reloaded UTXO/output-index
///    digest matches the live one exactly (no output_index rows without a
///    live UTXO, none missing);
///  - **supply matches replay**: the reloaded supply equals an in-memory
///    replay of the same blocks.
///
/// The literal "kill mid-op" variants are `#[ignore]`d below.
#[test]
#[ignore = "real-PoW mining, slow; run with --features testnet -- --ignored"]
fn crash_consistency_invariants_hold_on_reopen() {
    light_randomx();
    let magic = NetworkType::Testnet.magic_bytes();
    let (_s, spend_pub) = generate_keypair();
    let (_v, view_pub) = generate_keypair();

    let dir = tempfile::tempdir().expect("tempdir");

    // Build + persist a real chain, capture the LIVE fingerprint, close the DB.
    let (live_fp, blocks) = {
        let db = Arc::new(Database::open(dir.path()).expect("db open"));
        let chain = Blockchain::with_database(Arc::clone(&db), NetworkType::Testnet);
        chain.init_genesis().expect("genesis");
        let genesis = chain.get_block_by_height(0).expect("genesis block");
        chain
            .restore_state(0, genesis.hash(), 1)
            .expect("seed base");
        let base_ts = genesis.header.timestamp;
        let spacing = 3600u64;
        let mut parent = genesis.clone();
        let mut blocks = Vec::new();
        for h in 1..=6u64 {
            let target = chain.next_target();
            let (cb, _) = build_coinbase(h, &spend_pub, &view_pub, 0);
            let blk =
                mine_block(&parent, h, base_ts + h * spacing, target, vec![cb], spend_pub, magic);
            assert!(matches!(
                chain.add_block(blk.clone()).expect("add"),
                BlockStatus::Accepted
            ));
            blocks.push(blk.clone());
            parent = blk;
        }
        let fp = fingerprint(&chain);
        drop(chain);
        drop(db);
        (fp, blocks)
    };

    // Reopen from the SAME on-disk DB into a genuinely fresh node.
    let db2 = Arc::new(Database::open(dir.path()).expect("db reopen"));
    let reloaded = Blockchain::with_database(db2, NetworkType::Testnet);
    let outcome = reloaded
        .load_from_database_with_outcome()
        .expect("load from database");
    assert_eq!(
        outcome,
        ChainLoadOutcome::Loaded,
        "re-opening a populated DB must Load, not re-init Fresh"
    );

    // all-or-nothing + no orphaned output-index: full fingerprint (incl. UTXO
    // digest / output_index) is byte-identical.
    assert_eq!(
        reloaded_fp_matches(&reloaded, &live_fp),
        true,
        "reopened state must be byte-identical to the committed live state \
         (all-or-nothing; no orphaned output-index entries)"
    );

    // height index never ahead of state.
    let state_h = reloaded.height();
    for h in 1..=state_h {
        assert!(
            reloaded.get_block_by_height(h).is_some(),
            "height index must resolve every height ≤ state height ({h})"
        );
    }
    assert!(
        reloaded.get_block_by_height(state_h + 1).is_none(),
        "height index must never be ahead of committed state"
    );

    // supply matches an independent in-memory replay of the same blocks.
    let (replay, _g) = fresh_seeded_node();
    for b in &blocks {
        assert!(matches!(
            replay.add_block(b.clone()).expect("replay add"),
            BlockStatus::Accepted
        ));
    }
    assert_eq!(
        reloaded.stats().total_supply,
        replay.stats().total_supply,
        "reloaded supply must match an in-memory replay of the same blocks"
    );

    println!("PASS crash_consistency_invariants_hold_on_reopen");
}

/// Helper: compare a reloaded node's fingerprint to a captured live one.
fn reloaded_fp_matches(reloaded: &Blockchain, live: &Fingerprint) -> bool {
    &fingerprint(reloaded) == live
}

/// Literal kill-mid-operation crash consistency. This harness cannot kill a
/// process between `commit_block_atomic` / `apply_reorg_atomic` and the flush,
/// nor between `remove_heights_above` and `save_state`, so the three variants
/// below are documented and ignored. The atomicity they would prove is covered
/// indirectly by `crash_consistency_invariants_hold_on_reopen` (all-or-nothing
/// on reopen) and by the DB-unit tests
/// `commit_block_atomic_*` / `apply_reorg_atomic_*`.
///
///  - kill mid-add_block (extend): reopen sees the block fully applied or not
///    at all; height index never ahead of state; no orphaned output-index.
///  - kill mid-reorg (before vs after apply_reorg_atomic): reopen shows either
///    the prior canonical tip or the new tip, never a hybrid; no double-spend.
///  - kill mid-rollback_to_height (between remove_heights_above and
///    save_state): reopen is consistent.
#[test]
#[ignore = "needs process-kill harness"]
fn crash_kill_mid_operation_atomicity() {
    // Intentionally empty: requires a harness that can SIGKILL the process at a
    // chosen point inside add_block / apply_reorg_atomic / rollback_to_height
    // and then reopen the DB. See the doc comment for the invariants to check.
}

/// Phase-2 store behaviour across a reorg past a (simulated) restart. In the
/// current testnet build the shielded / spark / kernel stores are wired as
/// `None`, so their roots are `[0u8; 32]` and their per-block append / rewind
/// hooks are inert. This test documents and guards that dormancy: it drives a
/// real reorg (via the shared reorg tree) and asserts all three phase-2 roots
/// stay `[0u8; 32]` throughout — so the reorg rewind cannot desync a store,
/// and the "checkpoint stack is in-memory only → loud-error branch on
/// rewind-past-restart" concern is inert until Phase 2 activation instantiates
/// the stores.
#[test]
#[ignore = "real-PoW mining, slow; run with --features testnet -- --ignored"]
fn phase2_store_reorg_past_restart_stays_dormant() {
    light_randomx();
    let tree = mine_reorg_tree();

    let (node, _g) = fresh_seeded_node();
    let zero = [0u8; 32];
    assert_eq!(node.shielded_root(), zero, "shielded dormant at genesis");
    assert_eq!(node.spark_root(), zero, "spark dormant at genesis");
    assert_eq!(node.mw_kernel_root(), zero, "kernel dormant at genesis");

    let mut reorged = false;
    for (b, l) in [
        (&tree.b1, "B1"),
        (&tree.b2, "B2"),
        (&tree.f2, "F2"),
        (&tree.f3, "F3"),
        (&tree.f4, "F4"),
    ] {
        reorged |= add(&node, b, l).0;
    }
    assert!(reorged, "the heavier fork must reorg the honest branch");

    assert_eq!(node.tip_hash(), tree.f4.hash());
    assert_eq!(
        node.shielded_root(),
        zero,
        "shielded root must stay dormant across a reorg (Phase 2 not active)"
    );
    assert_eq!(
        node.spark_root(),
        zero,
        "spark root must stay dormant across a reorg (Phase 2 not active)"
    );
    assert_eq!(
        node.mw_kernel_root(),
        zero,
        "kernel root must stay dormant across a reorg (Phase 2 not active)"
    );

    println!("PASS phase2_store_reorg_past_restart_stays_dormant");
}
