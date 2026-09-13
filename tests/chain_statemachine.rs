//! # Chain state-machine: ACCEPTED reorg re-applying real transactions
//!
//! Companion to `tests/reorg_double_spend_e2e.rs`. That suite covers a
//! *rejected* reorg (a double-spending fork tip). This file covers the single
//! largest gap in the chain-storage test plan
//! (`docs/audit/test-plan/chain-storage.md`): a reorg that is **accepted** and
//! re-applies REAL non-coinbase transfers onto the winning branch.
//!
//! ## Topology (all below STRICT_RING_MEMBER_HEIGHT = 100)
//!
//! ```text
//!   genesis - B1(K1) - B2(K2) - B3(K3) - B4(K4) - B5 .. B13 - B14(spend K3,K4)   (honest tip)
//!                                                          \
//!                                                           F14(spend K1,K2) - F15   (heavier fork)
//! ```
//!
//! The attacker controls four coinbases K1..K4 (heights 1..4). Testnet coinbase
//! maturity requires age ≥ MIN_OUTPUT_AGE = 10, so the youngest, K4 (height 4),
//! first becomes spendable at height 14 (age 10) — the real transfers therefore
//! live at height 14, NOT 12 (at height 12, K3/K4 are age 9/8 and a transfer
//! spending them is consensus-rejected). The honest tip B14 carries a REAL
//! 2-in/2-out transfer spending K3,K4. The fork F14 carries a REAL 2-in/2-out
//! transfer spending K1,K2, and F15 (coinbase-only) makes the fork two blocks
//! above the fork point B13 versus the honest one — strictly more cumulative
//! work. Adding F15 triggers a reorg that:
//!   - disconnects B14 (un-marking K3,K4's key images, removing its outputs),
//!   - applies F14 (marking K1,K2's key images, adding its outputs),
//!   - applies F15,
//! and re-validates the tip against the reorged UTXO set (no double-spend, so
//! the reorg is ACCEPTED — unlike the sibling suite's rejected fork).
//!
//! ## Proven properties (the P0 gaps)
//!   - `BlockStatus::AcceptedReorg` with the disconnected block's non-coinbase
//!     tx returned in `orphaned_txs` (mempool restoration).
//!   - New key-image state correct: K1,K2 SPENT (fork applied); K3,K4 UNSPENT
//!     (orphaned block's key images un-marked on disconnect).
//!   - Supply AND total_burned conserved, and the reorged node's full
//!     fingerprint (tip, height, supply, burn, total_difficulty, UTXO count) is
//!     byte-identical to a node that built the SAME canonical chain LINEARLY —
//!     proving reorg/linear path-independence and that orphaned outputs were
//!     removed while re-applied ones were restored.
//!
//! Run (real PoW, slow):
//!   cargo test --features testnet --test chain_statemachine -- --ignored --nocapture

use coincync::chain::{BlockStatus, Blockchain};
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
use coincync::emission::calculate_block_reward;
use coincync::primitives::{hash_domain, merkle_root, Hash, PublicKey, SecretKey};
use coincync::transaction::{
    DecoyOutput, Recipient, SpendableInput, Transaction, TransactionBuilder, TxOutput, TxType,
};
use rand::rngs::OsRng;

// =============================================================================
// Harness — mirrors tests/reorg_double_spend_e2e.rs (the established, proven
// build-and-mine helpers). Kept in sync with that file; not re-derived crypto.
// =============================================================================

fn generate_keypair() -> (SecretKey, PublicKey) {
    let secret = SecretScalar::random(&mut OsRng);
    let public = secret.to_public();
    (
        SecretKey::from_bytes(secret.to_bytes()),
        PublicKey::from_bytes(public.to_bytes()),
    )
}

/// Build a coinbase paying `reward(height) + total_fees` to a stealth address
/// derived from (spend_pub, view_pub, height, 0). Returns the tx and the
/// `StealthAddress` so the caller can later spend it.
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

/// Fees a coinbase may claim, mirroring the validator's `max_coinbase` rule.
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

/// One matured coinbase the attacker controls and will spend.
struct SpendTarget {
    stealth: StealthAddress,
    amount: u64,
    height: u64,
}

/// Build a REAL, uniform-shape (2-in / 2-out) CLSAG transfer spending two
/// on-chain coinbase outputs the attacker controls. Verbatim shape from the
/// reorg e2e harness (`build_double_spend`); here used for single, distinct
/// spends on each branch.
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
        .expect("CLSAG build must succeed — balanced 2-in/2-out spend")
}

/// Find a nonce meeting `target` and assemble the block (real RandomX PoW).
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

// =============================================================================
// P0: accepted reorg re-applying real non-coinbase transactions
// =============================================================================

#[test]
#[ignore = "real-PoW mining, slow; run with --features testnet -- --ignored"]
fn accepted_reorg_reapplies_real_txs_and_conserves_state() {
    std::env::set_var("COINCYNC_RANDOMX_LIGHT_MODE", "1");
    coincync::consensus::bind_randomx_genesis_for_network(NetworkType::Testnet);

    let magic = NetworkType::Testnet.magic_bytes();

    // Attacker keys control coinbases K1..K4 and both branch transfers.
    let (spend_secret, spend_public) = generate_keypair();
    let (view_secret, view_public) = generate_keypair();
    let (_filler_spend_sk, filler_spend_pk) = generate_keypair();
    let (_filler_view_sk, filler_view_pk) = generate_keypair();
    let (_r_spend_sk, r_spend_pk) = generate_keypair();
    let (_r_view_sk, r_view_pk) = generate_keypair();

    let spacing = 3600u64;
    let fee = 50_000_000u64;

    // ── Build the honest chain genesis..B11 on chain A, capturing K1..K4 ──────
    let chain = Blockchain::new();
    chain.init_genesis().expect("genesis init");
    let genesis = chain.get_block_by_height(0).expect("genesis block");
    chain
        .restore_state(0, genesis.hash(), 1)
        .expect("seed cumulative-work genesis base = 1");
    let base_ts = genesis.header.timestamp;

    let mut chain_blocks: Vec<Block> = vec![genesis.clone()];
    let mut stealths: Vec<Option<StealthAddress>> = vec![None; 5]; // index by height 1..4
    let mut parent = genesis.clone();
    for h in 1..=13u64 {
        let ts = base_ts + h * spacing;
        let target = chain.next_target();
        let (coinbase, stealth) = if (1..=4).contains(&h) {
            build_coinbase(h, &spend_public, &view_public, 0) // attacker-controlled
        } else {
            build_coinbase(h, &filler_spend_pk, &filler_view_pk, 0)
        };
        if (1..=4).contains(&h) {
            stealths[h as usize] = Some(stealth);
        }
        let block = mine_block(&parent, h, ts, target, vec![coinbase], spend_public, magic);
        assert!(
            matches!(chain.add_block(block.clone()).expect("add B*"), BlockStatus::Accepted),
            "B{h} must extend the honest chain"
        );
        parent = block.clone();
        chain_blocks.push(block);
    }
    let b13 = parent.clone();
    assert_eq!(chain.height(), 13);

    let fork_targets = [
        SpendTarget { stealth: stealths[1].clone().unwrap(), amount: calculate_block_reward(1).as_atomic(), height: 1 },
        SpendTarget { stealth: stealths[2].clone().unwrap(), amount: calculate_block_reward(2).as_atomic(), height: 2 },
    ];
    let honest_targets = [
        SpendTarget { stealth: stealths[3].clone().unwrap(), amount: calculate_block_reward(3).as_atomic(), height: 3 },
        SpendTarget { stealth: stealths[4].clone().unwrap(), amount: calculate_block_reward(4).as_atomic(), height: 4 },
    ];

    // Transfers sit at height 14 (not 12): they spend coinbase outputs K1..K4
    // (heights 1..4), and testnet coinbase maturity requires age ≥ MIN_OUTPUT_AGE
    // (= 10). The youngest, K4 (height 4), first matures at height 14 (age 10). At
    // height 12, K3/K4 (age 9/8) are immature, so the transfer — and hence the
    // whole block — is consensus-rejected. Hence the honest chain runs to B13 and
    // the real-transfer blocks live at height 14 (tip) / 15 (fork tip).
    let t14 = chain.next_target();

    // ── Honest tip B14: coinbase(+fees) + REAL transfer spending K3,K4 ───────
    let spend_b14 = build_uniform_transfer(
        &honest_targets, &view_secret, &spend_secret, &r_spend_pk, &r_view_pk, fee, 14,
    );
    let b14_transfer_hash = spend_b14.hash();
    let k3_ki = spend_b14.inputs[0].key_image;
    let k4_ki = spend_b14.inputs[1].key_image;
    let (b14_coinbase, _) =
        build_coinbase(14, &filler_spend_pk, &filler_view_pk, claimable_fees(14, fee));
    let b14 = mine_block(
        &b13, 14, base_ts + 14 * spacing, t14,
        vec![b14_coinbase, spend_b14.clone()], spend_public, magic,
    );

    // ── Fork F14: coinbase(+fees) + REAL transfer spending K1,K2 ─────────────
    let spend_f14 = build_uniform_transfer(
        &fork_targets, &view_secret, &spend_secret, &r_spend_pk, &r_view_pk, fee, 14,
    );
    let k1_ki = spend_f14.inputs[0].key_image;
    let k2_ki = spend_f14.inputs[1].key_image;
    let (f14_coinbase, _) =
        build_coinbase(14, &filler_spend_pk, &filler_view_pk, claimable_fees(14, fee));

    // Keep the honest B14 as tip when F14 arrives (equal work): re-mine F14 with
    // bumped timestamps until F14.hash > B14.hash so B14 wins the tiebreak. F14's
    // timestamp does not affect its own difficulty target.
    let mut f14_ts = base_ts + 14 * spacing + 1;
    let f14 = loop {
        let candidate = mine_block(
            &b13, 14, f14_ts, t14,
            vec![f14_coinbase.clone(), spend_f14.clone()], spend_public, magic,
        );
        if candidate.hash().as_bytes() > b14.hash().as_bytes() {
            break candidate;
        }
        f14_ts += 1;
    };

    assert!(matches!(chain.add_block(b14.clone()).expect("add B14"), BlockStatus::Accepted));
    assert_eq!(chain.tip_hash(), b14.hash(), "B14 is the honest tip");
    assert!(chain.is_spent(&k3_ki), "K3 spent on the honest chain");
    assert!(chain.is_spent(&k4_ki), "K4 spent on the honest chain");

    assert!(
        matches!(chain.add_block(f14.clone()).expect("add F14"), BlockStatus::AcceptedFork),
        "F14 is stored as a non-winning side branch"
    );
    assert_eq!(chain.tip_hash(), b14.hash(), "tip still B14 after F14");

    // ── Fork tip F15 (coinbase-only) off F14 — makes the fork heavier ────────
    let mut dblocks: Vec<DifficultyBlock> =
        (0..=13u64).map(|h| diff_block(&chain_blocks[h as usize])).collect();
    dblocks.push(diff_block(&f14));
    let t15 = calculate_difficulty(&dblocks, 15);
    let (f15_coinbase, _) = build_coinbase(15, &filler_spend_pk, &filler_view_pk, 0);
    let f15 = mine_block(&f14, 15, f14_ts + spacing, t15, vec![f15_coinbase], spend_public, magic);

    // ── Adding F15 triggers an ACCEPTED reorg ────────────────────────────────
    let status = chain.add_block(f15.clone()).expect("add_block F15");
    let orphaned = match status {
        BlockStatus::AcceptedReorg { orphaned_txs } => orphaned_txs,
        other => panic!("F15 must be AcceptedReorg, got {other:?}"),
    };

    assert_eq!(chain.tip_hash(), f15.hash(), "tip switched to the heavier fork");
    assert_eq!(chain.height(), 15);

    // Orphaned B14 transfer is returned for mempool restoration; no coinbase is.
    assert!(
        orphaned.iter().any(|t| t.hash() == b14_transfer_hash),
        "B14's non-coinbase transfer must be returned as orphaned"
    );
    assert!(orphaned.iter().all(|t| !t.is_coinbase()), "no coinbase orphaned");

    // Key-image state after the reorg:
    assert!(chain.is_spent(&k1_ki), "K1 spent by the re-applied fork tx F14");
    assert!(chain.is_spent(&k2_ki), "K2 spent by the re-applied fork tx F14");
    assert!(!chain.is_spent(&k3_ki), "K3 un-marked — B14 was disconnected");
    assert!(!chain.is_spent(&k4_ki), "K4 un-marked — B14 was disconnected");

    // Supply is the gross emission schedule over the NEW canonical chain.
    let expected_supply: u128 =
        (0..=15u64).map(|h| calculate_block_reward(h).as_atomic() as u128).sum();
    assert_eq!(
        chain.stats().total_supply, expected_supply,
        "supply == Σ reward(0..=15) over the reorged canonical chain"
    );

    // ── Differential: a node that built the SAME canonical chain LINEARLY ─────
    // (genesis, B1..B13, F14, F15 — never B14) must reach a byte-identical
    // fingerprint. Replays already-mined blocks (no re-mining), so this is the
    // conservation + reorg-vs-linear path-independence proof for supply, burn,
    // total_difficulty, and the UTXO/output set.
    let linear = Blockchain::new();
    linear.init_genesis().expect("linear genesis");
    let lg = linear.get_block_by_height(0).expect("linear genesis block");
    linear.restore_state(0, lg.hash(), 1).expect("linear seed base");
    for h in 1..=13u64 {
        assert!(
            matches!(
                linear.add_block(chain_blocks[h as usize].clone()).expect("linear add B*"),
                BlockStatus::Accepted
            ),
            "linear replay B{h}"
        );
    }
    assert!(
        matches!(linear.add_block(f14.clone()).expect("linear add F14"), BlockStatus::Accepted),
        "F14 extends B13 as a plain main-chain block in the linear build"
    );
    assert!(
        matches!(linear.add_block(f15.clone()).expect("linear add F15"), BlockStatus::Accepted),
        "F15 extends F14 in the linear build"
    );

    let fp = |c: &Blockchain| {
        let s = c.stats();
        (
            c.height(),
            c.tip_hash(),
            s.total_supply,
            s.total_burned,
            s.total_difficulty,
            c.available_output_count(),
        )
    };
    assert_eq!(
        fp(&chain), fp(&linear),
        "reorged node must be byte-identical to a linearly-built node on the \
         same canonical chain (supply, burn, total_difficulty, UTXO set all conserved)"
    );

    println!("PASS accepted_reorg_reapplies_real_txs_and_conserves_state");
}

// =============================================================================
// H3 regression: a FAILED reorg (path A) must leave no stale height→hash
// mapping ABOVE the old tip
// =============================================================================
//
// ## The bug (fixed in `src/chain.rs`, path-A rollback)
//
// When a reorg attempt fails partway through the fork-connect loop, the chain
// rolls back to the pre-reorg tip. The buggy rollback removed the stale
// `height_to_hash` mappings bounded by the OLD tip height. But `inner.tip` is
// NOT advanced during a reorg attempt, so any fork block the loop already
// connected at a height ABOVE the old tip kept its `height_to_hash` mapping
// after the rollback — RPC/sync would then report an unapplied fork block as
// canonical, and a follow-up block parented on it could commit a chain with an
// unapplied gap. The fix bounds the removal by the HIGHEST fork-block height
// (`removal_top = pre_reorg_tip.height.max(highest_fork_height)`).
//
// ## Why the construction looks the way it does (the load-bearing subtlety)
//
// For the reorg loop to CONNECT a *valid* fork block strictly above the old tip
// and THEN fail on a *later* fork block, both of those blocks (and the whole
// fork up to the triggering tip) must already be stored as side branches when
// the reorg fires — `collect_fork_chain` EXCLUDES the triggering tip and only
// walks blocks already in storage. But a fork block that is strictly heavier
// than the main tip wins fork-choice the instant it is added and reorgs
// immediately; a *valid* block can therefore never rest above the old tip as a
// side branch **under equal per-block difficulty**. The only way to park valid
// fork blocks above the old tip without triggering an early reorg is to make
// the fork strictly TALLER yet strictly LIGHTER than main until the very last
// block. So:
//
//   * MAIN is mined with TIGHT spacing → ASERT ramps its difficulty well above
//     the MIN_DIFFICULTY floor (each main block carries more work).
//   * The FORK is mined off an early point (B2) with LOOSE spacing → ASERT
//     eases it to the floor (each fork block carries ~floor work).
//
// The fork can then grow several blocks taller than main while staying lighter;
// every fork block up to the trigger is `AcceptedFork` (a stored side branch),
// which the test ASSERTS block-by-block so it can never silently mis-stage.
//
// Topology (fork point = B2; K1@1, K2@2 are matured attacker coinbases BELOW the
// fork point, so they survive the reorg's disconnect and are unspent on main):
//
// ```text
//   genesis - B1(K1) - B2(K2) - B3 .. B11                       (heavy main tip @ N=11)
//                          \
//                           F3 .. F11 - G(spend K1,K2) - H(re-spend K1,K2) - fillers - T
//                           └── all floor-difficulty side branches (fork lighter) ──┘
// ```
//
//   * G = F12 is a VALID 2-in/2-out spend of K1,K2 — the block that gets
//     connected ABOVE the old tip (height 12 > 11) and receives the
//     height→hash mapping the bug leaves stale. Its height (12) is also the
//     first at which K1@1/K2@2 clear coinbase maturity (age ≥ 10).
//   * H = F13 re-spends the SAME key images (deterministic in the attacker
//     keys) → a double-spend that is valid standalone (against the main UTXO,
//     where K1,K2 are unspent) but INVALID in the reorg loop (G already marked
//     them spent). H is the block that fails the reorg → path A.
//   * T is the first floor filler that finally out-works the heavy main chain;
//     adding it triggers the reorg, whose loop connects F3..G, then rejects H,
//     then rolls back (path A). `add_block(T)` returns `Invalid(_)`.
//
// ## Proven property (H3)
//
// After the failed reorg: the tip is restored to main M@N, and there is NO
// stale `height_to_hash` mapping for any height above N — in particular
// `get_block_by_height(N+1)` (G's height) is `None`. Under the bug it would
// still resolve to the disconnected, never-applied fork block G.
//
// Run (real PoW, slow):
//   cargo test --features testnet --test chain_statemachine \
//     failed_reorg_rollback_leaves_no_stale_height_mapping_above_old_tip_h3 \
//     -- --ignored --nocapture
#[test]
#[ignore = "real-PoW mining, slow; run with --features testnet -- --ignored"]
fn failed_reorg_rollback_leaves_no_stale_height_mapping_above_old_tip_h3() {
    std::env::set_var("COINCYNC_RANDOMX_LIGHT_MODE", "1");
    coincync::consensus::bind_randomx_genesis_for_network(NetworkType::Testnet);

    let magic = NetworkType::Testnet.magic_bytes();

    // Attacker keys control K1,K2 and BOTH fork spends (G and H), so G and H
    // carry the SAME key images → H double-spends what G already consumed.
    let (spend_secret, spend_public) = generate_keypair();
    let (view_secret, view_public) = generate_keypair();
    let (_filler_spend_sk, filler_spend_pk) = generate_keypair();
    let (_filler_view_sk, filler_view_pk) = generate_keypair();
    let (_r_spend_sk, r_spend_pk) = generate_keypair();
    let (_r_view_sk, r_view_pk) = generate_keypair();

    let fee = 50_000_000u64;

    let chain = Blockchain::new();
    chain.init_genesis().expect("genesis init");
    let genesis = chain.get_block_by_height(0).expect("genesis block");
    chain
        .restore_state(0, genesis.hash(), 1)
        .expect("seed cumulative-work genesis base = 1");
    let base_ts = genesis.header.timestamp;

    // ── Heavy main chain: genesis + B1..B11, TIGHT spacing so ASERT ramps the
    //    per-block difficulty above the MIN_DIFFICULTY floor. This is what lets
    //    the floor-difficulty fork below sit TALLER-but-LIGHTER, so its
    //    above-old-tip blocks rest as side branches instead of reorging on
    //    arrival. B1/B2 are attacker-controlled coinbases K1/K2.
    //
    //    N is pinned at 11 by TWO opposing forces, and 11 is the unique feasible
    //    value (verified by an offline ASERT/work simulation):
    //      • coinbase maturity — G (height N+1) spends K1@1 and K2@2, so it needs
    //        N+1 - 2 ≥ MIN_OUTPUT_AGE (=10) ⇒ N ≥ 11, else G is consensus-rejected
    //        instead of resting as the above-tip side branch the bug needs; and
    //      • filler budget — the fork must out-work heavy main using floor-weight
    //        fillers, which costs ≈ main_work ≈ N·(genesis difficulty). N > 11
    //        pushes the fillers-to-trigger past a practical budget (and runtime).
    //    At N=11 the fork crosses main after ~1151 fillers (trigger T @ ~1164).
    const N: u64 = 11; // old main tip height (see the two-force pin above)
    let main_spacing = 8u64; // tight → difficulty ramps above the floor
    let mut main_blocks: Vec<Block> = vec![genesis.clone()];
    let mut k1_stealth: Option<StealthAddress> = None;
    let mut k2_stealth: Option<StealthAddress> = None;
    let mut parent = genesis.clone();
    for h in 1..=N {
        let ts = base_ts + h * main_spacing;
        // Let the chain supply the target: at h==1 next_target() maintains the
        // (easy) genesis difficulty — within the ±32x sanity clamp — then ASERT
        // ramps it up from the tight `main_spacing`. Hardcoding from_difficulty(500)
        // here is a 128x jump off the ~4-difficulty genesis and is rejected.
        let target = chain.next_target();
        let (coinbase, stealth) = if h == 1 || h == 2 {
            build_coinbase(h, &spend_public, &view_public, 0) // attacker-controlled K1,K2
        } else {
            build_coinbase(h, &filler_spend_pk, &filler_view_pk, 0)
        };
        match h {
            1 => k1_stealth = Some(stealth),
            2 => k2_stealth = Some(stealth),
            _ => {}
        }
        let block = mine_block(&parent, h, ts, target, vec![coinbase], spend_public, magic);
        let b_status = chain.add_block(block.clone()).expect("add main B*");
        assert!(
            matches!(b_status, BlockStatus::Accepted),
            "B{h} must extend the heavy main chain, got {b_status:?}"
        );
        parent = block.clone();
        main_blocks.push(block);
    }
    assert_eq!(chain.height(), N, "main tip must be at height N");
    let main_tip_hash = chain.tip_hash();

    // Matured attacker coinbases (heights 1,2), BELOW the fork point → present
    // and unspent in the reorged UTXO (every main block is coinbase-only, so
    // K1,K2 are never spent on the main chain).
    let targets = [
        SpendTarget {
            stealth: k1_stealth.expect("K1 stealth"),
            amount: calculate_block_reward(1).as_atomic(),
            height: 1,
        },
        SpendTarget {
            stealth: k2_stealth.expect("K2 stealth"),
            amount: calculate_block_reward(2).as_atomic(),
            height: 2,
        },
    ];

    // ── Fork off B2 (fork point 2), LOOSE spacing → floor difficulty. The
    //    ASERT window along the fork chain is the shared main B0,B1,B2 then the
    //    fork blocks; we recompute each fork block's exact enforced target with
    //    `expected_next_target` over that window (matches the validator's
    //    fork-aware difficulty check on add AND inside the reorg loop).
    let fork_point = 2u64;
    let fork_spacing = 3600u64; // loose → ASERT eases to the MIN_DIFFICULTY floor
    let fork_base_ts = main_blocks[fork_point as usize].header.timestamp;
    let mut fork_diff: Vec<DifficultyBlock> = vec![
        diff_block(&main_blocks[0]),
        diff_block(&main_blocks[1]),
        diff_block(&main_blocks[2]),
    ];
    let mut fork_parent = main_blocks[fork_point as usize].clone();
    let mut fork_step = 1u64; // timestamp multiplier for loose spacing

    // Fork fillers F3..F_N (heights 3..=N, at/below the old tip): coinbase-only,
    // each strictly lighter than main → stored side branches.
    for h in (fork_point + 1)..=N {
        let ts = fork_base_ts + fork_step * fork_spacing;
        fork_step += 1;
        let target = chain.expected_next_target(&fork_diff, h);
        let (cb, _) = build_coinbase(h, &filler_spend_pk, &filler_view_pk, 0);
        let blk = mine_block(&fork_parent, h, ts, target, vec![cb], spend_public, magic);
        let st = chain.add_block(blk.clone()).expect("add fork filler ≤ old tip");
        assert!(
            matches!(st, BlockStatus::AcceptedFork),
            "fork filler F{h} (≤ old tip) must be a stored side branch, got {st:?}"
        );
        fork_diff.push(diff_block(&blk));
        fork_parent = blk;
    }

    // ── G = F_{N+1}: a VALID 2-in/2-out spend of K1,K2, connected ABOVE the old
    //    tip. This is the block whose height→hash mapping the bug leaves stale.
    let g_height = N + 1;
    let g_transfer = build_uniform_transfer(
        &targets, &view_secret, &spend_secret, &r_spend_pk, &r_view_pk, fee, g_height,
    );
    let k1_ki = g_transfer.inputs[0].key_image;
    let k2_ki = g_transfer.inputs[1].key_image;
    let (g_cb, _) = build_coinbase(g_height, &filler_spend_pk, &filler_view_pk, claimable_fees(g_height, fee));
    let g_target = chain.expected_next_target(&fork_diff, g_height);
    let g_ts = fork_base_ts + fork_step * fork_spacing;
    fork_step += 1;
    let g = mine_block(
        &fork_parent, g_height, g_ts, g_target,
        vec![g_cb, g_transfer.clone()], spend_public, magic,
    );
    let g_status = chain.add_block(g.clone()).expect("add G");
    assert!(
        matches!(g_status, BlockStatus::AcceptedFork),
        "G (valid spend at height {g_height}, ABOVE old tip {N}) must rest as a side branch — \
         got {g_status:?}. If AcceptedReorg, the main chain was not heavy enough for the fork to \
         stay lighter here; tighten `main_spacing` or raise N."
    );
    fork_diff.push(diff_block(&g));
    fork_parent = g.clone();

    // ── H = F_{N+2}: re-spends the SAME K1,K2 (identical key images) → a
    //    double-spend. Valid standalone (against the main UTXO where K1,K2 are
    //    unspent), so it is stored as a side branch; INVALID inside the reorg
    //    loop (G marks K1,K2 spent first), which is what fails the reorg.
    let h_height = N + 2;
    let h_transfer = build_uniform_transfer(
        &targets, &view_secret, &spend_secret, &r_spend_pk, &r_view_pk, fee, h_height,
    );
    assert_eq!(
        h_transfer.inputs[0].key_image, k1_ki,
        "H must carry the SAME key image as G for K1 (this is the double-spend that fails the reorg)"
    );
    assert_eq!(h_transfer.inputs[1].key_image, k2_ki, "same for K2");
    let (h_cb, _) = build_coinbase(h_height, &filler_spend_pk, &filler_view_pk, claimable_fees(h_height, fee));
    let h_target = chain.expected_next_target(&fork_diff, h_height);
    let h_ts = fork_base_ts + fork_step * fork_spacing;
    fork_step += 1;
    let hblk = mine_block(
        &fork_parent, h_height, h_ts, h_target,
        vec![h_cb, h_transfer], spend_public, magic,
    );
    let h_status = chain.add_block(hblk.clone()).expect("add H");
    assert!(
        matches!(h_status, BlockStatus::AcceptedFork),
        "H (double-spend at height {h_height}, ABOVE old tip {N}) must rest as a side branch — got {h_status:?}"
    );
    fork_diff.push(diff_block(&hblk));
    fork_parent = hblk.clone();

    // Sanity: the failed reorg has NOT happened yet — tip is still heavy main,
    // and G/H's spends have NOT touched the (main) UTXO.
    assert_eq!(chain.tip_hash(), main_tip_hash, "tip still on heavy main before the reorg");
    assert!(!chain.is_spent(&k1_ki), "K1 unspent on main (G/H are only side branches)");

    // ── Floor fillers above H until the fork finally out-works heavy main. The
    //    first block that tips the balance triggers the reorg; its
    //    collect_fork_chain is [F3 .. G, H, fillers], so the loop connects
    //    F3..G (G above the old tip → mapping inserted), then REJECTS H
    //    (double-spend) → path A rollback. That block ("T") comes back Invalid.
    let mut next_h = h_height + 1;
    let mut t_height = 0u64;
    let mut triggered = None;
    // Budget: at N=11 the offline ASERT/work simulation puts the crossover at
    // ~1151 fillers (trigger T at height ~1164); 1400 leaves margin without
    // masking a genuine "fork never out-worked main" regression.
    for _ in 0..1400 {
        let ts = fork_base_ts + fork_step * fork_spacing;
        fork_step += 1;
        let target = chain.expected_next_target(&fork_diff, next_h);
        let (cb, _) = build_coinbase(next_h, &filler_spend_pk, &filler_view_pk, 0);
        let blk = mine_block(&fork_parent, next_h, ts, target, vec![cb], spend_public, magic);
        let st = chain.add_block(blk.clone()).expect("add fork filler / trigger T");
        match st {
            BlockStatus::AcceptedFork => {
                // Still lighter than heavy main — another stored side branch.
                fork_diff.push(diff_block(&blk));
                fork_parent = blk;
                next_h += 1;
            }
            BlockStatus::Invalid(_) => {
                // T out-worked main and triggered the reorg, which failed at H
                // (double-spend) and rolled back via path A.
                t_height = next_h;
                triggered = Some(st);
                break;
            }
            other => panic!(
                "unexpected status for fork block at height {next_h}: {other:?} \
                 (expected AcceptedFork while lighter, or Invalid when the failed reorg fires). \
                 AcceptedReorg here would mean H was NOT reached/rejected — check the double-spend."
            ),
        }
    }
    let t_status = triggered.expect(
        "fork never out-worked heavy main within the filler budget — main difficulty ramp \
         insufficient; tighten `main_spacing` or raise N",
    );
    assert!(
        matches!(t_status, BlockStatus::Invalid(_)),
        "the triggering block T must report Invalid after the failed path-A reorg, got {t_status:?}"
    );

    // ── Post-rollback assertions ─────────────────────────────────────────────

    // (1) The chain is back on the original heavy main tip M@N.
    assert_eq!(chain.height(), N, "height restored to the old main tip after rollback");
    assert_eq!(chain.tip_hash(), main_tip_hash, "tip restored to the old main tip M@N");

    // (2) H3 PROPERTY: no stale height→hash mapping survives ABOVE the restored
    //     tip. G was connected in the reorg loop at height N+1 (> old tip) and
    //     received a mapping; the buggy rollback (bounded by the OLD tip height)
    //     left it, so `get_block_by_height(N+1)` returned the disconnected,
    //     never-applied fork block G. The fix (bounded by the highest fork
    //     height) clears it. Assert None for every height above the restored
    //     tip up to and including T.
    for h in (N + 1)..=t_height {
        assert!(
            chain.get_block_by_height(h).is_none(),
            "H3 regression: stale height→hash mapping at height {h} after a failed path-A reorg \
             (this height is above the restored tip {N} and must have NO canonical block)"
        );
    }
    // Explicitly pin the exact bug site: G's height.
    assert!(
        chain.get_block_by_height(g_height).is_none(),
        "H3 regression: the never-applied fork block G is still reported canonical at its \
         height {g_height} (stale mapping the failed reorg should have removed)"
    );

    // (3) The original main blocks are all still canonical.
    for h in 0..=N {
        let got = chain
            .get_block_by_height(h)
            .unwrap_or_else(|| panic!("main block at height {h} must be canonical after rollback"));
        assert_eq!(
            got.hash(),
            main_blocks[h as usize].hash(),
            "canonical block at height {h} must be the original main block after rollback"
        );
    }

    // (4) The fork's spends were rolled back: K1,K2 remain unspent (they were
    //     never spent on main; G's in-loop marking was undone by path A).
    assert!(!chain.is_spent(&k1_ki), "K1 unspent after the failed reorg rolled back");
    assert!(!chain.is_spent(&k2_ki), "K2 unspent after the failed reorg rolled back");

    println!(
        "PASS failed_reorg_rollback_leaves_no_stale_height_mapping_above_old_tip_h3 \
         (old tip N={N}, G@{g_height}, H@{h_height}, T@{t_height})"
    );
}
