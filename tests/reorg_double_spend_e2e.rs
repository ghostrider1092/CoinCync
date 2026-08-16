//! # End-to-end regression: reorg-driven double-spend is rejected
//!
//! Reproduces the post-reorg double-spend / inflation bug and proves the
//! `SECURITY (REORG-TIP-VALIDATE)` fix in `src/chain.rs` rejects it.
//!
//! ## The attack
//!
//! An attacker's own matured coinbase output `K` is spent in fork block
//! `F12` AND spent again (same key image) in the fork tip `F13`. The fork
//! (`B11 + F12 + F13`) carries more cumulative work than the honest chain
//! (`B11 + B12`), so adding `F13` triggers a reorg. During the reorg the
//! chain disconnects `B12`, applies `F12` (marking `K`'s key image spent),
//! then applies the triggering tip `F13`.
//!
//! Before the fix, the tip block was applied via `UtxoSet::apply_batch`
//! WITHOUT re-validation against the reorged UTXO. `apply_batch` silently
//! no-ops the already-spent key image (mark returns `false`, not an error)
//! while STILL adding the tip's outputs — minting coins from a single
//! input (chain-wide inflation / double-spend). The fix re-validates the
//! tip against the reorged UTXO and, on failure, routes through the
//! unconditional rollback so the honest chain is restored.
//!
//! ## Topology (all below STRICT_RING_MEMBER_HEIGHT = 100)
//!
//! ```text
//!   genesis - B1(K) - B2 .. B11 - B12          (honest tip, coinbase-only)
//!                             \
//!                              F12(spend K) - F13(spend K again)   (fork)
//! ```
//!
//! `K` is `B1`'s coinbase, matured by height 11 (MIN_OUTPUT_AGE = 10). The
//! spends are REAL CLSAG signatures produced by `TransactionBuilder`; the
//! single real ring member is the on-chain coinbase `K`, the rest are
//! synthetic decoys (permitted below `STRICT_RING_MEMBER_HEIGHT`). PoW is
//! real RandomX on every block (the reorg path passes `checkpoint_height =
//! None`, so there is no PoW bypass).
//!
//! ## Proven against the bug
//!
//! This test was confirmed to FAIL when the REORG-TIP-VALIDATE block in
//! `src/chain.rs` is commented out (the reorg is wrongly accepted, tip
//! advances to `F13` at height 13 with inflated supply), and to PASS with
//! the fix in place.

use coincync::chain::{BlockStatus, Blockchain};
use coincync::config::NetworkType;
use coincync::consensus::{
    calculate_difficulty, compute_full_anchor, compute_pow_hash, BlockHeader, DifficultyBlock,
    PowAlgorithm,
};
use coincync::consensus::block::Block;
use coincync::consensus::fork_signal::{encode_coinbase_extra, SignalBits};
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
// Key material
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
// Coinbase — mirrors crates/coincync-rig/src/orchestrator.rs
// `create_mining_coinbase_with_fees`.
// =============================================================================

/// Build a coinbase paying `reward(height) + total_fees` to a stealth
/// address derived from (spend_pub, view_pub, height, output_index = 0).
/// Returns the tx and the `StealthAddress` so the caller can later spend it.
fn build_coinbase(
    height: u64,
    spend_pub: &PublicKey,
    view_pub: &PublicKey,
    total_fees: u64,
) -> (Transaction, StealthAddress) {
    let reward = calculate_block_reward(height);
    let total_amount = reward.as_atomic().saturating_add(total_fees);

    // Coinbase commitment uses a zero blinding factor: the reward is public.
    let commitment = PedersenCommitment::commit(total_amount, &BlindingFactor::zero());

    // miner_secret only feeds coinbase_stealth_address (sender side); the
    // spender recovers the one-time secret from the view key + tx_public_key,
    // so any deterministic value works as long as we reuse the returned
    // StealthAddress. Mirror the orchestrator's blake3(view_pub) recipe.
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

/// The fee amount a coinbase may claim, mirroring the validator's
/// `max_coinbase` rule (and the miner's `calculate_claimable_fees`). Below
/// `FEE_DISTRIBUTION_HEIGHT` the miner claims all fees; at/after it, only the
/// un-burned miner share. Our blocks are tiny, so congested = false.
///
/// `FEE_DISTRIBUTION_HEIGHT` is 0 in the default (non-`testnet`-feature)
/// build, so distribution is active from genesis; keying off the constant
/// keeps this correct under either feature set.
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
// Real CLSAG spend of the coinbase K
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

/// One matured coinbase the attacker controls and will spend.
struct SpendTarget {
    stealth: StealthAddress,
    amount: u64,
    height: u64,
}

/// Build a REAL, uniform-shape (2-in / 2-out) CLSAG transaction spending two
/// on-chain coinbase outputs the attacker controls.
///
/// Consensus requires exactly `STANDARD_INPUT_COUNT` (2) inputs and
/// `STANDARD_OUTPUT_COUNT` (2) outputs from `UNIFORM_TX_SHAPE_HEIGHT` (= 0).
///
/// For each input the single real ring member is the on-chain coinbase (its
/// commitment must equal `commit(reward, zero)`); the rest are synthetic
/// decoys (permitted below STRICT_RING_MEMBER_HEIGHT). The one-time secret —
/// and therefore each KEY IMAGE — is deterministic in (output, view_secret,
/// spend_secret), so two independent calls over the SAME targets produce the
/// SAME key images: that is the double-spend.
#[allow(clippy::too_many_arguments)]
fn build_double_spend(
    targets: &[SpendTarget; 2],
    view_secret: &SecretKey,
    spend_secret: &SecretKey,
    recipient_spend: &PublicKey,
    recipient_view: &PublicKey,
    fee: u64,
    target_height: u64,
) -> Transaction {
    let mut rng = OsRng;
    let ring_size = BOOTSTRAP_MIN_RING_SIZE; // 11 during bootstrap

    let mut builder = TransactionBuilder::transfer().with_target_height(target_height);

    let mut input_sum: u64 = 0;
    for t in targets {
        // Recover the one-time secret: one_time_secret.public_key() == stealth.public_key.
        let one_time_secret = compute_one_time_secret(&t.stealth, view_secret, spend_secret, 0)
            .expect("one-time secret recovery must succeed");
        let input = SpendableInput {
            tx_hash: Hash::zero(), // unused by the builder's ring construction
            output_index: 0,
            amount: coincync::primitives::Amount::from_atomic(t.amount),
            one_time_secret,
            blinding: BlindingFactor::zero(), // coinbase uses zero blinding
            height: t.height,
        };
        let decoys = create_real_decoys(ring_size - 1);
        builder
            .add_input(input, decoys, 0)
            .expect("add_input must succeed for a real coinbase output");
        input_sum += t.amount;
    }

    // Uniform 2 outputs: a recipient output plus a change output. The exact
    // split is irrelevant to the attack; both must be >= MIN_OUTPUT_AMOUNT and
    // sum with the fee to the input total.
    let change = 1_000_000_000u64; // 0.001 CYNC
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
// Real RandomX mining
// =============================================================================

/// Find a nonce whose RandomX PoW hash meets `target`, and assemble the block.
/// `prev` is the parent block; `anchor` is bound to `prev.hash()` exactly as
/// the validator recomputes it in `verify_pow`.
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
    let anchor = compute_full_anchor(&prev_hash, height, timestamp)
        .expect("anchor computation must succeed")
        .mixed_hash;

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

    let header = BlockHeader {
        network_magic: magic,
        version: block_version_at_height(height),
        height,
        timestamp,
        prev_hash,
        tx_root,
        anchor,
        algorithm: PowAlgorithm::RandomX as u8,
        nonce,
        target,
        miner_pubkey,
        supply_commitment: [0u8; 32],
        checkpoint_vote: None,
        spark_set_root: [0u8; 32],
        mw_kernel_root: [0u8; 32],
    };

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
// The regression test
// =============================================================================

// Requires the `testnet` feature (which also enables `randomx`): coinbase
// maturity (10 vs 100), the fee-burn activation height, and the
// MIN_OUTPUT_AGE hard-fork height are all cfg-gated to testnet values, and
// this sub-height-20 scenario with synthetic decoys depends on them. Run:
//   cargo test --features testnet --test reorg_double_spend_e2e -- --ignored
#[test]
#[ignore = "real-PoW mining, slow; run with --features testnet -- --ignored"]
fn reorg_tip_double_spend_is_rejected() {
    // Light mode keeps RandomX to ~256 MB (no 2 GB dataset build); the VM
    // key is epoch 0 for every height here, so exactly one cache is built.
    std::env::set_var("COINCYNC_RANDOMX_LIGHT_MODE", "1");
    coincync::consensus::bind_randomx_genesis_for_network(NetworkType::Testnet);

    let chain = Blockchain::new(); // in-memory, Testnet
    chain.init_genesis().expect("genesis init");
    let genesis = chain.get_block_by_height(0).expect("genesis block");
    let magic = NetworkType::Testnet.magic_bytes();

    // Seed the in-memory cumulative-work base to 1. `init_genesis` writes
    // `total_difficulty = 1` only to the (absent) DB state; the in-memory
    // `stats.total_difficulty` is left at 0. The reorg fork-work walk
    // (`calculate_fork_cumulative_work`) adds 1 for genesis, so without this
    // an equal-length fork would appear 1 unit heavier and reorg spuriously.
    // A DB-backed node self-heals this on load; here we set it explicitly so
    // an equal-work fork is a true tie (broken by the hash rule), exactly as
    // the topology below assumes. `restore_state` with `db=None` is a plain
    // stats write (its `load_from_database` returns Fresh, a no-op).
    chain
        .restore_state(0, genesis.hash(), 1)
        .expect("seed cumulative-work genesis base = 1");

    // Attacker keys — control coinbase K and both spends.
    let (spend_secret, spend_public) = generate_keypair();
    let (view_secret, view_public) = generate_keypair();
    // Filler-block coinbase recipient ("anyone") and spend recipient.
    let (_filler_spend_sk, filler_spend_pk) = generate_keypair();
    let (_filler_view_sk, filler_view_pk) = generate_keypair();
    let (_r_spend_sk, r_spend_pk) = generate_keypair();
    let (_r_view_sk, r_view_pk) = generate_keypair();

    let base_ts = genesis.header.timestamp;
    // Space blocks well beyond TARGET_BLOCK_TIME so ASERT eases difficulty
    // toward the MIN_DIFFICULTY floor within a few blocks (cheaper PoW).
    // Genesis is April 2026, so base_ts + 13h is still comfortably in the
    // past → the future-timestamp bound (now + 600s) is never approached.
    let spacing = 3600u64;

    // ── Main chain: B1 (coinbase K), B2 (coinbase K2), B3..B11 fillers ───
    // Consensus requires uniform 2-in/2-out Transfers (UNIFORM_TX_SHAPE_HEIGHT
    // = 0), so the attacker needs TWO matured coinbases to spend. K (h1) and
    // K2 (h2) both mature by height 12 (MIN_OUTPUT_AGE = 10).
    let mut chain_blocks: Vec<Block> = vec![genesis.clone()];
    let mut k_stealth: Option<StealthAddress> = None;
    let mut k2_stealth: Option<StealthAddress> = None;
    let mut parent = genesis.clone();

    for h in 1..=11u64 {
        let ts = base_ts + h * spacing;
        // B1 has no exact difficulty enforcement (its window is genesis-only,
        // < 2 blocks), only the loose sanity ratio check. Start it well below
        // genesis difficulty (within the allowed easing ratio) so ASERT then
        // clamps B2..B11 down to the MIN_DIFFICULTY floor, keeping real-PoW
        // mining cheap. From B2 on we use the exact ASERT target.
        let target = if h == 1 {
            Hash::from_difficulty(500)
        } else {
            chain.next_target() // tip == parent (height h-1)
        };
        let (coinbase, stealth) = if h == 1 || h == 2 {
            build_coinbase(h, &spend_public, &view_public, 0) // attacker-controlled
        } else {
            build_coinbase(h, &filler_spend_pk, &filler_view_pk, 0)
        };
        match h {
            1 => k_stealth = Some(stealth),
            2 => k2_stealth = Some(stealth),
            _ => {}
        }
        let block = mine_block(&parent, h, ts, target, vec![coinbase], spend_public, magic);
        let status = chain.add_block(block.clone()).expect("add_block B*");
        assert!(
            matches!(status, BlockStatus::Accepted),
            "B{h} must extend the main chain (got {status:?})"
        );
        parent = block.clone();
        chain_blocks.push(block);
    }
    let b11 = parent.clone();
    assert_eq!(chain.height(), 11, "tip must be B11");

    let targets = [
        SpendTarget {
            stealth: k_stealth.expect("K stealth captured"),
            amount: calculate_block_reward(1).as_atomic(),
            height: 1,
        },
        SpendTarget {
            stealth: k2_stealth.expect("K2 stealth captured"),
            amount: calculate_block_reward(2).as_atomic(),
            height: 2,
        },
    ];
    let fee = 50_000_000u64; // 0.05 CYNC — well above the dynamic minimum

    // Target for height 12 off B11 — identical for the honest B12 and the
    // fork F12 (both share the same difficulty window B1..B11).
    let t12 = chain.next_target();

    // ── Honest tip B12 (coinbase-only) off B11 ───────────────────────────
    let (b12_coinbase, _) = build_coinbase(12, &filler_spend_pk, &filler_view_pk, 0);
    let b12 = mine_block(
        &b11,
        12,
        base_ts + 12 * spacing,
        t12,
        vec![b12_coinbase],
        spend_public,
        magic,
    );

    // ── Fork F12 off B11: coinbase(reward+fee) + REAL 2-in/2-out spend ───
    let spend_f12 = build_double_spend(
        &targets,
        &view_secret,
        &spend_secret,
        &r_spend_pk,
        &r_view_pk,
        fee,
        12,
    );
    let k_key_image = spend_f12.inputs[0].key_image;
    let (f12_coinbase, _) =
        build_coinbase(12, &filler_spend_pk, &filler_view_pk, claimable_fees(12, fee));

    // F12 and B12 have equal cumulative work; the fork-choice tiebreak picks
    // the lexicographically-SMALLER tip hash. To keep the honest B12 as tip
    // when F12 is added (so the reorg is driven by F13, not F12), re-mine
    // F12 with bumped timestamps until F12.hash > B12.hash. Varying F12's
    // timestamp does NOT change F12's target (its difficulty window excludes
    // itself), so this is free of consensus side effects.
    let mut f12_ts = base_ts + 12 * spacing + 1;
    let f12 = loop {
        let candidate = mine_block(
            &b11,
            12,
            f12_ts,
            t12,
            vec![f12_coinbase.clone(), spend_f12.clone()],
            spend_public,
            magic,
        );
        if candidate.hash().as_bytes() > b12.hash().as_bytes() {
            break candidate;
        }
        f12_ts += 1;
    };

    // Add B12 first so it is the tip; THEN add F12 as a competing fork.
    let status_b12 = chain.add_block(b12.clone()).expect("add_block B12");
    assert!(
        matches!(status_b12, BlockStatus::Accepted),
        "B12 must be accepted as the honest tip (got {status_b12:?})"
    );
    assert_eq!(chain.tip_hash(), b12.hash(), "tip must be B12");

    let stats_before = chain.stats();

    let status_f12 = chain.add_block(f12.clone()).expect("add_block F12");
    assert!(
        matches!(status_f12, BlockStatus::AcceptedFork),
        "F12 must be stored as a non-winning side branch (got {status_f12:?})"
    );
    assert_eq!(
        chain.tip_hash(),
        b12.hash(),
        "tip must still be B12 after F12 (F12 lost the equal-work tiebreak)"
    );
    assert_eq!(chain.height(), 12, "height must still be 12 after F12");

    // ── Fork tip F13 off F12: coinbase + spend of the SAME K and K2 ──────
    // F13's difficulty window is main B1..B11 plus the fork block F12.
    let mut dblocks: Vec<DifficultyBlock> = (0..=11u64)
        .map(|h| diff_block(&chain_blocks[h as usize]))
        .collect();
    dblocks.push(diff_block(&f12));
    let t13 = calculate_difficulty(&dblocks, 13);

    let spend_f13 = build_double_spend(
        &targets,
        &view_secret,
        &spend_secret,
        &r_spend_pk,
        &r_view_pk,
        fee,
        13,
    );
    assert_eq!(
        spend_f13.inputs[0].key_image, k_key_image,
        "both spends of K MUST carry the same key image (this is the double-spend)"
    );
    let (f13_coinbase, _) =
        build_coinbase(13, &filler_spend_pk, &filler_view_pk, claimable_fees(13, fee));
    let f13 = mine_block(
        &f12,
        13,
        f12_ts + spacing,
        t13,
        vec![f13_coinbase, spend_f13],
        spend_public,
        magic,
    );

    // ── Adding F13 triggers a reorg attempt; the fix must reject it ──────
    let status_f13 = chain.add_block(f13.clone()).expect("add_block F13");

    // PRIMARY assertion — this is what fails without the fix (the reorg is
    // wrongly accepted and the tip advances to F13 at height 13).
    assert_eq!(
        chain.tip_hash(),
        b12.hash(),
        "REORG-TIP-VALIDATE fix failed: the reorg tip F13 re-spends K's key \
         image that F12 already consumed, so the reorg MUST be rejected and \
         the honest chain (tip B12) restored. Instead tip is now {} at height \
         {}. add_block returned {:?}.",
        chain.tip_hash().to_hex(),
        chain.height(),
        status_f13,
    );
    assert_eq!(
        chain.height(),
        12,
        "height must remain 12 (honest chain) after the rejected reorg"
    );
    assert!(
        matches!(status_f13, BlockStatus::Invalid(_)),
        "F13 must be reported Invalid (the double-spending reorg tip), got {status_f13:?}"
    );

    // K was NEVER spent on the honest chain — its key image must be unspent.
    assert!(
        !chain.is_spent(&k_key_image),
        "K's key image must be UNSPENT after the reorg rollback (the fork's \
         spends were discarded)"
    );

    // No phantom coins: supply/blocks are exactly the honest-chain values.
    let stats_after = chain.stats();
    assert_eq!(
        stats_after.total_supply, stats_before.total_supply,
        "total_supply must be unchanged — a rejected reorg tip must not mint \
         coins (before={}, after={})",
        stats_before.total_supply, stats_after.total_supply
    );
    assert_eq!(
        stats_after.height, 12,
        "stats height must remain at the honest tip"
    );
    assert_eq!(
        stats_after.tip_hash,
        b12.hash(),
        "stats tip_hash must remain B12"
    );
}
