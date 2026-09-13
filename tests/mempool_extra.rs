//! # Mempool — extra behavioral coverage (audit test-plan gap fill)
//!
//! Fills the MISSING `[ ]` items in the `src/mempool.rs` section of
//! `docs/audit/test-plan/mempool.md` that are reachable from the
//! integration surface. Uses the same `add_skip_crypto` escape-hatch
//! harness as `tests/mempool_ordering.rs`, `tests/adversarial.rs`,
//! `tests/tier6_dos_resource.rs`, and `tests/transaction_lifecycle.rs`,
//! and — for the persistence round-trip, which re-admits through the
//! full `add()` crypto path inside `load_from_disk` — the REAL crypto
//! builder pattern from `tests/full_pipeline_real_crypto.rs`.
//!
//! Named high-value gaps covered here:
//!   * ATOMICITY (2026-08-18): a REJECTED tx evicts ZERO residents.
//!   * RBF boundary math: exact 125% accepted, 124% rejected, equal-rate
//!     rejected, absolute-fee-vs-fee-rate semantics, multi-key-image
//!     conflict collects & replaces all.
//!   * `get_block_transactions` size bound + a size-skipped tx not
//!     blocking a later smaller tx.
//!   * `save_to_disk` -> `load_from_disk` round-trip that actually
//!     restores (with real crypto so re-admission succeeds).
//!   * `remove_confirmed` pass-2 shadow-conflict eviction + `EvictReason`
//!     audit, `shadow_evict_invalid` driven by a fake `ShadowEvictChain`.
//!
//! NOTE: the real `add()` crypto-rejection branches (range proof /
//! balance / ring sig) are already exercised at the mempool layer by
//! `tests/full_pipeline_real_crypto.rs` (TEST 2/3/4/5/6/7); they are not
//! duplicated here.

use coincync::constants::{BOOTSTRAP_MIN_RING_SIZE, MAX_TX_SIZE, MIN_FEE_PER_BYTE, TX_EXPIRY_BLOCKS};
use coincync::crypto::{
    BlindingFactor, ClsagSignature, KeyImage as CryptoKeyImage, PedersenCommitment, SecretScalar,
};
use coincync::error::{Error, Result};
use coincync::mempool::{AuditEvent, EvictReason, Mempool, ShadowEvictChain, SharedMempool};
use coincync::primitives::{Amount, Hash, KeyImage, PublicKey, SecretKey};
use coincync::transaction::{
    DecoyOutput, Recipient, RingMemberRef, SpendableInput, Transaction, TransactionBuilder,
    TxInput, TxOutput, TxType,
};
use rand::rngs::OsRng;
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Skip-crypto tx builders (mirrors the existing harness style)
// ---------------------------------------------------------------------------

/// Build a structurally-valid single-input Transfer tx with a fresh random
/// key image, `BOOTSTRAP_MIN_RING_SIZE` ring members, one output, and an
/// `extra` blob of `extra_len` bytes (used to control the tx byte size).
/// The fee is taken verbatim — callers pass a fee that clears whatever
/// policy floor the test needs (no auto-bump, so fee/size are exact).
fn tx(fee_atomic: u64, extra_len: usize) -> Transaction {
    let secret = SecretScalar::random(&mut OsRng);
    let pub_point = secret.to_public();
    let crypto_ki = CryptoKeyImage::from_secret(&secret);
    let key_image = KeyImage::from_bytes(crypto_ki.to_bytes());

    let mut ring_members = Vec::with_capacity(BOOTSTRAP_MIN_RING_SIZE);
    for _ in 0..BOOTSTRAP_MIN_RING_SIZE {
        let p = SecretScalar::random(&mut OsRng).to_public();
        ring_members.push(RingMemberRef {
            public_key: PublicKey::from_bytes(p.to_bytes()),
            commitment: p.to_bytes(),
        });
    }

    let signature = ClsagSignature {
        key_image: crypto_ki,
        commitment_image: pub_point,
        c1: [0u8; 32],
        responses: vec![[0u8; 32]; BOOTSTRAP_MIN_RING_SIZE],
    };

    let out_p = SecretScalar::random(&mut OsRng).to_public();
    let output = TxOutput {
        stealth_address: PublicKey::from_bytes(out_p.to_bytes()),
        tx_public_key: PublicKey::from_bytes(out_p.to_bytes()),
        commitment: out_p.to_bytes(),
        encrypted_amount: vec![0u8; 8],
        view_tag: 0,
        lock_height: None,
        encrypted_memo: Vec::new(),
    };

    Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            key_image,
            ring_members,
            signature,
            pseudo_output_commitment: pub_point.to_bytes(),
        }],
        outputs: vec![output],
        fee: Amount::from_atomic(fee_atomic),
        range_proof: vec![0u8; 64],
        extra: vec![0xAB; extra_len],
    }
}

/// Build a two-input Transfer whose input key images are forced to
/// `ki_a` and `ki_b` (for multi-conflict RBF). The CLSAG data is garbage
/// (skip-crypto path), but structural rules still apply.
fn two_input_tx(fee_atomic: u64, ki_a: KeyImage, ki_b: KeyImage) -> Transaction {
    let mk_input = |ki: KeyImage| {
        let secret = SecretScalar::random(&mut OsRng);
        let pub_point = secret.to_public();
        let crypto_ki = CryptoKeyImage::from_secret(&secret);
        let ring_members = (0..BOOTSTRAP_MIN_RING_SIZE)
            .map(|_| {
                let p = SecretScalar::random(&mut OsRng).to_public();
                RingMemberRef {
                    public_key: PublicKey::from_bytes(p.to_bytes()),
                    commitment: p.to_bytes(),
                }
            })
            .collect();
        TxInput {
            key_image: ki,
            ring_members,
            signature: ClsagSignature {
                key_image: crypto_ki,
                commitment_image: pub_point,
                c1: [0u8; 32],
                responses: vec![[0u8; 32]; BOOTSTRAP_MIN_RING_SIZE],
            },
            pseudo_output_commitment: pub_point.to_bytes(),
        }
    };

    let out_p = SecretScalar::random(&mut OsRng).to_public();
    Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        inputs: vec![mk_input(ki_a), mk_input(ki_b)],
        outputs: vec![TxOutput {
            stealth_address: PublicKey::from_bytes(out_p.to_bytes()),
            tx_public_key: PublicKey::from_bytes(out_p.to_bytes()),
            commitment: out_p.to_bytes(),
            encrypted_amount: vec![0u8; 8],
            view_tag: 0,
            lock_height: None,
            encrypted_memo: Vec::new(),
        }],
        fee: Amount::from_atomic(fee_atomic),
        range_proof: vec![0u8; 64],
        extra: Vec::new(),
    }
}

/// Byte size of the standard single-input tx (extra_len 0). Deterministic
/// because borsh sizes depend only on field lengths, not values.
fn base_size() -> usize {
    tx(1_000_000_000, 0).size()
}

// ---------------------------------------------------------------------------
// Real-crypto builders (copied from tests/full_pipeline_real_crypto.rs) —
// needed only for the persistence round-trip, because load_from_disk
// re-admits via the full add() crypto path.
// ---------------------------------------------------------------------------

fn generate_keypair() -> (SecretKey, PublicKey) {
    let secret = SecretScalar::random(&mut OsRng);
    let public = secret.to_public();
    (
        SecretKey::from_bytes(secret.to_bytes()),
        PublicKey::from_bytes(public.to_bytes()),
    )
}

fn create_real_input(amount: u64, seed: u8) -> SpendableInput {
    let secret = SecretScalar::random(&mut OsRng);
    let mut tx_hash_bytes = [0u8; 32];
    tx_hash_bytes[0] = seed;
    tx_hash_bytes[1] = seed.wrapping_mul(13);
    tx_hash_bytes[2] = seed.wrapping_mul(7);
    SpendableInput {
        tx_hash: Hash::from_bytes(tx_hash_bytes),
        output_index: 0,
        amount: Amount::from_atomic(amount),
        one_time_secret: SecretKey::from_bytes(secret.to_bytes()),
        blinding: BlindingFactor::random(&mut OsRng),
        height: 1000,
    }
}

fn create_real_decoys(count: usize) -> Vec<DecoyOutput> {
    (0..count)
        .map(|i| {
            let p = SecretScalar::random(&mut OsRng).to_public();
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

/// A fully valid transaction (real CLSAG + BP+ + balance), fee high enough
/// for mempool admission — what a wallet produces.
fn build_valid_tx_for_mempool() -> Transaction {
    let fee = 50_000_000u64;
    let output = 1_950_000_000u64;
    let input_amount = output + fee;

    let (_, recipient_spend) = generate_keypair();
    let (_, recipient_view) = generate_keypair();
    let mut rng = OsRng;

    let input = create_real_input(input_amount, rand::random::<u8>());
    let ring_size = BOOTSTRAP_MIN_RING_SIZE;
    let decoys = create_real_decoys(ring_size - 1);
    let real_index = rand::random::<usize>() % ring_size;

    let mut builder = TransactionBuilder::transfer().with_target_height(0);
    builder
        .add_input(input, decoys, real_index)
        .expect("add_input");
    builder
        .add_output(
            &Recipient {
                spend_public: recipient_spend,
                view_public: recipient_view,
                amount: Amount::from_atomic(output),
                lock_height: None,
            },
            0,
            &mut rng,
        )
        .expect("add_output");
    builder.set_fee(Amount::from_atomic(fee));
    builder.build(&mut rng).expect("build valid tx")
}

// A fake chain for shadow_evict_invalid: any tx whose hash is in `invalid`
// fails validation.
struct FakeShadowChain {
    invalid: HashSet<Hash>,
}
impl ShadowEvictChain for FakeShadowChain {
    fn validate_transaction(&self, tx: &Transaction) -> Result<()> {
        if self.invalid.contains(&tx.hash()) {
            Err(Error::InvalidTransaction("shadow-evict: no longer valid".into()))
        } else {
            Ok(())
        }
    }
}

// ===========================================================================
// ATOMICITY: a rejected admission evicts ZERO residents
// ===========================================================================

#[test]
fn rejected_admission_evicts_zero_residents_and_leaves_state_untouched() {
    let s = base_size();
    // Pool holds exactly 3 residents; fill it completely with HIGH fee-rate
    // txs (50x floor). Their fee-rate is far above any low-rate intruder.
    let mut pool = Mempool::with_max_size(3 * s);
    let hi_fee = 50 * (s as u64) * MIN_FEE_PER_BYTE;
    let mut resident_kis = Vec::new();
    for _ in 0..3 {
        let t = tx(hi_fee, 0);
        resident_kis.push(t.inputs[0].key_image);
        pool.add_skip_crypto(t).expect("resident admitted");
    }
    assert_eq!(pool.len(), 3);
    let size_before = pool.size();

    // Intruder clears the 8x dynamic-fee floor (pool is 100% full) but has a
    // strictly lower fee-rate than every resident, so it cannot evict any of
    // them. It must be rejected up-front, touching nothing.
    let intruder = tx(8 * (s as u64) * MIN_FEE_PER_BYTE, 0);
    let intruder_ki = intruder.inputs[0].key_image;
    let result = pool.add_skip_crypto(intruder);

    assert!(matches!(result, Err(Error::MempoolFull)), "got {:?}", result);
    assert_eq!(pool.len(), 3, "no resident may be evicted by a rejected tx");
    assert_eq!(pool.size(), size_before, "current_size must be unchanged");
    for ki in &resident_kis {
        assert!(pool.contains_key_image(ki), "resident key image must survive");
    }
    assert!(
        !pool.contains_key_image(&intruder_ki),
        "rejected tx must not have inserted its key image"
    );
    assert!(pool.verify_size_invariant());
}

#[test]
fn failed_add_preserves_size_invariant_and_key_image_set() {
    let s = base_size();
    let mut pool = Mempool::new();
    let resident = tx((s as u64) * MIN_FEE_PER_BYTE * 4, 0);
    let resident_ki = resident.inputs[0].key_image;
    pool.add_skip_crypto(resident).unwrap();

    // A zero-fee tx is rejected (FeeTooLow) — assert invariants unaffected.
    let bad = tx(0, 0);
    let bad_ki = bad.inputs[0].key_image;
    assert!(pool.add_skip_crypto(bad).is_err());

    assert!(pool.verify_size_invariant());
    assert_eq!(pool.len(), 1);
    assert!(pool.contains_key_image(&resident_ki));
    assert!(!pool.contains_key_image(&bad_ki));
}

#[test]
fn eviction_budget_cannot_be_exceeded_pool_left_untouched() {
    // Attacker cannot evict >100 residents with a single oversized send.
    // Fill a pool with 130 residents (all high fee so they clear the rising
    // dynamic floor), then submit a higher-rate tx so large that fitting it
    // would require evicting >100 residents. The 100-attempt budget stops
    // short, and the admission is rejected leaving the pool untouched.
    let s = base_size();
    let hi_fee = 8 * (s as u64) * MIN_FEE_PER_BYTE; // 8x floor: admits at any fullness
    let mut pool = Mempool::with_max_size(130 * s);
    for _ in 0..130 {
        pool.add_skip_crypto(tx(hi_fee, 0)).expect("resident admitted");
    }
    assert_eq!(pool.len(), 130);
    let size_before = pool.size();

    // Big tx of ~105*s bytes: freeing 100 residents (100*s) still cannot make
    // room. Fee/rate set well above residents so the eviction loop actually
    // tries (does not break on a higher-rate candidate).
    let big_extra = 105 * s;
    let big = tx(u64::MAX / 2, big_extra); // enormous fee -> highest rate, clears floor
    let result = pool.add_skip_crypto(big);

    assert!(result.is_err(), "oversized send must be rejected");
    assert_eq!(pool.len(), 130, "no more than the budget may be evicted -> none on reject");
    assert_eq!(pool.size(), size_before);
    assert!(pool.verify_size_invariant());
}

/// H8 (eviction off-by-one griefing fix): a valid tx that fits EXACTLY after the
/// 100th eviction must be ADMITTED, not rejected. Pre-fix the real eviction loop
/// rejected on the 100th attempt even though the tx then fit — having already
/// dropped 100 honest resident txs for free. An attacker could tune a valid tx
/// to need exactly 100 evictions, drop 100 honest txs, be rejected (never mined,
/// zero cost), and repeat forever. The admission simulation permits 100
/// evictions and admits on fit, so the real loop must too.
#[test]
fn eviction_that_fits_after_exactly_max_attempts_is_admitted_h8() {
    let s = base_size();
    let resident_fee = 8 * (s as u64) * MIN_FEE_PER_BYTE; // clears the floor at any fullness
    let mut pool = Mempool::with_max_size(100 * s);
    for _ in 0..100 {
        pool.add_skip_crypto(tx(resident_fee, 0)).expect("resident admitted");
    }
    assert_eq!(pool.len(), 100, "pool full with exactly 100 residents");

    // ~99.5*s bytes: fits ONLY after evicting all 100 residents (freeing 100*s),
    // i.e. exactly MAX_EVICTION_ATTEMPTS evictions; after 99 it is still 0.5*s
    // short. Enormous fee => highest fee-rate, clears the dynamic floor and
    // outranks every resident so the eviction loop actually proceeds through all
    // 100 (the #88 fee-rate guard would otherwise stop it early).
    let incoming = tx(u64::MAX / 2, 98 * s + s / 2);
    let result = pool.add_skip_crypto(incoming);

    assert!(
        result.is_ok(),
        "a tx that fits after exactly 100 evictions must be admitted (H8 off-by-one)"
    );
    assert_eq!(
        pool.len(),
        1,
        "the 100 low-rate residents are evicted and the incoming is admitted"
    );
    assert!(pool.verify_size_invariant());
}

// ===========================================================================
// Dynamic minimum-fee multiplier buckets
// ===========================================================================

#[test]
fn fee_exactly_equal_to_min_accepted_boundary_is_lt_not_lte() {
    let s = base_size();
    let mut pool = Mempool::new(); // empty -> fullness 0 -> 1x
    let min = (s as u64) * MIN_FEE_PER_BYTE;
    // fee == min must be accepted (the check is `<`, not `<=`).
    assert!(pool.add_skip_crypto(tx(min, 0)).is_ok(), "fee == min must admit");
    // fee == min-1 must be rejected.
    assert!(matches!(
        pool.add_skip_crypto(tx(min - 1, 0)),
        Err(Error::FeeTooLow { .. })
    ));
}

#[test]
fn dynamic_fee_multiplier_2x_at_25_percent_fullness() {
    let s = base_size();
    let mut pool = Mempool::with_max_size(8 * s);
    let hi = 8 * (s as u64) * MIN_FEE_PER_BYTE;
    for _ in 0..2 {
        pool.add_skip_crypto(tx(hi, 0)).unwrap(); // -> 2s = 25% full
    }
    let two_x = 2 * (s as u64) * MIN_FEE_PER_BYTE;
    // Just under 2x -> rejected; exactly 2x -> accepted.
    assert!(matches!(
        pool.add_skip_crypto(tx(two_x - 1, 0)),
        Err(Error::FeeTooLow { .. })
    ));
    assert!(pool.add_skip_crypto(tx(two_x, 0)).is_ok());
}

#[test]
fn dynamic_fee_multiplier_4x_at_50_percent_fullness() {
    let s = base_size();
    let mut pool = Mempool::with_max_size(8 * s);
    let hi = 8 * (s as u64) * MIN_FEE_PER_BYTE;
    for _ in 0..4 {
        pool.add_skip_crypto(tx(hi, 0)).unwrap(); // -> 4s = 50% full
    }
    let four_x = 4 * (s as u64) * MIN_FEE_PER_BYTE;
    assert!(matches!(
        pool.add_skip_crypto(tx(four_x - 1, 0)),
        Err(Error::FeeTooLow { .. })
    ));
    assert!(pool.add_skip_crypto(tx(four_x, 0)).is_ok());
}

#[test]
fn dynamic_fee_multiplier_8x_at_75_percent_fullness() {
    let s = base_size();
    let mut pool = Mempool::with_max_size(8 * s);
    let hi = 8 * (s as u64) * MIN_FEE_PER_BYTE;
    for _ in 0..6 {
        pool.add_skip_crypto(tx(hi, 0)).unwrap(); // -> 6s = 75% full
    }
    let eight_x = 8 * (s as u64) * MIN_FEE_PER_BYTE;
    assert!(matches!(
        pool.add_skip_crypto(tx(eight_x - 1, 0)),
        Err(Error::FeeTooLow { .. })
    ));
    assert!(pool.add_skip_crypto(tx(eight_x, 0)).is_ok());
}

#[test]
fn max_size_zero_does_not_divide_by_zero() {
    // fullness_pct is guarded when max_size == 0; admission is rejected
    // (MempoolFull) without panic or divide-by-zero.
    let s = base_size();
    let mut pool = Mempool::with_max_size(0);
    let result = pool.add_skip_crypto(tx((s as u64) * MIN_FEE_PER_BYTE, 0));
    assert!(matches!(result, Err(Error::MempoolFull)), "got {:?}", result);
    assert_eq!(pool.len(), 0);
}

// ===========================================================================
// RBF boundary math
// ===========================================================================

/// Admit an incumbent, then attempt an RBF replacement that shares its key
/// image. Returns (pool, incumbent_hash, replacement_result).
fn rbf_scenario(
    old_fee: u64,
    old_extra: usize,
    new_fee: u64,
    new_extra: usize,
) -> (Mempool, Hash, Result<Hash>) {
    let mut pool = Mempool::new();
    let incumbent = tx(old_fee, old_extra);
    let ki = incumbent.inputs[0].key_image;
    let incumbent_hash = pool.add_skip_crypto(incumbent).expect("incumbent admitted");

    let mut challenger = tx(new_fee, new_extra);
    challenger.inputs[0].key_image = ki; // force the key-image conflict
    let result = pool.add_skip_crypto(challenger);
    (pool, incumbent_hash, result)
}

#[test]
fn rbf_exact_125_percent_bump_accepted() {
    let s = base_size() as u64;
    // Equal sizes -> rate proportional to fee. old_rate=4*MIN*1e6,
    // new_rate=5*MIN*1e6 => new*100 == old*125 exactly, and new > old.
    let old_fee = 4 * s * MIN_FEE_PER_BYTE;
    let new_fee = 5 * s * MIN_FEE_PER_BYTE;
    let (pool, _, result) = rbf_scenario(old_fee, 0, new_fee, 0);
    assert!(result.is_ok(), "exact 125% bump must be accepted: {:?}", result);
    assert_eq!(pool.len(), 1, "RBF replaces, not adds");
}

#[test]
fn rbf_124_percent_bump_rejected() {
    let s = base_size() as u64;
    // old_rate=100*MIN*1e6, new_rate=124*MIN*1e6 => new*100 < old*125.
    let old_fee = 100 * s * MIN_FEE_PER_BYTE;
    let new_fee = 124 * s * MIN_FEE_PER_BYTE;
    let (pool, incumbent, result) = rbf_scenario(old_fee, 0, new_fee, 0);
    assert!(result.is_err(), "124% bump is below the 125% threshold");
    assert!(pool.contains(&incumbent), "incumbent must survive a failed RBF");
    assert_eq!(pool.len(), 1);
}

#[test]
fn rbf_equal_fee_rate_rejected_by_strict_greater_guard() {
    let s = base_size() as u64;
    // Same fee & size -> equal rate. Even though cross-multiply lhs>=rhs can
    // hold at low rates, the explicit `new_rate > old_rate` guard rejects.
    let fee = 100 * s * MIN_FEE_PER_BYTE;
    let (pool, incumbent, result) = rbf_scenario(fee, 0, fee, 0);
    assert!(result.is_err(), "equal fee-rate must not replace (no-bump guard)");
    assert!(pool.contains(&incumbent));
    assert_eq!(pool.len(), 1);
}

#[test]
fn rbf_higher_absolute_fee_but_lower_fee_rate_does_not_replace() {
    // RBF keys on fee-PER-BYTE, not absolute fee. A physically larger tx with
    // a higher absolute fee but a lower per-byte rate must NOT replace.
    let s = base_size() as u64;
    let old_fee = 100 * s * MIN_FEE_PER_BYTE; // small tx, high rate
    let new_fee = old_fee + 1; // higher ABSOLUTE fee...
    let big_extra = 2 * base_size(); // ...but ~3x the size => lower per-byte rate
    let (pool, incumbent, result) = rbf_scenario(old_fee, 0, new_fee, big_extra);
    assert!(result.is_err(), "lower fee-rate must not replace despite higher absolute fee");
    assert!(pool.contains(&incumbent));
    assert_eq!(pool.len(), 1);
}

#[test]
fn rbf_replacement_that_fails_size_check_leaves_incumbent_intact() {
    // Rejected-evicts-nothing, applied to RBF: a replacement that trips the
    // size cap (checked before the RBF removal runs) must not drop the
    // incumbent.
    let s = base_size() as u64;
    let (pool, incumbent, result) =
        rbf_scenario(100 * s * MIN_FEE_PER_BYTE, 0, u64::MAX / 2, MAX_TX_SIZE + 1);
    assert!(matches!(result, Err(Error::TransactionTooLarge { .. })), "got {:?}", result);
    assert!(pool.contains(&incumbent), "incumbent must survive an oversized RBF attempt");
    assert_eq!(pool.len(), 1);
}

#[test]
fn rbf_multi_key_image_conflict_replaces_all_conflicts() {
    // BUG-12: one incoming tx conflicting on MULTIPLE key images collects all
    // conflicts, dedups, and replaces every one — leaving the pool with a
    // single tx and no shared key images.
    let s = base_size() as u64;
    let mut pool = Mempool::new();
    let low = 4 * s * MIN_FEE_PER_BYTE;
    let a = tx(low, 0);
    let b = tx(low, 0);
    let ki_a = a.inputs[0].key_image;
    let ki_b = b.inputs[0].key_image;
    pool.add_skip_crypto(a).unwrap();
    pool.add_skip_crypto(b).unwrap();
    assert_eq!(pool.len(), 2);

    // Two-input tx conflicting with BOTH residents, high enough rate to beat
    // each incumbent's per-byte rate (build then size to compute the fee).
    let mut multi = two_input_tx(0, ki_a, ki_b);
    let msize = multi.size() as u64;
    multi.fee = Amount::from_atomic(msize * MIN_FEE_PER_BYTE * 100); // 100x -> clearly higher rate
    let h = pool.add_skip_crypto(multi).expect("multi-conflict RBF admitted");

    assert_eq!(pool.len(), 1, "both incumbents replaced by one tx");
    assert!(pool.contains(&h));
    assert!(pool.contains_key_image(&ki_a));
    assert!(pool.contains_key_image(&ki_b));
    assert!(pool.verify_size_invariant());
}

#[test]
fn no_two_mempool_txs_share_a_key_image_after_rbf() {
    // Property: after an RBF the key-image set stays a partition (no dup).
    let s = base_size() as u64;
    let (pool, _, result) = rbf_scenario(
        4 * s * MIN_FEE_PER_BYTE,
        0,
        5 * s * MIN_FEE_PER_BYTE,
        0,
    );
    assert!(result.is_ok());
    // Exactly one tx, exactly one key image tracked.
    let txs = pool.get_block_transactions(usize::MAX, usize::MAX);
    assert_eq!(txs.len(), 1);
    let mut seen = HashSet::new();
    for t in &txs {
        for ki in t.key_images() {
            assert!(seen.insert(ki), "key image duplicated across mempool txs");
        }
    }
}

// ===========================================================================
// Eviction: higher-fee-rate residents are protected
// ===========================================================================

#[test]
fn eviction_stops_at_equal_or_higher_fee_rate_candidate() {
    // A full pool with one low-rate and one high-rate resident. An incoming
    // mid-rate tx evicts ONLY the low-rate resident; the loop breaks before
    // touching the higher-rate one.
    let s = base_size();
    let mut pool = Mempool::with_max_size(2 * s);
    let low = tx((s as u64) * MIN_FEE_PER_BYTE, 0); // rate = 1x floor
    let low_ki = low.inputs[0].key_image;
    let low_hash = pool.add_skip_crypto(low).unwrap(); // added at 0% -> 1x ok
    let high = tx(50 * (s as u64) * MIN_FEE_PER_BYTE, 0); // rate = 50x
    let high_ki = high.inputs[0].key_image;
    pool.add_skip_crypto(high).unwrap(); // added at 50% -> needs 4x, 50x ok
    assert_eq!(pool.len(), 2);

    // Incoming rate 8x: > low(1x), < high(50x). Pool full -> evicts low, fits.
    let incoming = tx(8 * (s as u64) * MIN_FEE_PER_BYTE, 0);
    let incoming_hash = pool.add_skip_crypto(incoming).expect("mid-rate admitted by evicting low");

    assert!(pool.contains(&incoming_hash));
    assert!(!pool.contains(&low_hash), "low-rate resident evicted");
    assert!(pool.contains_key_image(&high_ki), "high-rate resident protected");
    assert!(!pool.contains_key_image(&low_ki));
    assert_eq!(pool.len(), 2);
    assert!(pool.verify_size_invariant());
}

#[test]
fn size_invariant_holds_across_add_evict_remove_expire_sequence() {
    let s = base_size();
    let mut pool = Mempool::with_max_size(5 * s);
    let mut hashes = Vec::new();
    for i in 0..40u64 {
        // rising fees so later txs can evict earlier ones
        let t = tx((s as u64) * MIN_FEE_PER_BYTE * (i + 1) * 8, 0);
        if let Ok(h) = pool.add_skip_crypto(t) {
            hashes.push(h);
        }
        assert!(pool.verify_size_invariant(), "invariant after add {}", i);
        assert!(pool.size() <= 5 * s, "size must stay within cap");
    }
    // Remove a few, then run a height update (expiry sweep) — invariant holds.
    for h in hashes.iter().take(3) {
        pool.remove(h);
        assert!(pool.verify_size_invariant());
    }
    pool.set_height(0);
    assert!(pool.verify_size_invariant());
}

// ===========================================================================
// remove / remove_conflicts
// ===========================================================================

#[test]
fn remove_nonexistent_hash_returns_none_and_no_state_change() {
    let s = base_size();
    let mut pool = Mempool::new();
    let t = tx((s as u64) * MIN_FEE_PER_BYTE * 4, 0);
    let h = pool.add_skip_crypto(t).unwrap();
    let size_before = pool.size();

    assert!(pool.remove(&Hash::from_bytes([0x77; 32])).is_none());
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.size(), size_before);

    // Removing the real one works and returns Some; a second remove is None
    // and does not underflow current_size (saturating_sub).
    assert!(pool.remove(&h).is_some());
    assert!(pool.remove(&h).is_none());
    assert_eq!(pool.size(), 0);
    assert!(pool.verify_size_invariant());
}

#[test]
fn remove_conflicts_removes_matching_and_empty_list_is_noop() {
    let s = base_size();
    let mut pool = Mempool::new();
    let a = tx((s as u64) * MIN_FEE_PER_BYTE * 4, 0);
    let b = tx((s as u64) * MIN_FEE_PER_BYTE * 4, 0);
    let ki_a = a.inputs[0].key_image;
    let ki_b = b.inputs[0].key_image;
    pool.add_skip_crypto(a).unwrap();
    pool.add_skip_crypto(b).unwrap();

    // Empty list: nothing removed.
    pool.remove_conflicts(&[]);
    assert_eq!(pool.len(), 2);

    // Matching key image: only that tx removed.
    pool.remove_conflicts(&[ki_a]);
    assert_eq!(pool.len(), 1);
    assert!(!pool.contains_key_image(&ki_a));
    assert!(pool.contains_key_image(&ki_b));
    assert!(pool.verify_size_invariant());
}

// ===========================================================================
// remove_confirmed — pass 2 shadow-conflict eviction + audit reasons
// ===========================================================================

#[test]
fn remove_confirmed_evicts_shadow_conflict_with_doublespend_reason() {
    let s = base_size();
    let mut pool = Mempool::new();

    // Mempool tx_B spends a UTXO (key image KI). A DIFFERENT confirmed tx_A,
    // never in our mempool, spends the same UTXO.
    let tx_b = tx((s as u64) * MIN_FEE_PER_BYTE * 4, 0);
    let ki = tx_b.inputs[0].key_image;
    let b_hash = pool.add_skip_crypto(tx_b).unwrap();

    let mut tx_a = tx((s as u64) * MIN_FEE_PER_BYTE * 4, 0);
    tx_a.inputs[0].key_image = ki; // same UTXO, different tx (never added)
    let a_hash = tx_a.hash();
    assert_ne!(a_hash, b_hash, "confirmed tx is a distinct tx");

    pool.clear_audit_log();
    pool.remove_confirmed(&[tx_a]);

    assert!(!pool.contains(&b_hash), "shadow-conflict tx_B must be evicted");
    assert_eq!(pool.len(), 0);
    // Audit records a DoubleSpend removal for tx_B (and a Confirmed removal for
    // tx_A, which was never resident so it's a no-op remove but still audited).
    let log = pool.audit_log();
    assert!(
        log.iter().any(|e| matches!(
            e,
            AuditEvent::TxRemoved { hash, reason: EvictReason::DoubleSpend, .. } if *hash == b_hash
        )),
        "expected a DoubleSpend eviction for tx_B, log={:?}",
        log
    );
    assert!(
        log.iter().any(|e| matches!(
            e,
            AuditEvent::TxRemoved { reason: EvictReason::Confirmed, .. }
        )),
        "expected a Confirmed removal audit event"
    );
    assert!(pool.verify_size_invariant());
}

#[test]
fn remove_confirmed_tx_also_in_mempool_is_not_double_counted() {
    let s = base_size();
    let mut pool = Mempool::new();
    let shared = tx((s as u64) * MIN_FEE_PER_BYTE * 4, 0);
    let other = tx((s as u64) * MIN_FEE_PER_BYTE * 4, 0);
    let shared_hash = pool.add_skip_crypto(shared.clone()).unwrap();
    let other_hash = pool.add_skip_crypto(other).unwrap();
    assert_eq!(pool.len(), 2);

    // `shared` is both confirmed AND resident. Pass 1 removes it; pass 2 finds
    // no lingering key-image conflict for it.
    pool.remove_confirmed(&[shared]);
    assert!(!pool.contains(&shared_hash));
    assert!(pool.contains(&other_hash));
    assert_eq!(pool.len(), 1);
    assert!(pool.verify_size_invariant());
}

#[test]
fn remove_confirmed_dedups_multiple_confirmed_sharing_conflicts() {
    let s = base_size();
    let mut pool = Mempool::new();
    let m = tx((s as u64) * MIN_FEE_PER_BYTE * 4, 0);
    let ki = m.inputs[0].key_image;
    let m_hash = pool.add_skip_crypto(m).unwrap();

    // Two confirmed txs both referencing the SAME key image as the resident.
    // conflicting_hashes must dedup so remove is not attempted twice.
    let mut c1 = tx((s as u64) * MIN_FEE_PER_BYTE * 4, 0);
    c1.inputs[0].key_image = ki;
    let mut c2 = tx((s as u64) * MIN_FEE_PER_BYTE * 4, 0);
    c2.inputs[0].key_image = ki;

    pool.remove_confirmed(&[c1, c2]);
    assert!(!pool.contains(&m_hash));
    assert_eq!(pool.len(), 0);
    assert!(pool.verify_size_invariant());
}

// ===========================================================================
// shadow_evict_invalid — driven by a fake ShadowEvictChain
// ===========================================================================

#[test]
fn shadow_evict_no_invalid_txs_is_noop() {
    let s = base_size();
    let mut pool = Mempool::new();
    for _ in 0..3 {
        pool.add_skip_crypto(tx((s as u64) * MIN_FEE_PER_BYTE * 4, 0)).unwrap();
    }
    let chain = FakeShadowChain { invalid: HashSet::new() };
    pool.shadow_evict_invalid(&chain);
    assert_eq!(pool.len(), 3, "nothing evicted when all txs still validate");
    assert!(pool.verify_size_invariant());
}

#[test]
fn shadow_evict_drops_exactly_the_now_invalid_subset() {
    let s = base_size();
    let mut pool = Mempool::new();
    let mut hashes = Vec::new();
    for _ in 0..4 {
        let t = tx((s as u64) * MIN_FEE_PER_BYTE * 4, 0);
        hashes.push(t.hash());
        pool.add_skip_crypto(t).unwrap();
    }
    // Invalidate a subset (2 of 4).
    let invalid: HashSet<Hash> = [hashes[0], hashes[2]].into_iter().collect();
    let chain = FakeShadowChain { invalid: invalid.clone() };
    pool.shadow_evict_invalid(&chain);

    assert_eq!(pool.len(), 2, "exactly the invalid subset is evicted");
    assert!(!pool.contains(&hashes[0]));
    assert!(pool.contains(&hashes[1]));
    assert!(!pool.contains(&hashes[2]));
    assert!(pool.contains(&hashes[3]));
    assert!(pool.verify_size_invariant());
}

// ===========================================================================
// get_block_transactions — size bound + continue-vs-break
// ===========================================================================

#[test]
fn get_block_transactions_respects_max_size_bytes() {
    let s = base_size();
    let mut pool = Mempool::new();
    for _ in 0..5 {
        pool.add_skip_crypto(tx((s as u64) * MIN_FEE_PER_BYTE * 8, 0)).unwrap();
    }
    // Budget for ~2 txs.
    let budget = 2 * s + s / 2;
    let selected = pool.get_block_transactions(budget, usize::MAX);
    let total: usize = selected.iter().map(|t| t.size()).sum();
    assert!(total <= budget, "assembled size {} exceeds budget {}", total, budget);
    assert!(selected.len() <= 2);
}

#[test]
fn get_block_transactions_size_skip_does_not_block_a_later_smaller_tx() {
    let s = base_size();
    let mut pool = Mempool::new();
    // Big high-fee tx (considered first) and small lower-fee tx.
    let big = tx((s as u64) * MIN_FEE_PER_BYTE * 100, 3 * s);
    let big_hash = pool.add_skip_crypto(big).unwrap();
    let small = tx((s as u64) * MIN_FEE_PER_BYTE * 8, 0);
    let small_hash = pool.add_skip_crypto(small).unwrap();

    // Budget fits only the small tx. The big one is skipped (continue), the
    // small one still gets selected.
    let selected = pool.get_block_transactions(s + s / 2, usize::MAX);
    let hashes: Vec<Hash> = selected.iter().map(|t| t.hash()).collect();
    assert!(hashes.contains(&small_hash), "smaller tx must still be selected");
    assert!(!hashes.contains(&big_hash), "oversized tx must be skipped");
}

#[test]
fn get_block_transactions_result_is_fee_descending_bounded_subset() {
    let s = base_size();
    let mut pool = Mempool::new();
    let mut resident = HashSet::new();
    for i in 0..6u64 {
        let t = tx((s as u64) * MIN_FEE_PER_BYTE * (i + 1) * 4, 0);
        resident.insert(t.hash());
        pool.add_skip_crypto(t).unwrap();
    }
    let selected = pool.get_block_transactions(usize::MAX, 4);
    assert!(selected.len() <= 4, "count bound honored");
    // subset
    for t in &selected {
        assert!(resident.contains(&t.hash()));
    }
    // fee-per-byte descending (all equal size -> compare fee)
    for w in selected.windows(2) {
        assert!(
            w[0].fee.as_atomic() >= w[1].fee.as_atomic(),
            "selection must be fee-descending"
        );
    }
    // key-image disjoint
    let mut seen = HashSet::new();
    for t in &selected {
        for ki in t.key_images() {
            assert!(seen.insert(ki), "selected txs must be key-image disjoint");
        }
    }
}

// ===========================================================================
// Height-based expiry
// ===========================================================================

#[test]
fn set_height_beyond_expiry_blocks_evicts_and_audits_expired() {
    let s = base_size();
    let mut pool = Mempool::new();
    // Added at height 0.
    let h = pool.add_skip_crypto(tx((s as u64) * MIN_FEE_PER_BYTE * 4, 0)).unwrap();
    assert_eq!(pool.len(), 1);
    pool.clear_audit_log();

    // Advance past TX_EXPIRY_BLOCKS -> height-based eviction.
    pool.set_height(TX_EXPIRY_BLOCKS + 1);
    assert!(!pool.contains(&h), "stale-by-height tx must be evicted");
    assert_eq!(pool.len(), 0);
    assert!(
        pool.audit_log().iter().any(|e| matches!(
            e,
            AuditEvent::TxRemoved { reason: EvictReason::Expired, .. }
        )),
        "height-expired tx must be audited with Expired reason"
    );
}

#[test]
fn set_height_backwards_reorg_uses_saturating_sub_no_panic() {
    let s = base_size();
    let mut pool = Mempool::new();
    pool.set_height(100); // height_added will be 100
    let h = pool.add_skip_crypto(tx((s as u64) * MIN_FEE_PER_BYTE * 4, 0)).unwrap();
    // Reorg to a lower height: saturating_sub keeps age at 0 -> not expired.
    pool.set_height(50);
    assert!(pool.contains(&h), "reorg to lower height must not expire fresh tx");
    assert_eq!(pool.len(), 1);
}

// ===========================================================================
// fee_percentiles
// ===========================================================================

#[test]
fn fee_percentiles_empty_returns_min_fee_and_zero_count() {
    let pool = Mempool::new();
    let p = pool.fee_percentiles();
    assert_eq!(p.count, 0);
    assert_eq!(p.p25, MIN_FEE_PER_BYTE);
    assert_eq!(p.p50, MIN_FEE_PER_BYTE);
    assert_eq!(p.p75, MIN_FEE_PER_BYTE);
    assert_eq!(p.p90, MIN_FEE_PER_BYTE);
}

#[test]
fn fee_percentiles_single_tx_all_equal_and_floored() {
    let s = base_size();
    let mut pool = Mempool::new();
    pool.add_skip_crypto(tx((s as u64) * MIN_FEE_PER_BYTE * 4, 0)).unwrap();
    let p = pool.fee_percentiles();
    assert_eq!(p.count, 1);
    assert_eq!(p.p25, p.p90, "single tx: all percentiles equal");
    assert!(p.p25 >= MIN_FEE_PER_BYTE, "floored at MIN_FEE_PER_BYTE");
}

#[test]
fn fee_percentiles_are_monotonic_nondecreasing() {
    let s = base_size();
    let mut pool = Mempool::new();
    for i in 0..20u64 {
        pool.add_skip_crypto(tx((s as u64) * MIN_FEE_PER_BYTE * (i + 1) * 4, 0)).unwrap();
    }
    let p = pool.fee_percentiles();
    assert_eq!(p.count, 20);
    assert!(p.p25 <= p.p50, "p25 <= p50");
    assert!(p.p50 <= p.p75, "p50 <= p75");
    assert!(p.p75 <= p.p90, "p75 <= p90");
    assert!(p.p25 >= MIN_FEE_PER_BYTE);
}

// ===========================================================================
// contains_key_image / clear / stats
// ===========================================================================

#[test]
fn contains_key_image_true_after_add_false_after_remove() {
    let s = base_size();
    let mut pool = Mempool::new();
    let t = tx((s as u64) * MIN_FEE_PER_BYTE * 4, 0);
    let ki = t.inputs[0].key_image;
    let h = pool.add_skip_crypto(t).unwrap();
    assert!(pool.contains_key_image(&ki));
    pool.remove(&h);
    assert!(!pool.contains_key_image(&ki));
}

#[test]
fn clear_empties_txs_but_preserves_audit_log() {
    let s = base_size();
    let mut pool = Mempool::new();
    for _ in 0..5 {
        pool.add_skip_crypto(tx((s as u64) * MIN_FEE_PER_BYTE * 4, 0)).unwrap();
    }
    let audit_before = pool.audit_log_len();
    assert!(audit_before > 0);

    pool.clear();
    assert_eq!(pool.len(), 0);
    assert_eq!(pool.size(), 0);
    // clear() intentionally does NOT touch the audit log.
    assert_eq!(
        pool.audit_log_len(),
        audit_before,
        "clear() must not reset the audit log"
    );
}

#[test]
fn stats_reports_count_size_and_total_fee() {
    let s = base_size();
    let mut pool = Mempool::with_max_size(1234 * s);
    let fee = (s as u64) * MIN_FEE_PER_BYTE * 4;
    pool.add_skip_crypto(tx(fee, 0)).unwrap();
    pool.add_skip_crypto(tx(fee, 0)).unwrap();
    let st = pool.stats();
    assert_eq!(st.tx_count, 2);
    assert_eq!(st.total_fee.as_atomic(), fee * 2, "total_fee sums entries");
    assert_eq!(st.size_bytes, pool.size());
    assert_eq!(st.max_size, 1234 * s);
}

// ===========================================================================
// Audit log
// ===========================================================================

#[test]
fn audit_log_records_added_rejected_and_removed_events() {
    let s = base_size();
    let mut pool = Mempool::new();
    let good = tx((s as u64) * MIN_FEE_PER_BYTE * 4, 0);
    pool.add_skip_crypto(good.clone()).unwrap();
    let _ = pool.add_skip_crypto(tx(0, 0)); // rejected: FeeTooLow
    // remove_confirmed emits an audited TxRemoved{Confirmed}; the bare
    // remove(&hash) API path is intentionally NOT audited (it's a direct
    // removal, not a mempool-policy event).
    pool.remove_confirmed(&[good]);

    let log = pool.audit_log();
    assert!(log.iter().any(|e| matches!(e, AuditEvent::TxAdded { .. })));
    assert!(log.iter().any(|e| matches!(e, AuditEvent::TxRejected { .. })));
    assert!(log.iter().any(|e| matches!(e, AuditEvent::TxRemoved { .. })));
}

#[test]
fn audit_log_capped_at_capacity_drops_oldest() {
    // Generate > AUDIT_LOG_CAPACITY (4096) cheap rejection events (coinbase is
    // rejected before any crypto) and assert the log is capped.
    let mut pool = Mempool::new();
    let mut cb = tx(0, 0);
    cb.tx_type = TxType::Coinbase;
    for _ in 0..4200 {
        let _ = pool.add_skip_crypto(cb.clone());
    }
    assert_eq!(pool.audit_log_len(), 4096, "audit log must cap at AUDIT_LOG_CAPACITY");
}

#[test]
fn clear_audit_log_empties_without_touching_txs() {
    let s = base_size();
    let mut pool = Mempool::new();
    let h = pool.add_skip_crypto(tx((s as u64) * MIN_FEE_PER_BYTE * 4, 0)).unwrap();
    assert!(pool.audit_log_len() > 0);
    pool.clear_audit_log();
    assert_eq!(pool.audit_log_len(), 0);
    assert!(pool.contains(&h), "clearing the audit log must not touch txs");
}

// ===========================================================================
// Persistence — save -> load round-trip (real crypto so re-admission works)
// ===========================================================================

#[test]
fn persistence_save_load_round_trip_restores_all_txs() {
    let dir = tempfile::tempdir().unwrap();

    let mut pool = Mempool::new();
    let mut expected = Vec::new();
    for _ in 0..3 {
        let t = build_valid_tx_for_mempool();
        expected.push(t.hash());
        pool.add(t).expect("valid tx admitted through full crypto path");
    }
    let saved = pool.save_to_disk(dir.path()).expect("save");
    assert_eq!(saved, 3);

    // Fresh mempool loads them back — load_from_disk re-admits via add(), so
    // only genuinely-valid txs restore. All 3 must return.
    let mut restored_pool = Mempool::new();
    let loaded = restored_pool.load_from_disk(dir.path()).expect("load");
    assert_eq!(loaded, 3, "all saved txs must be restored");
    for h in &expected {
        assert!(restored_pool.contains(h), "restored mempool must contain {:?}", h);
    }
    // The .dat file is consumed on load.
    assert!(!dir.path().join("mempool.dat").exists());
}

#[test]
fn save_empty_mempool_removes_stale_file_and_returns_zero() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mempool.dat");
    // Pre-create a stale file.
    std::fs::write(&path, b"stale").unwrap();

    let pool = Mempool::new();
    let saved = pool.save_to_disk(dir.path()).expect("save empty");
    assert_eq!(saved, 0);
    assert!(!path.exists(), "empty save must remove the stale mempool.dat");
}

#[test]
fn save_uses_atomic_rename_and_load_ignores_stray_tmp() {
    let dir = tempfile::tempdir().unwrap();
    let mut pool = Mempool::new();
    pool.add(build_valid_tx_for_mempool()).unwrap();
    pool.save_to_disk(dir.path()).unwrap();

    // After a successful save, the target exists and no .tmp is left behind.
    assert!(dir.path().join("mempool.dat").exists());
    assert!(
        !dir.path().join("mempool.dat.tmp").exists(),
        "atomic rename must not leave a .tmp behind"
    );

    // A stray partial .tmp (simulating a crash mid-write) is ignored by load,
    // which only reads mempool.dat.
    let stray = dir.path().join("mempool.dat.tmp");
    std::fs::write(&stray, b"partial-garbage").unwrap();
    let mut restored = Mempool::new();
    let loaded = restored.load_from_disk(dir.path()).expect("load ignores stray tmp");
    assert_eq!(loaded, 1);
    assert!(stray.exists(), "load must not touch the stray .tmp file");
}

#[test]
fn load_from_disk_missing_file_returns_zero() {
    let dir = tempfile::tempdir().unwrap();
    let mut pool = Mempool::new();
    assert_eq!(pool.load_from_disk(dir.path()).expect("load"), 0);
}

#[test]
fn load_from_disk_skips_invalid_txs_loaded_less_than_file_count() {
    // load_from_disk re-admits each tx via add() (full crypto). A file of
    // skip-crypto (garbage-proof) txs therefore restores ZERO, proving the
    // per-tx re-validation skip on load.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mempool.dat");
    let s = base_size();
    let txs: Vec<Transaction> = (0..3)
        .map(|_| tx((s as u64) * MIN_FEE_PER_BYTE * 4, 0))
        .collect();
    std::fs::write(&path, borsh::to_vec(&txs).unwrap()).unwrap();

    let mut pool = Mempool::new();
    let loaded = pool.load_from_disk(dir.path()).expect("load");
    assert!(loaded < txs.len(), "garbage-crypto txs must be skipped on load");
    assert_eq!(loaded, 0);
    assert!(!path.exists(), "file consumed after load");
}

// ===========================================================================
// SharedMempool wrappers
// ===========================================================================

#[test]
fn shared_mempool_wrappers_reflect_contents() {
    let shared = SharedMempool::new();
    assert_eq!(shared.get_all().len(), 0);
    assert_eq!(shared.total_fees().as_atomic(), 0);
    assert_eq!(shared.oldest_timestamp(), 0);

    let t = build_valid_tx_for_mempool();
    let fee = t.fee.as_atomic();
    let h = t.hash();
    shared.add(t).expect("valid tx admitted");

    assert_eq!(shared.len(), 1);
    assert!(shared.contains(&h));
    assert_eq!(shared.get_all().len(), 1);
    assert_eq!(shared.total_fees().as_atomic(), fee);
    assert!(shared.oldest_timestamp() > 0, "oldest_timestamp reflects the added tx");
}
