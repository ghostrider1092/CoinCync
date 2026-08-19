//! Layer-4 differential oracle for the transaction structural validator.
//!
//! `coincync::consensus::validate_transaction_basic` enforces ~20 crypto-free
//! structural / policy rules (version, i/o counts, sizes, fee floor, ring-size
//! minimum, range-proof presence, duplicate/zero/off-curve key images, output
//! field bounds and point validity). This file reimplements those rules
//! INDEPENDENTLY from the spec + constants (`reference_verdict`) and diffs the
//! two accept/reject verdicts across (a) an explicit single-rule mutation matrix
//! and (b) a randomized proptest over the bug-prone numeric knobs.
//!
//! Any disagreement is a finding: the production validator's accept/reject
//! boundary deviates from the specified rule (or the reference is wrong and must
//! be reconciled). The reference is written from the RULES, not copied from the
//! validator, so it is a genuine oracle. No mining / no CLSAG / no range-proof
//! crypto is exercised — this is fast and runs in normal CI.

use coincync::consensus::validate_transaction_basic;
use coincync::constants::{
    BOOTSTRAP_MIN_RING_SIZE, MAX_TX_INPUTS, MAX_TX_OUTPUTS, MAX_TX_SIZE, MIN_FEE_PER_BYTE,
    MIN_TX_SIZE,
};
use coincync::crypto::{ClsagSignature, KeyImage as CryptoKeyImage, PublicPoint, SecretScalar};
use coincync::primitives::{Amount, KeyImage, PublicKey};
use coincync::transaction::{RingMemberRef, Transaction, TxInput, TxOutput, TxType};
use proptest::prelude::*;

/// Spec value of the max accepted tx version (v2 activation). Mirrors the
/// private `MAX_TX_VERSION` in validation.rs; if the production constant ever
/// changes, this differential flags it — a version bump must be deliberate.
const REF_MAX_TX_VERSION: u8 = 2;

/// A valid Ristretto point's compressed bytes, derived from a seed.
fn valid_point_bytes(seed: u8) -> [u8; 32] {
    SecretScalar::from_bytes([seed.wrapping_add(1); 32])
        .to_public()
        .to_bytes()
}

// ─────────────────────────────────────────────────────────────────────────────
// Parameterized, mutation-friendly tx builder
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct P {
    version: u8,
    coinbase: bool,
    num_inputs: usize,
    num_outputs: usize,
    ring_size: usize,
    fee: u64,
    enc_len: usize,
    memo_len: usize,
    stealth_zero: bool,
    commit_zero: bool,
    ki_zero: bool,
    dup_ki: bool,
    range_empty: bool,
}

/// A fully-structurally-valid Transfer baseline. Fee is set generously above the
/// per-byte floor so the baseline passes the fee rule regardless of exact size.
fn valid_params() -> P {
    P {
        version: 1,
        coinbase: false,
        num_inputs: 1,
        num_outputs: 1,
        ring_size: BOOTSTRAP_MIN_RING_SIZE,
        fee: 50_000_000,
        enc_len: 8,
        memo_len: 0,
        stealth_zero: false,
        commit_zero: false,
        ki_zero: false,
        dup_ki: false,
        range_empty: false,
    }
}

fn build_output(seed: u8, enc_len: usize, memo_len: usize, stealth_zero: bool, commit_zero: bool) -> TxOutput {
    let p = valid_point_bytes(seed);
    let stealth = if stealth_zero { [0u8; 32] } else { p };
    let commitment = if commit_zero {
        [0u8; 32]
    } else {
        valid_point_bytes(seed.wrapping_add(50))
    };
    TxOutput {
        stealth_address: PublicKey::from_bytes(stealth),
        tx_public_key: PublicKey::from_bytes(p),
        commitment,
        encrypted_amount: vec![7u8; enc_len],
        view_tag: seed,
        lock_height: None,
        encrypted_memo: vec![9u8; memo_len],
    }
}

fn build_input(seed: u8, ring_size: usize, ki_zero: bool, ki_override: Option<[u8; 32]>) -> TxInput {
    let secret = SecretScalar::from_bytes([seed.wrapping_add(1); 32]);
    let pub_point = secret.to_public();
    let crypto_ki = CryptoKeyImage::from_secret(&secret);
    let ki_bytes = match (ki_override, ki_zero) {
        (Some(b), _) => b,
        (None, true) => [0u8; 32],
        (None, false) => crypto_ki.to_bytes(),
    };
    let key_image = KeyImage::from_bytes(ki_bytes);

    let mut ring_members = Vec::with_capacity(ring_size);
    for i in 0..ring_size {
        let rm_pub = SecretScalar::from_bytes([seed.wrapping_add(i as u8 + 2); 32]).to_public();
        ring_members.push(RingMemberRef {
            public_key: PublicKey::from_bytes(rm_pub.to_bytes()),
            commitment: rm_pub.to_bytes(),
        });
    }
    let signature = ClsagSignature {
        key_image: crypto_ki,
        commitment_image: pub_point,
        c1: [seed; 32],
        responses: vec![[seed; 32]; ring_size.max(1)],
    };
    TxInput {
        key_image,
        ring_members,
        signature,
        pseudo_output_commitment: pub_point.to_bytes(),
    }
}

fn build(p: &P) -> Transaction {
    let mut inputs = Vec::new();
    if !p.coinbase {
        // dup_ki forces every input to share one key image (a duplicate when
        // there are >= 2 inputs).
        let dup = if p.dup_ki { Some(valid_point_bytes(200)) } else { None };
        for i in 0..p.num_inputs {
            inputs.push(build_input(i as u8, p.ring_size, p.ki_zero, dup));
        }
    }
    let mut outputs = Vec::new();
    for o in 0..p.num_outputs {
        outputs.push(build_output(
            o as u8,
            p.enc_len,
            p.memo_len,
            p.stealth_zero,
            p.commit_zero,
        ));
    }
    Transaction {
        version: p.version,
        tx_type: if p.coinbase {
            TxType::Coinbase
        } else {
            TxType::Transfer
        },
        inputs,
        outputs,
        fee: Amount::from_atomic(p.fee),
        range_proof: if p.range_empty { vec![] } else { vec![0u8; 64] },
        extra: vec![],
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Independent reference: reimplements validate_transaction_basic's rules from
// the spec + constants. Returns Ok(()) iff the tx should pass.
// ─────────────────────────────────────────────────────────────────────────────

fn reference_verdict(tx: &Transaction) -> Result<(), &'static str> {
    let is_coinbase = tx.tx_type == TxType::Coinbase;

    if tx.version == 0 || tx.version > REF_MAX_TX_VERSION {
        return Err("version");
    }
    if tx.inputs.is_empty() {
        return Err("empty inputs");
    }
    if tx.outputs.is_empty() {
        return Err("empty outputs");
    }
    let size = tx.size();
    if size > MAX_TX_SIZE {
        return Err("too large");
    }
    if size < MIN_TX_SIZE {
        return Err("too small");
    }
    if !is_coinbase {
        let min_fee = (size as u64) * MIN_FEE_PER_BYTE;
        if tx.fee.as_atomic() < min_fee {
            return Err("fee too low");
        }
        for input in &tx.inputs {
            if input.ring_members.len() < BOOTSTRAP_MIN_RING_SIZE {
                return Err("ring too small");
            }
        }
        if tx.range_proof.is_empty() {
            return Err("missing range proof");
        }
    }
    {
        let mut seen = std::collections::HashSet::new();
        for input in &tx.inputs {
            if !seen.insert(input.key_image) {
                return Err("dup key image");
            }
        }
    }
    if tx.inputs.len() > MAX_TX_INPUTS {
        return Err("too many inputs");
    }
    if tx.outputs.len() > MAX_TX_OUTPUTS {
        return Err("too many outputs");
    }
    for output in &tx.outputs {
        if output.encrypted_amount.is_empty() {
            return Err("empty enc amount");
        }
        if output.encrypted_amount.len() > 64 {
            return Err("enc amount too large");
        }
        if output.encrypted_memo.len() > 256 {
            return Err("memo too large");
        }
        if output.stealth_address.as_bytes() == &[0u8; 32] {
            return Err("zero stealth");
        }
        if PublicPoint::from_bytes(*output.stealth_address.as_bytes()).is_none() {
            return Err("bad stealth point");
        }
        if output.commitment == [0u8; 32] {
            return Err("zero commitment");
        }
        if PublicPoint::from_bytes(output.commitment).is_none() {
            return Err("bad commitment point");
        }
    }
    if !is_coinbase {
        for input in &tx.inputs {
            let ki = input.key_image.as_bytes();
            if ki == &[0u8; 32] {
                return Err("zero key image");
            }
            if PublicPoint::from_bytes(*ki).is_none() {
                return Err("bad key image point");
            }
        }
    }
    Ok(())
}

/// The core differential assertion: the production validator and the independent
/// reference must AGREE on accept vs reject.
fn assert_agree(label: &str, tx: &Transaction) {
    let real = validate_transaction_basic(tx).is_ok();
    let reference = reference_verdict(tx).is_ok();
    assert_eq!(
        real,
        reference,
        "[{label}] verdict differs: validate_transaction_basic={real} reference={reference} \
         (reference reason on reject: {:?})",
        reference_verdict(tx).err()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn baseline_transfer_is_valid_in_both() {
    let tx = build(&valid_params());
    assert!(
        validate_transaction_basic(&tx).is_ok(),
        "baseline must pass the production validator: {:?}",
        validate_transaction_basic(&tx).err()
    );
    assert!(
        reference_verdict(&tx).is_ok(),
        "baseline must pass the reference: {:?}",
        reference_verdict(&tx).err()
    );
}

#[test]
fn single_rule_mutation_matrix_agrees() {
    // Each mutation breaks exactly one rule; the production validator and the
    // independent reference must agree it is now rejected (and the un-mutated
    // baseline is accepted).
    assert_agree("baseline", &build(&valid_params()));

    let m = |f: &dyn Fn(&mut P)| {
        let mut p = valid_params();
        f(&mut p);
        build(&p)
    };

    assert_agree("version-0", &m(&|p| p.version = 0));
    assert_agree("version-3", &m(&|p| p.version = 3));
    assert_agree("version-255", &m(&|p| p.version = 255));
    assert_agree("empty-inputs", &m(&|p| p.num_inputs = 0));
    assert_agree("empty-outputs", &m(&|p| p.num_outputs = 0));
    assert_agree("fee-zero", &m(&|p| p.fee = 0));
    assert_agree("fee-one", &m(&|p| p.fee = 1));
    assert_agree("ring-too-small", &m(&|p| p.ring_size = BOOTSTRAP_MIN_RING_SIZE - 1));
    assert_agree("ring-at-min", &m(&|p| p.ring_size = BOOTSTRAP_MIN_RING_SIZE));
    assert_agree("range-empty", &m(&|p| p.range_empty = true));
    assert_agree("dup-key-image", &m(&|p| {
        p.num_inputs = 2;
        p.dup_ki = true;
    }));
    assert_agree("too-many-outputs", &m(&|p| p.num_outputs = MAX_TX_OUTPUTS + 1));
    assert_agree("outputs-at-max", &m(&|p| p.num_outputs = MAX_TX_OUTPUTS));
    assert_agree("enc-amount-empty", &m(&|p| p.enc_len = 0));
    assert_agree("enc-amount-64", &m(&|p| p.enc_len = 64));
    assert_agree("enc-amount-65", &m(&|p| p.enc_len = 65));
    assert_agree("memo-256", &m(&|p| p.memo_len = 256));
    assert_agree("memo-257", &m(&|p| p.memo_len = 257));
    assert_agree("zero-stealth", &m(&|p| p.stealth_zero = true));
    assert_agree("zero-commitment", &m(&|p| p.commit_zero = true));
    assert_agree("zero-key-image", &m(&|p| p.ki_zero = true));

    // Two-inputs valid (distinct key images) should still agree = accept.
    assert_agree("two-distinct-inputs", &m(&|p| p.num_inputs = 2));
    // Coinbase baseline (exempt from fee/ring/range/key-image rules).
    assert_agree("coinbase", &m(&|p| p.coinbase = true));
    assert_agree("coinbase-empty-range", &m(&|p| {
        p.coinbase = true;
        p.range_empty = true;
    }));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// Randomized differential over the bug-prone numeric knobs. Whatever the
    /// production validator decides, the independent reference must decide the
    /// same. A counterexample is a validator/spec divergence.
    #[test]
    fn randomized_verdicts_agree(
        version in 0u8..4,
        coinbase in any::<bool>(),
        num_inputs in 0usize..3,
        num_outputs in 0usize..3,
        ring_size in 9usize..14,
        fee in prop_oneof![Just(0u64), Just(1u64), 1_000u64..2_000_000u64, Just(50_000_000u64)],
        enc_len in prop_oneof![Just(0usize), Just(8usize), Just(64usize), Just(65usize)],
        memo_len in prop_oneof![Just(0usize), Just(256usize), Just(257usize)],
        stealth_zero in any::<bool>(),
        commit_zero in any::<bool>(),
        ki_zero in any::<bool>(),
        dup_ki in any::<bool>(),
        range_empty in any::<bool>(),
    ) {
        let p = P {
            version,
            coinbase,
            num_inputs,
            num_outputs,
            ring_size,
            fee,
            enc_len,
            memo_len,
            stealth_zero,
            commit_zero,
            ki_zero,
            dup_ki,
            range_empty,
        };
        let tx = build(&p);
        let real = validate_transaction_basic(&tx).is_ok();
        let reference = reference_verdict(&tx).is_ok();
        prop_assert_eq!(
            real,
            reference,
            "verdict differs for {:?}: real={} reference={} (reason {:?})",
            p, real, reference, reference_verdict(&tx).err()
        );
    }
}
