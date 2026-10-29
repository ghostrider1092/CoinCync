//! LIVE wired-breaker test: the mempool circuit breaker, wired into the REAL
//! admission chokepoint (`Mempool::admit_after_checks`), driven by REAL
//! transactions through the real admission path — then watched tripping on a
//! real flood and recovering on a real drain.
//!
//! Uses `add_skip_crypto` (the `test-utilities` admission escape hatch that runs
//! ALL non-crypto admission — structural / fee / key-image / size — and funnels
//! through the same `admit_after_checks` the production `add()` uses, so the
//! wired breaker hook fires on real post-admission mempool state). The txs are
//! real minimal Transfers with distinct key images; only the (expensive) ring/
//! range-proof crypto is skipped, which the mempool-SIZE breaker doesn't read.
//!
//! Run:
//!   cargo test --test mempool_breaker_wired_live \
//!     --features "testnet test-utilities mempool-breaker breaker-recovery" -- --nocapture

#![cfg(all(
    feature = "test-utilities",
    feature = "mempool-breaker",
    feature = "breaker-recovery"
))]

use coincync::breaker_recovery::BreakerState;
use coincync::constants::MIN_FEE_PER_BYTE;
use coincync::crypto::{ClsagSignature, KeyImage as CryptoKeyImage, SecretScalar};
use coincync::mempool::Mempool;
use coincync::mempool_live_breaker as lb;
use coincync::primitives::{Amount, KeyImage, PublicKey};
use coincync::transaction::{RingMemberRef, Transaction, TxInput, TxOutput, TxType};

fn make_secret(seed: u8) -> SecretScalar {
    // Distinct per seed AND never the zero scalar (a zero scalar yields a zero
    // key image, which admission rejects as a double-spend-bypass).
    let mut b = [0u8; 32];
    b[0] = seed;
    b[1] = 0x11;
    SecretScalar::from_bytes(b)
}
fn make_keyimage(seed: u8) -> (KeyImage, CryptoKeyImage, SecretScalar) {
    let secret = make_secret(seed);
    let crypto_ki = CryptoKeyImage::from_secret(&secret);
    (KeyImage::from_bytes(crypto_ki.to_bytes()), crypto_ki, secret)
}
fn make_ring(seed: u8, size: usize) -> Vec<RingMemberRef> {
    (0..size)
        .map(|i| {
            let s = make_secret(seed.wrapping_add(i as u8 + 100));
            let p = s.to_public();
            RingMemberRef {
                public_key: PublicKey::from_bytes(p.to_bytes()),
                commitment: p.to_bytes(),
            }
        })
        .collect()
}
fn make_output(seed: u8) -> TxOutput {
    let s = make_secret(seed.wrapping_add(200));
    let p = s.to_public();
    TxOutput {
        stealth_address: PublicKey::from_bytes(p.to_bytes()),
        tx_public_key: PublicKey::from_bytes(p.to_bytes()),
        commitment: p.to_bytes(),
        encrypted_amount: vec![0u8; 8],
        view_tag: seed,
        lock_height: None,
        encrypted_memo: Vec::new(),
    }
}
/// A minimal, admissible (non-crypto) Transfer with a key image unique to `seed`.
fn make_transfer(seed: u8) -> Transaction {
    // Mandatory-privacy policy enforces a minimum ring size (Article III) even on
    // the skip-crypto admission path, so use the required ring size.
    const RING: usize = 11;
    let (ki, crypto_ki, secret) = make_keyimage(seed);
    let ring = make_ring(seed, RING);
    let sig = ClsagSignature {
        key_image: crypto_ki,
        commitment_image: secret.to_public(),
        c1: [seed; 32],
        responses: vec![[seed; 32]; RING],
    };
    let mut tx = Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            key_image: ki,
            ring_members: ring,
            signature: sig,
            pseudo_output_commitment: secret.to_public().to_bytes(),
        }],
        outputs: vec![make_output(seed)],
        fee: Amount::from_atomic(0),
        range_proof: vec![0u8; 64],
        extra: vec![seed],
    };
    let min_fee = tx.size() as u64 * MIN_FEE_PER_BYTE;
    tx.fee = Amount::from_atomic(min_fee.max(1));
    tx
}

#[test]
fn mempool_breaker_wired_live_on_real_txs() {
    std::env::set_var("COINCYNC_MEMPOOL_BREAKER_MAX_COUNT", "5");
    lb::reset();

    let mut mp = Mempool::new();
    println!("\n== mempool breaker WIRED LIVE (real Transfer txs via admit path, cap=5) ==");

    // FLOOD: 10 real txs through the real admission chokepoint.
    let mut hashes = Vec::new();
    for seed in 0..10u8 {
        let h = mp.add_skip_crypto(make_transfer(seed)).expect("admit");
        hashes.push(h);
        println!("  admit seed={seed:<2} real_len={} breaker={:?}", mp.len(), lb::state());
    }
    assert_eq!(mp.len(), 10, "ten real txs admitted");
    assert_eq!(
        lb::state(),
        Some(BreakerState::Open),
        "a REAL mempool flood (len>5) must trip the wired breaker"
    );

    // DRAIN below the cap.
    for h in &hashes {
        mp.remove(h);
    }
    assert_eq!(mp.len(), 0);
    println!("  drained -> real_len=0 (breaker still {:?}; removals don't tick it)", lb::state());

    // HEAL: re-admit under the cap → healthy observations → recovery.
    for seed in 100..104u8 {
        mp.add_skip_crypto(make_transfer(seed)).expect("re-admit");
        println!("  heal admit seed={seed:<3} real_len={} breaker={:?}", mp.len(), lb::state());
    }
    assert_eq!(
        lb::state(),
        Some(BreakerState::Closed),
        "real drain + under-cap re-admits must reconnect the wired breaker"
    );
    println!("  => wired breaker tripped on a REAL flood and recovered on real drain.\n");
}
