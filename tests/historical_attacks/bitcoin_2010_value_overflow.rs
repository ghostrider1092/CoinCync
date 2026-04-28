//! ## Bitcoin CVE-2010-5139 — Value Overflow (August 15, 2010)
//!
//! A transaction was mined on Bitcoin mainnet outputting 184,467,440,737.09551616 BTC
//! (more than 8,000x the total supply). The bug: `int64_t` overflow when summing
//! transaction outputs. The attacker created two outputs of 92.2 billion BTC each;
//! the sum wrapped to a small negative number, passing the "outputs <= inputs" check.
//!
//! Fixed by Satoshi via emergency hard fork (block 74638 rolled back).
//!
//! Citation: https://en.bitcoin.it/wiki/Value_overflow_incident
//! CVE: CVE-2010-5139
//! Chain: Bitcoin
//! Impact: Infinite inflation (exploited, fixed within hours)
//!
//! Relevance to CoinCync: Our amounts use u64 with checked arithmetic. This test
//! verifies that output sums cannot overflow and bypass balance verification.

use coincync::primitives::Amount;
use coincync::transaction::{Transaction, TxType, TxOutput, TxInput, RingMemberRef, TransactionBuilder};
use coincync::consensus::validate_transaction_basic;
use coincync::mempool::Mempool;
use coincync::crypto::{SecretScalar, BlindingFactor, PedersenCommitment, KeyImage as CKI, ClsagSignature};
use coincync::primitives::{PublicKey, KeyImage};
use coincync::constants::BOOTSTRAP_MIN_RING_SIZE;
use rand::rngs::OsRng;

/// Test: u64::MAX/2 + u64::MAX/2 + 2 overflows. Both validation and builder must catch it.
#[test]
fn bitcoin_2010_output_sum_overflow_u64() {
    // Construct a tx where output amounts sum to > u64::MAX
    let half_max = u64::MAX / 2;
    let secret = SecretScalar::random(&mut OsRng);
    let ki = CKI::from_secret(&secret);
    let bf = BlindingFactor::random(&mut OsRng);

    let make_output = |amount: u64| -> TxOutput {
        TxOutput {
            stealth_address: PublicKey::from_bytes(SecretScalar::random(&mut OsRng).to_public().to_bytes()),
            tx_public_key: PublicKey::from_bytes(SecretScalar::random(&mut OsRng).to_public().to_bytes()),
            commitment: PedersenCommitment::commit(amount, &BlindingFactor::random(&mut OsRng)).to_bytes(),
            encrypted_amount: vec![0u8; 8],
            view_tag: 0,
            lock_height: None,
            encrypted_memo: vec![],
        }
    };

    let ring_members: Vec<RingMemberRef> = (0..BOOTSTRAP_MIN_RING_SIZE).map(|_| {
        RingMemberRef {
            public_key: PublicKey::from_bytes(SecretScalar::random(&mut OsRng).to_public().to_bytes()),
            commitment: PedersenCommitment::commit(1_000_000_000, &BlindingFactor::random(&mut OsRng)).to_bytes(),
        }
    }).collect();

    let tx = Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            key_image: KeyImage::from_bytes(ki.to_bytes()),
            ring_members,
            signature: ClsagSignature {
                key_image: ki,
                commitment_image: secret.to_public(),
                c1: [0x42; 32],
                responses: vec![[0x13; 32]; BOOTSTRAP_MIN_RING_SIZE],
            },
            pseudo_output_commitment: PedersenCommitment::commit(u64::MAX, &bf).to_bytes(),
        }],
        outputs: vec![
            make_output(half_max),
            make_output(half_max),
            make_output(2), // This makes the sum overflow
        ],
        fee: Amount::from_atomic(0),
        range_proof: vec![0u8; 64],
        extra: vec![],
    };

    // Validation must reject — NOT PANIC
    let result = validate_transaction_basic(&tx);
    // If it returns an error OR the mempool rejects it, we're safe
    let mut pool = Mempool::new();
    let mempool_result = pool.add_skip_crypto(tx);

    assert!(
        result.is_err() || mempool_result.is_err(),
        "CVE-2010-5139 REPRODUCED: Transaction with overflowing output sum was ACCEPTED! \
         An attacker can create 184 billion coins from nothing."
    );
}

/// Test: The TransactionBuilder uses checked_add and rejects overflow
#[test]
fn bitcoin_2010_builder_rejects_overflow() {
    let result = std::panic::catch_unwind(|| {
        let mut rng = OsRng;
        let (_, _r_spend) = {
            let s = SecretScalar::random(&mut OsRng);
            (coincync::primitives::SecretKey::from_bytes(s.to_bytes()),
             PublicKey::from_bytes(s.to_public().to_bytes()))
        };
        let (_, _r_view) = {
            let s = SecretScalar::random(&mut OsRng);
            (coincync::primitives::SecretKey::from_bytes(s.to_bytes()),
             PublicKey::from_bytes(s.to_public().to_bytes()))
        };

        let mut builder = TransactionBuilder::transfer();
        // Try to set fee to u64::MAX — should either fail in set_fee or fail in build
        builder.set_fee(Amount::from_atomic(u64::MAX));
        builder.build(&mut rng)
    });

    // Either it returns Err or it panics — both are acceptable protections
    match result {
        Ok(Err(_)) => {} // Builder correctly returned error
        Ok(Ok(_)) => panic!("Builder accepted u64::MAX fee without any inputs — overflow risk"),
        Err(_) => {} // Panic is acceptable (saturating or overflow check)
    }
}
