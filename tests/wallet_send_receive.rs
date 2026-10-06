//! # Send ↔ receive derivation symmetry (P0 funds-correctness)
//!
//! These integration tests close the highest-value gap in the wallet test
//! plan: nothing previously proved that an output *built by the send/assembly
//! path* is *re-detected by the scanner* and decrypts to the exact amount. A
//! silent asymmetry between the two sides is a fund-loss bug — the recipient
//! (or the sender, for change) would never see the money.
//!
//! Each test drives one real output kind end to end, using only real crypto /
//! wallet builders (no hand-rolled stealth math):
//!
//!   1. **main-address payment** — built via `prepare_privacy_transaction` +
//!      `build_prepared_privacy_transaction`, detected by the recipient.
//!   2. **subaddress payment** (`is_subaddress = true`, so `R = r*D_i`) —
//!      detected on the subaddress key AND shown spendable via
//!      `decrypted_to_utxo` (its key image uses the +m subaddress offset).
//!   3. **change output** back to the sender's own primary address — the same
//!      transaction's change is re-detected by the *sender's* scanner.
//!   4. **coinbase output** — built exactly as `mining::block_builder` does
//!      (`coinbase_stealth_address` + plaintext amount), detected as coinbase.
//!   5. **coinbase-to-subaddress** — pins the *actual* behaviour: the scanner's
//!      coinbase path is primary-only and forces `subaddress_index = None`, so
//!      a coinbase mined to a subaddress is NOT recovered (documented limit).
//!
//! Plus the **negative control**: a subaddress destination sent with the
//! `is_subaddress` flag WRONG (marked standard, `R = r*G`) is undetectable by
//! the recipient — the exact bug the `is_subaddress` flag exists to prevent.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use coincync::crypto::{
    coinbase_stealth_address, BlindingFactor, PedersenCommitment, SecretScalar, Subaddress,
};
use coincync::decoy::{
    DecoyDistributionSnapshot, HeightOutputCount, OutputLocator, ResolvedDecoyOutput,
    ResolvedDecoySnapshot, DECOY_LOCATOR_POLICY_VERSION,
};
use coincync::primitives::{Amount, Hash, KeyImage, PublicKey, SecretKey};
use coincync::transaction::{Transaction, TxOutput, TxType};
use coincync::wallet::decoy_selection::{
    allocate_unique_rings, build_covered_request, validate_covered_response, AllocatedRings,
    RealOutputIdentity, ValidatedDecoySnapshot,
};
use coincync::wallet::scanner::decrypted_to_utxo;
use coincync::wallet::send::{
    build_prepared_privacy_transaction, estimate_fee_with_multiplier, prepare_privacy_transaction,
    Payment, SendRequest, SpendContext,
};
use coincync::wallet::{generate_view_tag, Balance, KeyEpoch, WalletScanner, UTXO};

const TARGET_HEIGHT: u64 = 500;
const UTXO_AMOUNT: u64 = 40_000_000;

// ===========================================================================
// Helpers
// ===========================================================================

/// A spendable `KeyEpoch` with real (deterministic) curve keys.
fn epoch_from_seed(seed: u8) -> KeyEpoch {
    let spend_secret = SecretKey::from_bytes([seed; 32]);
    let view_secret = SecretKey::from_bytes([seed ^ 0x55; 32]);
    let spend_public = spend_secret.public_key();
    let view_public = view_secret.public_key();
    KeyEpoch {
        epoch: 0,
        spend_secret,
        spend_public,
        view_secret,
        view_public,
    }
}

/// A mature UTXO with a canonical locator (required by `prepare`). The
/// `tx_public_key` is the identity point (a valid curve point), which is all
/// `prepare_input`'s one-time-secret derivation needs.
fn mature_utxo(amount: u64, tag: u8, out_index: u8, loc_height: u64) -> UTXO {
    UTXO {
        tx_hash: Hash::from_bytes([tag; 32]),
        output_index: out_index,
        output_locator: Some(OutputLocator {
            height: loc_height,
            ordinal: 0,
        }),
        amount: Amount::from_atomic(amount),
        height: 10,
        key_image: KeyImage::from_bytes([tag; 32]),
        spent: false,
        amount_blinding_bytes: [tag; 32],
        tx_public_key: PublicKey::from_bytes([0u8; 32]),
        lock_height: None,
        subaddress_account: None,
        subaddress_index: None,
    }
}

/// Allocate transaction-wide rings for a set of real outputs via the real
/// decoy-selection pipeline. Real locators resolve to their true identity;
/// decoy locators resolve to fresh valid (non-identity) curve points so the
/// built transaction's CLSAG signing succeeds.
fn rings_for(
    real_outputs: &[RealOutputIdentity],
    ring_size: usize,
    rng: &mut ChaCha20Rng,
) -> AllocatedRings {
    let raw = DecoyDistributionSnapshot {
        snapshot_height: 1_000,
        snapshot_hash: Hash::from_bytes([7; 32]),
        policy_version: DECOY_LOCATOR_POLICY_VERSION,
        heights: (0..=1_000)
            .map(|height| HeightOutputCount { height, count: 1 })
            .collect(),
    };
    let snapshot = ValidatedDecoySnapshot::try_from(raw).expect("valid snapshot");
    let real_locators: Vec<OutputLocator> =
        real_outputs.iter().map(|real| real.locator()).collect();
    let request = build_covered_request(&snapshot, &real_locators, ring_size, 10, rng)
        .expect("covered request");

    let real_by_locator: std::collections::HashMap<OutputLocator, &RealOutputIdentity> =
        real_outputs.iter().map(|real| (real.locator(), real)).collect();
    let outputs: Vec<ResolvedDecoyOutput> = request
        .locators()
        .iter()
        .map(|locator| {
            if let Some(real) = real_by_locator.get(locator) {
                ResolvedDecoyOutput {
                    locator: *locator,
                    public_key: real.public_key(),
                    commitment: real.commitment(),
                    height: locator.height,
                    is_coinbase: false,
                    lock_height: None,
                }
            } else {
                let public_key =
                    PublicKey::from_bytes(SecretScalar::random(rng).to_public().to_bytes());
                let commitment =
                    PedersenCommitment::commit(0, &BlindingFactor::random(rng)).to_bytes();
                ResolvedDecoyOutput {
                    locator: *locator,
                    public_key,
                    commitment,
                    height: locator.height,
                    is_coinbase: false,
                    lock_height: None,
                }
            }
        })
        .collect();
    let snapshot_id = request.snapshot_id();
    let response = ResolvedDecoySnapshot {
        snapshot_height: snapshot_id.height(),
        snapshot_hash: snapshot_id.hash(),
        policy_version: snapshot_id.policy_version(),
        outputs,
    };
    let validated = validate_covered_response(request, response).expect("validated response");
    allocate_unique_rings(validated, real_outputs, rng).expect("rings allocate")
}

/// Build a real single-recipient transfer via the send/assembly path. The
/// change (if any) goes back to `sender`'s primary address. Funds the wallet
/// with two mature UTXOs summing to `2 * UTXO_AMOUNT`.
fn send_transfer(
    sender: &KeyEpoch,
    recipient_spend: PublicKey,
    recipient_view: PublicKey,
    is_subaddress: bool,
    amount: u64,
    rng: &mut ChaCha20Rng,
) -> Transaction {
    let context = SpendContext::for_target_height(TARGET_HEIGHT);
    let payment = if is_subaddress {
        Payment::new_subaddress(recipient_spend, recipient_view, Amount::from_atomic(amount))
    } else {
        Payment::new(recipient_spend, recipient_view, Amount::from_atomic(amount))
    };
    let mut balance = Balance::new();
    balance.add_utxo(mature_utxo(UTXO_AMOUNT, 0xA0, 0, 100));
    balance.add_utxo(mature_utxo(UTXO_AMOUNT, 0xB0, 1, 110));

    let prepared =
        prepare_privacy_transaction(&balance, SendRequest::new(vec![payment], context), sender, rng)
            .expect("prepare");
    let rings = rings_for(&prepared.real_outputs(), context.ring_size(), rng);
    build_prepared_privacy_transaction(prepared, rings, rng).expect("build")
}

/// The change amount `send_transfer` leaves for a single payment of `amount`
/// (two `UTXO_AMOUNT` inputs, standard fee).
fn expected_change(amount: u64) -> u64 {
    let fee = estimate_fee_with_multiplier(2, 2, TARGET_HEIGHT, 1.0).as_atomic();
    UTXO_AMOUNT * 2 - amount - fee
}

/// Build a coinbase `TxOutput` exactly as `mining::block_builder` does:
/// ECDH-derived stealth address + plaintext little-endian amount + sender-side
/// view tag + zero-blinding commitment.
fn coinbase_output(spend_pub: &PublicKey, view_pub: &PublicKey, height: u64, amount: u64) -> TxOutput {
    let miner_secret = [0x9Au8; 32];
    let (stealth, tx_secret) =
        coinbase_stealth_address(spend_pub, view_pub, height, 0, &miner_secret)
            .expect("coinbase stealth");
    let view_tag = generate_view_tag(view_pub, &tx_secret, 0);
    let commitment = PedersenCommitment::commit(amount, &BlindingFactor::zero()).to_bytes();
    TxOutput {
        stealth_address: stealth.public_key,
        tx_public_key: stealth.tx_public_key,
        commitment,
        encrypted_amount: amount.to_le_bytes().to_vec(),
        view_tag,
        lock_height: None,
        encrypted_memo: vec![],
    }
}

fn coinbase_tx(outputs: Vec<TxOutput>) -> Transaction {
    Transaction {
        version: 1,
        tx_type: TxType::Coinbase,
        inputs: vec![],
        outputs,
        fee: Amount::ZERO,
        range_proof: vec![],
        extra: vec![],
    }
}

// ===========================================================================
// Symmetry tests — the five output kinds
// ===========================================================================

/// Kind 1 (main-address payment) AND kind 3 (change back to sender's primary),
/// in one built transfer: the recipient re-detects the payment and the sender
/// re-detects the change, both decrypting to the exact amounts.
#[test]
fn symmetry_main_address_payment_and_change_detected_and_decrypt() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let sender = epoch_from_seed(0x10);
    let recipient = epoch_from_seed(0x20);
    let amount = 10_000_000u64;

    let tx = send_transfer(
        &sender,
        recipient.spend_public,
        recipient.view_public,
        false,
        amount,
        &mut rng,
    );

    // Kind 1: recipient detects the payment output and decrypts the amount.
    let mut recipient_scanner = WalletScanner::new();
    recipient_scanner.add_keys(recipient.view_secret.clone(), recipient.spend_public, 0);
    let recipient_found = recipient_scanner.scan_transaction(&tx);
    assert_eq!(
        recipient_found.len(),
        1,
        "recipient detects exactly the payment output"
    );
    assert_eq!(recipient_found[0].amount, amount, "payment decrypts exactly");
    assert!(
        recipient_found[0].subaddress_index.is_none(),
        "a main-address payment is not attributed to a subaddress"
    );

    // Kind 3: sender re-detects the change output (back to own primary).
    let mut sender_scanner = WalletScanner::new();
    sender_scanner.add_keys(sender.view_secret.clone(), sender.spend_public, 0);
    let sender_found = sender_scanner.scan_transaction(&tx);
    assert_eq!(
        sender_found.len(),
        1,
        "sender detects exactly the change output"
    );
    assert_eq!(
        sender_found[0].amount,
        expected_change(amount),
        "change decrypts to inputs - payment - fee"
    );
}

/// Kind 2 (subaddress payment): built with `is_subaddress = true` (so
/// `R = r*D_i`), detected on the subaddress key, decrypts to the exact amount,
/// and `decrypted_to_utxo` yields a spendable UTXO carrying the (account,index)
/// association.
#[test]
fn symmetry_subaddress_payment_detected_spendable_and_decrypts() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let sender = epoch_from_seed(0x30);
    let recipient = epoch_from_seed(0x40);
    let account = 0u32;
    let index = 7u32;
    // D_i (spend) and C_i = a*D_i (view) via the canonical subaddress derivation.
    let sub = Subaddress::generate(&recipient.spend_public, &recipient.view_secret, account, index)
        .expect("subaddress");
    let amount = 12_000_000u64;

    let tx = send_transfer(
        &sender,
        sub.spend_public,
        sub.view_public,
        true,
        amount,
        &mut rng,
    );

    let mut scanner = WalletScanner::new();
    scanner.add_keys(recipient.view_secret.clone(), recipient.spend_public, 0);
    scanner.add_subaddress_keys(vec![(account, index, sub.spend_public)]);
    let found = scanner.scan_transaction(&tx);
    let payment = found
        .iter()
        .find(|output| output.subaddress_index == Some((account, index)))
        .expect("subaddress payment detected on the subaddress key");
    assert_eq!(payment.amount, amount, "subaddress payment decrypts exactly");

    // Spendability: the key image is derived with the +m subaddress offset and
    // the UTXO carries the (account, index) association.
    let utxo = decrypted_to_utxo(payment, &recipient.view_secret, &recipient.spend_secret, 600)
        .expect("decrypted_to_utxo");
    assert_eq!(utxo.subaddress_account, Some(account));
    assert_eq!(utxo.subaddress_index, Some(index));
    assert_eq!(utxo.amount, Amount::from_atomic(amount));
}

/// Kind 4 (coinbase): a coinbase output built the way the miner builds it is
/// detected by the payee's scanner and decrypts to the plaintext amount.
#[test]
fn symmetry_coinbase_output_detected_and_decrypts_to_plaintext_amount() {
    let miner = epoch_from_seed(0x50);
    let height = 42u64;
    let amount = 50_000_000_000u64;

    let tx = coinbase_tx(vec![coinbase_output(
        &miner.spend_public,
        &miner.view_public,
        height,
        amount,
    )]);

    let mut scanner = WalletScanner::new();
    scanner.add_keys(miner.view_secret.clone(), miner.spend_public, 0);
    let found = scanner.scan_transaction(&tx);
    assert_eq!(found.len(), 1, "miner detects the coinbase output");
    assert_eq!(
        found[0].amount, amount,
        "coinbase amount is read from the plaintext little-endian field"
    );
    assert!(
        found[0].subaddress_index.is_none(),
        "coinbase is always attributed to the primary address"
    );
}

/// Kind 5 (coinbase-to-subaddress): pins the *actual* behaviour. The scanner's
/// coinbase path checks the PRIMARY spend key only and forces
/// `subaddress_index = None`, so a coinbase whose payout keys are a subaddress
/// is NOT recovered — a documented attribution limitation. The same miner's
/// primary coinbase is recovered, confirming the scanner itself is healthy.
#[test]
fn symmetry_coinbase_to_subaddress_is_not_recovered_primary_only_scan() {
    let miner = epoch_from_seed(0x60);
    let account = 0u32;
    let index = 3u32;
    let sub = Subaddress::generate(&miner.spend_public, &miner.view_secret, account, index)
        .expect("subaddress");
    let height = 77u64;
    let amount = 50_000_000_000u64;

    let mut scanner = WalletScanner::new();
    scanner.add_keys(miner.view_secret.clone(), miner.spend_public, 0);
    scanner.add_subaddress_keys(vec![(account, index, sub.spend_public)]);

    // Coinbase mined to the subaddress: undetectable under the primary-only
    // coinbase scan (subaddress keys are never consulted on coinbase outputs).
    let to_sub = coinbase_tx(vec![coinbase_output(
        &sub.spend_public,
        &sub.view_public,
        height,
        amount,
    )]);
    assert!(
        scanner.scan_transaction(&to_sub).is_empty(),
        "a coinbase mined to a subaddress is not attributable (primary-only coinbase scan)"
    );

    // Control: the same miner's PRIMARY coinbase IS recovered.
    let to_primary = coinbase_tx(vec![coinbase_output(
        &miner.spend_public,
        &miner.view_public,
        height,
        amount,
    )]);
    let found = scanner.scan_transaction(&to_primary);
    assert_eq!(found.len(), 1, "primary coinbase is recovered");
    assert!(found[0].subaddress_index.is_none());
}

// ===========================================================================
// Negative control
// ===========================================================================

/// A subaddress destination sent with `is_subaddress = FALSE` (mis-flagged as
/// a standard/main-address payment, so `R = r*G` instead of `R = r*D_i`) is
/// undetectable by the recipient: their published subaddress view key is
/// `C_i = a*D_i`, so `a*R = a*r*G != r*C_i` and ownership never matches. This is
/// the exact fund-loss bug the `is_subaddress` flag exists to prevent.
#[test]
fn negative_control_subaddress_marked_standard_is_undetectable_by_recipient() {
    let mut rng = ChaCha20Rng::seed_from_u64(5);
    let sender = epoch_from_seed(0x70);
    let recipient = epoch_from_seed(0x80);
    let account = 0u32;
    let index = 9u32;
    let sub = Subaddress::generate(&recipient.spend_public, &recipient.view_secret, account, index)
        .expect("subaddress");
    let amount = 15_000_000u64;

    // BUG: subaddress destination, but flagged standard (is_subaddress = false).
    let tx = send_transfer(
        &sender,
        sub.spend_public,
        sub.view_public,
        false,
        amount,
        &mut rng,
    );

    let mut scanner = WalletScanner::new();
    scanner.add_keys(recipient.view_secret.clone(), recipient.spend_public, 0);
    scanner.add_subaddress_keys(vec![(account, index, sub.spend_public)]);
    let found = scanner.scan_transaction(&tx);

    assert!(
        found
            .iter()
            .all(|output| output.subaddress_index != Some((account, index))),
        "a mis-flagged subaddress payment must not be detected on the subaddress key"
    );
    assert!(
        found.is_empty(),
        "recipient detects nothing — neither the primary nor the subaddress key matches"
    );
}
