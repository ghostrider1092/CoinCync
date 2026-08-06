use coincync::config::NetworkType;
use coincync::consensus::{v1_0_12_rules_active, validate_transaction_for_network};
use coincync::constants::HARD_FORK_V1_0_12_HEIGHT;
use coincync::crypto::{ClsagSignature, KeyImage as CryptoKeyImage, SecretScalar};
use coincync::primitives::{Amount, KeyImage, PublicKey};
use coincync::storage::UtxoSet;
use coincync::transaction::{Transaction, TxInput, TxOutput, TxType};

fn malformed_amount_transaction() -> Transaction {
    let secret = SecretScalar::from_bytes([7; 32]);
    let point = secret.to_public();
    let crypto_key_image = CryptoKeyImage::from_secret(&secret);
    Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            key_image: KeyImage::from_bytes(point.to_bytes()),
            ring_members: Vec::new(),
            signature: ClsagSignature {
                key_image: crypto_key_image,
                commitment_image: point,
                c1: [1; 32],
                responses: Vec::new(),
            },
            pseudo_output_commitment: point.to_bytes(),
        }],
        outputs: vec![TxOutput {
            stealth_address: PublicKey::from_bytes(point.to_bytes()),
            tx_public_key: PublicKey::from_bytes(point.to_bytes()),
            commitment: point.to_bytes(),
            encrypted_amount: vec![0; 7],
            view_tag: 0,
            lock_height: None,
            encrypted_memo: Vec::new(),
        }],
        fee: Amount::from_atomic(1),
        range_proof: Vec::new(),
        extra: Vec::new(),
    }
}

#[test]
fn mainnet_activates_v1_0_12_rules_from_genesis() {
    assert!(v1_0_12_rules_active(NetworkType::Mainnet, 0));
    assert!(v1_0_12_rules_active(NetworkType::Mainnet, 1));
    assert!(v1_0_12_rules_active(
        NetworkType::Mainnet,
        HARD_FORK_V1_0_12_HEIGHT.saturating_sub(1),
    ));
}

#[test]
fn testnet_preserves_the_height_13_000_flag_day() {
    assert!(HARD_FORK_V1_0_12_HEIGHT > 0);
    assert!(!v1_0_12_rules_active(NetworkType::Testnet, 0));
    assert!(!v1_0_12_rules_active(
        NetworkType::Testnet,
        HARD_FORK_V1_0_12_HEIGHT - 1,
    ));
    assert!(v1_0_12_rules_active(
        NetworkType::Testnet,
        HARD_FORK_V1_0_12_HEIGHT,
    ));
}

#[test]
fn regtest_uses_hardened_rules_from_genesis() {
    assert!(v1_0_12_rules_active(NetworkType::Regtest, 0));
}

#[test]
fn transaction_validation_uses_the_network_activation_schedule() {
    let tx = malformed_amount_transaction();
    let utxos = UtxoSet::new();

    let mainnet_error = validate_transaction_for_network(&tx, &utxos, 0, NetworkType::Mainnet)
        .unwrap_err()
        .to_string();
    assert!(mainnet_error.contains("encrypted_amount must be exactly 8 bytes"));

    let testnet_before = validate_transaction_for_network(
        &tx,
        &utxos,
        HARD_FORK_V1_0_12_HEIGHT - 1,
        NetworkType::Testnet,
    )
    .unwrap_err()
    .to_string();
    assert!(!testnet_before.contains("encrypted_amount must be exactly 8 bytes"));

    let testnet_at = validate_transaction_for_network(
        &tx,
        &utxos,
        HARD_FORK_V1_0_12_HEIGHT,
        NetworkType::Testnet,
    )
    .unwrap_err()
    .to_string();
    assert!(testnet_at.contains("encrypted_amount must be exactly 8 bytes"));

    let regtest_error = validate_transaction_for_network(&tx, &utxos, 0, NetworkType::Regtest)
        .unwrap_err()
        .to_string();
    assert!(regtest_error.contains("encrypted_amount must be exactly 8 bytes"));
}
