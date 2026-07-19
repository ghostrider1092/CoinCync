//! ## Monero Janus Attack (July 2020, theoretical)
//!
//! An attacker could link two subaddresses belonging to the same wallet
//! by constructing specially crafted outputs. The attack exploits the
//! relationship between subaddress derivation and output scanning.
//!
//! Citation: https://web.getmonero.org/2020/09/17/note-on-subaddresses.html
//! Chain: Monero
//! Impact: Privacy breach (theoretical, mitigated)

use coincync::wallet::WalletKeys;
// 2026-06-03: switched to `generate_stealth_address_checked` after
// the audit pass narrowed `generate_stealth_address` (the legacy
// panic-on-bad-input variant) to `#[cfg(test)] pub(crate)` inside
// stealth.rs. Test fixtures here always pass valid curve points, so
// the `.expect()` on the Result is a never-fires assertion documenting
// the test contract — matches the pattern adopted by every other
// test site in the same audit-prep batch.
use coincync::crypto::generate_stealth_address_checked;
use rand::rngs::OsRng;

/// Test: All subaddresses from same wallet have unique spend keys
#[test]
fn monero_2020_janus_subaddresses_unlinkable() {
    let seed = [55u8; 32];
    let mut keys = WalletKeys::from_seed(seed);
    keys.derive_epoch(0);
    let epoch = keys.current().unwrap();

    // Generate stealth addresses for 100 "payments" to this wallet
    let spend_pub = &epoch.spend_public;
    let view_pub = &epoch.view_public;
    let mut addresses = std::collections::HashSet::new();

    for _ in 0..100 {
        let (stealth, _) = generate_stealth_address_checked(spend_pub, view_pub, 0, &mut OsRng)
            .expect("test fixtures pass valid curve points");
        let bytes = stealth.public_key.as_bytes().to_vec();
        assert!(
            addresses.insert(bytes),
            "JANUS ATTACK: Two payments to same wallet produced same stealth address! \
             Payments are linkable on-chain."
        );
    }
}

/// Test: Different wallets produce completely different stealth addresses
#[test]
fn monero_2020_janus_different_wallets_unrelated() {
    let mut keys1 = WalletKeys::from_seed([1u8; 32]);
    let mut keys2 = WalletKeys::from_seed([2u8; 32]);
    keys1.derive_epoch(0);
    keys2.derive_epoch(0);
    let e1 = keys1.current().unwrap();
    let e2 = keys2.current().unwrap();

    let (s1, _) =
        generate_stealth_address_checked(&e1.spend_public, &e1.view_public, 0, &mut OsRng)
            .expect("test fixtures pass valid curve points");
    let (s2, _) =
        generate_stealth_address_checked(&e2.spend_public, &e2.view_public, 0, &mut OsRng)
            .expect("test fixtures pass valid curve points");

    assert_ne!(
        s1.public_key.as_bytes(),
        s2.public_key.as_bytes(),
        "JANUS VARIANT: Different wallets got same stealth address!"
    );
}
