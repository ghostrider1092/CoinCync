//! ## Monero CVE-2019-18936 — check_money_overflow (November 2019)
//!
//! The check_money_overflow function had a bug allowing transactions where
//! the sum of amounts could overflow, appearing valid despite spending
//! more than existed.
//!
//! Citation: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-18936
//! Chain: Monero
//! Impact: Potential inflation (patched before exploitation)

use coincync::primitives::Amount;

/// Test: Amount::saturating_add doesn't wrap
#[test]
fn monero_2019_amount_saturating_add() {
    let max = Amount::from_atomic(u64::MAX);
    let one = Amount::from_atomic(1);
    let result = max.saturating_add(one);
    assert_eq!(
        result.as_atomic(), u64::MAX,
        "CVE-2019-18936: Amount addition wraps around instead of saturating!"
    );
}

/// Test: Amount overflow check catches MAX + MAX
#[test]
fn monero_2019_double_max_saturates() {
    let max = Amount::from_atomic(u64::MAX);
    let result = max.saturating_add(max);
    assert_eq!(
        result.as_atomic(), u64::MAX,
        "CVE-2019-18936: Adding u64::MAX + u64::MAX wraps to small number!"
    );
}

/// Test: checked_add returns None on overflow
#[test]
fn monero_2019_checked_add_catches_overflow() {
    let a = u64::MAX - 100;
    let b = 200u64;
    let result = a.checked_add(b);
    assert!(
        result.is_none(),
        "CVE-2019-18936: checked_add doesn't catch overflow! \
         Attacker can overflow amount sums."
    );
}
