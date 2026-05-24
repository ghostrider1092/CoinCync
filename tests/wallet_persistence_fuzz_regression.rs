//! # Wallet-persistence fuzz-crash regressions
//!
//! Locks in the fixes for every `crash-*` artifact the overnight fuzz
//! harness has discovered against `fuzz_wallet_persistence`. Each
//! crash file is bundled here as a fixture; the test asserts the
//! current code returns `Err` (not panic, not SIGABRT, not infinite
//! loop) when fed the input.
//!
//! Adding a new crash regression:
//!   1. Copy the crash artifact from
//!      `~/coincync-fuzz/fuzz/artifacts/fuzz_wallet_persistence/`
//!      into `tests/fixtures/wallet_persistence_crashes/`.
//!   2. Add the file path to the `CRASHES` list below.
//!   3. Run `cargo test --test wallet_persistence_fuzz_regression`
//!      — expect failure if the crash isn't fixed yet.
//!   4. Land the fix in `src/wallet/persistence.rs::WalletHeader::validate`
//!      (or upstream of it). Test should now pass.
//!
//! The fixtures are tracked in git so a fresh checkout doesn't
//! silently lose coverage of historically-known crashes.

use coincync::wallet::persistence::load_wallet_from_bytes;

/// Crash artifacts. Each one is a known-fixed input that previously
/// panicked the wallet loader. Adding a new entry should be paired
/// with the fix; see the module doc comment for the workflow.
const CRASHES: &[(&str, &str)] = &[
    (
        "crash-1c3a7e3e370f472432dfbedaba8b8ce6b7338246",
        "Argon2 MemoryTooLittle: m_cost < 8 * p_cost — fixed by RFC 9106 §3.1 \
         cross-constraint in validate() (commit 69c27dc, 2026-05-23)",
    ),
    (
        "crash-6b3e53ff71c9e8e1cda383857565624d387c68fe",
        "Argon2 m_cost ABOVE upper bound — fixed by KDF_M_COST_MAX_KIB check \
         in validate() (2026-05-19)",
    ),
    (
        "crash-c0a0e826ccb435bd9d48b5b1ed6ab0e0e6063050",
        "Argon2 m_cost BELOW MIN_M_COST — fixed by KDF_M_COST_MIN_KIB check \
         in validate() (2026-05-19)",
    ),
];

#[test]
fn known_crashes_return_err_not_panic() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/wallet_persistence_crashes");
    let mut failures = Vec::new();

    for (filename, description) in CRASHES {
        let path = format!("{}/{}", dir, filename);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                failures.push(format!("FIXTURE-MISSING {}: {} ({})", filename, e, description));
                continue;
            }
        };

        // Both password-less and password-attempted paths must surface
        // an Err for the same crash input — the fuzz target probes
        // both, so the regression test does too.
        let none_result = std::panic::catch_unwind(|| {
            load_wallet_from_bytes(&bytes, None)
        });
        let some_result = std::panic::catch_unwind(|| {
            load_wallet_from_bytes(&bytes, Some("fuzz-passphrase"))
        });

        match none_result {
            Ok(Err(_)) => { /* expected */ }
            Ok(Ok(_)) => {
                failures.push(format!(
                    "REGRESSION {}: load_wallet_from_bytes(_, None) returned Ok (should be Err). {}",
                    filename, description
                ));
            }
            Err(_) => {
                failures.push(format!(
                    "REGRESSION {}: load_wallet_from_bytes(_, None) PANICKED (should be Err). {}",
                    filename, description
                ));
            }
        }
        match some_result {
            Ok(Err(_)) => { /* expected */ }
            Ok(Ok(_)) => {
                failures.push(format!(
                    "REGRESSION {}: load_wallet_from_bytes(_, Some(pw)) returned Ok (should be Err). {}",
                    filename, description
                ));
            }
            Err(_) => {
                failures.push(format!(
                    "REGRESSION {}: load_wallet_from_bytes(_, Some(pw)) PANICKED (should be Err). {}",
                    filename, description
                ));
            }
        }
    }

    if !failures.is_empty() {
        panic!(
            "Wallet-persistence fuzz-crash regression failures:\n  - {}",
            failures.join("\n  - ")
        );
    }
}
