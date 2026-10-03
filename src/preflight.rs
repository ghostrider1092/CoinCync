//! Boot-time self-preflight guards.
//!
//! These are deliberately small, dependency-free checks that run before a node
//! touches the chain, in the same "refusing to start is the SAFE behaviour"
//! spirit as `db::verify_or_stamp_schema_version` and the genesis-on-load guard
//! in `chain::recovery`. See `docs/design/self-preflight-boot-guard.md`.
//!
//! The most important check here has no existing precedent in the codebase: the
//! consensus network is partly a *compile-time* cargo feature (`testnet` vs the
//! default/mainnet build — see the `#[cfg(feature = "testnet")]` pairs in
//! `constants.rs`), while `--network` is a *runtime* flag. Nothing stopped a
//! mainnet-compiled binary from being started as `--network testnet` (or the
//! reverse) — a footgun that can only be caught today by an operator manually
//! running `print-genesis-hash`. This module makes that check automatic.

use crate::config::NetworkType;
use crate::error::{Error, Result};

/// Environment override to skip the compiled-network guard for a deliberate
/// edge case. Mirrors the schema guard's "safe by default, operator can
/// override" stance. Set to `1` to disable.
pub const SKIP_ENV: &str = "COINCYNC_SKIP_NETWORK_PREFLIGHT";

/// True when this binary was compiled with the `testnet` cargo feature — the
/// same discriminator `constants.rs` uses for compile-time consensus consts.
/// A build without the feature is a mainnet (default) build.
pub const fn compiled_network_is_testnet() -> bool {
    cfg!(feature = "testnet")
}

/// Refuse the two dangerous crossings between the *compiled* network and the
/// requested *runtime* `--network`:
///
/// * a testnet-compiled binary asked to run `--network mainnet`, or
/// * a mainnet-compiled binary asked to run `--network testnet`.
///
/// `regtest` is permitted on either build (local/dev use), and running the same
/// network the binary was built for is of course fine.
///
/// Returns `Ok(())` immediately when [`SKIP_ENV`] is set to `1`.
pub fn check_compiled_network(runtime: NetworkType) -> Result<()> {
    if std::env::var(SKIP_ENV).as_deref() == Ok("1") {
        tracing::warn!(
            "{}=1 set - skipping the compiled-network preflight guard. \
             You are responsible for ensuring this binary matches --network {}.",
            SKIP_ENV,
            runtime.name(),
        );
        return Ok(());
    }
    classify(compiled_network_is_testnet(), runtime)
}

/// Pure classifier, split out so it is testable without touching env vars or the
/// compiled feature. `compiled_testnet` is what [`compiled_network_is_testnet`]
/// would return.
fn classify(compiled_testnet: bool, runtime: NetworkType) -> Result<()> {
    let compiled_label = if compiled_testnet { "testnet" } else { "mainnet" };
    match runtime {
        NetworkType::Mainnet if compiled_testnet => Err(Error::ConfigError(format!(
            "network mismatch: this binary was built with `--features testnet` (a {compiled} \
             build) but was asked to run --network mainnet. A testnet binary must never run on \
             mainnet — its compile-time consensus parameters differ. Rebuild without the testnet \
             feature for mainnet, or run --network testnet. (Override: {skip}=1)",
            compiled = compiled_label,
            skip = SKIP_ENV,
        ))),
        NetworkType::Testnet if !compiled_testnet => Err(Error::ConfigError(format!(
            "network mismatch: this binary was built WITHOUT the testnet feature (a {compiled} \
             build) but was asked to run --network testnet. Rebuild with \
             `--features \"randomx testnet\"` for testnet, or run --network mainnet. \
             (Override: {skip}=1)",
            compiled = compiled_label,
            skip = SKIP_ENV,
        ))),
        // Same network as compiled, or regtest on either build: allowed.
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_network_is_allowed() {
        // testnet binary -> testnet ok; mainnet binary -> mainnet ok
        assert!(classify(true, NetworkType::Testnet).is_ok());
        assert!(classify(false, NetworkType::Mainnet).is_ok());
    }

    #[test]
    fn regtest_allowed_on_either_build() {
        assert!(classify(true, NetworkType::Regtest).is_ok());
        assert!(classify(false, NetworkType::Regtest).is_ok());
    }

    #[test]
    fn testnet_binary_refuses_mainnet() {
        let err = classify(true, NetworkType::Mainnet).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("network mismatch"), "got: {msg}");
        assert!(msg.contains("mainnet"), "got: {msg}");
    }

    #[test]
    fn mainnet_binary_refuses_testnet() {
        let err = classify(false, NetworkType::Testnet).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("network mismatch"), "got: {msg}");
        assert!(msg.contains("testnet"), "got: {msg}");
    }

    #[test]
    fn compiled_discriminator_matches_this_build() {
        // Whatever this test binary was compiled with, the guard must accept the
        // matching network and reject the opposite one — a self-consistency
        // check that fails loudly if the feature model ever changes.
        if compiled_network_is_testnet() {
            assert!(check_compiled_network(NetworkType::Testnet).is_ok());
        } else {
            assert!(check_compiled_network(NetworkType::Mainnet).is_ok());
        }
    }
}
