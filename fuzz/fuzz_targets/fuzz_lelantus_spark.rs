//! Fuzz target for Lelantus-Spark spend verification (CIP-005).
//!
//! `verify_spark_spend` is invoked when validating spark spends. The
//! pubkey set + spend params are peer-controlled; a panic = consensus
//! halt or per-tx DoS.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // SparkNote + SparkSpendProof derive serde only (not borsh).
    // Probe the serde_json parser; a panic in either = remote DoS via
    // crafted spark spend.
    let _ = serde_json::from_slice::<coincync::crypto::lelantus_spark::SparkNote>(data);
    let _ = serde_json::from_slice::<coincync::crypto::lelantus_spark::SparkSpendProof>(data);
});
