//! Fuzz target for strict-binding DLEQ proof verification (cyncswap).
//!
//! Strict-DLEQ proofs ride across the cyncswap coordinator transport
//! from the counterparty. Peer-controlled proof bytes flow into
//! `verify_bit_btc` / `verify_bit_cync`. A panic here = remote DoS
//! mid-swap (or worse if the panic exposes a verification bypass).

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct DleqFuzzInput {
    // BTC-side commitment (compressed secp256k1 point)
    c_btc: [u8; 33],
    // BitOrProofBtc fields (BE secp256k1 scalars)
    btc_e_0: [u8; 32],
    btc_e_1: [u8; 32],
    btc_s_0: [u8; 32],
    btc_s_1: [u8; 32],
    // CYNC-side commitment (compressed Ristretto255 point)
    c_cync: [u8; 32],
    // BitOrProofCync fields (LE Ristretto scalars)
    cync_e_0: [u8; 32],
    cync_e_1: [u8; 32],
    cync_s_0: [u8; 32],
    cync_s_1: [u8; 32],
}

fuzz_target!(|input: DleqFuzzInput| {
    use coincync_swap::strict_dleq::{
        verify_bit_btc, verify_bit_cync, BitOrProofBtc, BitOrProofCync,
    };

    let btc_proof = BitOrProofBtc {
        e_0: input.btc_e_0,
        e_1: input.btc_e_1,
        s_0: input.btc_s_0,
        s_1: input.btc_s_1,
    };
    let _ = verify_bit_btc(&input.c_btc, &btc_proof);

    let cync_proof = BitOrProofCync {
        e_0: input.cync_e_0,
        e_1: input.cync_e_1,
        s_0: input.cync_s_0,
        s_1: input.cync_s_1,
    };
    let _ = verify_bit_cync(&input.c_cync, &cync_proof);
});
