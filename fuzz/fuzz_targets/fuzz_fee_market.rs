//! Fuzz target for fee-market construction + arithmetic.
//!
//! Shim: borsh-decode a FeeContext from fuzz bytes, construct a
//! FeeMarket. The arithmetic paths exercise integer-overflow surfaces
//! (sum of fees, distribution math, congestion-driven scaling).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use coincync::consensus::fee_market::{
        calculate_fee, calculate_priority_fee, congestion_multiplier,
        distribute_fee, is_congested, FeeCalculator, FeeContext, FeeTier,
    };

    // FeeContext is a plain `{ congestion_pct: u64 }` (no derives) —
    // build it from the first 8 fuzz bytes. FeeCalculator wraps it; the
    // free fns below also exercise the overflow surfaces directly.
    if data.len() < 16 {
        return;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[..8]);
    let congestion_pct = u64::from_le_bytes(buf);

    let mut tx_buf = [0u8; 8];
    tx_buf.copy_from_slice(&data[8..16]);
    // Cap tx_size — gigantic sizes overflow into the multiplier and the
    // fuzz value would dominate. 16 MiB is well past any real tx.
    let tx_size = (u64::from_le_bytes(tx_buf) as usize) & 0x00FF_FFFF;

    let ctx = FeeContext { congestion_pct };
    let calc = FeeCalculator::new(ctx);
    let _ = calc.estimate(tx_size, FeeTier::Economy);
    let _ = calc.estimate(tx_size, FeeTier::Standard);
    let _ = calc.estimate(tx_size, FeeTier::Priority);

    // Free-function surface — same arithmetic paths the calculator wraps.
    let fee = calculate_fee(tx_size, congestion_pct);
    let _ = calculate_priority_fee(tx_size, congestion_pct, 1.5);
    let _ = congestion_multiplier(congestion_pct);
    let _ = is_congested(congestion_pct);
    let _ = distribute_fee(fee, is_congested(congestion_pct));
    let _ = calc.distribute(fee);
});
