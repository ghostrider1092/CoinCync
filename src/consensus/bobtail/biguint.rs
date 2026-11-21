//! 512-bit unsigned integer for Bobtail k-mean arithmetic.
//!
//! The k-mean acceptance test (`kmean::k_mean_meets_target`) sums `K` 256-bit
//! sample hashes and compares against `T·K·(K+1)`. Both the sum (up to
//! `K·2^256`) and the product (up to `2^256·K·(K+1)`) exceed 256 bits for any
//! `K > 1`, so a 512-bit accumulator is required to evaluate the bar without
//! truncation or rounding. For the settled `K = 20` the largest intermediate is
//! `≈ 2^265`, far inside 512 bits.
//!
//! Built on the already-vendored `uint` crate (no new dependency).

uint::construct_uint! {
    /// 512-bit unsigned integer, 8 × u64 limbs.
    pub(crate) struct U512(8);
}
