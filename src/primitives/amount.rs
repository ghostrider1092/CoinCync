//! # Amount Type for CoinCync 1.0
//!
//! ## Denomination System
//!
//! | Unit      | Value             | Symbol | Syncs               |
//! |-----------|-------------------|--------|---------------------|
//! | CYNC      | 1                 | CYNC   | 1,000,000,000,000   |
//! | millicync | 0.001             | mCYNC  | 1,000,000,000       |
//! | microcync | 0.000001          | μCYNC  | 1,000,000           |
//! | nanocync  | 0.000000001       | nCYNC  | 1,000               |
//! | sync      | 0.000000000001    | sync   | 1                   |

use std::fmt;
use std::ops::{Add, Sub, Mul, Div, AddAssign, SubAssign};
use std::str::FromStr;
use serde::{Serialize, Deserialize};
use borsh::{BorshSerialize, BorshDeserialize};
use crate::constants::{ATOMIC_UNITS, MILLICYNC, MICROCYNC, NANOCYNC};
use crate::error::{Error, Result};

/// Denomination unit for display
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denomination {
    /// Main unit: 1 CYNC = 10^12 syncs
    Cync,
    /// Milli: 1 mCYNC = 10^9 syncs
    MilliCync,
    /// Micro: 1 μCYNC = 10^6 syncs
    MicroCync,
    /// Nano: 1 nCYNC = 10^3 syncs
    NanoCync,
    /// Atomic: 1 sync (smallest unit)
    Sync,
}

impl Denomination {
    /// Get the multiplier for this denomination
    pub fn multiplier(&self) -> u64 {
        match self {
            Denomination::Cync => ATOMIC_UNITS,
            Denomination::MilliCync => MILLICYNC,
            Denomination::MicroCync => MICROCYNC,
            Denomination::NanoCync => NANOCYNC,
            Denomination::Sync => 1,
        }
    }

    /// Get the symbol for this denomination
    pub fn symbol(&self) -> &'static str {
        match self {
            Denomination::Cync => "CYNC",
            Denomination::MilliCync => "mCYNC",
            Denomination::MicroCync => "μCYNC",
            Denomination::NanoCync => "nCYNC",
            Denomination::Sync => "sync",
        }
    }

    /// Get decimal places for this denomination
    pub fn decimals(&self) -> u8 {
        match self {
            Denomination::Cync => 12,
            Denomination::MilliCync => 9,
            Denomination::MicroCync => 6,
            Denomination::NanoCync => 3,
            Denomination::Sync => 0,
        }
    }
}

/// Amount in atomic units (1 CYNC = 10^12 syncs)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Amount(u64);

impl Amount {
    pub const ZERO: Amount = Amount(0);
    pub const MAX: Amount = Amount(u64::MAX);
    pub const ONE_CYNC: Amount = Amount(ATOMIC_UNITS);
    
    pub const fn from_atomic(atomic: u64) -> Self { Amount(atomic) }
    pub fn from_cync(cync: u64) -> Result<Self> {
        cync.checked_mul(ATOMIC_UNITS).map(Amount).ok_or(Error::AmountOverflow)
    }
    pub fn from_float_cync(cync: f64) -> Result<Self> {
        // SECURITY: Reject NaN and infinity
        if cync.is_nan() || cync.is_infinite() { return Err(Error::AmountOverflow); }
        if cync < 0.0 { return Err(Error::AmountUnderflow); }
        if cync > u64::MAX as f64 / ATOMIC_UNITS as f64 { return Err(Error::AmountOverflow); }
        Ok(Amount((cync * ATOMIC_UNITS as f64).round() as u64))
    }
    
    pub const fn as_atomic(&self) -> u64 { self.0 }
    pub const fn as_cync(&self) -> u64 { self.0 / ATOMIC_UNITS }
    pub fn as_float_cync(&self) -> f64 { self.0 as f64 / ATOMIC_UNITS as f64 }
    pub const fn is_zero(&self) -> bool { self.0 == 0 }
    
    pub fn checked_add(&self, other: Amount) -> Result<Amount> {
        self.0.checked_add(other.0).map(Amount).ok_or(Error::AmountOverflow)
    }
    pub fn checked_sub(&self, other: Amount) -> Result<Amount> {
        self.0.checked_sub(other.0).map(Amount).ok_or(Error::AmountUnderflow)
    }
    pub fn checked_mul(&self, factor: u64) -> Result<Amount> {
        self.0.checked_mul(factor).map(Amount).ok_or(Error::AmountOverflow)
    }
    pub fn checked_div(&self, divisor: u64) -> Result<Amount> {
        if divisor == 0 { return Err(Error::AmountOverflow); }
        Ok(Amount(self.0 / divisor))
    }
    
    pub fn saturating_add(&self, other: Amount) -> Amount { Amount(self.0.saturating_add(other.0)) }
    pub fn saturating_sub(&self, other: Amount) -> Amount { Amount(self.0.saturating_sub(other.0)) }
    
    /// Calculate percentage of amount using basis points (1/100th of a percent)
    /// 100 basis points = 1%, 10000 basis points = 100%
    ///
    /// Uses proper rounding to minimize precision loss:
    /// - Adds half the divisor before dividing (round half up)
    /// - This ensures values at exactly 0.5 round up rather than being truncated
    ///
    /// # Example
    /// ```ignore
    /// let amount = Amount::from_atomic(1000);
    /// assert_eq!(amount.percentage(5000).as_atomic(), 500); // 50%
    /// assert_eq!(amount.percentage(3333).as_atomic(), 333); // 33.33% rounds to 333
    /// ```
    pub fn percentage(&self, basis_points: u64) -> Amount {
        // Use u128 to prevent overflow during calculation
        let numerator = self.0 as u128 * basis_points as u128;
        // Add half of divisor for proper rounding (5000 = 10000 / 2)
        let rounded = (numerator + 5000) / 10000;
        // Clamp to u64::MAX to prevent overflow on cast
        Amount(rounded.min(u64::MAX as u128) as u64)
    }

    /// Calculate percentage without rounding (truncates toward zero)
    /// Use this when you need exact truncation behavior for consistency
    /// with other systems or when rounding could cause issues
    pub fn percentage_truncate(&self, basis_points: u64) -> Amount {
        // SECURITY (L-5): Clamp u128 result to u64::MAX to prevent silent wrapping.
        let result = self.0 as u128 * basis_points as u128 / 10000;
        Amount(result.min(u64::MAX as u128) as u64)
    }
    
    pub fn format(&self, decimals: usize) -> String {
        let whole = self.0 / ATOMIC_UNITS;
        let frac = self.0 % ATOMIC_UNITS;
        if decimals == 0 { return whole.to_string(); }
        let frac_str = format!("{:012}", frac);
        let trimmed = frac_str[..decimals.min(12)].trim_end_matches('0');
        if trimmed.is_empty() { whole.to_string() } else { format!("{}.{}", whole, trimmed) }
    }

    /// Format amount in a specific denomination
    pub fn format_in(&self, denom: Denomination) -> String {
        let multiplier = denom.multiplier();
        let whole = self.0 / multiplier;
        let frac = self.0 % multiplier;
        let decimals = denom.decimals() as usize;

        if decimals == 0 || frac == 0 {
            format!("{} {}", whole, denom.symbol())
        } else {
            let frac_str = format!("{:0width$}", frac, width = decimals);
            let trimmed = frac_str.trim_end_matches('0');
            format!("{}.{} {}", whole, trimmed, denom.symbol())
        }
    }

    /// Format with automatic denomination selection (human-friendly)
    pub fn format_auto(&self) -> String {
        if self.0 >= ATOMIC_UNITS {
            self.format_in(Denomination::Cync)
        } else if self.0 >= MILLICYNC {
            self.format_in(Denomination::MilliCync)
        } else if self.0 >= MICROCYNC {
            self.format_in(Denomination::MicroCync)
        } else if self.0 >= NANOCYNC {
            self.format_in(Denomination::NanoCync)
        } else {
            self.format_in(Denomination::Sync)
        }
    }

    /// Get amount in syncs (atomic units)
    pub fn as_syncs(&self) -> u64 {
        self.0
    }

    /// Get amount in millicync
    pub fn as_millicync(&self) -> f64 {
        self.0 as f64 / MILLICYNC as f64
    }

    /// Get amount in microcync
    pub fn as_microcync(&self) -> f64 {
        self.0 as f64 / MICROCYNC as f64
    }

    /// Create amount from syncs (atomic units)
    pub fn from_syncs(syncs: u64) -> Self {
        Amount(syncs)
    }

    /// Create amount from millicync
    pub fn from_millicync(mcync: f64) -> Result<Self> {
        // SECURITY (L-4): Match from_float_cync's NaN/Infinity/overflow guards
        if mcync.is_nan() || mcync.is_infinite() { return Err(Error::AmountOverflow); }
        if mcync < 0.0 { return Err(Error::AmountUnderflow); }
        if mcync > u64::MAX as f64 / MILLICYNC as f64 { return Err(Error::AmountOverflow); }
        Ok(Amount((mcync * MILLICYNC as f64).round() as u64))
    }

    /// Create amount from microcync
    pub fn from_microcync(ucync: f64) -> Result<Self> {
        // SECURITY (L-4): Match from_float_cync's NaN/Infinity/overflow guards
        if ucync.is_nan() || ucync.is_infinite() { return Err(Error::AmountOverflow); }
        if ucync < 0.0 { return Err(Error::AmountUnderflow); }
        if ucync > u64::MAX as f64 / MICROCYNC as f64 { return Err(Error::AmountOverflow); }
        Ok(Amount((ucync * MICROCYNC as f64).round() as u64))
    }

    /// Parse amount from string
    pub fn from_string(s: &str) -> Result<Self> {
        s.parse()
    }
}

impl fmt::Debug for Amount { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "Amount({} CYNC)", self.format(4)) } }
impl fmt::Display for Amount { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{} CYNC", self.format(4)) } }

impl FromStr for Amount {
    type Err = Error;
    /// FIX: Exact decimal parsing — no f64 intermediate.
    /// f64 loses precision for amounts with >3-4 integer digits + fractional syncs.
    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() { return Err(Error::InvalidAddress("empty amount".into())); }
        if s.starts_with('-') { return Err(Error::AmountUnderflow); }

        let (int_str, frac_opt) = match s.find('.') {
            Some(pos) => (&s[..pos], Some(&s[pos+1..])),
            None => (s, None),
        };

        let int_part: u128 = int_str.parse()
            .map_err(|_| Error::InvalidAddress(format!("invalid amount: {}", s)))?;
        let max_int = u64::MAX as u128 / ATOMIC_UNITS as u128;
        if int_part > max_int { return Err(Error::AmountOverflow); }
        let int_syncs = int_part * ATOMIC_UNITS as u128;

        let frac_syncs: u128 = if let Some(frac_str) = frac_opt {
            if frac_str.is_empty() { 0 }
            else if !frac_str.chars().all(|c| c.is_ascii_digit()) {
                return Err(Error::InvalidAddress(format!("invalid amount: {}", s)));
            } else {
                let padded = format!("{:0<12}", &frac_str[..frac_str.len().min(12)]);
                padded.parse::<u128>().map_err(|_| Error::InvalidAddress(format!("invalid amount: {}", s)))?
            }
        } else { 0 };

        let total = int_syncs.checked_add(frac_syncs).ok_or(Error::AmountOverflow)?;
        if total > u64::MAX as u128 { return Err(Error::AmountOverflow); }
        Ok(Amount(total as u64))
    }
}

// =============================================================================
// ARITHMETIC OPERATORS - SATURATING SEMANTICS
// =============================================================================
//
// # Saturation Behavior
//
// All arithmetic operators (+, -, *, /) use **saturating semantics**:
// - Addition saturates at `u64::MAX` instead of overflowing
// - Subtraction saturates at `0` instead of underflowing
// - Multiplication saturates at `u64::MAX` instead of overflowing
// - Division by zero returns `Amount::ZERO` instead of panicking
//
// # Rationale
//
// This design prevents panics during transaction processing, which could be
// exploited for DoS attacks. Invalid amounts are caught during validation,
// not during arithmetic operations.
//
// # When to Use Checked Operations Instead
//
// Use `checked_add`, `checked_sub`, `checked_mul`, `checked_div` when:
// - Building transactions (to detect insufficient funds)
// - Validating user input (to provide meaningful error messages)
// - Any code path where overflow indicates a bug
//
// Use saturating operators (via +, -, *, /) when:
// - Summing transaction outputs (validation catches issues)
// - Display/formatting purposes
// - Non-critical aggregations
//
// # Example
// ```ignore
// // BAD: Silent saturation might hide bugs
// let total = amount1 + amount2;  // Could saturate!
//
// // GOOD: Explicit error handling
// let total = amount1.checked_add(amount2)?;  // Returns error on overflow
// ```
// =============================================================================

impl Add for Amount {
    type Output = Amount;
    fn add(self, other: Amount) -> Amount {
        self.saturating_add(other)
    }
}
impl Sub for Amount {
    type Output = Amount;
    fn sub(self, other: Amount) -> Amount {
        self.saturating_sub(other)
    }
}
impl Mul<u64> for Amount {
    type Output = Amount;
    fn mul(self, factor: u64) -> Amount {
        Amount(self.0.saturating_mul(factor))
    }
}
impl Div<u64> for Amount {
    type Output = Amount;
    fn div(self, divisor: u64) -> Amount {
        // Division by zero returns zero to prevent panics
        // Use checked_div() if you need to detect division by zero
        if divisor == 0 {
            Amount::ZERO
        } else {
            Amount(self.0 / divisor)
        }
    }
}
impl AddAssign for Amount { fn add_assign(&mut self, other: Amount) { *self = *self + other; } }
impl SubAssign for Amount { fn sub_assign(&mut self, other: Amount) { *self = *self - other; } }
impl From<u64> for Amount { fn from(atomic: u64) -> Self { Amount(atomic) } }
impl From<Amount> for u64 { fn from(a: Amount) -> Self { a.0 } }
impl std::iter::Sum for Amount { fn sum<I: Iterator<Item=Self>>(iter: I) -> Self { iter.fold(Amount::ZERO, |a, x| a.saturating_add(x)) } }
impl<'a> std::iter::Sum<&'a Amount> for Amount { fn sum<I: Iterator<Item=&'a Self>>(iter: I) -> Self { iter.fold(Amount::ZERO, |a, x| a.saturating_add(*x)) } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amount_ops() {
        let a = Amount::from_cync(100).unwrap();
        let b = Amount::from_cync(50).unwrap();
        assert_eq!((a - b).as_cync(), 50);
        assert_eq!((a + b).as_cync(), 150);
    }

    #[test]
    fn test_format() {
        // 1.5 CYNC = 1,500,000,000,000 syncs
        let a = Amount::from_atomic(1_500_000_000_000);
        assert_eq!(a.format(4), "1.5");
        assert_eq!(a.format_in(Denomination::Cync), "1.5 CYNC");
    }

    #[test]
    fn test_denominations() {
        // 1 CYNC
        let one_cync = Amount::from_cync(1).unwrap();
        assert_eq!(one_cync.as_syncs(), 1_000_000_000_000);
        assert_eq!(one_cync.format_in(Denomination::Cync), "1 CYNC");
        assert_eq!(one_cync.format_in(Denomination::MilliCync), "1000 mCYNC");

        // 0.5 millicync = 500,000,000 syncs
        let half_milli = Amount::from_atomic(500_000_000);
        assert_eq!(half_milli.format_in(Denomination::MilliCync), "0.5 mCYNC");
        assert_eq!(half_milli.format_in(Denomination::MicroCync), "500 μCYNC");

        // 1000 syncs = 1 nanocync
        let thousand_syncs = Amount::from_atomic(1000);
        assert_eq!(thousand_syncs.format_in(Denomination::NanoCync), "1 nCYNC");
        assert_eq!(thousand_syncs.format_in(Denomination::Sync), "1000 sync");
    }

    #[test]
    fn test_auto_format() {
        assert_eq!(Amount::from_cync(5).unwrap().format_auto(), "5 CYNC");
        assert_eq!(Amount::from_atomic(5_000_000_000).format_auto(), "5 mCYNC");
        assert_eq!(Amount::from_atomic(5_000_000).format_auto(), "5 μCYNC");
        assert_eq!(Amount::from_atomic(5_000).format_auto(), "5 nCYNC");
        assert_eq!(Amount::from_atomic(500).format_auto(), "500 sync");
    }

    #[test]
    fn test_overflow_boundary() {
        let max = Amount::from_atomic(u64::MAX);
        let one = Amount::from_atomic(1);
        // Addition should saturate, not wrap
        let sum = max + one;
        assert_eq!(sum.as_atomic(), u64::MAX);
        // Subtraction from 0 should saturate to 0
        let zero = Amount::ZERO;
        let diff = zero.saturating_sub(one);
        assert_eq!(diff.as_atomic(), 0);
    }
}
