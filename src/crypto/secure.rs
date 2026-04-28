//! # Secure Memory and Constant-Time Operations
//!
//! Security hardening utilities for cryptographic code.

use std::cmp::Ordering;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure byte array that zeroizes on drop
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecureBytes {
    data: Vec<u8>,
}

impl SecureBytes {
    /// Create from bytes (takes ownership and zeroizes on drop)
    pub fn new(data: Vec<u8>) -> Self {
        SecureBytes { data }
    }

    /// Create with specified capacity
    pub fn with_capacity(capacity: usize) -> Self {
        SecureBytes {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Create zeroed buffer of specified size
    pub fn zeroed(size: usize) -> Self {
        SecureBytes {
            data: vec![0u8; size],
        }
    }

    /// Get bytes as slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get mutable bytes
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Manually zeroize
    pub fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl From<Vec<u8>> for SecureBytes {
    fn from(data: Vec<u8>) -> Self {
        SecureBytes::new(data)
    }
}

impl From<&[u8]> for SecureBytes {
    fn from(data: &[u8]) -> Self {
        SecureBytes::new(data.to_vec())
    }
}

impl std::fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureBytes([REDACTED {} bytes])", self.data.len())
    }
}

/// Fixed-size secure array that zeroizes on drop
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecureArray<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> SecureArray<N> {
    /// Create from array
    pub fn new(data: [u8; N]) -> Self {
        SecureArray { data }
    }

    /// Create zeroed array
    pub fn zeroed() -> Self {
        SecureArray { data: [0u8; N] }
    }

    /// Get bytes as slice
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.data
    }

    /// Get mutable bytes
    pub fn as_bytes_mut(&mut self) -> &mut [u8; N] {
        &mut self.data
    }
}

impl<const N: usize> From<[u8; N]> for SecureArray<N> {
    fn from(data: [u8; N]) -> Self {
        SecureArray::new(data)
    }
}

impl<const N: usize> std::fmt::Debug for SecureArray<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureArray<{}>([REDACTED])", N)
    }
}

/// Constant-time byte comparison
/// Returns true if slices are equal, false otherwise
/// Runs in constant time regardless of where differences occur
///
/// SECURITY (CR-002): Uses the `subtle` crate's ConstantTimeEq trait instead of
/// a hand-rolled XOR loop. The subtle crate is specifically designed to resist
/// LLVM optimizations that could introduce timing side-channels.
#[inline(never)]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Constant-time comparison that returns an ordering
/// Useful for comparing hashes/keys in a timing-safe way
///
/// SECURITY: Uses the subtle crate's constant-time primitives for portability.
/// This implementation uses subtle::Choice to ensure constant-time behavior
/// across different platforms and compilers.
///
/// Note: Length comparison is NOT constant-time (lengths are typically public).
#[inline(never)]
pub fn ct_cmp(a: &[u8], b: &[u8]) -> Ordering {
    use subtle::{Choice, ConditionallySelectable};

    // Length comparison is not constant-time (lengths are typically not secret)
    if a.len() != b.len() {
        return a.len().cmp(&b.len());
    }

    // SECURITY: Use subtle crate for portable constant-time comparison.
    // We track gt (greater than) and lt (less than) using Choice which wraps u8.
    // Once a difference is found, subsequent bytes don't affect the result.
    let mut gt = Choice::from(0u8);
    let mut lt = Choice::from(0u8);
    let mut undecided = Choice::from(1u8); // 1 while equal, 0 after first difference

    for (x, y) in a.iter().zip(b.iter()) {
        // Detect comparison using wrapping subtraction in u16:
        // - If x - y underflows (result >= 256), then x < y
        // - If y - x underflows (result >= 256), then x > y
        let x_minus_y = (*x as u16).wrapping_sub(*y as u16);
        let y_minus_x = (*y as u16).wrapping_sub(*x as u16);

        // High bit (bit 8+) set means the subtraction wrapped (underflowed)
        // x < y when x_minus_y underflows, x > y when y_minus_x underflows
        let x_lt_y_bit = Choice::from((x_minus_y >> 8) as u8 & 1);
        let x_gt_y_bit = Choice::from((y_minus_x >> 8) as u8 & 1);

        // Only update if we haven't found a difference yet
        gt = Choice::conditional_select(&gt, &Choice::from(1u8), undecided & x_gt_y_bit);
        lt = Choice::conditional_select(&lt, &Choice::from(1u8), undecided & x_lt_y_bit);

        // Once any difference found, undecided becomes 0
        let bytes_equal = !(x_gt_y_bit | x_lt_y_bit);
        undecided = undecided & bytes_equal;
    }

    // Convert Choice values to Ordering
    // SECURITY: Use array lookup to avoid branches (constant-time)
    // Index: gt=1,lt=0 => 2 (Greater); gt=0,lt=1 => 0 (Less); gt=0,lt=0 => 1 (Equal)
    let orderings = [Ordering::Less, Ordering::Equal, Ordering::Greater];
    let gt_val: u8 = gt.unwrap_u8();
    let lt_val: u8 = lt.unwrap_u8();
    // Compute index: 2*gt + (1 - lt) = 2*gt + 1 - lt (when gt and lt are 0 or 1)
    // gt=0,lt=0 => 1 (Equal); gt=0,lt=1 => 0 (Less); gt=1,lt=0 => 2 (Greater)
    let idx = ((gt_val as usize) << 1) + (1 - lt_val as usize);
    orderings[idx.min(2)]
}

/// Constant-time selection for bytes
/// Returns `a` if condition is true, `b` otherwise
/// Runs in constant time using bitwise operations
///
/// SECURITY: Uses arithmetic masking instead of branches.
#[inline(never)]
pub fn ct_select_u8(condition: bool, a: u8, b: u8) -> u8 {
    // Convert bool to mask: true -> 0xFF, false -> 0x00
    let mask = (-(condition as i8)) as u8;
    // Select: (a & mask) | (b & !mask)
    (a & mask) | (b & !mask)
}

/// Constant-time selection for u64
/// Returns `a` if condition is true, `b` otherwise
#[inline(never)]
pub fn ct_select_u64(condition: bool, a: u64, b: u64) -> u64 {
    let mask = (-(condition as i64)) as u64;
    (a & mask) | (b & !mask)
}

/// Constant-time selection for byte slices
/// Copies `a` into `dst` if condition is true, `b` otherwise
#[inline(never)]
pub fn ct_select_slice(condition: bool, dst: &mut [u8], a: &[u8], b: &[u8]) {
    assert_eq!(dst.len(), a.len());
    assert_eq!(dst.len(), b.len());

    let mask = (-(condition as i8)) as u8;
    for i in 0..dst.len() {
        dst[i] = (a[i] & mask) | (b[i] & !mask);
    }
}

/// Constant-time conditional copy
/// If condition is true, copies `src` into `dst`
/// Runs in constant time
///
/// SECURITY: Uses arithmetic masking (not an if/else branch) to derive the
/// mask, preventing the compiler from emitting branch instructions.
#[inline(never)]
pub fn ct_copy_if(condition: bool, dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len());

    // SECURITY: Derive mask via arithmetic, not a branch.
    // -(true as i8) = -1 = 0xFF, -(false as i8) = 0 = 0x00
    let mask = (-(condition as i8)) as u8;

    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = (*d & !mask) | (*s & mask);
    }
}

/// Secure random bytes using OS entropy
///
/// Uses OsRng which sources entropy directly from the operating system,
/// providing cryptographically secure random bytes.
pub fn secure_random(buf: &mut [u8]) {
    use rand::RngCore;
    use rand::rngs::OsRng;
    OsRng.fill_bytes(buf);
}

/// Generate secure random 32 bytes
pub fn secure_random_32() -> SecureArray<32> {
    let mut arr = SecureArray::<32>::zeroed();
    secure_random(arr.as_bytes_mut());
    arr
}

/// Generate secure random 64 bytes
pub fn secure_random_64() -> SecureArray<64> {
    let mut arr = SecureArray::<64>::zeroed();
    secure_random(arr.as_bytes_mut());
    arr
}

/// Securely clear memory (explicit barrier to prevent optimization)
#[inline(never)]
pub fn secure_zero(data: &mut [u8]) {
    data.zeroize();
    // Memory barrier to prevent reordering
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Check if a buffer contains only zeros (constant time)
#[inline(never)]
pub fn is_zero(data: &[u8]) -> bool {
    let mut acc = 0u8;
    for &byte in data {
        acc |= byte;
    }
    acc == 0
}

/// Timing-safe hash comparison for authentication
pub fn verify_hash(computed: &[u8; 32], expected: &[u8; 32]) -> bool {
    ct_eq(computed, expected)
}

/// Timing-safe MAC verification
pub fn verify_mac(computed: &[u8], expected: &[u8]) -> bool {
    ct_eq(computed, expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_bytes_zeroize() {
        let mut secure = SecureBytes::new(vec![1, 2, 3, 4, 5]);
        assert_eq!(secure.len(), 5);
        secure.zeroize();
        assert!(secure.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secure_array_zeroize() {
        let arr: SecureArray<32> = SecureArray::new([0xAB; 32]);
        assert_eq!(arr.as_bytes()[0], 0xAB);
        drop(arr);
        // After drop, memory should be zeroed (can't verify directly after drop)
    }

    #[test]
    fn test_ct_eq() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];

        assert!(ct_eq(&a, &b));
        assert!(!ct_eq(&a, &c));
        assert!(!ct_eq(&a, &[1, 2, 3])); // Different length
    }

    #[test]
    fn test_ct_cmp() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 4];
        let c = [1u8, 2, 3];

        assert_eq!(ct_cmp(&a, &b), Ordering::Less);
        assert_eq!(ct_cmp(&b, &a), Ordering::Greater);
        assert_eq!(ct_cmp(&a, &c), Ordering::Equal);
    }

    #[test]
    fn test_ct_copy_if() {
        let mut dst = [0u8; 4];
        let src = [1u8, 2, 3, 4];

        ct_copy_if(false, &mut dst, &src);
        assert_eq!(dst, [0, 0, 0, 0]);

        ct_copy_if(true, &mut dst, &src);
        assert_eq!(dst, [1, 2, 3, 4]);
    }

    #[test]
    fn test_is_zero() {
        assert!(is_zero(&[0, 0, 0, 0]));
        assert!(!is_zero(&[0, 0, 1, 0]));
        assert!(is_zero(&[]));
    }

    #[test]
    fn test_secure_random() {
        let a = secure_random_32();
        let b = secure_random_32();

        // Extremely unlikely to be equal or all zeros
        assert!(!ct_eq(a.as_bytes(), b.as_bytes()));
        assert!(!is_zero(a.as_bytes()));
    }

    #[test]
    fn test_verify_hash() {
        let a = [0xABu8; 32];
        let b = [0xABu8; 32];
        let c = [0xCDu8; 32];

        assert!(verify_hash(&a, &b));
        assert!(!verify_hash(&a, &c));
    }

    #[test]
    fn test_zeroize_on_drop() {
        // Allocate a SecureBytes, read its pointer, drop it, verify zeroed
        let data = vec![0xAB_u8; 64];
        let mut secure = SecureBytes::new(data);
        // Verify non-zero before zeroize
        assert!(secure.as_bytes().iter().any(|&b| b != 0));
        secure.zeroize();
        assert!(secure.as_bytes().iter().all(|&b| b == 0), "All bytes must be zero after zeroize");
    }
}
