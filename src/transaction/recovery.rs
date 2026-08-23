//! # Dead Man's Switch — Time-Locked Recovery
//!
//! Allows a wallet owner to designate a recovery address that can sweep
//! UTXOs after a configurable inactivity timeout. If the original owner
//! doesn't sign any transaction for `timeout_blocks` blocks after the
//! output was created, the recovery address can spend without the
//! original spend key.
//!
//! ## Encoding
//!
//! Recovery metadata is stored in the **Transaction `extra` field** using
//! a tagged TLV (type-length-value) format. This avoids changing the
//! `TxOutput` struct and is fully backwards compatible with existing
//! blocks — nodes that don't understand the tag simply ignore it.
//!
//! ```text
//! Tag format in `extra`:
//! [0xDE]                      — recovery tag byte
//! [output_index: u8]          — which output this applies to
//! [recovery_address: 32 bytes] — stealth address of the backup wallet
//! [timeout_blocks: 8 bytes LE] — inactivity threshold in blocks
//! ```
//!
//! Total per-output: 1 + 1 + 32 + 8 = 42 bytes (well within 256-byte extra limit).
//!
//! ## Consensus rules
//!
//! - At chain height H, output O (created at height C) with recovery
//!   metadata is "recovery-eligible" if `H - C >= timeout_blocks`.
//! - A recovery spend requires the spender to prove ownership of the
//!   `recovery_address` (via ring signature / key image as usual).
//! - Recovery does NOT violate Article I (supply cap) — coins aren't
//!   created, just transferred after timeout.
//! - Recovery does NOT violate Article III (privacy) — the recovery
//!   address is a stealth address; an observer can't link it to a person.
//!
//! ## Constitutional basis
//!
//! Bill of Rights, Amendment IV:
//! > No person shall be deprived of property without due process.
//!
//! A dead man's switch IS due process — the owner explicitly opted in,
//! the timeout is publicly verifiable, and the recovery key was set by
//! the owner themselves.

use serde::{Deserialize, Serialize};

/// Tag byte marking recovery metadata in the transaction extra field.
pub const RECOVERY_TAG: u8 = 0xDE;

/// Size of one recovery entry: tag(1) + index(1) + address(32) + timeout(8).
pub const RECOVERY_ENTRY_SIZE: usize = 42;

/// Maximum reasonable timeout: ~2 years at 120-second block time.
/// 525,960 blocks ≈ 365.25 days * 24 * 60 / 2 minutes.
pub const MAX_RECOVERY_TIMEOUT: u64 = 525_960;

/// Minimum timeout: 720 blocks ≈ 24 hours at 120-second block time.
pub const MIN_RECOVERY_TIMEOUT: u64 = 720;

/// Recovery metadata for a single output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryMeta {
    /// Index of the output in the transaction this applies to.
    pub output_index: u8,
    /// Stealth public key of the recovery/backup wallet. If the owner
    /// goes inactive for `timeout_blocks`, this key can spend.
    pub recovery_address: [u8; 32],
    /// Number of blocks of inactivity before recovery activates.
    /// Measured from the block height where the output was created.
    pub timeout_blocks: u64,
}

impl RecoveryMeta {
    /// Encode this recovery entry as bytes for the `extra` field.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RECOVERY_ENTRY_SIZE);
        out.push(RECOVERY_TAG);
        out.push(self.output_index);
        out.extend_from_slice(&self.recovery_address);
        out.extend_from_slice(&self.timeout_blocks.to_le_bytes());
        out
    }

    /// Decode a recovery entry from a slice starting at position 0.
    /// Returns `None` if the slice is too short or tag doesn't match.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < RECOVERY_ENTRY_SIZE {
            return None;
        }
        if data[0] != RECOVERY_TAG {
            return None;
        }
        let output_index = data[1];
        let mut recovery_address = [0u8; 32];
        recovery_address.copy_from_slice(&data[2..34]);
        let timeout_blocks = u64::from_le_bytes([
            data[34], data[35], data[36], data[37], data[38], data[39], data[40], data[41],
        ]);
        Some(Self {
            output_index,
            recovery_address,
            timeout_blocks,
        })
    }

    /// Extract ALL recovery entries from a transaction's `extra` field.
    ///
    /// Scans the extra bytes for `RECOVERY_TAG` markers and decodes
    /// each entry. Non-recovery tags are skipped.
    pub fn decode_all(extra: &[u8]) -> Vec<Self> {
        let mut results = Vec::new();
        let mut pos = 0;
        while pos < extra.len() {
            if extra[pos] == RECOVERY_TAG && pos + RECOVERY_ENTRY_SIZE <= extra.len() {
                if let Some(meta) = Self::decode(&extra[pos..]) {
                    results.push(meta);
                }
                pos += RECOVERY_ENTRY_SIZE;
            } else if extra[pos] == crate::transaction::payment_id::PAYMENT_ID_TAG
                && pos + 2 <= extra.len()
            {
                // Length-skip an encrypted payment-id entry so its (encrypted,
                // possibly 0xDE-containing) bytes are never misread as a
                // recovery entry. Coexistence is covered by payment_id tests.
                let len = extra[pos + 1] as usize;
                pos = (pos + 2 + len).min(extra.len());
            } else {
                pos += 1;
            }
        }
        results
    }

    /// Encode multiple recovery entries into a single `extra` blob.
    pub fn encode_all(entries: &[RecoveryMeta]) -> Vec<u8> {
        let mut out = Vec::with_capacity(entries.len() * RECOVERY_ENTRY_SIZE);
        for entry in entries {
            out.extend_from_slice(&entry.encode());
        }
        out
    }

    /// Validate this recovery entry's parameters.
    pub fn validate(&self, output_count: usize) -> Result<(), String> {
        if self.output_index as usize >= output_count {
            return Err(format!(
                "recovery output_index {} out of range (tx has {} outputs)",
                self.output_index, output_count
            ));
        }
        if self.timeout_blocks < MIN_RECOVERY_TIMEOUT {
            return Err(format!(
                "recovery timeout {} too short (minimum {} blocks ≈ 24h)",
                self.timeout_blocks, MIN_RECOVERY_TIMEOUT
            ));
        }
        if self.timeout_blocks > MAX_RECOVERY_TIMEOUT {
            return Err(format!(
                "recovery timeout {} too long (maximum {} blocks ≈ 2 years)",
                self.timeout_blocks, MAX_RECOVERY_TIMEOUT
            ));
        }
        if self.recovery_address == [0u8; 32] {
            return Err("recovery address must not be zero".into());
        }
        Ok(())
    }

    /// Check if this output is eligible for recovery spending at the
    /// given current height, assuming the output was created at
    /// `creation_height`.
    pub fn is_recovery_eligible(&self, creation_height: u64, current_height: u64) -> bool {
        current_height.saturating_sub(creation_height) >= self.timeout_blocks
    }
}

/// Validate all recovery entries in a transaction's extra field.
///
/// Called by the structural validator. Returns Ok if all entries are
/// well-formed, or Err with a description of the first invalid entry.
pub fn validate_recovery_extra(extra: &[u8], output_count: usize) -> Result<(), String> {
    let entries = RecoveryMeta::decode_all(extra);
    let mut seen_indices = std::collections::HashSet::new();
    for entry in &entries {
        entry.validate(output_count)?;
        if !seen_indices.insert(entry.output_index) {
            return Err(format!(
                "duplicate recovery entry for output index {}",
                entry.output_index
            ));
        }
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_recovery() -> RecoveryMeta {
        RecoveryMeta {
            output_index: 0,
            recovery_address: [0xAB; 32],
            timeout_blocks: 262_800, // ~6 months
        }
    }

    #[test]
    fn encode_decode_round_trip() {
        let meta = make_recovery();
        let encoded = meta.encode();
        assert_eq!(encoded.len(), RECOVERY_ENTRY_SIZE);
        let decoded = RecoveryMeta::decode(&encoded).unwrap();
        assert_eq!(meta, decoded);
    }

    #[test]
    fn decode_all_from_extra() {
        let meta1 = RecoveryMeta {
            output_index: 0,
            recovery_address: [0xAA; 32],
            timeout_blocks: 1000,
        };
        let meta2 = RecoveryMeta {
            output_index: 1,
            recovery_address: [0xBB; 32],
            timeout_blocks: 2000,
        };
        let extra = RecoveryMeta::encode_all(&[meta1.clone(), meta2.clone()]);
        let decoded = RecoveryMeta::decode_all(&extra);
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0], meta1);
        assert_eq!(decoded[1], meta2);
    }

    #[test]
    fn recovery_eligibility() {
        let meta = RecoveryMeta {
            output_index: 0,
            recovery_address: [0xCC; 32],
            timeout_blocks: 1000,
        };
        // Created at 100, current at 500 → not eligible (400 < 1000)
        assert!(!meta.is_recovery_eligible(100, 500));
        // Created at 100, current at 1100 → eligible (1000 >= 1000)
        assert!(meta.is_recovery_eligible(100, 1100));
        // Created at 100, current at 2000 → eligible (1900 >= 1000)
        assert!(meta.is_recovery_eligible(100, 2000));
    }

    #[test]
    fn validate_rejects_bad_timeout() {
        let mut meta = make_recovery();
        meta.timeout_blocks = 10; // too short
        assert!(meta.validate(2).is_err());

        meta.timeout_blocks = 999_999; // too long
        assert!(meta.validate(2).is_err());
    }

    #[test]
    fn validate_rejects_bad_index() {
        let mut meta = make_recovery();
        meta.output_index = 5;
        assert!(meta.validate(2).is_err()); // only 2 outputs
    }

    #[test]
    fn validate_rejects_zero_address() {
        let mut meta = make_recovery();
        meta.recovery_address = [0u8; 32];
        assert!(meta.validate(2).is_err());
    }

    #[test]
    fn validate_rejects_duplicate_indices() {
        let meta1 = make_recovery();
        let meta2 = make_recovery(); // same output_index
        let extra = RecoveryMeta::encode_all(&[meta1, meta2]);
        assert!(validate_recovery_extra(&extra, 2).is_err());
    }

    #[test]
    fn empty_extra_is_valid() {
        assert!(validate_recovery_extra(&[], 2).is_ok());
    }
}
