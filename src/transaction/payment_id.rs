//! # Encrypted payment IDs (integrated addresses)
//!
//! An *integrated address* is a normal address that also carries an 8-byte
//! payment ID, so a receiver (typically an exchange) can associate an incoming
//! payment with a specific account/invoice without handing out a unique address
//! per depositor.
//!
//! On a stealth-address privacy chain a cleartext payment ID would be a privacy
//! leak (chain observers could cluster deposits) — the model Monero deprecated.
//! So the payment ID is **encrypted** with the same ECDH channel as memos
//! (`crypto::memo`): the sender encrypts it with the recipient output's tx
//! secret + the recipient's view public key; the recipient recovers it on scan
//! with their view secret + the output's tx public key.
//!
//! The ciphertext is carried in `tx.extra` as a length-prefixed entry so it
//! coexists with recovery-metadata entries (see `transaction::recovery`):
//!
//! ```text
//! [PAYMENT_ID_TAG=0x9D][len: u8][encrypted payment id … len bytes]
//! ```
//!
//! Both this parser and the recovery parser length-skip each other's tags, so a
//! `0xDE` byte inside encrypted payment-id data is never misread as a recovery
//! entry (and vice-versa).

use crate::transaction::recovery::{RECOVERY_ENTRY_SIZE, RECOVERY_TAG};

/// tx.extra entry tag for an encrypted payment ID. Distinct from
/// [`RECOVERY_TAG`] (`0xDE`).
pub const PAYMENT_ID_TAG: u8 = 0x9D;

/// A plaintext payment ID is exactly 8 bytes.
pub const PAYMENT_ID_LEN: usize = 8;

/// Encode an already-encrypted payment ID as a length-prefixed `tx.extra`
/// entry: `[0x9D][len][ciphertext]`. The ciphertext (8-byte id + memo AEAD
/// overhead) is well under 255 bytes, so a `u8` length suffices.
pub fn encode_extra(encrypted_pid: &[u8]) -> Vec<u8> {
    debug_assert!(encrypted_pid.len() <= u8::MAX as usize);
    let mut out = Vec::with_capacity(2 + encrypted_pid.len());
    out.push(PAYMENT_ID_TAG);
    out.push(encrypted_pid.len() as u8);
    out.extend_from_slice(encrypted_pid);
    out
}

/// Find the encrypted payment ID in a `tx.extra` blob, if present. Skips
/// recovery entries (fixed-size, tagged `0xDE`) by their size so the two entry
/// types never misparse each other. Returns the ciphertext (still encrypted).
pub fn find_encrypted(extra: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;
    while pos < extra.len() {
        let tag = extra[pos];
        if tag == PAYMENT_ID_TAG {
            if pos + 2 > extra.len() {
                return None; // truncated header
            }
            let len = extra[pos + 1] as usize;
            let start = pos + 2;
            if start + len > extra.len() {
                return None; // truncated value
            }
            return Some(extra[start..start + len].to_vec());
        } else if tag == RECOVERY_TAG && pos + RECOVERY_ENTRY_SIZE <= extra.len() {
            pos += RECOVERY_ENTRY_SIZE; // skip a recovery entry
        } else {
            pos += 1;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::recovery::RecoveryMeta;

    #[test]
    fn encode_find_roundtrip() {
        let ct = vec![0xAAu8; 36]; // ~8-byte id + AEAD overhead
        let extra = encode_extra(&ct);
        assert_eq!(find_encrypted(&extra), Some(ct));
    }

    #[test]
    fn none_when_absent() {
        assert_eq!(find_encrypted(&[]), None);
        // A pure recovery blob has no payment id.
        let rec = RecoveryMeta::encode_all(&[RecoveryMeta {
            output_index: 0,
            recovery_address: [7u8; 32],
            timeout_blocks: 720,
        }]);
        assert_eq!(find_encrypted(&rec), None);
    }

    #[test]
    fn coexists_with_recovery_either_order() {
        // Ciphertext deliberately contains a 0xDE byte to prove the recovery
        // scanner won't misread it once payment-id entries are length-skipped.
        let ct = vec![0xDE, 0x01, 0x02, 0xDE, 0xDE, 0x99, 0x00, 0x42];
        let pid_entry = encode_extra(&ct);
        let rec = RecoveryMeta::encode_all(&[RecoveryMeta {
            output_index: 1,
            recovery_address: [0xCC; 32],
            timeout_blocks: 1000,
        }]);

        for (a, b) in [(pid_entry.clone(), rec.clone()), (rec.clone(), pid_entry.clone())] {
            let mut extra = a;
            extra.extend_from_slice(&b);
            // Payment id recovered intact...
            assert_eq!(find_encrypted(&extra), Some(ct.clone()));
            // ...and the recovery entry is still decoded (not corrupted, no
            // spurious entry from the 0xDE bytes inside the ciphertext).
            let recs = RecoveryMeta::decode_all(&extra);
            assert_eq!(recs.len(), 1, "exactly one recovery entry");
            assert_eq!(recs[0].timeout_blocks, 1000);
        }
    }
}
