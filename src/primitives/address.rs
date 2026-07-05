//! # Address Types for CoinCync 1.0
//!
//! ## Security Notes:
//! - `from_bytes_checked` validates that public keys are valid curve points
//! - `from_bytes` is unchecked for performance in trusted contexts
//! - Use checked variant when parsing untrusted input (network, user input)

use std::fmt;
use std::str::FromStr;
use serde::{Serialize, Deserialize};
use borsh::{BorshSerialize, BorshDeserialize};
use super::{PublicKey, hash_data};
use crate::constants::{MAINNET_MAGIC, TESTNET_MAGIC, NAME_SUFFIX};
use crate::error::{Error, Result};
use crate::crypto::PublicPoint;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum Network {
    #[default]
    Mainnet,
    Testnet,
}

impl Network {
    pub fn magic(&self) -> [u8; 4] { match self { Network::Mainnet => MAINNET_MAGIC, Network::Testnet => TESTNET_MAGIC } }
    pub fn prefix(&self) -> &'static str { match self { Network::Mainnet => "CYNC", Network::Testnet => "tCYNC" } }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum AddressType {
    #[default]
    Standard,
    Subaddress,
    Integrated,
}

impl AddressType {
    pub fn type_byte(&self) -> u8 { match self { AddressType::Standard => 0, AddressType::Subaddress => 1, AddressType::Integrated => 2 } }
    pub fn from_byte(b: u8) -> Option<Self> { match b { 0 => Some(AddressType::Standard), 1 => Some(AddressType::Subaddress), 2 => Some(AddressType::Integrated), _ => None } }
}

#[derive(Clone, PartialEq, Eq, Hash, BorshSerialize)]
pub struct Address {
    pub network: Network,
    pub address_type: AddressType,
    pub spend_public_key: PublicKey,
    pub view_public_key: PublicKey,
    pub payment_id: Option<[u8; 8]>,
}

// AUDIT (2026-07-02): manual BorshDeserialize (instead of derive) that
// validates the spend/view public keys are actual Ristretto curve points
// (not the identity element and not junk bytes). Closes the gap the
// 2026-07-02 Serde binary fix (commit 6c15d043) explicitly deferred:
// "the persisted-Address surface is currently wallet-internal ...
// if a future feature accepts Borsh-encoded Address from a peer, a
// custom BorshDeserialize impl mirroring this fix will be needed there
// too." The 2026-07-02 30-scan pass turned up this deferral as an
// unclosed gap under the "prevent Zcash-shape unchecked-decode bugs"
// framing — closing proactively before any consumer emerges rather
// than waiting for one and hoping the follow-up fix lands in time.
//
// The derived BorshSerialize above is fine: encoding an already-
// constructed Address is safe (the invariants were checked at
// construction). The problem is only on the decode side.
impl BorshDeserialize for Address {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        // Decode the fields into a raw struct via the derive-equivalent
        // reads, then validate the public keys are on-curve non-identity
        // before returning. Any invalid encoding turns into an
        // InvalidData error at the same layer Borsh's own read errors
        // surface, so callers using the `?` operator get a uniform
        // error type.
        let network = Network::deserialize_reader(reader)?;
        let address_type = AddressType::deserialize_reader(reader)?;
        let spend_public_key = PublicKey::deserialize_reader(reader)?;
        let view_public_key = PublicKey::deserialize_reader(reader)?;
        let payment_id = <Option<[u8; 8]>>::deserialize_reader(reader)?;

        // Validate both keys are valid Ristretto curve points and
        // non-identity. Same check `from_bytes_checked` runs (see L107
        // of this file); factoring out into a helper would be nice but
        // is a separate refactor.
        PublicKey::from_bytes_checked(*spend_public_key.as_bytes())
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Address.spend_public_key not a valid non-identity Ristretto point: {}", e),
            ))?;
        PublicKey::from_bytes_checked(*view_public_key.as_bytes())
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Address.view_public_key not a valid non-identity Ristretto point: {}", e),
            ))?;

        Ok(Address {
            network,
            address_type,
            spend_public_key,
            view_public_key,
            payment_id,
        })
    }
}

impl Address {
    pub fn new(network: Network, spend: PublicKey, view: PublicKey) -> Self {
        Address { network, address_type: AddressType::Standard, spend_public_key: spend, view_public_key: view, payment_id: None }
    }
    
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(70);
        bytes.push(match self.network { Network::Mainnet => 0, Network::Testnet => 1 });
        bytes.push(self.address_type.type_byte());
        bytes.extend_from_slice(self.spend_public_key.as_bytes());
        bytes.extend_from_slice(self.view_public_key.as_bytes());
        if let Some(pid) = self.payment_id { bytes.extend_from_slice(&pid); }
        let hash = hash_data(&bytes);
        let checksum = &hash.as_bytes()[..4];
        bytes.extend_from_slice(checksum);
        bytes
    }
    
    /// Parse address from bytes (unchecked - does not validate curve points)
    /// Use `from_bytes_checked` for untrusted input
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 70 { return Err(Error::InvalidAddress("too short".into())); }
        let checksum_pos = bytes.len() - 4;
        let data = &bytes[..checksum_pos];
        let checksum = &bytes[checksum_pos..];
        let expected_checksum = hash_data(data);
        if checksum != &expected_checksum.as_bytes()[..4] { return Err(Error::InvalidAddress("bad checksum".into())); }

        let network = match data[0] { 0 => Network::Mainnet, 1 => Network::Testnet, _ => return Err(Error::InvalidAddress("bad network".into())) };
        let address_type = AddressType::from_byte(data[1]).ok_or_else(|| Error::InvalidAddress("bad type".into()))?;

        // M-3 FIX: Reject oversized payloads — each address type has a fixed length
        // (including the 4-byte checksum already stripped into `bytes`).
        let expected_len = match address_type {
            AddressType::Standard | AddressType::Subaddress => 70,
            AddressType::Integrated => 78,
        };
        if bytes.len() != expected_len {
            return Err(Error::InvalidAddress(
                format!("wrong length: expected {} bytes, got {}", expected_len, bytes.len()),
            ));
        }

        let spend = PublicKey::from_slice(&data[2..34])?;
        let view = PublicKey::from_slice(&data[34..66])?;
        let payment_id = if address_type == AddressType::Integrated {
            // Integrated addresses require additional 8 bytes for payment ID
            if data.len() < 74 {
                return Err(Error::InvalidAddress("integrated address too short".into()));
            }
            let mut pid = [0u8; 8]; pid.copy_from_slice(&data[66..74]); Some(pid)
        } else { None };

        Ok(Address { network, address_type, spend_public_key: spend, view_public_key: view, payment_id })
    }

    /// Parse address from bytes with curve point validation
    /// SECURITY: Use this for untrusted input (network, user input)
    pub fn from_bytes_checked(bytes: &[u8]) -> Result<Self> {
        let addr = Self::from_bytes(bytes)?;

        // SECURITY: Validate that public keys are valid curve points
        // Invalid points would cause ECDH operations to fail or produce wrong results
        if PublicPoint::from_bytes(*addr.spend_public_key.as_bytes()).is_none() {
            return Err(Error::InvalidAddress("spend key is not a valid curve point".into()));
        }
        if PublicPoint::from_bytes(*addr.view_public_key.as_bytes()).is_none() {
            return Err(Error::InvalidAddress("view key is not a valid curve point".into()));
        }

        Ok(addr)
    }
    
    /// Format address as string (delegates to Display impl).
    /// FIX: Previously duplicated the Display impl — could silently drift.
    /// Now removed in favour of the auto-derived to_string() from Display.
    fn format_string(&self) -> String {
        format!("{}{}", self.network.prefix(), bs58::encode(self.to_bytes()).into_string())
    }

    /// Parse address from string representation
    /// SECURITY: Uses checked parsing to validate curve points (user input is untrusted)
    pub fn from_string(s: &str) -> Result<Self> {
        let (network, rest) = if let Some(rest) = s.strip_prefix("tCYNC") {
            (Network::Testnet, rest)
        } else if let Some(rest) = s.strip_prefix("CYNC") {
            (Network::Mainnet, rest)
        } else {
            return Err(Error::InvalidAddress("bad prefix".into()));
        };
        let bytes = bs58::decode(rest).into_vec().map_err(|e| Error::InvalidAddress(e.to_string()))?;
        // SECURITY: Use checked parsing for user input
        let addr = Self::from_bytes_checked(&bytes)?;
        if addr.network != network { return Err(Error::InvalidAddress("network mismatch".into())); }
        Ok(addr)
    }
    
    pub fn short(&self) -> String {
        let full = self.format_string();
        if full.len() > 20 { format!("{}...{}", &full[..12], &full[full.len()-6..]) } else { full }
    }
}

impl fmt::Debug for Address { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "Address({})", self.short()) } }
impl fmt::Display for Address { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.format_string()) } }

impl FromStr for Address {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        if s.ends_with(NAME_SUFFIX) { return Err(Error::InvalidAddress("name lookup required".into())); }
        Address::from_string(s)
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> where S: serde::Serializer {
        if ser.is_human_readable() { ser.serialize_str(&self.format_string()) } else { ser.serialize_bytes(&self.to_bytes()) }
    }
}
impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(de: D) -> std::result::Result<Self, D::Error> where D: serde::Deserializer<'de> {
        if de.is_human_readable() {
            // `from_string` calls `from_bytes_checked` internally (see L143).
            Address::from_string(&<String as Deserialize>::deserialize(de)?).map_err(serde::de::Error::custom)
        } else {
            // AUDIT (2026-07-02): use `from_bytes_checked` instead of the
            // unchecked `from_bytes`. Serde is the entry point for any
            // non-Borsh deserialization surface (CBOR / MessagePack / any
            // future RPC-request path that uses a binary Serde format),
            // so this IS an untrusted-input branch — the exact case
            // `from_bytes`'s own doc comment (L69–70) warns against:
            // "Parse address from bytes (unchecked - does not validate
            // curve points). Use `from_bytes_checked` for untrusted input".
            // The human-readable branch above already routes through
            // `from_string` → `from_bytes_checked`, so this closes the
            // documentation-vs-code drift and makes both Serde paths
            // consistent.
            //
            // Not touching the derived BorshDeserialize impl at L42 in this
            // pass — the persisted-Address surface is currently wallet-
            // internal (wallet.dat sidecars, RPC responses we produced
            // ourselves), not attacker-controlled. If a future feature
            // accepts Borsh-encoded Address from a peer, a custom
            // BorshDeserialize impl mirroring this fix will be needed
            // there too.
            Address::from_bytes_checked(&<Vec<u8> as Deserialize>::deserialize(de)?).map_err(serde::de::Error::custom)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use crate::crypto::SecretScalar;

    /// Generate a proper EC keypair (valid curve points)
    fn generate_ec_keypair() -> (crate::primitives::SecretKey, PublicKey) {
        let secret = SecretScalar::random(&mut OsRng);
        let public = secret.to_public();
        (
            crate::primitives::SecretKey::from_bytes(secret.to_bytes()),
            PublicKey::from_bytes(public.to_bytes()),
        )
    }

    #[test]
    fn test_address_roundtrip() {
        let (_spend_secret, spend_public) = generate_ec_keypair();
        let (_view_secret, view_public) = generate_ec_keypair();
        let addr = Address::new(Network::Mainnet, spend_public, view_public);
        let s = addr.to_string();
        assert!(s.starts_with("CYNC"));
        let parsed = Address::from_string(&s).unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_invalid_curve_point_rejected() {
        // Random bytes are NOT valid curve points
        let invalid_spend = PublicKey::from_bytes([0xAB; 32]);
        let invalid_view = PublicKey::from_bytes([0xCD; 32]);
        let addr = Address::new(Network::Mainnet, invalid_spend, invalid_view);
        let s = addr.to_string();

        // from_string uses checked parsing, should reject invalid points
        let result = Address::from_string(&s);
        assert!(result.is_err());
    }

    #[test]
    fn test_malformed_address_rejected() {
        // Empty string
        assert!(Address::from_string("").is_err());
        // Random garbage
        assert!(Address::from_string("not_a_real_address_at_all").is_err());
        // Correct prefix but garbage body
        assert!(Address::from_string("CYNC1234567890abcdef").is_err());
        // Too short
        assert!(Address::from_string("CYNC").is_err());
    }
}
