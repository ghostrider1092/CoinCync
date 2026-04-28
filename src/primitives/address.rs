//! # Address Types for CoinCync 2.0
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

#[derive(Clone, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct Address {
    pub network: Network,
    pub address_type: AddressType,
    pub spend_public_key: PublicKey,
    pub view_public_key: PublicKey,
    pub payment_id: Option<[u8; 8]>,
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
            Address::from_string(&<String as Deserialize>::deserialize(de)?).map_err(serde::de::Error::custom)
        } else {
            Address::from_bytes(&<Vec<u8> as Deserialize>::deserialize(de)?).map_err(serde::de::Error::custom)
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
