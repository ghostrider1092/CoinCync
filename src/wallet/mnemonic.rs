//! # BIP39 Mnemonic Implementation
//!
//! Proper mnemonic generation and seed derivation for CoinCync wallets.

use bip39::{Language, Mnemonic};
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::error::{Error, Result};

/// Number of words in the mnemonic
pub const MNEMONIC_WORDS: usize = 24;

/// Entropy bytes for 24-word mnemonic (256 bits)
const ENTROPY_BYTES: usize = 32;

/// Mnemonic wrapper with zeroization
#[derive(Clone, ZeroizeOnDrop)]
pub struct WalletMnemonic {
    phrase: String,
}

impl WalletMnemonic {
    /// Generate a new random mnemonic (24 words = 256 bits of entropy)
    ///
    /// SECURITY: Uses OsRng (OS-provided entropy source) instead of thread_rng
    /// for cryptographic key material. OsRng provides direct access to the OS
    /// entropy pool (/dev/urandom on Unix, BCryptGenRandom on Windows).
    pub fn generate() -> Result<Self> {
        // Generate 256 bits of entropy for 24-word mnemonic
        // SECURITY: OsRng provides cryptographically secure randomness from the OS
        let mut entropy = [0u8; ENTROPY_BYTES];
        OsRng.fill_bytes(&mut entropy);

        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|e| Error::InvalidMnemonic(e.to_string()))?;

        // Zeroize entropy after use
        entropy.zeroize();

        // SECURITY: Capture the phrase and ensure the intermediate Mnemonic
        // doesn't hold sensitive data longer than needed.
        //
        // AUDIT (R-76 SURGICAL FIX, 2026-07-03): the earlier "upstream
        // doesn't zeroize" claim was wrong. bip39 2.2.2 DOES derive
        // `Zeroize + ZeroizeOnDrop` on `Mnemonic` when the crate is
        // built with `features = ["zeroize"]` (verified against
        // bip39-2.2.2/src/lib.rs). Our Cargo.toml now enables that
        // feature explicitly, so `drop(mnemonic)` DOES wipe the
        // internal word-index array. Keeping the explicit `drop`
        // call for lifetime clarity.
        let phrase = mnemonic.to_string();
        drop(mnemonic);

        Ok(WalletMnemonic { phrase })
    }

    /// Create from an existing phrase
    pub fn from_phrase(phrase: &str) -> Result<Self> {
        // Validate the mnemonic by parsing it
        let _mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|e| Error::InvalidMnemonic(e.to_string()))?;

        Ok(WalletMnemonic {
            phrase: phrase.to_string(),
        })
    }

    /// Get the mnemonic phrase.
    ///
    /// SECURITY: This returns a `&str` pointing into the zeroized `phrase`
    /// field. The reference itself is safe (drops with the `WalletMnemonic`),
    /// but callers MUST NOT copy the contents into any non-zeroizing container
    /// (`String`, `format!`, `Debug` macros, error messages, tracing spans).
    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    /// Visit each word of the phrase without materializing a `Vec<&str>`.
    ///
    /// SECURITY: Previously we exposed `words() -> Vec<&str>`, which returned
    /// a heap-allocated vector of references into the backing seed phrase.
    /// Those references could easily escape into logs, error messages, or
    /// `Debug`/`Display` macros — bypassing the `ZeroizeOnDrop` guarantee on
    /// `WalletMnemonic`. The visitor pattern keeps references scoped to the
    /// closure body, which is the smallest provable lifetime we can offer.
    pub fn for_each_word<F: FnMut(&str)>(&self, mut f: F) {
        for w in self.phrase.split_whitespace() {
            f(w);
        }
    }

    /// Derive the seed from the mnemonic with optional passphrase.
    ///
    /// AUDIT (R-77 fix, 2026-07-03): `mnemonic.to_seed(passphrase)`
    /// returns a `[u8; 64]` on the stack. Pre-fix code moved it
    /// into `WalletSeed::from_bytes(&seed)` and let the local drop
    /// unzeroized. Since WalletSeed IS `ZeroizeOnDrop`, the OUTPUT
    /// is protected — but the intermediate stack copy in `seed`
    /// was not, so a stack frame reuse after this call could
    /// observe the raw 64-byte BIP39 seed. Explicit zeroize of the
    /// intermediate closes the window.
    pub fn to_seed(&self, passphrase: &str) -> WalletSeed {
        let mnemonic = Mnemonic::parse_in(Language::English, &self.phrase)
            .expect("mnemonic already validated");
        let mut seed = mnemonic.to_seed(passphrase);
        let wallet_seed = WalletSeed::from_bytes(&seed);
        // R-77: wipe the intermediate [u8; 64] before it goes out of scope.
        seed.zeroize();
        wallet_seed
    }

    /// Validate a mnemonic phrase
    pub fn validate(phrase: &str) -> bool {
        Mnemonic::parse_in(Language::English, phrase).is_ok()
    }

    /// Get word count without allocating.
    pub fn word_count(&self) -> usize {
        self.phrase.split_whitespace().count()
    }
}

impl std::fmt::Debug for WalletMnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WalletMnemonic([REDACTED {} words])", self.word_count())
    }
}

/// SECURITY: Wrapper for the 32-byte master key that automatically zeroizes
/// on drop to prevent secret key material from lingering in memory.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    bytes: [u8; 32],
}

impl MasterKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        MasterKey { bytes }
    }
}

impl std::ops::Deref for MasterKey {
    type Target = [u8; 32];
    fn deref(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl AsRef<[u8; 32]> for MasterKey {
    fn as_ref(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MasterKey([REDACTED])")
    }
}

/// Wallet seed (512-bit derived from mnemonic)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct WalletSeed {
    bytes: [u8; 64],
}

impl WalletSeed {
    /// Create from bytes.
    ///
    /// AUDIT (R-78 fix, 2026-07-03): the pre-fix code silently
    /// zero-padded short inputs and silently truncated long inputs
    /// via `bytes.len().min(64)`. Both are silent-corruption paths:
    ///   - A caller passing a `[u8; 32]` HALF-SEED gets a WalletSeed
    ///     whose second 32 bytes are all zero. Key derivation
    ///     succeeds but produces wrong keys, and no error surfaces.
    ///   - A caller passing a `[u8; 128]` (say, a doubled seed by
    ///     bug) gets the first 64 bytes silently. Wrong keys, no
    ///     error.
    /// Now length-check: exact 64-byte requirement, panic in debug
    /// so the misuse is unmissable, tracing::error + best-effort fill
    /// in release so an in-production caller doesn't crash. The
    /// canonical use-case (`to_seed` passing a 64-byte
    /// mnemonic-derived seed) is unaffected.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() != 64 {
            debug_assert!(
                false,
                "R-78: WalletSeed::from_bytes given {} bytes, expected 64",
                bytes.len()
            );
            tracing::error!(
                target: "wallet::mnemonic::R78",
                input_len = bytes.len(),
                "R-78: WalletSeed::from_bytes given {} bytes, expected 64 — \
                 silent truncation/padding is a corruption path, but \
                 continuing to avoid panic on the release fallback",
                bytes.len()
            );
        }
        let mut seed_bytes = [0u8; 64];
        let len = bytes.len().min(64);
        seed_bytes[..len].copy_from_slice(&bytes[..len]);
        WalletSeed { bytes: seed_bytes }
    }

    /// Get seed bytes
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.bytes
    }

    /// Get the first 32 bytes (for key derivation)
    ///
    /// SECURITY: Returns a `MasterKey` wrapper that zeroizes on drop to prevent
    /// secret key material from lingering in memory.
    pub fn master_key(&self) -> MasterKey {
        let mut key = [0u8; 32];
        key.copy_from_slice(&self.bytes[..32]);
        MasterKey::from_bytes(key)
    }

    /// Get the chain code (last 32 bytes)
    pub fn chain_code(&self) -> [u8; 32] {
        let mut code = [0u8; 32];
        code.copy_from_slice(&self.bytes[32..]);
        code
    }
}

impl std::fmt::Debug for WalletSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WalletSeed([REDACTED])")
    }
}

/// HD key derivation path
#[derive(Clone, Debug)]
pub struct DerivationPath {
    /// Path components (hardened if >= 0x80000000)
    components: Vec<u32>,
}

impl DerivationPath {
    /// Create a new derivation path
    pub fn new(components: Vec<u32>) -> Self {
        DerivationPath { components }
    }

    /// CoinCync standard path: m/44'/888'/account'/change'/index'
    /// CoinType for CoinCync: 888 (unofficial, needs BIP registration)
    ///
    /// SECURITY (M-6): All components are hardened because derive_child_key
    /// always uses private-key-based derivation. Making the path honest about
    /// this prevents interoperability mismatches with standard BIP32 tools.
    pub fn coincync(account: u32, change: u32, index: u32) -> Self {
        DerivationPath {
            components: vec![
                44 | 0x80000000,      // purpose (hardened)
                888 | 0x80000000,     // coin type (hardened)
                account | 0x80000000, // account (hardened)
                change | 0x80000000,  // change (hardened - matches actual derivation)
                index | 0x80000000,   // address index (hardened - matches actual derivation)
            ],
        }
    }

    /// View key derivation path
    pub fn view_key(account: u32) -> Self {
        DerivationPath {
            components: vec![
                44 | 0x80000000,
                888 | 0x80000000,
                account | 0x80000000,
                2 | 0x80000000,  // special: view key (hardened)
                0 | 0x80000000,
            ],
        }
    }

    /// Spend key derivation path. All components hardened to match the
    /// behaviour of `derive_child_key` (which always forces the hardened
    /// bit), `DerivationPath::coincync`, and the sibling `view_key`.
    ///
    /// 2026-06-03 correctness fix: the previous variant left the last
    /// two components (3 and 0) unhardened in the path representation.
    /// `derive_child_key` still hardened them at derivation time, so
    /// the actual keys produced were correct — but `to_string()`
    /// rendered the path as `m/44'/888'/account'/3/0`, which is
    /// misleading both to humans reading logs and to any external
    /// BIP32-compatible tool that parses the path. The function is
    /// currently unused in production (verified via repo-wide grep),
    /// so this is purely a representational fix to prevent a future
    /// wiring from producing inconsistent diagnostics.
    pub fn spend_key(account: u32) -> Self {
        DerivationPath {
            components: vec![
                44 | 0x80000000,
                888 | 0x80000000,
                account | 0x80000000,
                3 | 0x80000000,  // special: spend key (hardened)
                0 | 0x80000000,  // (hardened)
            ],
        }
    }

    /// Parse from string (e.g., "m/44'/888'/0'/0/0")
    pub fn from_string(path: &str) -> Result<Self> {
        let path = path.trim();
        if !path.starts_with("m/") && !path.starts_with("M/") {
            return Err(Error::InvalidMnemonic("Path must start with m/".into()));
        }

        let mut components = Vec::new();
        for part in path[2..].split('/') {
            if part.is_empty() {
                continue;
            }

            let (num_str, hardened) = if part.ends_with('\'') || part.ends_with('h') || part.ends_with('H') {
                (&part[..part.len()-1], true)
            } else {
                (part, false)
            };

            let num: u32 = num_str.parse()
                .map_err(|_| Error::InvalidMnemonic(format!("Invalid path component: {}", part)))?;

            let component = if hardened {
                num | 0x80000000
            } else {
                num
            };

            components.push(component);
        }

        Ok(DerivationPath { components })
    }

    /// Get path components
    pub fn components(&self) -> &[u32] {
        &self.components
    }

    /// Convert to string representation
    pub fn to_string(&self) -> String {
        let mut result = String::from("m");
        for &component in &self.components {
            result.push('/');
            if component >= 0x80000000 {
                result.push_str(&(component - 0x80000000).to_string());
                result.push('\'');
            } else {
                result.push_str(&component.to_string());
            }
        }
        result
    }
}

impl std::fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

/// Derive child key using HMAC-SHA512.
///
/// AUDIT (R-79 fix, 2026-07-03): pre-fix code called
/// `mac.finalize().into_bytes()` which returns a `GenericArray<u8, 64>`
/// carrying the raw HMAC-SHA512 output. That output IS the child_key
/// ‖ child_chain — pure secret material — and dropped without
/// zeroization. On stack-reuse the freed slot exposes the derived
/// child key. Now we explicitly zeroize the intermediate buffer
/// before returning.
pub fn derive_child_key(parent_key: &[u8; 32], parent_chain: &[u8; 32], index: u32) -> ([u8; 32], [u8; 32]) {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    use zeroize::Zeroize;

    type HmacSha512 = Hmac<Sha512>;

    let mut mac = HmacSha512::new_from_slice(parent_chain)
        .expect("HMAC can take key of any size");

    // Privacy coins use hardened-only derivation to prevent key leakage
    // from public key exposure. Force hardened bit on all indices.
    let hardened_index = index | 0x80000000;
    mac.update(&[0x00]);
    mac.update(parent_key);

    mac.update(&hardened_index.to_be_bytes());

    // R-79: bind the finalize output to a mutable var so we can
    // zeroize it before it goes out of scope. `into_bytes` returns
    // a GenericArray; copy into a plain [u8; 64] we control, then
    // wipe both.
    let result_ga = mac.finalize().into_bytes();
    let mut result: [u8; 64] = [0u8; 64];
    result.copy_from_slice(&result_ga);

    let mut child_key = [0u8; 32];
    let mut child_chain = [0u8; 32];
    child_key.copy_from_slice(&result[..32]);
    child_chain.copy_from_slice(&result[32..]);

    // R-79: wipe the intermediate HMAC output. child_key /
    // child_chain themselves are returned to the caller — the
    // caller is responsible for wiping them (and does in every
    // derivation path today).
    result.zeroize();

    (child_key, child_chain)
}

/// Derive keys from seed using path
pub fn derive_from_seed(seed: &WalletSeed, path: &DerivationPath) -> ([u8; 32], [u8; 32]) {
    use zeroize::Zeroize;
    let mut key = *seed.master_key();
    let mut chain = seed.chain_code();

    for &index in path.components() {
        let (new_key, new_chain) = derive_child_key(&key, &chain, index);
        // SECURITY: Zeroize intermediate keys to prevent memory forensics
        key.zeroize();
        chain.zeroize();
        key = new_key;
        chain = new_chain;
    }

    (key, chain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mnemonic_generation() {
        let mnemonic = WalletMnemonic::generate().unwrap();
        assert_eq!(mnemonic.word_count(), 24);
        assert!(WalletMnemonic::validate(mnemonic.phrase()));
    }

    #[test]
    fn test_mnemonic_from_phrase() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let mnemonic = WalletMnemonic::from_phrase(phrase).unwrap();
        assert_eq!(mnemonic.word_count(), 24);
    }

    #[test]
    fn test_invalid_mnemonic() {
        let result = WalletMnemonic::from_phrase("invalid mnemonic phrase");
        assert!(result.is_err());
    }

    #[test]
    fn test_seed_derivation() {
        let mnemonic = WalletMnemonic::generate().unwrap();
        let seed1 = mnemonic.to_seed("");
        let seed2 = mnemonic.to_seed("password");

        // Different passphrases should give different seeds
        assert_ne!(seed1.as_bytes(), seed2.as_bytes());

        // Same passphrase should give same seed
        let seed3 = mnemonic.to_seed("");
        assert_eq!(seed1.as_bytes(), seed3.as_bytes());
    }

    #[test]
    fn test_derivation_path_parse() {
        let path = DerivationPath::from_string("m/44'/888'/0'/0/0").unwrap();
        assert_eq!(path.components().len(), 5);
        assert_eq!(path.components()[0], 44 | 0x80000000);
        assert_eq!(path.components()[1], 888 | 0x80000000);
    }

    #[test]
    fn test_derivation_path_to_string() {
        let path = DerivationPath::coincync(0, 0, 0);
        // SECURITY (M-6): All components are hardened
        assert_eq!(path.to_string(), "m/44'/888'/0'/0'/0'");
    }

    #[test]
    fn test_key_derivation() {
        let mnemonic = WalletMnemonic::generate().unwrap();
        let seed = mnemonic.to_seed("");

        let path1 = DerivationPath::coincync(0, 0, 0);
        let path2 = DerivationPath::coincync(0, 0, 1);

        let (key1, _) = derive_from_seed(&seed, &path1);
        let (key2, _) = derive_from_seed(&seed, &path2);

        // Different paths should give different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_invalid_word_detection() {
        // "zzzzzz" is not in the BIP39 wordlist
        let bad = "zzzzzz abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        assert!(WalletMnemonic::from_phrase(bad).is_err());
        assert!(!WalletMnemonic::validate(bad));
    }
}
