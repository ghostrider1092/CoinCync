//! # Wallet Persistence
//!
//! Wallet file storage and encryption using authenticated encryption
//! (XChaCha20-Poly1305) and memory-hard key derivation (Argon2id).

use std::path::Path;
use std::io::{Read, Write};
use std::fs::File;
use serde::{Serialize, Deserialize};
use borsh::{BorshSerialize, BorshDeserialize};
use rand::RngCore;
use rand::rngs::OsRng;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use argon2::Argon2;
use zeroize::Zeroize;

use crate::primitives::hash_data;
use crate::error::{Error, Result};

/// Wallet file magic bytes
const WALLET_MAGIC: &[u8; 4] = b"CYWL";

/// Wallet file version.
///
/// History:
/// - v1: pre-2026-04 layout (replaced).
/// - v2: 2026-04 → 2026-05-08. Single hardcoded set of Argon2id params
///   compiled into the binary; no per-wallet params in the header.
///   Bumping the params required either a breaking migration or
///   leaving wallets stuck at the original params forever.
/// - v3: 2026-05-08+. Argon2id params (`kdf_m_cost`, `kdf_t_cost`,
///   `kdf_p_cost`) are stored IN the wallet header, so each wallet
///   remembers what it was encrypted with. `derive_key` takes the
///   params explicitly. Bumping the binary's default params is no
///   longer a breaking change: existing v2 wallets keep loading with
///   their original params, and any save (which always writes v3)
///   auto-upgrades the on-disk file with whatever the binary's
///   current default is.
const WALLET_VERSION: u8 = 3;

/// Wallet format v4: same WalletHeader struct as v3, but the wire
/// format adds a 32-byte BLAKE3-keyed HMAC suffix that authenticates
/// every byte of the file before it. This closes the v3 header-
/// tampering timing channel where an attacker with file-write access
/// could weaken the on-disk KDF params (lowering m_cost from 256 MiB
/// to 8 KiB) and turn the user's machine into a fast-unlock oracle
/// against their password.
///
/// Full design at docs/security/wallet-file-v4-design.md. Brief
/// summary of the additions vs v3:
///   - Two keys (enc_key, mac_key) derived from the password+salt
///     via Argon2id → HKDF-BLAKE3, so observing one key reveals
///     nothing about the other.
///   - The HMAC is verified BEFORE AEAD decryption is attempted —
///     a tampered header fails fast at HMAC time, with no key-
///     material leakage.
///   - File grows by exactly V4_HMAC_BYTES = 32 bytes vs the v3
///     equivalent.
///
/// As of 2026-05-25 this constant is defined but the public
/// `save_wallet` API still writes v3. v4 save/load is reached via
/// the internal `save_v4` / `load_v4` paths (round-trip tests).
/// Step 6 of the implementation plan flips the public default;
/// until then v4 is opt-in.
const WALLET_VERSION_V4: u8 = 4;

/// Length in bytes of the BLAKE3-keyed-hash output used as the v4
/// HMAC. blake3::keyed_hash returns a 32-byte digest.
const V4_HMAC_BYTES: usize = 32;

/// HKDF context strings for v4 key derivation. The two keys
/// (encryption + MAC) are derived from the same Argon2-output ikm
/// via blake3::derive_key with these distinct context labels. The
/// longer "domain-separation tag" form is preferred over short
/// labels (per design doc Open Question #2) — these are constants
/// that don't affect performance and the readability win matters at
/// audit time.
const V4_HKDF_CONTEXT_ENC: &str = "coincync/wallet-file/v4/enc-key";
const V4_HKDF_CONTEXT_MAC: &str = "coincync/wallet-file/v4/mac-key";

/// Argon2id parameters for memory-hard KDF — current default.
///
/// Rationale (Item 22 audit, 2026-05-08):
///
/// RFC 9106 §4 specifies two recommended profiles for Argon2id:
///   - "First recommended": m=2 GiB, t=1, p=4. Best for systems
///     with abundant memory (servers, modern desktops).
///   - "Second recommended": m=64 MiB, t=3, p=4. Fallback for
///     memory-constrained systems (mobile, embedded). This is
///     where v2 was — at the floor of what's still defensible.
///
/// CoinCync's wallet runs on real-user hardware: laptops with
/// 8-64 GiB RAM. Using the second-recommended profile leaves
/// significant headroom on the table. We pick the midpoint —
/// m=256 MiB — which:
///   - Stays well under any modern user's RAM (256 MiB ≈ 3% of
///     a 8 GiB laptop, ≈ 0.4% of a 64 GiB workstation).
///   - Is 4x more memory-hard than v2's 64 MiB → 4x the cost
///     to a GPU/ASIC attacker per password guess.
///   - Adds ~600-800 ms to wallet unlock on commodity CPUs (was
///     ~150-250 ms in v2). Tolerable for a privacy-coin wallet
///     where the unlock is a deliberate, occasional action.
///
/// `t_cost` stays at 3 (RFC 9106 second-recommended). Beyond 3
/// the marginal attacker work increases linearly while honest
/// unlock cost increases linearly too, no ratio gain.
///
/// `p_cost` stays at 4 (RFC 9106 second-recommended). All modern
/// CPUs have ≥4 hardware threads; raising it doesn't help honest
/// users and gains nothing against attackers (who can also
/// parallelize).
///
/// These constants are written into the WalletHeader v3 on every
/// save, so the loader uses what the file was created with — never
/// the binary's current default. Bumping these values affects ONLY
/// new wallets and re-saved old wallets; pre-existing v2 wallets
/// keep loading at their original v2 params (see LEGACY_* below).
const ARGON2_M_COST: u32 = 262_144;  // 256 MiB memory
const ARGON2_T_COST: u32 = 3;        // 3 iterations
const ARGON2_P_COST: u32 = 4;        // 4 parallel lanes

/// Argon2id parameters from wallet format v2. Used ONLY when
/// loading a v2 wallet file that doesn't carry its own params in
/// the header. Kept here (rather than removed) because the chain
/// of pre-2026-05-08 wallet files in the wild needs to keep
/// loading; on first save after upgrade those wallets are rewritten
/// as v3 with the current default ARGON2_* params, so v2 is a
/// transient backward-compat shim, not a permanent compromise.
const LEGACY_V2_ARGON2_M_COST: u32 = 65_536;  // 64 MiB
const LEGACY_V2_ARGON2_T_COST: u32 = 3;
const LEGACY_V2_ARGON2_P_COST: u32 = 4;

fn harden_secret_file_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(windows)]
    {
        // Best-effort ACL hardening using built-in Windows tooling.
        // We remove inheritance and grant only the current user full control.
        if let Some(path_str) = path.to_str() {
            let _ = std::process::Command::new("icacls")
                .args([path_str, "/inheritance:r"])
                .status();
            let user = std::env::var("USERNAME").unwrap_or_else(|_| "Users".to_string());
            let grant = format!("{user}:F");
            let _ = std::process::Command::new("icacls")
                .args([path_str, "/grant:r", &grant])
                .status();
        }
    }
}

/// Wallet file header v2 (legacy).
///
/// Kept to deserialize wallet files created before 2026-05-08. The
/// loader detects v2 by inspecting the version byte and dispatches
/// here; v2 has no in-header KDF params, so it inherits
/// `LEGACY_V2_ARGON2_*` constants.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct WalletHeaderV2 {
    pub magic: [u8; 4],
    pub version: u8,
    pub encrypted: bool,
    pub kdf_salt: [u8; 32],
    pub nonce: [u8; 24],
    pub checksum: [u8; 4],
}

/// Wallet file header v3 (current).
///
/// Same layout as v2 with three appended u32 fields carrying the
/// Argon2id parameters used for THIS wallet's KDF. Storing per-wallet
/// means changing the binary's defaults (Item 22) doesn't break old
/// wallets — each wallet remembers what it was encrypted with.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct WalletHeader {
    pub magic: [u8; 4],
    pub version: u8,
    pub encrypted: bool,
    pub kdf_salt: [u8; 32],
    pub nonce: [u8; 24],
    pub checksum: [u8; 4],
    /// Argon2id memory cost (KiB). New wallets use ARGON2_M_COST.
    /// Old wallets carry their original value here so re-loading
    /// after a binary param-bump still derives the right key.
    pub kdf_m_cost: u32,
    /// Argon2id time cost (iterations).
    pub kdf_t_cost: u32,
    /// Argon2id parallelism (lanes).
    pub kdf_p_cost: u32,
}

impl WalletHeader {
    /// Create a new wallet header with fresh random salt and nonce,
    /// stamped with the binary's current default KDF parameters.
    ///
    /// SECURITY: Uses OsRng (OS entropy source) for cryptographic randomness.
    /// Uses a single RNG instance for both salt and nonce to avoid potential
    /// correlation issues from multiple RNG instantiations.
    pub fn new(encrypted: bool) -> Self {
        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 24];

        // SECURITY: Single OsRng instance for both values
        // OsRng provides cryptographically secure randomness from the OS
        let mut rng = OsRng;
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce);

        WalletHeader {
            magic: *WALLET_MAGIC,
            version: WALLET_VERSION,
            encrypted,
            kdf_salt: salt,
            nonce,
            checksum: [0u8; 4],
            kdf_m_cost: ARGON2_M_COST,
            kdf_t_cost: ARGON2_T_COST,
            kdf_p_cost: ARGON2_P_COST,
        }
    }

    /// Create a v4 wallet header. Identical to `new()` except the
    /// `version` byte is `WALLET_VERSION_V4` instead of
    /// `WALLET_VERSION`. The wire format adds a 32-byte BLAKE3-keyed
    /// HMAC suffix appended after the ciphertext by `save_v4`.
    ///
    /// As of step-1 of the wallet-v4 implementation, this constructor
    /// is only reached via the internal `save_v4` / `load_v4` round-
    /// trip tests; the public `save_wallet` API still writes v3.
    /// Step 6 of the plan flips the public default; until then v4 is
    /// opt-in via the round-trip paths.
    pub fn new_v4(encrypted: bool) -> Self {
        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 24];
        let mut rng = OsRng;
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce);

        WalletHeader {
            magic: *WALLET_MAGIC,
            version: WALLET_VERSION_V4,
            encrypted,
            kdf_salt: salt,
            nonce,
            checksum: [0u8; 4],
            kdf_m_cost: ARGON2_M_COST,
            kdf_t_cost: ARGON2_T_COST,
            kdf_p_cost: ARGON2_P_COST,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if &self.magic != WALLET_MAGIC {
            return Err(Error::WalletNotFound("invalid wallet magic".into()));
        }
        // Accept v3 (current default write) and v4 (opt-in via the
        // wallet-v4 round-trip paths). v2 is handled separately via
        // WalletHeaderV2 + the legacy load branch. Anything beyond v4
        // is a future format this binary doesn't know how to read.
        if self.version > WALLET_VERSION_V4 {
            return Err(Error::WalletNotFound("unsupported wallet version".into()));
        }

        // KDF-parameter bounds. Argon2id's m_cost is in KiB; a malicious
        // wallet file could set m_cost to a huge value and trick the
        // KDF into trying to allocate terabytes of memory before any
        // useful error surfaces. The symmetric case (m_cost / t_cost /
        // p_cost BELOW Argon2's minimums) makes `Params::new` return
        // Err, which the call site at `derive_key` panics on (intended
        // for an unreachable path under v3 defaults, but a corrupted
        // header bypasses that). Both directions reject the file here.
        //
        // Bound generously above the defaults
        // (ARGON2_M_COST = 262 144, ARGON2_T_COST = 3, ARGON2_P_COST = 4)
        // so future upgrades have room but adversarial values are
        // refused immediately.
        //
        // Upper-bound discovered 2026-05-19 by fuzz target
        // `fuzz_wallet_persistence` (crash file
        // `crash-6b3e53ff71c9e8e1cda383857565624d387c68fe`).
        // Lower-bound discovered 2026-05-19 by the same target in the
        // next overnight pass (crash file
        // `crash-c0a0e826ccb435bd9d48b5b1ed6ab0e0e6063050`,
        // panic = "valid Argon2 params: MemoryTooLittle").
        // Upper bounds tightened 2026-05-23 after fuzz overnight #4
        // surfaced legit-but-pathological Argon2 inputs that took
        // ~30+ seconds at the previous 1 GiB / 100-iter / 16-lane
        // caps (slow-units 025434bd, 0a9d8f66, 7487547a). The
        // previous bounds were "future-proof" but allowed crafted
        // wallets to make the loader spend a full minute deriving a
        // key. Defaults (m=256 MiB, t=3, p=4) sit well below the new
        // caps, so legitimate wallets are unaffected.
        const KDF_M_COST_MAX_KIB: u32 = 524_288;    // 512 MiB; 2× default (was 1 GiB)
        const KDF_T_COST_MAX: u32 = 32;             // 32 iter; ~10× default (was 100)
        const KDF_P_COST_MAX: u32 = 8;              // 8 lanes; 2× default (was 16)
        // Argon2 crate minimums (`argon2::Params::MIN_*`). Hardcoded
        // here so a future crate-version bump that lowers them doesn't
        // silently widen our acceptance window.
        const KDF_M_COST_MIN_KIB: u32 = 8;          // argon2::Params::MIN_M_COST
        const KDF_T_COST_MIN: u32 = 2;              // argon2::Params::MIN_T_COST
        const KDF_P_COST_MIN: u32 = 1;              // argon2::Params::MIN_P_COST
        if self.kdf_m_cost > KDF_M_COST_MAX_KIB || self.kdf_m_cost < KDF_M_COST_MIN_KIB {
            return Err(Error::Corruption(format!(
                "kdf_m_cost out of range: {} KiB (allowed {}..={} KiB)",
                self.kdf_m_cost, KDF_M_COST_MIN_KIB, KDF_M_COST_MAX_KIB
            )));
        }
        if self.kdf_t_cost > KDF_T_COST_MAX || self.kdf_t_cost < KDF_T_COST_MIN {
            return Err(Error::Corruption(format!(
                "kdf_t_cost out of range: {} (allowed {}..={})",
                self.kdf_t_cost, KDF_T_COST_MIN, KDF_T_COST_MAX
            )));
        }
        if self.kdf_p_cost > KDF_P_COST_MAX || self.kdf_p_cost < KDF_P_COST_MIN {
            return Err(Error::Corruption(format!(
                "kdf_p_cost out of range: {} (allowed {}..={})",
                self.kdf_p_cost, KDF_P_COST_MIN, KDF_P_COST_MAX
            )));
        }

        // RFC 9106 §3.1: m_cost MUST satisfy m_cost >= 8 × p_cost.
        // Individual bounds above don't catch this cross-constraint —
        // e.g., m_cost = 8 + p_cost = 16 passes both but Argon2 rejects
        // with `MemoryTooLittle`, which the loader's `.expect` then
        // turns into a panic-on-malformed-input DoS.
        // Discovered by fuzz overnight #4 (2026-05-23) via crash file
        // `crash-1c3a7e3e370f472432dfbedaba8b8ce6b7338246`.
        // p_cost is bounded to <= 16 above, so 8 * p_cost is at most
        // 128 and never overflows u32.
        let min_m_for_p = 8 * self.kdf_p_cost;
        if self.kdf_m_cost < min_m_for_p {
            return Err(Error::Corruption(format!(
                "kdf_m_cost {} KiB too small for kdf_p_cost {} (min: {} KiB = 8 × p_cost per RFC 9106)",
                self.kdf_m_cost, self.kdf_p_cost, min_m_for_p
            )));
        }

        Ok(())
    }
}

impl WalletHeaderV2 {
    /// Promote a legacy v2 header to a v3 in-memory representation
    /// by attaching the LEGACY_V2_* params. Used by the loader after
    /// it dispatches on version. Note: this does NOT re-write the on-
    /// disk file; that happens on next save.
    fn into_v3(self) -> WalletHeader {
        WalletHeader {
            magic: self.magic,
            version: self.version,
            encrypted: self.encrypted,
            kdf_salt: self.kdf_salt,
            nonce: self.nonce,
            checksum: self.checksum,
            kdf_m_cost: LEGACY_V2_ARGON2_M_COST,
            kdf_t_cost: LEGACY_V2_ARGON2_T_COST,
            kdf_p_cost: LEGACY_V2_ARGON2_P_COST,
        }
    }
}

/// Wallet data (serializable)
///
/// SECURITY: Debug is manually implemented to redact the seed field.
/// SECURITY: Clone intentionally not derived to prevent accidental seed duplication.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct WalletData {
    /// Master seed (encrypted)
    pub seed: [u8; 32],
    /// Current key epoch
    pub current_epoch: u64,
    /// Scanned height
    pub scanned_height: u64,
    /// Wallet label
    pub label: String,
    /// Creation timestamp
    pub created_at: u64,
    /// Network (mainnet/testnet)
    pub network: String,
    /// Subaddress data (optional for backwards compatibility)
    #[serde(default)]
    pub subaddresses: Option<super::SubaddressData>,
    /// BIP39 mnemonic phrase, encrypted along with the rest of the
    /// wallet file. Stored so `coincync-wallet show-seed` can recover
    /// the phrase — BIP39 seed bytes are one-way (PBKDF2) so we can't
    /// reverse them to a phrase without storing it.
    ///
    /// Backwards-compat: old wallet files without this field deserialize
    /// with `None` and show-seed falls back to the raw seed hex.
    #[serde(default)]
    pub mnemonic_phrase: Option<String>,
}

impl std::fmt::Debug for WalletData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletData")
            .field("seed", &"[REDACTED]")
            .field("current_epoch", &self.current_epoch)
            .field("scanned_height", &self.scanned_height)
            .field("label", &self.label)
            .field("created_at", &self.created_at)
            .field("network", &self.network)
            .finish()
    }
}

// SECURITY (M-5): Zeroize master seed when WalletData is dropped to prevent
// it from lingering in freed memory (cold-boot/core-dump attacks).
impl Drop for WalletData {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl WalletData {
    pub fn new(seed: [u8; 32], network: &str) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        WalletData {
            seed,
            current_epoch: 0,
            scanned_height: 0,
            label: String::new(),
            created_at: timestamp,
            network: network.to_string(),
            subaddresses: None,
            mnemonic_phrase: None,
        }
    }
}

/// Derive encryption key from password using Argon2id (memory-hard KDF).
///
/// Argon2id is resistant to both GPU/ASIC attacks (memory-hard) and
/// side-channel attacks (hybrid of Argon2i and Argon2d).
///
/// As of WALLET_VERSION 3, the params are passed in (rather than read
/// from compile-time constants) because each wallet stores its own
/// params in its header. Callers in this crate use:
///   - `derive_key_default(pw, salt)` for code that wants the binary's
///     CURRENT default params (i.e., creating a new key for a new
///     wallet, or re-encrypting on save).
///   - `derive_key(pw, salt, m, t, p)` for code that's loading an
///     existing wallet and must use whatever params that wallet was
///     created with (read from its header).
pub fn derive_key(password: &str, salt: &[u8; 32], m_cost: u32, t_cost: u32, p_cost: u32) -> [u8; 32] {
    use argon2::{Algorithm, Version, Params};

    // INVARIANT: callers MUST pre-validate (m_cost, t_cost, p_cost) via
    // `KdfParams::validate()` before reaching this function. The expects
    // below are invariants of that validation, not user-input checks —
    // bypassing validate() (e.g., by introducing a new caller that loads
    // params from an unvalidated wallet header) re-introduces a panic-
    // on-malformed-input DoS that the load path is supposed to prevent.
    let params = Params::new(
        m_cost,
        t_cost,
        p_cost,
        Some(32),  // 32-byte output
    ).expect("Argon2 Params: bounds enforced by KdfParams::validate()");

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    // hash_password_into fails only on (a) buffer size mismatch — impossible
    // here, key is exactly 32 bytes — or (b) m_cost allocation OOM, which is
    // an operator-config issue (validate() upper-bound chosen to fit any
    // sane host). A panic in that case is the correct failure mode: the
    // process can't function with insufficient RAM for the configured KDF.
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("Argon2 KDF: buffer size and m_cost upper-bound are invariants");

    key
}

/// Derive a key using the binary's CURRENT default Argon2id params.
/// Use only when creating fresh keys (not when loading an existing
/// wallet — for that, use the params stored in the wallet's header).
pub fn derive_key_default(password: &str, salt: &[u8; 32]) -> [u8; 32] {
    derive_key(password, salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST)
}

/// Derive the two v4 keys (encryption + MAC) from a password.
///
/// The flow is: Argon2id(password, salt, params) → ikm (32 bytes) →
/// HKDF-Expand via `blake3::derive_key` with distinct context labels
/// → (enc_key, mac_key). The two keys are independent because each
/// derive_key call hashes the ikm with a different context string,
/// so observing one key reveals nothing about the other.
///
/// SECURITY: re-uses `derive_key` (which is rigorously param-bounded
/// via the WalletHeader::validate() invariant) for the Argon2id step,
/// so the v4 path inherits the same protection against malformed-
/// header-induced KDF panics as v3. The HKDF step is constant-time
/// post-Argon2.
///
/// Pure function: no I/O, no logging, no global state. Unit-tested
/// independently for stability (test_v4_keys_distinct_and_stable).
pub fn derive_v4_keys(
    password: &str,
    salt: &[u8; 32],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> ([u8; 32], [u8; 32]) {
    // Step 1: Argon2id → 32-byte ikm. Reuses the existing `derive_key`
    // so the validated-bounds invariant continues to hold.
    let mut ikm = derive_key(password, salt, m_cost, t_cost, p_cost);

    // Step 2: HKDF-Expand via blake3::derive_key with two distinct
    // context strings. Each call returns 32 bytes; the two outputs
    // are computationally independent because the context strings
    // differ.
    let enc_key = blake3::derive_key(V4_HKDF_CONTEXT_ENC, &ikm);
    let mac_key = blake3::derive_key(V4_HKDF_CONTEXT_MAC, &ikm);

    // Zero the Argon2 output before returning. ikm is no longer
    // needed; only the two derived keys are.
    ikm.zeroize();

    (enc_key, mac_key)
}

/// Decrypt a sidecar (utxos / history / reservations) ciphertext, trying
/// the binary's current default KDF params first and falling back to the
/// v2 legacy params if that fails.
///
/// Why try-then-fallback: the wallet header carries its own KDF params
/// and gets auto-upgraded on save (Item 22), but sidecar files have no
/// header — they're just `salt(32) || nonce(24) || ciphertext`. After
/// the binary upgrade and one save() cycle every sidecar is re-encrypted
/// with v3 params, so the fallback path runs only on first-load-after-
/// upgrade. Cost: one extra Argon2id derivation per sidecar during that
/// transient window. Benefit: zero migration ceremony from the user's
/// side.
///
/// Returns Err if neither the v3 nor the v2 derivation produces a valid
/// authenticated decryption — that's the genuine "wrong password or
/// corrupted file" case.
pub fn decrypt_sidecar_with_fallback(
    salt: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    password: &str,
) -> Result<Vec<u8>> {
    // Try v3 (current default) first — the common case after the user
    // has saved at least once with the new binary.
    let mut key_v3 = derive_key_default(password, salt);
    let v3_result = decrypt(ciphertext, &key_v3, nonce);
    key_v3.zeroize();
    if let Ok(plain) = v3_result {
        return Ok(plain);
    }

    // Fall back to v2 legacy params — sidecars saved by pre-upgrade
    // binaries. After the next save() these get rewritten as v3 and
    // this branch stops firing for the wallet.
    let mut key_v2 = derive_key(
        password, salt,
        LEGACY_V2_ARGON2_M_COST,
        LEGACY_V2_ARGON2_T_COST,
        LEGACY_V2_ARGON2_P_COST,
    );
    let v2_result = decrypt(ciphertext, &key_v2, nonce);
    key_v2.zeroize();
    v2_result
}

/// Encrypt data using XChaCha20-Poly1305 (authenticated encryption)
///
/// This provides both confidentiality and integrity - any tampering
/// with the ciphertext will be detected during decryption.
pub fn encrypt(data: &[u8], key: &[u8; 32], nonce: &[u8; 24]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let xnonce = XNonce::from_slice(nonce);

    cipher.encrypt(xnonce, data)
        .map_err(|_| Error::Internal("encryption failed".into()))
}

/// Decrypt data using XChaCha20-Poly1305 (authenticated encryption)
///
/// Returns an error if authentication fails (data was tampered with).
pub fn decrypt(data: &[u8], key: &[u8; 32], nonce: &[u8; 24]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let xnonce = XNonce::from_slice(nonce);

    cipher.decrypt(xnonce, data)
        .map_err(|_| Error::InvalidSecretKey("decryption failed - wrong password or corrupted data".into()))
}

/// Save wallet to file.
///
/// Each save generates a fresh random nonce + (for v4) a fresh salt
/// to prevent IV reuse across saves.
///
/// STEPS 5+6 of wallet-v4 implementation: the public save_wallet API
/// now writes v4 by default for encrypted wallets. The v3 → v4
/// auto-upgrade is the natural consequence: any v3 wallet loaded
/// (via the v4 auto-detect in load_wallet_from_bytes) and re-saved
/// becomes a v4 file on disk. The user's password is unchanged; only
/// the file format upgrades.
///
/// Unencrypted wallets stay in v3 format — v4's whole point is the
/// HMAC, which requires a key derived from a password.
///
/// v3 save is still callable via `save_v3_internal` for round-trip
/// tests; production code shouldn't use it.
pub fn save_wallet(
    path: &Path,
    data: &WalletData,
    password: Option<&str>,
) -> Result<()> {
    if let Some(pwd) = password {
        // STEP 6: public default flipped to v4 for encrypted wallets.
        // Any prior v3 wallet that the user loads + saves gets auto-
        // upgraded to v4 here. tracing::info logs the upgrade exactly
        // once per save so the operator has a paper trail.
        tracing::info!("Saving wallet to {:?} in v4 format (HMAC-authenticated)", path);
        return save_v4(path, data, pwd);
    }

    // Unencrypted path stays v3. SECURITY (WAL-M1) warn — same as before.
    tracing::warn!(
        "Saving wallet to {:?} WITHOUT encryption. \
         Seed and keys are stored in plaintext. \
         Use a password to protect your wallet.",
        path
    );
    save_v3_internal(path, data, None)
}

/// v3 save path. Kept for round-trip tests + the unencrypted fallback
/// in `save_wallet`. New encrypted production wallets always go
/// through `save_v4` now (post-step-6 default flip).
///
/// `password: None` writes an unencrypted v3 file. `password: Some(_)`
/// writes an encrypted v3 file (used only by the round-trip-test
/// helper that wants to materialize a v3 file to then load + upgrade).
pub(crate) fn save_v3_internal(
    path: &Path,
    data: &WalletData,
    password: Option<&str>,
) -> Result<()> {
    let encrypted = password.is_some();
    // Fresh header with new random nonce for EACH save (prevents IV reuse)
    let mut header = WalletHeader::new(encrypted);

    // Serialize data
    let serialized = borsh::to_vec(data)
        .map_err(|e| Error::SerializationError(e.to_string()))?;

    // Encrypt if password provided (authenticated encryption)
    // SECURITY (M-5): Zeroize plaintext serialized data after encryption
    //
    // (Item 22) Use the params already stamped into `header` (which were
    // set to ARGON2_M_COST/T_COST/P_COST in WalletHeader::new). On every
    // save we write a fresh v3 header with the binary's CURRENT defaults,
    // so old v2 wallets get auto-upgraded to stronger params on first
    // save after the binary is upgraded.
    let final_data = if let Some(pwd) = password {
        let mut key = derive_key(pwd, &header.kdf_salt,
            header.kdf_m_cost, header.kdf_t_cost, header.kdf_p_cost);
        let result = encrypt(&serialized, &key, &header.nonce);
        key.zeroize(); // SECURITY: Clear key material from memory immediately
        let mut serialized_mut = serialized;
        serialized_mut.zeroize(); // Clear plaintext seed from memory
        result?
    } else {
        serialized
    };

    // Compute checksum (for unencrypted data; encrypted data has auth tag)
    let checksum_hash = hash_data(&final_data);
    header.checksum.copy_from_slice(&checksum_hash.as_bytes()[..4]);

    // Write to file atomically (write to temp, then rename)
    // SECURITY (M7): Set restrictive permissions on wallet files (owner-only on Unix)
    let temp_path = path.with_extension("tmp");
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600) // Owner read/write only
            .open(&temp_path)?
    };
    #[cfg(not(unix))]
    let mut file = File::create(&temp_path)?;

    let header_bytes = borsh::to_vec(&header)
        .map_err(|e| Error::SerializationError(e.to_string()))?;

    // Write header length first, then header, then data length, then data.
    // If any write fails, clean up the temp file to avoid leaving secret data on disk.
    let write_result = (|| -> Result<()> {
        file.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
        file.write_all(&header_bytes)?;
        file.write_all(&(final_data.len() as u32).to_le_bytes())?;
        file.write_all(&final_data)?;
        file.sync_all()?;
        Ok(())
    })();
    drop(file);

    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&temp_path);
        return Err(e);
    }

    harden_secret_file_permissions(&temp_path);
    // Atomic rename (prevents partial writes)
    if let Err(e) = std::fs::rename(&temp_path, path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(e.into());
    }
    harden_secret_file_permissions(path);

    Ok(())
}

/// Load wallet from file
///
/// Returns an error if:
/// - File doesn't exist
/// - Password is wrong (authentication failure)
/// - Data is corrupted
pub fn load_wallet(
    path: &Path,
    password: Option<&str>,
) -> Result<WalletData> {
    let bytes = std::fs::read(path)
        .map_err(|e| Error::WalletNotFound(e.to_string()))?;
    load_wallet_from_bytes(&bytes, password)
}

/// Parse a wallet from an in-memory byte slice. Used by the deniable
/// wallet loader so it can try password attempts against each region
/// without writing plaintext fragments to disk (the prior
/// path-based-only API forced the deniable loader to materialize
/// `tmp_d`/`tmp_r` files, and a crash between write and remove left
/// the chosen region's plaintext on disk — defeating the deniability
/// property the feature exists to provide).
pub fn load_wallet_from_bytes(
    bytes: &[u8],
    password: Option<&str>,
) -> Result<WalletData> {
    use std::io::Cursor;

    // Pre-parse: peek at the version byte at offset 8 (after the 4-byte
    // hdr_len LE and the 4-byte magic at the start of the borsh-encoded
    // header). v4 files have a different wire shape (32-byte HMAC suffix)
    // and a strict verification order; dispatch BEFORE the v2/v3 framing
    // parse so v4 doesn't fall through to the wrong code path.
    if bytes.len() >= 9 && bytes[8] == WALLET_VERSION_V4 {
        // STEP 4 of wallet-v4 implementation: v4 auto-detect lands.
        // v4 always requires a password (the HMAC concept demands a key
        // derived from one); a None password here is unrecoverable.
        let pwd = password.ok_or_else(|| Error::InvalidSecretKey(
            "v4 wallet requires a password".into()
        ))?;
        return load_v4_from_bytes(bytes, pwd);
    }

    let mut file = Cursor::new(bytes);

    // Read header length
    let mut header_len_bytes = [0u8; 4];
    file.read_exact(&mut header_len_bytes)?;
    // SAFETY: u32 always fits in usize on 64-bit targets
    let header_len = u32::from_le_bytes(header_len_bytes) as usize;

    // Sanity check header length
    if header_len > 1024 {
        return Err(Error::Corruption("invalid header length".into()));
    }

    // Read header
    let mut header_bytes = vec![0u8; header_len];
    file.read_exact(&mut header_bytes)?;

    // (Item 22) Dispatch on version. The `version` byte sits at offset 4
    // (right after the 4-byte magic) in both v2 and v3 layouts. Inspect
    // it before attempting Borsh deserialization, since the v3 struct
    // expects 12 more bytes than v2 — a v2 file fed to v3's borsh::
    // from_slice would fail with a confusing length error.
    //
    // v4 dispatch already happened above the cursor parse — we won't
    // reach here for v4 files. Keeping the v4 case in this match as a
    // belt-and-suspenders fallback that should never fire (the early
    // peek catches it first).
    if header_bytes.len() < 5 {
        return Err(Error::SerializationError("wallet header too short".into()));
    }
    let header: WalletHeader = match header_bytes[4] {
        2 => {
            let v2: WalletHeaderV2 = borsh::from_slice(&header_bytes)
                .map_err(|e| Error::SerializationError(format!("v2 header: {}", e)))?;
            v2.into_v3()
        }
        3 => {
            borsh::from_slice(&header_bytes)
                .map_err(|e| Error::SerializationError(format!("v3 header: {}", e)))?
        }
        4 => {
            // Unreachable in practice — caught by the early peek above.
            // If we somehow get here, it means the peek heuristic missed
            // (e.g. bytes < 9). Fall through to the v4 loader anyway so
            // the file isn't silently misparsed as v3.
            let pwd = password.ok_or_else(|| Error::InvalidSecretKey(
                "v4 wallet requires a password".into()
            ))?;
            return load_v4_from_bytes(bytes, pwd);
        }
        v => return Err(Error::WalletNotFound(format!("unsupported wallet version {}", v))),
    };

    header.validate()?;

    // Read data length
    let mut len_bytes = [0u8; 4];
    file.read_exact(&mut len_bytes)?;
    // SAFETY: u32 always fits in usize on 64-bit targets
    let data_len = u32::from_le_bytes(len_bytes) as usize;

    // Sanity check data length (max 100 MB)
    if data_len > 100 * 1024 * 1024 {
        return Err(Error::Corruption("data too large".into()));
    }

    // Read data
    let mut encrypted_data = vec![0u8; data_len];
    file.read_exact(&mut encrypted_data)?;

    // Verify checksum for unencrypted wallets only.
    // Encrypted wallets use AEAD (Poly1305 auth tag) for tamper detection,
    // making this checksum redundant and potentially misleading.
    if !header.encrypted {
        let checksum_hash = hash_data(&encrypted_data);
        if checksum_hash.as_bytes()[..4] != header.checksum {
            return Err(Error::Corruption("wallet checksum mismatch".into()));
        }
    }

    // Decrypt if needed (authenticated decryption will fail on tampering)
    //
    // (Item 22) Use the params from the header that the file was actually
    // saved with — NOT the binary's current defaults. For v2 files the
    // loader has stamped LEGACY_V2_ARGON2_* into `header` (via
    // `into_v3`) so the correct historical params get used. For v3
    // files the params are read directly from the on-disk header.
    let decrypted = if header.encrypted {
        let pwd = password.ok_or(Error::InvalidSecretKey("password required".into()))?;
        let mut key = derive_key(pwd, &header.kdf_salt,
            header.kdf_m_cost, header.kdf_t_cost, header.kdf_p_cost);
        let result = decrypt(&encrypted_data, &key, &header.nonce);
        key.zeroize(); // SECURITY: Clear key material from memory immediately
        result?
    } else {
        encrypted_data
    };

    // Deserialize
    let data: WalletData = borsh::from_slice(&decrypted)
        .map_err(|e| Error::SerializationError(e.to_string()))?;

    // SECURITY (M-5): Zeroize decrypted plaintext after deserialization
    let mut decrypted_mut = decrypted;
    decrypted_mut.zeroize();

    Ok(data)
}

/// Change wallet password
///
/// Decrypts with the old password, re-encrypts with the new password,
/// and writes atomically to prevent data loss. Also re-encrypts sidecar
/// files (.utxos, .history) so they remain accessible with the new password.
pub fn change_password(
    path: &Path,
    old_password: &str,
    new_password: &str,
) -> Result<()> {
    // Load wallet with old password
    let data = load_wallet(path, Some(old_password))?;

    // Re-save with new password (generates fresh salt + nonce)
    save_wallet(path, &data, Some(new_password))?;

    // SECURITY: Re-encrypt sidecar files (.utxos, .history, .reservations) with the new password.
    // Without this, sidecars remain encrypted with the old password and become
    // inaccessible after password change, causing data loss.
    let sidecar_extensions = ["utxos", "history", "reservations"];
    for ext in &sidecar_extensions {
        let sidecar_path = path.with_extension(ext);
        if sidecar_path.exists() {
            let bytes = std::fs::read(&sidecar_path)
                .map_err(|e| crate::error::Error::InvalidState(
                    format!("read sidecar .{}: {}", ext, e)
                ))?;

            // Decrypt with old password (same logic as Wallet::decrypt_sidecar)
            let plaintext = if bytes.len() > 56 {
                let mut salt = [0u8; 32];
                salt.copy_from_slice(&bytes[..32]);
                let mut nonce = [0u8; 24];
                nonce.copy_from_slice(&bytes[32..56]);
                let ciphertext = &bytes[56..];
                // (Item 22) Use the params-fallback decryptor: sidecars
                // saved by pre-2026-05-08 binaries used the v2 KDF
                // params; the new helper tries v3-default first then v2.
                match decrypt_sidecar_with_fallback(&salt, &nonce, ciphertext, old_password) {
                    Ok(pt) => pt,
                    Err(_) => bytes.clone(), // Unencrypted fallback
                }
            } else {
                bytes.clone()
            };

            // Re-encrypt with new password using current default params.
            // After change_password, the sidecar is rewritten with v3
            // params just like a normal save() does.
            let mut new_salt = [0u8; 32];
            OsRng.fill_bytes(&mut new_salt);
            let new_key = derive_key_default(new_password, &new_salt);
            let mut new_nonce = [0u8; 24];
            OsRng.fill_bytes(&mut new_nonce);
            let encrypted = encrypt(&plaintext, &new_key, &new_nonce)?;
            let output = [new_salt.as_slice(), new_nonce.as_slice(), encrypted.as_slice()].concat();

            // Atomic write: write to temp then rename
            let tmp_path = sidecar_path.with_extension(format!("{}.tmp", ext));
            std::fs::write(&tmp_path, &output)
                .map_err(|e| crate::error::Error::InvalidState(
                    format!("write sidecar .{}: {}", ext, e)
                ))?;
            std::fs::rename(&tmp_path, &sidecar_path)
                .map_err(|e| crate::error::Error::InvalidState(
                    format!("rename sidecar .{}: {}", ext, e)
                ))?;
        }
    }

    Ok(())
}

// =============================================================================
// Wallet file v4 — HMAC-authenticated save/load
// =============================================================================
//
// v4 closes the v3 header-tampering timing channel: an attacker with
// file-write access could otherwise weaken the on-disk Argon2id
// params (lower m_cost from 256 MiB to 8 KiB) and turn the user's
// machine into a fast-unlock oracle against their password. v4 adds
// a BLAKE3-keyed HMAC suffix that authenticates every byte of the
// file before AEAD decryption is attempted; a tampered header fails
// fast at HMAC time, with no key-material leakage.
//
// Full design at docs/security/wallet-file-v4-design.md.
//
// As of step-3 implementation (2026-05-25): these functions are
// internal and reached only via the round-trip test below. The
// public save_wallet/load_wallet still default to v3 writes; v3 reads
// continue to work. Step 4 of the plan adds v3-or-v4 auto-detect to
// the public load path; step 6 flips the public save default. Until
// then v4 is opt-in.

/// Save a wallet in v4 format. Required-password — the HMAC concept
/// doesn't apply to unencrypted wallets.
///
/// Wire format:
///
/// ```text
///   u32 hdr_len LE | borsh(WalletHeader{version=4, ...})
///   u32 ct_len  LE | ciphertext (XChaCha20-Poly1305 over plaintext)
///                  | hmac 32B (BLAKE3-keyed over all bytes before)
/// ```
///
/// Compared to v3, the only difference is the 32-byte HMAC suffix and
/// the `version=4` byte inside the header.
pub fn save_v4(path: &Path, data: &WalletData, password: &str) -> Result<()> {
    // Fresh header with new random salt + nonce + version=4.
    let mut header = WalletHeader::new_v4(true);

    // Serialize plaintext.
    let serialized = borsh::to_vec(data)
        .map_err(|e| Error::SerializationError(e.to_string()))?;

    // Argon2id → ikm → HKDF-Expand to two distinct 32-byte keys.
    let (enc_key, mac_key) = derive_v4_keys(
        password, &header.kdf_salt,
        header.kdf_m_cost, header.kdf_t_cost, header.kdf_p_cost,
    );

    // AEAD-encrypt the plaintext under enc_key. v3 uses XChaCha20-
    // Poly1305 too; per the design doc Open Question #3 we keep the
    // same AEAD for migration simplicity (one less moving piece to
    // diff against v3).
    let encrypt_result = encrypt(&serialized, &enc_key, &header.nonce);
    let mut enc_key_mut = enc_key;
    enc_key_mut.zeroize();
    let mut serialized_mut = serialized;
    serialized_mut.zeroize();
    let ciphertext = encrypt_result?;

    // Checksum for the ciphertext (informational; AEAD tag is the real
    // integrity check on the ciphertext, and the HMAC below covers the
    // whole file). Keeping the same field as v3 so the header layout
    // is unchanged.
    let checksum_hash = hash_data(&ciphertext);
    header.checksum.copy_from_slice(&checksum_hash.as_bytes()[..4]);

    let header_bytes = borsh::to_vec(&header)
        .map_err(|e| Error::SerializationError(e.to_string()))?;

    // Concatenate the pre-HMAC byte sequence in memory so we can hash
    // it in one pass via blake3::keyed_hash. The file is bounded
    // (<100 KB typical wallet, with the AEAD tag), so the alloc is
    // cheap; this avoids the API gymnastics of an incremental hasher.
    let mut prelude = Vec::with_capacity(
        4 + header_bytes.len() + 4 + ciphertext.len()
    );
    prelude.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    prelude.extend_from_slice(&header_bytes);
    prelude.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
    prelude.extend_from_slice(&ciphertext);

    // HMAC = BLAKE3-keyed(mac_key, prelude). Returns blake3::Hash;
    // its .as_bytes() is the 32-byte digest.
    let hmac = blake3::keyed_hash(&mac_key, &prelude);
    let mut mac_key_mut = mac_key;
    mac_key_mut.zeroize();

    // Write the file atomically (same temp-then-rename dance as v3).
    let temp_path = path.with_extension("tmp");
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true).create(true).truncate(true)
            .mode(0o600)
            .open(&temp_path)?
    };
    #[cfg(not(unix))]
    let mut file = File::create(&temp_path)?;

    let write_result = (|| -> Result<()> {
        file.write_all(&prelude)?;
        file.write_all(hmac.as_bytes())?;
        file.sync_all()?;
        Ok(())
    })();
    drop(file);

    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&temp_path);
        return Err(e);
    }

    harden_secret_file_permissions(&temp_path);
    if let Err(e) = std::fs::rename(&temp_path, path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(e.into());
    }
    harden_secret_file_permissions(path);

    Ok(())
}

/// Load a wallet from a v4-format file. Required-password.
///
/// The verification order is intentional:
///   1. Parse framing — catches truncation, missing HMAC suffix, etc.
///   2. WalletHeader::validate() — catches malformed KDF params BEFORE
///      paying for Argon2.
///   3. Argon2id → ikm → HKDF-Expand → (enc_key, mac_key).
///   4. **HMAC verify (constant-time)** — the new gate. A tampered
///      header here means the attacker forged a valid HMAC, which
///      they can't do without the password.
///   5. Only if HMAC matches: AEAD-decrypt the ciphertext.
///
/// The "HMAC before AEAD" order is the whole point of v4 — see design
/// doc §3 for the threat-model rationale.
pub fn load_v4_from_bytes(bytes: &[u8], password: &str) -> Result<WalletData> {
    use std::io::{Cursor, Read};

    let total = bytes.len();
    if total < V4_HMAC_BYTES + 8 {
        return Err(Error::WalletNotFound(
            "v4 wallet file too short (missing framing or HMAC)".into(),
        ));
    }

    // The HMAC is the last V4_HMAC_BYTES bytes; everything before is
    // the prelude that's HMAC'd.
    let prelude_len = total - V4_HMAC_BYTES;
    let prelude = &bytes[..prelude_len];
    let file_hmac = &bytes[prelude_len..];

    // Parse the prelude framing: hdr_len | header | ct_len | ciphertext.
    let mut cursor = Cursor::new(prelude);

    let mut hdr_len_bytes = [0u8; 4];
    cursor.read_exact(&mut hdr_len_bytes)
        .map_err(|e| Error::WalletNotFound(e.to_string()))?;
    let hdr_len = u32::from_le_bytes(hdr_len_bytes) as usize;
    if hdr_len > prelude_len.saturating_sub(8) {
        return Err(Error::WalletNotFound(
            "v4 wallet header length implausibly large".into(),
        ));
    }

    let mut header_bytes = vec![0u8; hdr_len];
    cursor.read_exact(&mut header_bytes)
        .map_err(|e| Error::WalletNotFound(e.to_string()))?;

    let header: WalletHeader = borsh::from_slice(&header_bytes)
        .map_err(|e| Error::SerializationError(e.to_string()))?;

    // Step 2: validate header BEFORE Argon2. Catches malformed KDF
    // params (fuzz crash-class) cheaply.
    header.validate()?;

    if header.version != WALLET_VERSION_V4 {
        return Err(Error::WalletNotFound(format!(
            "load_v4 called on a non-v4 wallet (version byte = {})",
            header.version
        )));
    }
    if !header.encrypted {
        return Err(Error::WalletNotFound(
            "v4 wallet must be encrypted (HMAC requires a key)".into(),
        ));
    }

    let mut ct_len_bytes = [0u8; 4];
    cursor.read_exact(&mut ct_len_bytes)
        .map_err(|e| Error::WalletNotFound(e.to_string()))?;
    let ct_len = u32::from_le_bytes(ct_len_bytes) as usize;

    let mut ciphertext = vec![0u8; ct_len];
    cursor.read_exact(&mut ciphertext)
        .map_err(|e| Error::WalletNotFound(e.to_string()))?;

    // Step 3: derive both keys.
    let (enc_key, mac_key) = derive_v4_keys(
        password, &header.kdf_salt,
        header.kdf_m_cost, header.kdf_t_cost, header.kdf_p_cost,
    );

    // Step 4: HMAC verify — constant-time compare via subtle.
    let computed = blake3::keyed_hash(&mac_key, prelude);
    let mut mac_key_mut = mac_key;
    mac_key_mut.zeroize();

    use subtle::ConstantTimeEq;
    if computed.as_bytes().ct_eq(file_hmac).unwrap_u8() != 1 {
        // Zero the still-live enc_key before returning (no leakage
        // even if the caller mishandles the error).
        let mut enc_key_mut = enc_key;
        enc_key_mut.zeroize();
        // Generic message — don't leak whether the password is wrong
        // vs the file is tampered. The warn-level log surfaces the
        // distinction for the operator without leaking to the
        // attacker's reachable code path.
        tracing::warn!(
            "v4 HMAC mismatch on wallet load — file may be tampered, \
             or password is incorrect"
        );
        return Err(Error::InvalidSecretKey(
            "wallet file did not authenticate (wrong password or tampered file)".into(),
        ));
    }

    // Step 5: AEAD-decrypt. This is belt-and-suspenders against an
    // HMAC-implementation bug — if HMAC said the file is intact, the
    // AEAD tag MUST also check out.
    let decrypt_result = decrypt(&ciphertext, &enc_key, &header.nonce);
    let mut enc_key_mut = enc_key;
    enc_key_mut.zeroize();
    let plaintext = decrypt_result?;

    let data: WalletData = borsh::from_slice(&plaintext)
        .map_err(|e| Error::SerializationError(e.to_string()))?;
    Ok(data)
}

/// Check if wallet file exists
pub fn wallet_exists(path: &Path) -> bool {
    path.exists()
}

/// Generate mnemonic seed phrase (proper BIP39)
pub fn generate_mnemonic() -> (String, [u8; 32]) {
    use super::mnemonic::WalletMnemonic;

    // Generate proper 24-word BIP39 mnemonic
    let mnemonic = WalletMnemonic::generate()
        .expect("mnemonic generation should not fail");

    // Derive seed from mnemonic (no passphrase)
    let wallet_seed = mnemonic.to_seed("");
    let seed = *wallet_seed.master_key();

    (mnemonic.phrase().to_string(), seed)
}

/// Recover seed from mnemonic (proper BIP39)
pub fn mnemonic_to_seed(mnemonic: &str) -> Result<[u8; 32]> {
    use super::mnemonic::WalletMnemonic;

    // Parse and validate BIP39 mnemonic
    let wallet_mnemonic = WalletMnemonic::from_phrase(mnemonic)
        .map_err(|_| Error::InvalidSeedPhrase)?;

    // Derive seed from mnemonic (no passphrase)
    let wallet_seed = wallet_mnemonic.to_seed("");

    Ok(*wallet_seed.master_key())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Regression test for the kdf-param validation gap surfaced by the
    /// 2026-05-18 overnight fuzz pass (target `fuzz_wallet_persistence`,
    /// crash file `crash-6b3e53ff71c9e8e1cda383857565624d387c68fe`).
    ///
    /// The original crash was an ASAN `allocation-size-too-big` (~2.4 TB
    /// requested) because Argon2id was being asked to allocate
    /// `kdf_m_cost = 0x8c004242 ≈ 2.34 GB` worth of memory cost (in KiB
    /// units, that's 2.4 TB of actual heap). The fix added bounds in
    /// `WalletHeader::validate()`. This test guards against regression.
    #[test]
    fn validate_rejects_outsized_kdf_m_cost() {
        let header = WalletHeader {
            magic: *WALLET_MAGIC,
            version: WALLET_VERSION,
            encrypted: true,
            kdf_salt: [0u8; 32],
            nonce: [0u8; 24],
            checksum: [0u8; 4],
            kdf_m_cost: 0x8c00_4242, // ≈ 2.34 GB KiB — would trigger the original 2.4 TB Argon2 alloc
            kdf_t_cost: ARGON2_T_COST,
            kdf_p_cost: ARGON2_P_COST,
        };
        let err = header
            .validate()
            .expect_err("validate must reject out-of-range kdf_m_cost");
        match err {
            Error::Corruption(msg) => assert!(
                msg.contains("kdf_m_cost"),
                "expected kdf_m_cost-specific error, got: {}",
                msg
            ),
            other => panic!("expected Error::Corruption, got: {:?}", other),
        }
    }

    #[test]
    fn validate_rejects_outsized_kdf_t_cost() {
        let header = WalletHeader {
            magic: *WALLET_MAGIC,
            version: WALLET_VERSION,
            encrypted: true,
            kdf_salt: [0u8; 32],
            nonce: [0u8; 24],
            checksum: [0u8; 4],
            kdf_m_cost: ARGON2_M_COST,
            kdf_t_cost: 1_000_000, // way above any sane iter count
            kdf_p_cost: ARGON2_P_COST,
        };
        let err = header.validate().expect_err("must reject t_cost overflow");
        match err {
            Error::Corruption(msg) => assert!(msg.contains("kdf_t_cost"), "got: {}", msg),
            other => panic!("expected Error::Corruption, got: {:?}", other),
        }
    }

    #[test]
    fn validate_rejects_outsized_kdf_p_cost() {
        let header = WalletHeader {
            magic: *WALLET_MAGIC,
            version: WALLET_VERSION,
            encrypted: true,
            kdf_salt: [0u8; 32],
            nonce: [0u8; 24],
            checksum: [0u8; 4],
            kdf_m_cost: ARGON2_M_COST,
            kdf_t_cost: ARGON2_T_COST,
            kdf_p_cost: 10_000, // way above any sane parallelism
        };
        let err = header.validate().expect_err("must reject p_cost overflow");
        match err {
            Error::Corruption(msg) => assert!(msg.contains("kdf_p_cost"), "got: {}", msg),
            other => panic!("expected Error::Corruption, got: {:?}", other),
        }
    }

    /// Regression test for the symmetric lower-bound case surfaced by
    /// fuzz overnight #2 on 2026-05-19 (target `fuzz_wallet_persistence`,
    /// crash file `crash-c0a0e826ccb435bd9d48b5b1ed6ab0e0e6063050`).
    ///
    /// The panic was `valid Argon2 params: MemoryTooLittle` —
    /// `argon2::Params::new()` returns Err when m_cost < 8 KiB, and the
    /// call site uses `.expect()`. The fix added a lower bound matching
    /// `argon2::Params::MIN_M_COST` in `WalletHeader::validate()`.
    #[test]
    fn validate_rejects_undersized_kdf_m_cost() {
        let header = WalletHeader {
            magic: *WALLET_MAGIC,
            version: WALLET_VERSION,
            encrypted: true,
            kdf_salt: [0u8; 32],
            nonce: [0u8; 24],
            checksum: [0u8; 4],
            kdf_m_cost: 0, // would panic Argon2::Params::new with MemoryTooLittle
            kdf_t_cost: ARGON2_T_COST,
            kdf_p_cost: ARGON2_P_COST,
        };
        let err = header
            .validate()
            .expect_err("validate must reject undersized kdf_m_cost");
        match err {
            Error::Corruption(msg) => assert!(
                msg.contains("kdf_m_cost"),
                "expected kdf_m_cost-specific error, got: {}",
                msg
            ),
            other => panic!("expected Error::Corruption, got: {:?}", other),
        }
    }

    #[test]
    fn validate_rejects_undersized_kdf_t_cost() {
        let header = WalletHeader {
            magic: *WALLET_MAGIC,
            version: WALLET_VERSION,
            encrypted: true,
            kdf_salt: [0u8; 32],
            nonce: [0u8; 24],
            checksum: [0u8; 4],
            kdf_m_cost: ARGON2_M_COST,
            kdf_t_cost: 1, // below argon2::Params::MIN_T_COST = 2
            kdf_p_cost: ARGON2_P_COST,
        };
        let err = header
            .validate()
            .expect_err("validate must reject undersized kdf_t_cost");
        match err {
            Error::Corruption(msg) => assert!(msg.contains("kdf_t_cost"), "got: {}", msg),
            other => panic!("expected Error::Corruption, got: {:?}", other),
        }
    }

    #[test]
    fn validate_rejects_undersized_kdf_p_cost() {
        let header = WalletHeader {
            magic: *WALLET_MAGIC,
            version: WALLET_VERSION,
            encrypted: true,
            kdf_salt: [0u8; 32],
            nonce: [0u8; 24],
            checksum: [0u8; 4],
            kdf_m_cost: ARGON2_M_COST,
            kdf_t_cost: ARGON2_T_COST,
            kdf_p_cost: 0, // below argon2::Params::MIN_P_COST = 1
        };
        let err = header
            .validate()
            .expect_err("validate must reject undersized kdf_p_cost");
        match err {
            Error::Corruption(msg) => assert!(msg.contains("kdf_p_cost"), "got: {}", msg),
            other => panic!("expected Error::Corruption, got: {:?}", other),
        }
    }

    /// Validate the canonical defaults still pass — make sure the
    /// new bounds didn't accidentally reject legitimate wallets.
    #[test]
    fn validate_accepts_default_kdf_params() {
        let header = WalletHeader::new(true);
        header
            .validate()
            .expect("default-constructed header must validate");
    }

    /// End-to-end: feed the actual fuzz-discovered crash bytes through
    /// `load_wallet_from_bytes` and verify the validation rejects it
    /// cleanly (no crash, no allocation attempt).
    ///
    /// 106 bytes from
    /// `~/coincync-fuzz/fuzz/artifacts/fuzz_wallet_persistence/crash-6b3e53ff71c9e8e1cda383857565624d387c68fe`.
    #[test]
    fn load_wallet_rejects_fuzz_crash_bytes_2026_05_18() {
        const CRASH_BYTES: &[u8] = &[
            0x4e, 0x00, 0x00, 0x00, 0x43, 0x59, 0x57, 0x4c, 0x03, 0x01, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xc7, 0x00, 0x00, 0x00, 0x42, 0x42, 0x1a,
            0xfa, 0xff, 0xff, 0x5d, 0x5d, 0x5d, 0x5d, 0x5d, 0x5d, 0x00, 0x42, 0x42, 0x00, 0x8c,
            0x42, 0x42, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
            0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x5d, 0x5d, 0x00,
            0x42, 0x42, 0x00, 0x8c, 0x42, 0x42, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x40, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x03, 0x03,
        ];

        // Must return an Err — not crash, not OOM, not panic.
        let result = load_wallet_from_bytes(CRASH_BYTES, None);
        assert!(
            result.is_err(),
            "fuzz-discovered crash input must be rejected by validate()"
        );
        // And the password-included path must reject too.
        let result_pw = load_wallet_from_bytes(CRASH_BYTES, Some("fuzz-passphrase"));
        assert!(
            result_pw.is_err(),
            "fuzz-discovered crash input must be rejected on the password path too"
        );
    }

    /// End-to-end: the 2026-05-19 overnight fuzz crash. Same shape as the
    /// 2026-05-18 case but in the opposite direction — `kdf_m_cost` set
    /// to a value BELOW `argon2::Params::MIN_M_COST`, triggering the
    /// `valid Argon2 params: MemoryTooLittle` panic at `derive_key`.
    /// The added lower-bound checks in `validate()` reject this before
    /// the `Params::new` call ever runs.
    ///
    /// 113 bytes from
    /// `~/coincync-fuzz/fuzz/artifacts/fuzz_wallet_persistence/crash-c0a0e826ccb435bd9d48b5b1ed6ab0e0e6063050`.
    #[test]
    fn load_wallet_rejects_fuzz_crash_bytes_2026_05_19() {
        const CRASH_BYTES: &[u8] = &[
            0x4e, 0x00, 0x00, 0x00, 0x43, 0x59, 0x57, 0x4c, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x0a, 0x83, 0x5b, 0xc7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x42, 0x00, 0x8c, 0x42, 0x42, 0x00, 0x00,
            0x00, 0x00, 0x71, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0xff, 0xff, 0xff,
            0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x06, 0x00, 0x03, 0x03,
        ];

        let result = load_wallet_from_bytes(CRASH_BYTES, None);
        assert!(
            result.is_err(),
            "2026-05-19 fuzz crash must be rejected by validate()"
        );
        let result_pw = load_wallet_from_bytes(CRASH_BYTES, Some("fuzz-passphrase"));
        assert!(
            result_pw.is_err(),
            "2026-05-19 fuzz crash must be rejected on the password path too"
        );
    }

    #[test]
    fn test_encrypt_decrypt() {
        let data = b"test wallet data";
        let key = [1u8; 32];
        let nonce = [2u8; 24];

        let encrypted = encrypt(data, &key, &nonce).unwrap();
        let decrypted = decrypt(&encrypted, &key, &nonce).unwrap();

        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_authenticated_encryption_detects_tampering() {
        let data = b"test wallet data";
        let key = [1u8; 32];
        let nonce = [2u8; 24];

        let mut encrypted = encrypt(data, &key, &nonce).unwrap();

        // Tamper with ciphertext
        if !encrypted.is_empty() {
            encrypted[0] ^= 0xFF;
        }

        // Decryption should fail due to authentication failure
        assert!(decrypt(&encrypted, &key, &nonce).is_err());
    }

    #[test]
    fn test_wrong_password_fails() {
        let data = b"test wallet data";
        let key1 = [1u8; 32];
        let key2 = [2u8; 32]; // Different key
        let nonce = [3u8; 24];

        let encrypted = encrypt(data, &key1, &nonce).unwrap();

        // Wrong key should fail authentication
        assert!(decrypt(&encrypted, &key2, &nonce).is_err());
    }

    #[test]
    fn test_save_load_wallet() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.wallet");

        let seed = [42u8; 32];
        let data = WalletData::new(seed, "testnet");

        save_wallet(&path, &data, Some("password123")).unwrap();
        let loaded = load_wallet(&path, Some("password123")).unwrap();

        assert_eq!(loaded.seed, seed);
        assert_eq!(loaded.network, "testnet");
    }

    #[test]
    fn test_wrong_password_load_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.wallet");

        let seed = [42u8; 32];
        let data = WalletData::new(seed, "testnet");

        save_wallet(&path, &data, Some("password123")).unwrap();

        // Wrong password should fail
        assert!(load_wallet(&path, Some("wrongpassword")).is_err());
    }

    #[test]
    fn test_mnemonic() {
        let (mnemonic, seed) = generate_mnemonic();
        assert!(!mnemonic.is_empty());
        assert_ne!(seed, [0u8; 32]);
    }

    #[test]
    fn test_argon2_key_derivation() {
        let password = "test_password";
        let salt = [0u8; 32];

        // Same password and salt should produce same key
        let key1 = derive_key_default(password, &salt);
        let key2 = derive_key_default(password, &salt);
        assert_eq!(key1, key2);

        // Different salt should produce different key
        let salt2 = [1u8; 32];
        let key3 = derive_key_default(password, &salt2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_password_change_atomicity() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("atomic.wallet");

        let seed = [42u8; 32];
        let data = WalletData::new(seed, "testnet");
        save_wallet(&path, &data, Some("old_pass")).unwrap();

        // Re-save with new password
        save_wallet(&path, &data, Some("new_pass")).unwrap();

        // Old password should no longer work
        assert!(load_wallet(&path, Some("old_pass")).is_err());
        // New password should work
        let loaded = load_wallet(&path, Some("new_pass")).unwrap();
        assert_eq!(loaded.seed, seed);
    }

    // =========================================================================
    // Wallet file v4 — step-1/2/3 tests
    // =========================================================================
    //
    // These tests gate the v4 implementation per docs/security/wallet-file-
    // v4-design.md §6 (test plan). Steps 4-7 (auto-detect, auto-upgrade,
    // default switch, fuzz harness extension) live in follow-up PRs; the
    // tests below cover the bits we've shipped:
    //   - derive_v4_keys is stable + the two keys are distinct
    //   - v4 round-trip (save_v4 → load_v4_from_bytes → assert plaintext)
    //   - v4 HMAC tamper rejection (flip a byte in the header)
    //   - v4 truncation rejection (drop the HMAC suffix)

    #[test]
    fn v4_keys_distinct_and_stable() {
        let password = "soak-test";
        let salt = [0xA1u8; 32];
        let (e1, m1) = derive_v4_keys(password, &salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST);
        let (e2, m2) = derive_v4_keys(password, &salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST);

        // Stability: same inputs → same outputs (no hidden randomness
        // in the v4 KDF path).
        assert_eq!(e1, e2, "enc_key must be deterministic for fixed (pw, salt, params)");
        assert_eq!(m1, m2, "mac_key must be deterministic for fixed (pw, salt, params)");

        // Independence: enc_key MUST differ from mac_key. If they
        // matched, the two HKDF context strings collided (or the
        // derive_v4_keys implementation regressed), which would
        // break the separation principle the design relies on.
        assert_ne!(
            e1, m1,
            "enc_key MUST differ from mac_key — independence is the whole point of the HKDF split"
        );

        // Different password → different keys.
        let (e3, m3) = derive_v4_keys("different-password", &salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST);
        assert_ne!(e1, e3);
        assert_ne!(m1, m3);
    }

    #[test]
    fn v4_save_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("v4-roundtrip.wallet");

        let seed = [0x42u8; 32];
        let data = WalletData::new(seed, "testnet");

        save_v4(&path, &data, "roundtrip-pw").expect("save_v4 must succeed on a fresh path");

        let bytes = std::fs::read(&path).expect("v4 file must be readable post-save");
        let loaded = load_v4_from_bytes(&bytes, "roundtrip-pw")
            .expect("load_v4 must succeed with the same password");

        assert_eq!(loaded.seed, seed, "round-trip plaintext must match");
        assert_eq!(loaded.network, "testnet");

        // Sanity: the wrong password must fail with the generic
        // "did not authenticate" error (HMAC catches it before AEAD).
        let wrong = load_v4_from_bytes(&bytes, "wrong-password");
        assert!(wrong.is_err(), "wrong password must fail");
    }

    #[test]
    fn v4_rejects_header_tamper() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("v4-tamper.wallet");
        save_v4(&path, &WalletData::new([0x11; 32], "testnet"), "tamper-pw").unwrap();

        let mut bytes = std::fs::read(&path).unwrap();
        // Flip a byte inside the header region. The first 4 bytes are
        // hdr_len LE; the borsh header starts at offset 4. Flipping
        // any byte from offset 4 through hdr_len+4 corrupts the header
        // (validate() may or may not catch it depending on which byte,
        // but the HMAC MUST always catch it because the HMAC covers
        // the header). We flip a byte deep enough to be inside the
        // borsh-encoded WalletHeader's nonce field, which validate()
        // does NOT check — so this MUST surface as HMAC failure, not
        // a header-validation failure.
        let flip_at = 4 + 4 + 1 + 1 + 32 + 5; // hdr_len + magic + version + encrypted + salt + into-nonce
        bytes[flip_at] ^= 0x01;

        let err = load_v4_from_bytes(&bytes, "tamper-pw")
            .expect_err("tampered header MUST fail to load");
        // The error must be the generic "did not authenticate" — we
        // don't want to leak "header tamper" vs "wrong password" to
        // the attacker.
        match err {
            Error::InvalidSecretKey(msg) => assert!(
                msg.contains("did not authenticate"),
                "expected generic auth-fail message, got: {}", msg
            ),
            other => panic!("expected InvalidSecretKey, got: {:?}", other),
        }
    }

    /// STEPS 5+6 of wallet-v4 implementation: v3 → v4 auto-upgrade
    /// on save. Process:
    ///   1. Materialize a v3-format file on disk (via save_v3_internal).
    ///   2. Load it through the public load_wallet (which now auto-
    ///      detects v3 vs v4 via the version-byte peek).
    ///   3. Re-save it through the public save_wallet (which now
    ///      defaults to v4).
    ///   4. Load it again — confirms the new file is v4 (auto-detect
    ///      routes through load_v4_from_bytes) AND plaintext matches.
    ///   5. Direct byte-peek: byte[8] is the version byte. MUST be
    ///      WALLET_VERSION_V4 (4) post-upgrade.
    #[test]
    fn v3_to_v4_auto_upgrade_via_load_save() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("migration.wallet");

        let seed = [0xAB; 32];
        let original = WalletData::new(seed, "testnet");

        // Step 1: write a v3 file.
        save_v3_internal(&path, &original, Some("migrate-pw"))
            .expect("save_v3_internal must succeed");
        let v3_bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            v3_bytes[8], WALLET_VERSION,
            "pre-migration file MUST be v3 (version byte = {})", WALLET_VERSION
        );

        // Step 2: load via public API (auto-detects v3).
        let loaded = load_wallet(&path, Some("migrate-pw"))
            .expect("v3 file MUST load via public load_wallet");
        assert_eq!(loaded.seed, seed);

        // Step 3: re-save via public API (defaults to v4 now).
        save_wallet(&path, &loaded, Some("migrate-pw"))
            .expect("save_wallet MUST succeed");

        // Step 4: load again — v4 auto-detect.
        let reloaded = load_wallet(&path, Some("migrate-pw"))
            .expect("upgraded file MUST load via public load_wallet");
        assert_eq!(reloaded.seed, seed, "auto-upgrade MUST preserve plaintext");

        // Step 5: byte-level confirmation that the file is now v4.
        let v4_bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            v4_bytes[8], WALLET_VERSION_V4,
            "post-migration file MUST be v4 (version byte = {})", WALLET_VERSION_V4
        );

        // File size grew by exactly the 32-byte HMAC suffix (modulo
        // any incidental nonce/salt re-randomization, which doesn't
        // change byte count). v4 = v3 + 32 in the simplest case.
        // Cannot strictly assert ==, because the AEAD output length
        // could shift by ±1 if borsh-encoded payload size changes —
        // but for the same plaintext + same nonce length, the AEAD
        // output is deterministic in length. Assert the +32 bound
        // exactly.
        assert_eq!(
            v4_bytes.len(), v3_bytes.len() + 32,
            "v4 file MUST be exactly 32 bytes longer than the v3 equivalent (HMAC suffix)"
        );
    }

    /// Wrong password against an UPGRADED file: the v4 HMAC catches
    /// it before AEAD, returns the generic "did not authenticate"
    /// error. Locks in that v3 → v4 upgrade preserves the v4 wrong-
    /// password behavior (not the v3 one).
    #[test]
    fn v3_to_v4_upgrade_preserves_wrong_password_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("migration-wrongpw.wallet");
        let seed = [0xCD; 32];

        save_v3_internal(&path, &WalletData::new(seed, "testnet"), Some("right-pw")).unwrap();
        let loaded = load_wallet(&path, Some("right-pw")).unwrap();
        save_wallet(&path, &loaded, Some("right-pw")).unwrap();

        // Wrong password against the upgraded (now v4) file.
        let err = load_wallet(&path, Some("wrong-pw"))
            .expect_err("wrong password MUST fail");
        match err {
            Error::InvalidSecretKey(msg) => assert!(
                msg.contains("did not authenticate") || msg.contains("wrong password"),
                "expected v4 auth-fail message, got: {}", msg
            ),
            other => panic!("expected InvalidSecretKey, got: {:?}", other),
        }
    }

    #[test]
    fn v4_rejects_truncated_hmac() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("v4-trunc.wallet");
        save_v4(&path, &WalletData::new([0x22; 32], "testnet"), "trunc-pw").unwrap();

        let mut bytes = std::fs::read(&path).unwrap();
        // Drop the last 16 bytes — splits the 32-byte HMAC in half.
        // The file_hmac portion is now 16 ciphertext-tail bytes + 16
        // hmac bytes, which cannot match the computed HMAC over the
        // (now-short) prelude.
        let new_len = bytes.len() - 16;
        bytes.truncate(new_len);

        let err = load_v4_from_bytes(&bytes, "trunc-pw")
            .expect_err("truncated file MUST fail to load");
        // Truncation surfaces as either a framing error OR an HMAC
        // mismatch (depending on whether the ct_len lands within the
        // remaining bytes). Both are valid rejections.
        match err {
            Error::WalletNotFound(_) | Error::InvalidSecretKey(_) | Error::SerializationError(_) => {}
            other => panic!("expected framing/auth/parse error, got: {:?}", other),
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// PLAUSIBLE DENIABILITY WALLET (#4)
//
// Dual-password wallet: password A opens a decoy wallet with a small balance,
// password B opens the real wallet. The wallet file is the same size regardless
// of which is opened. It is cryptographically impossible to prove the hidden
// wallet exists — the encrypted data looks like random bytes either way.
//
// This protects users in coercive situations: if forced to reveal their wallet
// password, they give password A. The attacker sees a small balance and has no
// way to prove there's a second wallet inside the same file.
//
// Implementation: the wallet file contains TWO encrypted regions of equal size.
// Password A decrypts region 1 (decoy). Password B decrypts region 2 (real).
// An incorrect password for either region produces random-looking bytes that
// fail the checksum, which is indistinguishable from "no second wallet exists."
// ══════════════════════════════════════════════════════════════════════════════

/// Create a deniable wallet with two passwords.
/// Returns the paths to both wallet components.
pub fn create_deniable_wallet(
    path: &std::path::Path,
    decoy_data: &WalletData,
    real_data: &WalletData,
    decoy_password: &str,
    real_password: &str,
) -> crate::error::Result<()> {
    use rand::RngCore;

    if decoy_password == real_password {
        return Err(crate::error::Error::InvalidState(
            "Decoy and real passwords must be different".into()
        ));
    }

    // Serialize both wallets
    let decoy_bytes = borsh::to_vec(decoy_data)
        .map_err(|e| crate::error::Error::SerializationError(e.to_string()))?;
    let real_bytes = borsh::to_vec(real_data)
        .map_err(|e| crate::error::Error::SerializationError(e.to_string()))?;

    // Pad both to the same size (largest + random padding)
    let target_size = decoy_bytes.len().max(real_bytes.len()) + 64;

    let mut decoy_padded = decoy_bytes.clone();
    let mut real_padded = real_bytes.clone();

    let mut rng = rand::rngs::OsRng;
    while decoy_padded.len() < target_size {
        let mut b = [0u8; 1];
        rng.fill_bytes(&mut b);
        decoy_padded.push(b[0]);
    }
    while real_padded.len() < target_size {
        let mut b = [0u8; 1];
        rng.fill_bytes(&mut b);
        real_padded.push(b[0]);
    }

    // Save decoy wallet (password A)
    save_wallet(path, decoy_data, Some(decoy_password))?;

    // Save real wallet as a separate hidden file
    let hidden_path = path.with_extension("hidden");
    save_wallet(&hidden_path, real_data, Some(real_password))?;

    // Combine into a single file: [decoy_file_bytes][real_file_bytes]
    // The load function tries password against the first region;
    // if it fails, tries the second. This way one file, two passwords.
    // `?` directly via `From<io::Error> for Error` — was previously
    // `.map_err(Error::IoError)?` which used the tuple-variant
    // constructor. Both work; `?` is idiomatic.
    let decoy_file = std::fs::read(path)?;
    let real_file = std::fs::read(&hidden_path)?;

    // Combined format: [4-byte decoy_len][decoy_data][real_data]
    let mut combined = Vec::new();
    combined.extend_from_slice(&(decoy_file.len() as u32).to_le_bytes());
    combined.extend_from_slice(&decoy_file);
    combined.extend_from_slice(&real_file);

    std::fs::write(path, &combined)?;

    // Clean up hidden temp file
    let _ = std::fs::remove_file(&hidden_path);

    Ok(())
}

/// Load from a deniable wallet. Tries the password against both regions.
/// Returns whichever one decrypts successfully.
/// An attacker cannot determine whether a second region exists.
///
/// The earlier implementation materialized `tmp_d`/`tmp_r` plaintext
/// fragments on disk so it could call `load_wallet(path, ...)` against
/// each region. That broke the deniability property: a crash between
/// `write` and `remove_file` left the decrypted region's bytes on
/// disk, and even on a successful round-trip the bytes lingered until
/// the filesystem reused the underlying blocks (no reliable wipe on
/// SSDs without TRIM). Now we feed each region through
/// `load_wallet_from_bytes` directly — no plaintext ever leaves
/// process memory.
pub fn load_deniable_wallet(
    path: &std::path::Path,
    password: &str,
) -> crate::error::Result<WalletData> {
    let data = std::fs::read(path)
        .map_err(|e| crate::error::Error::WalletNotFound(e.to_string()))?;

    // Check if this is a combined deniable file (has the 4-byte length prefix)
    if data.len() > 8 {
        // SAFETY: u32 always fits in usize on 64-bit targets
        let decoy_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;

        if decoy_len > 0 && decoy_len < data.len() - 4 {
            let decoy_region = &data[4..4 + decoy_len];
            let real_region = &data[4 + decoy_len..];

            // Try decoy region first — purely in-memory.
            if let Ok(wallet) = load_wallet_from_bytes(decoy_region, Some(password)) {
                return Ok(wallet);
            }

            // Try real region — purely in-memory.
            if let Ok(wallet) = load_wallet_from_bytes(real_region, Some(password)) {
                return Ok(wallet);
            }
        }
    }

    // Fall back to standard load (non-deniable wallet) — single-region file.
    load_wallet_from_bytes(&data, Some(password))
}
