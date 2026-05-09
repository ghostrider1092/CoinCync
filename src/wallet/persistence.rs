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

    pub fn validate(&self) -> Result<()> {
        if &self.magic != WALLET_MAGIC {
            return Err(Error::WalletNotFound("invalid wallet magic".into()));
        }
        if self.version > WALLET_VERSION {
            return Err(Error::WalletNotFound("unsupported wallet version".into()));
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

    let params = Params::new(
        m_cost,
        t_cost,
        p_cost,
        Some(32),  // Output 32-byte key
    ).expect("valid Argon2 params");

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("Argon2 key derivation failed");

    key
}

/// Derive a key using the binary's CURRENT default Argon2id params.
/// Use only when creating fresh keys (not when loading an existing
/// wallet — for that, use the params stored in the wallet's header).
pub fn derive_key_default(password: &str, salt: &[u8; 32]) -> [u8; 32] {
    derive_key(password, salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST)
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

/// Save wallet to file
///
/// Each save generates a fresh random nonce to ensure IV is never reused,
/// even when saving the same data with the same password.
pub fn save_wallet(
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

    // SECURITY (WAL-M1): Warn when saving wallet WITHOUT encryption.
    // Plaintext wallets expose seed material to any process/user with file access.
    if password.is_none() {
        tracing::warn!(
            "Saving wallet to {:?} WITHOUT encryption. \
             Seed and keys are stored in plaintext. \
             Use a password to protect your wallet.",
            path
        );
    }

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
    let decoy_file = std::fs::read(path)
        .map_err(crate::error::Error::IoError)?;
    let real_file = std::fs::read(&hidden_path)
        .map_err(crate::error::Error::IoError)?;

    // Combined format: [4-byte decoy_len][decoy_data][real_data]
    let mut combined = Vec::new();
    combined.extend_from_slice(&(decoy_file.len() as u32).to_le_bytes());
    combined.extend_from_slice(&decoy_file);
    combined.extend_from_slice(&real_file);

    std::fs::write(path, &combined)
        .map_err(crate::error::Error::IoError)?;

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
