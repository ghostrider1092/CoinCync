//! # Error Types
//!
//! Unified error handling for CoinCync 1.0.
//!
//! Variants are organized into:
//! - **Active** — constructed and returned in production code
//! - **Phase 2** — reserved for Spark, Halo2, assets, name registry (not yet wired)

use thiserror::Error;

/// Main result type for CoinCync operations
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for CoinCync
#[derive(Error, Debug)]
pub enum Error {
    // ========================================================================
    // Primitive Errors
    // ========================================================================

    #[error("Invalid hash length: expected {expected}, got {got}")]
    InvalidHashLength { expected: usize, got: usize },

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Amount overflow")]
    AmountOverflow,

    #[error("Amount underflow")]
    AmountUnderflow,

    // ========================================================================
    // Cryptographic Errors
    // ========================================================================

    #[error("Range proof verification failed")]
    RangeProofInvalid,

    #[error("Commitment mismatch")]
    CommitmentMismatch,

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    // ── Phase 2: Confidential Assets ───────────────────────────
    #[error("Invalid asset surjection proof")]
    InvalidAssetSurjectionProof,

    #[error("Asset not found: {0}")]
    AssetNotFound(String),

    #[error("Asset already exists: {0}")]
    AssetAlreadyExists(String),

    #[error("Invalid asset issuance: {0}")]
    InvalidAssetIssuance(String),

    #[error("Insufficient asset balance for {asset_id}: have {have}, need {need}")]
    InsufficientAssetBalance { asset_id: String, have: u64, need: u64 },

    // ── Phase 2: Multi-sig ─────────────────────────────────────
    #[error("Multisig threshold not met: have {have} signatures, need {need}")]
    ThresholdNotMet { have: usize, need: usize },

    #[error("Duplicate signature from signer {signer_index}")]
    DuplicateMultisigSignature { signer_index: u8 },

    // ── Phase 2: Shielded pool ─────────────────────────────────
    #[error("Halo2 proof verification failed")]
    Halo2VerifyFailed,

    #[error("binding signature verification failed")]
    BindingSigFailed,

    #[error("nullifier already spent")]
    NullifierSpent,

    #[error("duplicate nullifier in block")]
    DuplicateNullifier,

    #[error("bad commitment tree root")]
    BadCommitmentRoot,

    #[error("Invalid anchor: {0}")]
    InvalidAnchor(String),

    #[error("Invalid supply commitment")]
    InvalidSupplyCommitment,

    // ── Privacy constitution violations ─────────────────────────
    #[error("transparent output forbidden: all outputs must use Pedersen commitments")]
    TransparentOutputForbidden,

    #[error("raw pubkey output forbidden: all outputs must use stealth or Spark addresses")]
    RawPubkeyForbidden,

    #[error("unshielded transaction forbidden: non-coinbase tx must hide sender")]
    UnshieldedForbidden,

    #[error("Lelantus Spark verification failed")]
    SparkVerifyFailed,

    #[error("MimbleWimble cut-through kernel verification failed")]
    MwCutthroughVerifyFailed,

    // ========================================================================
    // Transaction Errors
    // ========================================================================

    #[error("Transaction too large: {size} bytes (max {max})")]
    TransactionTooLarge { size: usize, max: usize },

    #[error("Transaction too small: {size} bytes (min {min})")]
    TransactionTooSmall { size: usize, min: usize },

    #[error("Invalid input count: {count} (max {max})")]
    InvalidInputCount { count: usize, max: usize },

    #[error("Invalid output count: {count} (max {max})")]
    InvalidOutputCount { count: usize, max: usize },

    #[error("Invalid ring size: expected {expected}, got {got}")]
    InvalidRingSize { expected: usize, got: usize },

    #[error("Duplicate key image: {0}")]
    DuplicateKeyImage(String),

    #[error("Fee too low: {fee} (minimum {min})")]
    FeeTooLow { fee: u64, min: u64 },

    #[error("Insufficient decoy outputs: {available} available, {needed} needed")]
    InsufficientDecoys { available: usize, needed: usize },

    #[error("Output amount too small: {amount} (minimum {min})")]
    OutputTooSmall { amount: u64, min: u64 },

    #[error("Transaction unbalanced: inputs={inputs}, outputs={outputs}")]
    TransactionUnbalanced { inputs: u64, outputs: u64 },

    #[error("Invalid transaction version: {0}")]
    InvalidTxVersion(u8),

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Mempool full: cannot accept transaction")]
    MempoolFull,

    // ========================================================================
    // Block / Chain Errors
    // ========================================================================

    #[error("PoW validation failed: {0}")]
    PowValidation(String),

    #[error("Reorg too deep: {depth} blocks (max {max})")]
    ReorgTooDeep { depth: u64, max: u64 },

    // ========================================================================
    // Wallet Errors
    // ========================================================================

    #[error("Wallet not found: {0}")]
    WalletNotFound(String),

    #[error("Wallet already exists: {0}")]
    WalletExists(String),

    #[error("Invalid seed phrase")]
    InvalidSeedPhrase,

    #[error("Insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },

    /// The wallet has UTXOs that together cover the requested send, but they
    /// haven't reached MIN_OUTPUT_AGE yet. Distinct from `InsufficientBalance`
    /// (genuinely no funds): the user just needs to wait. Reporting "have 0"
    /// when the wallet actually has the money is misleading and was a real
    /// pain point during 2026-05-07 testnet onboarding.
    #[error(
        "Balance pending maturity: {pending_atomic} atomic in {pending_utxos} UTXO(s) confirmed but \
         not yet spendable (spendable now: {spendable_atomic}; need: {need_atomic}). \
         Wait ~{blocks_to_wait} more block(s) (about {seconds_to_wait}s at 120s blocks)."
    )]
    BalancePendingMaturity {
        spendable_atomic: u64,
        pending_atomic: u64,
        pending_utxos: usize,
        need_atomic: u64,
        blocks_to_wait: u64,
        seconds_to_wait: u64,
    },

    #[error("No outputs available for spending")]
    NoOutputsAvailable,

    #[error("Wallet has only {have} eligible UTXO(s); uniform 2-in tx shape needs at least {need}. Wait for more outputs to confirm.")]
    InsufficientInputs { have: usize, need: usize },

    /// No two-UTXO pair in the wallet sums to >= target+fee.
    /// Distinct from `InsufficientInputs` (count problem) and `InsufficientBalance`
    /// (total problem): the wallet has enough total balance and enough UTXO count,
    /// but post-activation uniform tx shape requires exactly 2 inputs and no
    /// pair of UTXOs together covers the requested amount.
    #[error(
        "Cannot find 2 UTXOs whose sum covers {target_atomic} atomic ({utxo_count} UTXOs in wallet, total {total_atomic} atomic; \
         largest pair sums to {largest_pair_atomic} atomic). \
         Either send no more than {max_safe_atomic} atomic per tx, or run `auto-churn` to redistribute UTXO sizes into a larger one."
    )]
    NoUtxoPairCovers {
        target_atomic: u64,
        utxo_count: usize,
        total_atomic: u64,
        largest_pair_atomic: u64,
        max_safe_atomic: u64,
    },

    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("Wallet is locked")]
    WalletLocked,

    // ── Phase 2: Scoped view keys ──────────────────────────────
    #[error("Invalid view key: {0}")]
    InvalidViewKey(String),

    #[error("View key expired")]
    ViewKeyExpired,

    #[error("View key revoked")]
    ViewKeyRevoked,

    // ========================================================================
    // Network Errors
    // ========================================================================

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Noise handshake failed: {0}")]
    NoiseHandshakeFailed(String),

    #[error("Noise decryption failed: {0}")]
    NoiseDecryptionFailed(String),

    #[error("TLS error: {0}")]
    TlsError(String),

    #[error("Message too large")]
    MessageTooLarge,

    #[error("P2P payload memory budget exhausted while reserving a {requested}-byte chunk")]
    P2pMemoryBudgetExceeded { requested: usize },

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Unsupported protocol version: peer has v{peer_version}, we support v{min_supported}-v{max_supported}")]
    UnsupportedProtocolVersion {
        peer_version: u32,
        min_supported: u32,
        max_supported: u32,
    },

    // ========================================================================
    // Storage Errors
    // ========================================================================

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Data corruption detected: {0}")]
    Corruption(String),

    // ========================================================================
    // Phase 2: Name Registry
    // ========================================================================

    #[error("Name already registered: {0}")]
    NameTaken(String),

    #[error("Name not found: {0}")]
    NameNotFound(String),

    #[error("Invalid name: {0}")]
    InvalidName(String),

    #[error("Name too short: {len} chars (min {min})")]
    NameTooShort { len: usize, min: usize },

    #[error("Name too long: {len} chars (max {max})")]
    NameTooLong { len: usize, max: usize },

    #[error("Name expired: {0}")]
    NameExpired(String),

    #[error("Not the owner of name: {0}")]
    NotNameOwner(String),

    // ========================================================================
    // RPC / Config / General
    // ========================================================================

    #[error("RPC error: {0}")]
    RpcError(String),

    #[error("Invalid parameters: {0}")]
    InvalidParams(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    // Path-redacted IO error. `std::io::Error`'s Display (since Rust
    // 1.66 for path-aware ops like `File::open`) includes the
    // attempted path in the message — leaks filesystem-layout info
    // through any error logged/displayed. Audit-prep nicety on a
    // privacy chain: surface only `kind()` in Display, keep the full
    // error available via `#[source]` for debug logging that's
    // explicit about path exposure.
    #[error("IO error: {kind}")]
    IoError {
        kind: std::io::ErrorKind,
        #[source]
        source: std::io::Error,
    },

    #[error("{0}")]
    Other(String),
}

impl From<rocksdb::Error> for Error {
    fn from(e: rocksdb::Error) -> Self {
        Error::DatabaseError(e.to_string())
    }
}

// Manual `From<io::Error>` replaces the `#[from]` removed from the
// struct variant above. Same `?` operator ergonomics, path-redacted
// Display.
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IoError {
            kind: e.kind(),
            source: e,
        }
    }
}

impl Error {
    pub fn is_validation_error(&self) -> bool {
        matches!(self,
            Error::InvalidHashLength { .. } |
            Error::InvalidPublicKey(_) |
            Error::InvalidSecretKey(_) |
            Error::InvalidSignature(_) |
            Error::InvalidAddress(_) |
            Error::AmountOverflow |
            Error::AmountUnderflow |
            Error::RangeProofInvalid |
            Error::TransactionTooLarge { .. } |
            Error::TransactionTooSmall { .. } |
            Error::InvalidInputCount { .. } |
            Error::InvalidOutputCount { .. } |
            Error::InvalidRingSize { .. } |
            Error::DuplicateKeyImage(_) |
            Error::FeeTooLow { .. } |
            Error::OutputTooSmall { .. } |
            Error::InvalidTxVersion(_) |
            Error::InvalidParams(_)
        )
    }

    pub fn is_network_error(&self) -> bool {
        matches!(self,
            Error::ConnectionFailed(_) |
            Error::ProtocolError(_)
        )
    }

    pub fn is_storage_error(&self) -> bool {
        matches!(self,
            Error::DatabaseError(_) |
            Error::Corruption(_) |
            Error::IoError { .. }
        )
    }
}
