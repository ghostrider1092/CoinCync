//! # Protocol Constants
//!
//! Core protocol constants for CoinCync 2.0.

// SECURITY (HIGH-10): Prevent test-vdf feature from being used in release builds.
// The test-vdf feature reduces VDF iterations to near-zero, which would make
// the proof of work trivially easy to forge in production.
#[cfg(all(feature = "test-vdf", not(debug_assertions), not(test)))]
compile_error!(
    "SECURITY: The 'test-vdf' feature MUST NOT be used in release builds! \
     It reduces VDF iterations to insecure levels. \
     Remove 'test-vdf' from your feature flags for production builds."
);

// ═══════════════════════════════════════════════════════════════════════════
// CONSTITUTIONAL ENFORCEMENT
//
// These compile-time and const assertions enforce the CoinCync Constitution
// and Bill of Rights. They cannot be bypassed without modifying this file,
// which is tracked by critical_files.lock.
//
// Constitution Article I:  Supply cap is 100,000,000 CYNC. Immutable.
// Constitution Article II: No dev tax, no pre-mine. Zero fee extraction.
// Constitution Article III: Mandatory privacy. BOOTSTRAP_MIN_RING_SIZE >= 11, RING_SIZE = 16.
// Constitution Article IX: No blacklists, no surveillance infrastructure.
// Bill of Rights I:  Ring signatures, stealth addresses, Bulletproofs required.
// Bill of Rights IV: No freeze mechanism. No key escrow. No backdoors.
// Bill of Rights X:  No transaction censorship. No address blocking.
// ═══════════════════════════════════════════════════════════════════════════

/// Protocol version
pub const PROTOCOL_VERSION: u32 = 2;

/// Target block time in seconds (2 minutes — mountain curve, 250M cap ~year 15).
pub const TARGET_BLOCK_TIME: u64 = 120;

// Note: this file used to declare NUM_POW_ALGORITHMS and ALGO_WINDOW for
// a multi-algorithm rotation scaffold (RandomX + YescryptHeavy + YescryptLight).
// Constitution Article V now commits to RandomX only; see the rationale in
// CONSTITUTION.md and docs/src/protocol/consensus.md. The constants were dead
// code — nothing in src/ referenced them — and removing them prevents anyone
// from accidentally reviving the scaffold without a constitutional change.

// =============================================================================
// Block Size Limits
// =============================================================================

/// Maximum block size in bytes (2 MB)
pub const MAX_BLOCK_SIZE: usize = 2 * 1024 * 1024;

/// Maximum transactions per block
pub const MAX_TXS_PER_BLOCK: usize = 5000;

/// Minimum transaction size in bytes
pub const MIN_TX_SIZE: usize = 100;

// =============================================================================
// Difficulty Adjustment (ASERT)
// =============================================================================

/// ASERT halflife in seconds (1 hour)
pub const ASERT_HALFLIFE: u64 = 3600;

/// Short window for difficulty adjustment (blocks)
/// With 30 sec blocks: 8 blocks = 4 minutes
pub const DIFFICULTY_SHORT_WINDOW: u64 = 8;

/// Long window for difficulty adjustment (blocks)
/// With 30 sec blocks: 144 blocks = 72 minutes (~1.2 hours)
pub const DIFFICULTY_LONG_WINDOW: u64 = 144;

/// Weight for short window (70 out of 100)
pub const DIFFICULTY_SHORT_WEIGHT: u64 = 70;

/// Weight for long window (30 out of 100)
pub const DIFFICULTY_LONG_WEIGHT: u64 = 30;

/// Sum of weights (must equal SHORT + LONG)
pub const DIFFICULTY_WEIGHT_SCALE: u64 = 100;

/// Blocks before triggering emergency difficulty drop
/// With 30 sec blocks: 12 blocks = 6 minutes
pub const EMERGENCY_DIFFICULTY_BLOCKS: u64 = 12;

/// Time multiplier for emergency detection
pub const EMERGENCY_TIME_MULTIPLIER: u64 = 10;

/// Emergency drop factor (integer multiplier on max adjustment)
pub const EMERGENCY_DROP_FACTOR: u64 = 4;

/// Maximum difficulty adjustment per block: target can increase by 2x (numerator)
pub const MAX_DIFFICULTY_ADJ_NUM: u64 = 2;
/// Maximum difficulty adjustment per block: denominator
pub const MAX_DIFFICULTY_ADJ_DEN: u64 = 1;

/// Minimum difficulty adjustment per block: target can decrease to 1/2 (numerator)
pub const MIN_DIFFICULTY_ADJ_NUM: u64 = 1;
/// Minimum difficulty adjustment per block: denominator
pub const MIN_DIFFICULTY_ADJ_DEN: u64 = 2;

// =============================================================================
// Network Ports
// =============================================================================

/// Default P2P port for mainnet
pub const DEFAULT_P2P_PORT: u16 = 19080;

/// Default RPC port for mainnet
pub const DEFAULT_RPC_PORT: u16 = 19081;

/// Default P2P port for testnet
pub const TESTNET_P2P_PORT: u16 = 28080;

/// Default RPC port for testnet
pub const TESTNET_RPC_PORT: u16 = 28081;

/// Default P2P port for mainnet (alias)
pub const MAINNET_P2P_PORT: u16 = DEFAULT_P2P_PORT;

/// Default RPC port for mainnet (alias)
pub const MAINNET_RPC_PORT: u16 = DEFAULT_RPC_PORT;

/// Default P2P port for regtest
pub const REGTEST_P2P_PORT: u16 = 18080;

/// Default RPC port for regtest
pub const REGTEST_RPC_PORT: u16 = 18081;

/// Mainnet bech32 address HRP
pub const ADDRESS_HRP: &str = "cync";

/// Testnet bech32 address HRP
pub const T_ADDRESS_HRP: &str = "tcync";

/// Regtest bech32 address HRP
pub const R_ADDRESS_HRP: &str = "rcync";

/// LWMA difficulty window (blocks).
pub const LWMA_WINDOW: u64 = 60;

/// Median time past window for timestamp rules (blocks).
pub const MTP_WINDOW: usize = 11;

/// Maximum time in the future a block timestamp may claim (seconds).
pub const MAX_FUTURE_TIMESTAMP: u64 = 60 * 10;

/// How often a new RandomX key block is chosen (blocks).
pub const RANDOMX_KEY_INTERVAL: u64 = 2048;

/// Standard ring size.
pub const RING_SIZE: usize = 16;

/// Rolling checkpoint interval (blocks).
/// C-5 FIX: Set to 144 (~5 hours at 120s blocks). Large enough to absorb
/// realistic network partitions, small enough to protect against long-range reorgs.
/// Previously 1000 in constants (shadowed by chain.rs local = 5).
pub const CHECKPOINT_INTERVAL: u64 = 144;

/// BIP9-style signaling window size (blocks).
pub const SIGNAL_WINDOW: u64 = 2016;

/// BIP9 signal threshold (blocks within the window).
pub const SIGNAL_THRESHOLD: u64 = 1814;

/// Base unit: 1 CYNC = 1 trillion atomic units (10^12).
pub const COIN: u64 = 1_000_000_000_000;

/// Hard supply cap in atomic units: 100,000,000 CYNC × 10^12.
/// `u128` because 100M × COIN (10^12) = 10^20 overflows u64 (max ~1.8 × 10^19).
pub const MAX_SUPPLY: u128 = 100_000_000u128 * COIN as u128;

/// Ticker symbol.
pub const COIN_TICKER: &str = "CYNC";

/// Maximum mempool size in bytes.
pub const MAX_MEMPOOL_BYTES: usize = 300 * 1024 * 1024;

/// Maximum number of transactions in the mempool.
pub const MAX_MEMPOOL_TXS: usize = 100_000;

/// How many blocks after which a mempool tx expires.
pub const TX_EXPIRY_BLOCKS: u64 = 500;

// =============================================================================
// P2P Configuration
// =============================================================================

/// Maximum number of connected peers
pub const MAX_PEERS: usize = 125;

/// Maximum inbound peers
pub const MAX_INBOUND_PEERS: usize = 100;

/// Maximum outbound peers
pub const MAX_OUTBOUND_PEERS: usize = 25;

/// Peer connection timeout in seconds
pub const PEER_TIMEOUT: u64 = 30;

/// Peer handshake timeout in seconds
pub const HANDSHAKE_TIMEOUT: u64 = 10;

// =============================================================================
// Database
// =============================================================================

/// Database cache size in MB
pub const DB_CACHE_SIZE_MB: usize = 256;

// =============================================================================
// Currency Units
// =============================================================================

/// Atomic units per CYNC (10^12 = 1 trillion)
// 10^12 atomic units per CYNC (same as Monero). UX note: wallet displays should limit to 4-6 decimal places.
pub const ATOMIC_UNITS: u64 = 1_000_000_000_000;

/// Atomic units per milliCYNC
pub const MILLICYNC: u64 = 1_000_000_000;

/// Atomic units per microCYNC
pub const MICROCYNC: u64 = 1_000_000;

/// Atomic units per nanoCYNC
pub const NANOCYNC: u64 = 1_000;

// =============================================================================
// Network Magic
// =============================================================================

/// Mainnet magic bytes
pub const MAINNET_MAGIC: [u8; 4] = [0x43, 0x59, 0x4E, 0x43]; // "CYNC"

/// Testnet magic bytes
pub const TESTNET_MAGIC: [u8; 4] = [0x74, 0x43, 0x59, 0x4E]; // "tCYN"

/// Regtest magic bytes
pub const REGTEST_MAGIC: [u8; 4] = [0x72, 0x43, 0x59, 0x4E]; // "rCYN"

// =============================================================================
// Address
// =============================================================================

/// Address suffix for display
pub const NAME_SUFFIX: &str = ".cync";

/// Mainnet address prefix
pub const MAINNET_ADDRESS_PREFIX: &str = "CYNC";

/// Testnet address prefix
pub const TESTNET_ADDRESS_PREFIX: &str = "tCYNC";

// =============================================================================
// Ring Signatures
// =============================================================================

/// Minimum ring size for privacy
/// Bootstrap minimum ring size — used when UTXO set is too small for full ring-16.
/// After BOOTSTRAP_CUTOVER_HEIGHT (10,000 blocks), full RING_SIZE (16) is enforced.
/// Named explicitly to distinguish from the post-bootstrap target.
pub const BOOTSTRAP_MIN_RING_SIZE: usize = 11;

/// Maximum ring size
pub const MAX_RING_SIZE: usize = 32;

/// Default ring size
pub const DEFAULT_RING_SIZE: usize = 16;

// =============================================================================
// Timestamps
// =============================================================================

/// Maximum block timestamp drift from network time (seconds)
pub const MAX_TIMESTAMP_DRIFT: u64 = 600; // 10 minutes (reduced from 2h to limit difficulty manipulation)

/// Minimum timestamp for valid blocks (genesis time)
pub const MIN_TIMESTAMP: u64 = 1704067200; // 2024-01-01 00:00:00 UTC

// =============================================================================
// Sequential Padding Anchor
// =============================================================================

/// Sequential padding iteration count — set to 1 (effectively disabled).
///
/// IMPORTANT: This is NOT a VDF (Verifiable Delay Function). No verifiable
/// sequential delay property is provided. The chain simply binds the PoW
/// anchor to the previous block via a short hash chain.
///
/// The iteration count was reduced from a larger value because sequential
/// hashing caused 2–5 second verification per block, making IBD take hours.
/// The actual PoW (nonce grinding against target) is unchanged.
pub const SEQ_PAD_ITERATIONS: u32 = 1;

// =============================================================================
// Block Version
// =============================================================================

/// Get block version for a given height
/// Height at which V2 transaction format activates.
///
/// V2 transactions include real asset_commitment bytes in the CLSAG signing hash
/// instead of zero placeholders. This makes asset field tampering detectable by
/// the ring signature, closing the malleability gap in V1 asset transactions.
///
/// Before this height: only version=1 txs are accepted (asset fields NOT signed)
/// At/after this height: version=2 txs are accepted (asset fields ARE signed)
///
/// SECURITY: Changing this after mainnet launch is a consensus-breaking hard fork.
/// Must be coordinated across all nodes. Set to a future height agreed by governance.
pub const V2_TX_ACTIVATION_HEIGHT: u64 = 50_000; // ~69 days at 120s blocks

pub fn block_version_at_height(height: u64) -> u8 {
    if height >= V2_TX_ACTIVATION_HEIGHT { 2 } else { 1 }
}

// =============================================================================
// Algorithm Selection
// =============================================================================

/// Get PoW algorithm index for a given height.
///
/// CoinCync 1.0 is RandomX-only, so this always returns 0.
pub fn algorithm_at_height(_height: u64) -> u8 {
    0
}

// =============================================================================
// Transaction Limits
// =============================================================================

/// Maximum transaction size in bytes
pub const MAX_TX_SIZE: usize = 500_000;

/// Maximum transaction inputs
pub const MAX_TX_INPUTS: usize = 256;

/// Maximum transaction outputs
pub const MAX_TX_OUTPUTS: usize = 16;

/// Minimum fee per byte in atomic units
pub const MIN_FEE_PER_BYTE: u64 = 1_000;

/// Minimum fee rate (atomic units per byte) for a tx to enter the mempool.
pub const MIN_RELAY_FEE_RATE: f64 = 1.0;

/// Minimum output amount in atomic units (dust threshold)
pub const MIN_OUTPUT_AMOUNT: u64 = 1_000_000; // 0.000001 CYNC

/// Minimum output age for spending (blocks)
pub const MIN_OUTPUT_AGE: u64 = 10;

// =============================================================================
// Fee Distribution (Normal Conditions)
// =============================================================================

/// Miner fee percent under normal conditions.
/// Constitution Article II: 0% dev tax. No protocol fee.
pub const FEE_MINER_NORMAL_PERCENT: u64 = 70;

/// Burn fee percent under normal conditions.
/// 30% of fees are permanently destroyed, reducing circulating supply.
/// At tail emission (0.6 CYNC/block), if fees exceed ~0.86 CYNC/block
/// the chain becomes deflationary.
pub const FEE_BURN_NORMAL_PERCENT: u64 = 30;

/// Protocol fee — ZERO. Constitution Article II forbids dev tax.
pub const FEE_PROTOCOL_NORMAL_PERCENT: u64 = 0;

// =============================================================================
// Fee Distribution (Congested Conditions)
// =============================================================================

/// Miner fee percent under congested conditions.
/// Reduced from 70% to 50% during congestion — more burn discourages spam.
pub const FEE_MINER_CONGESTED_PERCENT: u64 = 50;

/// Burn fee percent under congested conditions.
/// 50% burn during congestion makes spam attacks self-destructive.
pub const FEE_BURN_CONGESTED_PERCENT: u64 = 50;

/// Protocol fee under congestion — ZERO.
pub const FEE_PROTOCOL_CONGESTED_PERCENT: u64 = 0;

/// Congestion threshold (percentage of block fullness)
pub const CONGESTION_THRESHOLD: u64 = 80;

// =============================================================================
// Protocol Version Support
// =============================================================================

/// Minimum supported protocol version
pub const MIN_SUPPORTED_PROTOCOL_VERSION: u32 = 1;

/// Maximum supported protocol version
pub const MAX_SUPPORTED_PROTOCOL_VERSION: u32 = 2;

/// Check if protocol version is supported
pub fn is_protocol_version_supported(version: u32) -> bool {
    version >= MIN_SUPPORTED_PROTOCOL_VERSION && version <= MAX_SUPPORTED_PROTOCOL_VERSION
}

// =============================================================================
// Dandelion++ Privacy (Monero-grade, BIP 156 / Fanti et al. 2018)
// =============================================================================

/// Number of outbound relay peers per epoch (quasi-4-regular graph).
/// Monero: CRYPTONOTE_DANDELIONPP_STEMS = 2
pub const DANDELION_STEMS: usize = 2;

/// Fluff probability per epoch (0–100).  At epoch start, the node has this
/// percent chance of being a "fluff node" that immediately broadcasts all
/// received stem transactions.
/// Monero: CRYPTONOTE_DANDELIONPP_FLUFF_PROBABILITY = 20
/// (Paper recommends 10–20%; Monero tuned to 20% for privacy vs latency.)
pub const DANDELION_FLUFF_PROBABILITY: u32 = 20;

/// Base epoch duration in seconds (10 minutes).
/// Monero: CRYPTONOTE_DANDELIONPP_MIN_EPOCH = 10 (minutes)
pub const DANDELION_EPOCH_BASE_SECS: u64 = 600;

/// Random jitter added to epoch duration (seconds).  Prevents network-wide
/// synchronized epoch rotations.
/// Monero: CRYPTONOTE_DANDELIONPP_EPOCH_RANGE = 30 (seconds)
pub const DANDELION_EPOCH_JITTER_SECS: u64 = 30;

/// Mean embargo timeout in seconds (exponential distribution).
/// If a stem-forwarded tx hasn't appeared back via diffusion by this deadline,
/// the node fluffs it as a fail-safe.  Uses exponential distribution for the
/// memoryless property (Monero PR #9295 corrected from Poisson to exponential).
/// Monero: CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE = 39
pub const DANDELION_EMBARGO_MEAN_SECS: u64 = 39;

/// Maximum embargo timeout in seconds.  Cap to prevent black-hole attacks
/// from holding transactions indefinitely.
pub const DANDELION_EMBARGO_MAX_SECS: u64 = 180;

// =============================================================================
// Bulletproofs+ Activation
// =============================================================================

/// Block height at which Bulletproofs+ range proofs become mandatory.
/// Below this height, version 2 (standard Bulletproofs) proofs are accepted.
/// At and above this height, only version 3 (BP+) proofs are valid.
pub const BULLETPROOFS_PLUS_HEIGHT: u64 = 0; // BP+ from genesis — eliminates old bulletproofs crate

/// Range proof version byte for Bulletproofs+ proofs.
pub const RANGE_PROOF_VERSION_BP_PLUS: u8 = 3;

// =============================================================================
// Uniform 2-in/2-out Transaction Shape
// =============================================================================

/// Block height at which uniform shape becomes mandatory.
///
/// M6 (audit fix): there are TWO standard shapes, each forming its own
/// anonymity set, both enforced post-activation:
///   - CYNC Transfer/Churn:  2 inputs, 2 outputs
///   - Asset Transfer:       2 inputs, 3 outputs (CYNC fee in,
///                                                asset out + CYNC change + asset change)
///
/// Coinbase is exempt. Asset issuance (TxType::AssetIssuance) is exempt.
/// See `validation::validate_transaction` for the enforcement code.
/// Same activation height as BP+ (single hard fork).
pub const UNIFORM_TX_SHAPE_HEIGHT: u64 = BULLETPROOFS_PLUS_HEIGHT;

/// Required number of inputs for standard transactions after activation.
/// Both CYNC and asset transfers use this same input count (CYNC for fee,
/// either CYNC or asset for value).
pub const STANDARD_INPUT_COUNT: usize = 2;

/// Required number of outputs for standard CYNC Transfer/Churn after activation.
/// Asset Transfers use STANDARD_OUTPUT_COUNT + 1 (the extra output is the
/// asset-side change).
pub const STANDARD_OUTPUT_COUNT: usize = 2;

// =============================================================================
// Fee Distribution Enforcement
// =============================================================================

/// Block height at which fee burn (miner/burn split) is enforced at
/// consensus level. Before this height, miners claim all fees.
///
/// Testnet: block 525 (immediate activation for testing).
/// Mainnet: block 0 (active from genesis — no reason to delay).
#[cfg(feature = "testnet")]
pub const FEE_DISTRIBUTION_HEIGHT: u64 = 525;
#[cfg(not(feature = "testnet"))]
pub const FEE_DISTRIBUTION_HEIGHT: u64 = 0;

// =============================================================================
// Ring Size by Height
// =============================================================================

/// Get target ring size for a given block height
/// Returns the target ring size for a given height.
/// During bootstrap (< 10,000 blocks), allows BOOTSTRAP_MIN_RING_SIZE (11).
/// After bootstrap, enforces full RING_SIZE (16).
pub fn ring_size_at_height(height: u64) -> usize {
    if height < 10_000 {
        BOOTSTRAP_MIN_RING_SIZE // 11 during bootstrap
    } else {
        DEFAULT_RING_SIZE // 16 after bootstrap
    }
}

/// Get effective ring size, adapting to available outputs on young chains.
///
/// On a freshly launched chain, there may be fewer outputs than the target
/// ring size. Rather than making transactions impossible, we allow a smaller
/// ring size (minimum 2: the real output + 1 decoy) when the chain is young.
/// Once the chain matures past height 10,000 OR has enough outputs, the
/// full target ring size is enforced.
pub fn effective_ring_size(height: u64, available_outputs: usize) -> usize {
    let target = ring_size_at_height(height);
    if available_outputs >= target {
        target
    } else if height >= 10_000 {
        // After bootstrap period, enforce full ring size even if outputs are sparse
        // (this shouldn't happen on a healthy chain)
        target
    } else {
        // Young chain: adapt to what's available, minimum 2 for any privacy
        available_outputs.max(2).min(target)
    }
}

// =============================================================================
// Emission Schedule
// =============================================================================

/// Blocks per year (~262,800 with 120-second blocks).
pub const BLOCKS_PER_YEAR: u64 = 365 * 24 * 60 * 60 / TARGET_BLOCK_TIME;

/// Tail emission per block (perpetual, in atomic units): 0.6 CYNC.
/// This is the floor — the minimum reward any miner will ever receive.
/// With 30% fee burn, fees above ~2 CYNC/block make the chain deflationary.
pub const TAIL_EMISSION: u64 = 600_000_000_000; // 0.6 CYNC

/// Maximum burn rate in basis points (100 = 1%)
pub const MAX_BURN_RATE: u64 = 5000; // 50%

/// Activity window for adaptive emission (blocks)
pub const ACTIVITY_WINDOW: u64 = 1000;

/// Miner split percentage of fees (0-100)
pub const MINER_SPLIT_PERCENT: u64 = 60;

/// Hard-fork height at which demand-responsive emission activates.
/// Before this height, block rewards are purely deterministic from height.
/// After this height (when feature = "demand-responsive"), rewards adjust
/// based on difficulty, fees, and block fullness.
///
/// Set to u64::MAX to effectively disable until a governance decision sets a real height.
/// SECURITY: Changing this after testnet launch requires a coordinated hard fork.
#[cfg(feature = "demand-responsive")]
pub const DEMAND_RESPONSIVE_ACTIVATION_HEIGHT: u64 = u64::MAX; // TBD by governance

/// Total supply target: 100 million CYNC (in whole units, not atomic).
/// The asymptotic emission curve approaches but never reaches this cap.
/// With tail emission + 30% fee burn, circulating supply stabilizes
/// well below this number.
pub const TOTAL_SUPPLY_TARGET: u64 = 100_000_000;

/// Asymptotic emission divisor. The block reward is:
///   max(TAIL_EMISSION, (TOTAL_SUPPLY_TARGET - already_mined) * COIN / EMISSION_DIVISOR)
///
/// With EMISSION_DIVISOR = 2,000,000:
///   - At supply 0:    reward = 100M / 2M = 50 CYNC
///   - At supply 50M:  reward = 50M / 2M  = 25 CYNC
///   - At supply 75M:  reward = 25M / 2M  = 12.5 CYNC
///   - At supply 99M:  reward = 1M / 2M   = 0.5 CYNC → tail kicks in
///
/// This creates a smooth, self-adjusting curve with no eras and no halvings.
pub const EMISSION_DIVISOR: u64 = 2_000_000;

// ═══════════════════════════════════════════════════════════════════════════
// CONSTITUTIONAL GUARDS — Compile-time enforcement
// ═══════════════════════════════════════════════════════════════════════════
//
// Each assertion below locks a specific Article of the canonical Constitution
// (CONSTITUTION.md at the repository root) into the binary at compile time.
// Any build that tries to violate one fails with a message naming the Article.
// Modifying this file also triggers critical_files.lock verification in
// build.rs — so constitutional drift cannot happen silently in a local hack.

// ── Article I — Fixed Supply (100,000,000 CYNC asymptotic cap) ──────
const _: () = assert!(TOTAL_SUPPLY_TARGET == 100_000_000,
    "UNCONSTITUTIONAL: Article I — Supply cap must be exactly 100,000,000 CYNC");
const _: () = assert!(MAX_SUPPLY == 100_000_000u128 * COIN as u128,
    "UNCONSTITUTIONAL: Article I — MAX_SUPPLY atomic-unit value must match 100M cap");
const _: () = assert!(TAIL_EMISSION == 600_000_000_000,
    "Asymptotic curve: tail emission is 0.6 CYNC/block = 600_000_000_000 atomic");

// ── Article II — No Pre-mine, No Developer Tax ──────────────────────
/// Constitution Article II — no percentage-based fee or tax is ever routed
/// to developers, a foundation treasury, or any other address. A non-zero
/// value here is a constitutional violation.
pub const DEV_TAX_PERCENT: u64 = 0;
const _: () = assert!(DEV_TAX_PERCENT == 0,
    "UNCONSTITUTIONAL: Article II — Dev tax must be zero. No fee extraction to developers.");

// ── Article III — Mandatory Privacy ─────────────────────────────────
//
// The three compile-time rules backing Article III ("All transactions
// on CoinCync are private"): minimum ring size for sender anonymity,
// mandatory Pedersen commitments for hidden amounts, and mandatory
// stealth addresses for hidden recipients. Each is enforced at the
// consensus level by src/consensus/privacy_policy.rs.

/// Article III — ring size floor (11). Lower values have been shown to
/// be statistically deanonymizable on Monero's historical ledger; 11 is
/// the settled Monero-school floor as of 2024.
const _: () = assert!(BOOTSTRAP_MIN_RING_SIZE >= 11,
    "UNCONSTITUTIONAL: Article III — Minimum ring size must be >= 11 for mandatory privacy");

/// Article III — hidden amounts. Every non-coinbase output must carry a
/// non-zero Pedersen commitment. Enforced structurally in
/// `consensus::privacy_policy::check_tx_privacy`.
pub const MANDATORY_CONFIDENTIAL: bool = true;
const _: () = assert!(MANDATORY_CONFIDENTIAL,
    "UNCONSTITUTIONAL: Article III — all amounts must be hidden (Pedersen commitments)");

/// Article III — hidden recipients. Every output must use a stealth
/// address or a Spark address (Phase 2). Raw public-key outputs are
/// invalid at the consensus level.
pub const MANDATORY_STEALTH: bool = true;
const _: () = assert!(MANDATORY_STEALTH,
    "UNCONSTITUTIONAL: Article III — all outputs must use stealth or Spark addresses");

/// Article III — no trusted setup. Halo2 (IPA) is the shielded-pool
/// proving system; Groth16 and any other ceremony-dependent scheme are
/// forbidden because they require destroying toxic-waste material that
/// future participants must trust was actually destroyed.
pub const NO_TRUSTED_SETUP: bool = true;
const _: () = assert!(NO_TRUSTED_SETUP,
    "UNCONSTITUTIONAL: Article III — no trusted setup (Halo2 IPA only, no Groth16)");

// ── Article V — Open Mining (RandomX only) ──────────────────────────
/// Constitution Article V — RandomX is the only proof-of-work algorithm.
/// Multi-algorithm rotation schemes are permanently forbidden; the
/// rationale is in CONSTITUTION.md ("Why RandomX and not multi-algorithm
/// rotation"). Flipping this flag requires a constitutional amendment,
/// which Article X forbids.
pub const RANDOMX_ONLY: bool = true;
const _: () = assert!(RANDOMX_ONLY,
    "UNCONSTITUTIONAL: Article V — CoinCync is RandomX-only, no algorithm rotation");

// ── Article IX — No Surveillance Infrastructure ─────────────────────
//
// The three flags below collectively implement Article IX: no address
// blacklist, no transaction censorship, no surveillance metadata hooks.
// Any mechanism whose primary purpose is to identify participants
// without their consent is forbidden at the protocol level.

/// Article IX — no address blacklist. Also supports Bill of Rights IV
/// (self-custody) and X (no censorship).
pub const ADDRESS_BLACKLIST_ENABLED: bool = false;
const _: () = assert!(!ADDRESS_BLACKLIST_ENABLED,
    "UNCONSTITUTIONAL: Article IX / Bill of Rights IV & X — No address blacklisting");

/// Article IX — no transaction censorship. Valid transactions must
/// always be eligible for inclusion. Supports Bill of Rights X.
pub const TX_CENSORSHIP_ENABLED: bool = false;
const _: () = assert!(!TX_CENSORSHIP_ENABLED,
    "UNCONSTITUTIONAL: Article IX / Bill of Rights X — Transaction censorship is permanently prohibited");

/// Article IX — no surveillance infrastructure. Chain-analysis hooks,
/// metadata-leak fields, and reporting mechanisms that transmit user
/// data to third parties are permanently forbidden.
pub const SURVEILLANCE_HOOKS_ENABLED: bool = false;
const _: () = assert!(!SURVEILLANCE_HOOKS_ENABLED,
    "UNCONSTITUTIONAL: Article IX — Surveillance infrastructure is permanently prohibited");

// ═══════════════════════════════════════════════════════════════════════════
// Lelantus Spark (Phase 2)
// ═══════════════════════════════════════════════════════════════════════════

/// Bech32m human-readable prefix for Spark mainnet addresses.
pub const SPARK_HRP: &str = "ys";
/// Bech32m HRP for Spark testnet addresses.
pub const SPARK_T_HRP: &str = "ts";

/// Maximum anonymity set size for a Spark one-out-of-many proof.
/// Matches Firo's Spark parameters: 16,384 coins per proof.
pub const SPARK_ANON_SET_MAX: usize = 16_384;

/// Minimum anonymity set size — a spend with fewer than this many decoys
/// is rejected at the mempool level.
pub const SPARK_ANON_SET_MIN: usize = 64;

/// Diversifier length for Spark addresses (bytes).
pub const SPARK_DIVERSIFIER_LEN: usize = 11;

/// Target serialized size of a Spark spend proof, in bytes. Used for
/// fee calculation and dust rejection.
pub const SPARK_PROOF_SIZE: usize = 2048;

// ═══════════════════════════════════════════════════════════════════════════
// MimbleWimble cut-through (Phase 2)
// ═══════════════════════════════════════════════════════════════════════════

/// Number of confirmations required before an MW cut-through candidate is
/// actually pruned. Prevents cut-through from racing against reorgs.
pub const MW_CUTTHROUGH_DEPTH: u64 = 1_000;

/// Phase burn rates: (end_height, burn_rate_basis_points)
pub const PHASE_BURN_RATES: [(u64, u64); 4] = [
    (BLOCKS_PER_YEAR, 0),        // Year 1: no burn
    (BLOCKS_PER_YEAR * 2, 500),  // Year 2: 5% burn
    (BLOCKS_PER_YEAR * 5, 1000), // Year 3-5: 10% burn
    (u64::MAX, 2000),            // After year 5: 20% burn
];

/// Get burn rate at a given height (in basis points)
pub fn burn_rate_at_height(height: u64) -> u64 {
    for (end_height, rate) in PHASE_BURN_RATES {
        if height < end_height {
            return rate;
        }
    }
    PHASE_BURN_RATES[PHASE_BURN_RATES.len() - 1].1
}

/// Get supply cap burn rate in basis points.
/// Increases as circulating supply approaches the 250M cap,
/// creating deflationary pressure near the supply ceiling.
///
/// FORMAL VERIFICATION FIX: Thresholds lowered and rates increased to ensure
/// total emission stays under 250M CYNC. Property-based tests proved the
/// previous thresholds (50%/75%/90%) with rates (2%/5%/10%) allowed ~257M
/// emission — violating the Constitutional 250M hard cap (Article I).
///
/// New thresholds activate earlier (40%/60%/80%/95%) with steeper rates
/// (2%/5%/10%/20%) to provide sufficient deflationary pressure.
/// C-6 FIX: Re-derived for 100M cap (was calibrated for 250M).
/// Thresholds are now correct absolute values against TOTAL_SUPPLY_TARGET = 100M.
pub fn supply_cap_burn_rate(current_supply: u64) -> u64 {
    let cap = TOTAL_SUPPLY_TARGET; // 100_000_000
    if current_supply < cap * 40 / 100 {
        // Below 40M: no extra burn — early emission phase
        0
    } else if current_supply < cap * 60 / 100 {
        // 40M–60M (40%–60%): 200 basis points (2%)
        200
    } else if current_supply < cap * 80 / 100 {
        // 60M–80M (60%–80%): 500 basis points (5%)
        500
    } else if current_supply < cap * 95 / 100 {
        // 80M–95M (80%–95%): 1000 basis points (10%)
        1000
    } else {
        // 95M+ (>95%): 2000 basis points (20%) — hard brake near cap
        2000
    }
}

/// Protocol split percentage of fees (0-100)
pub const PROTOCOL_SPLIT_PERCENT: u64 = 10;

/// Bonus split percentage (0-100)
pub const BONUS_SPLIT_PERCENT: u64 = 30;

// =============================================================================
// Miner Bans & Reputation
// =============================================================================

/// Double sign ban duration in blocks (~35 days with 30s blocks)
pub const DOUBLE_SIGN_BAN: u64 = 100_800;

/// Blocks to reach elder reputation
pub const REPUTATION_ELDER_BLOCKS: u64 = 525_600; // ~1 year

/// Blocks to reach veteran reputation
pub const REPUTATION_VETERAN_BLOCKS: u64 = 175_200; // ~4 months

/// Blocks to reach established reputation
pub const REPUTATION_ESTABLISHED_BLOCKS: u64 = 43_800; // ~1 month

/// Grace period blocks for forgivable double-signs
pub const GRACE_PERIOD_BLOCKS: u64 = 2400; // ~4 hours

/// Critical grace blocks (short grace for veterans)
pub const CRITICAL_GRACE_BLOCKS: u64 = 300; // ~30 minutes

/// Evidence chain domain for hashing
pub const EVIDENCE_CHAIN_DOMAIN: &[u8] = b"COINCYNC_EVIDENCE_v1";

/// Fingerprint similarity threshold for detection (0-100)
pub const FINGERPRINT_SIMILARITY_THRESHOLD: u64 = 80;

// =============================================================================
// Initial Ring Size
// =============================================================================

/// Initial ring size for transactions
pub const RING_SIZE_INITIAL: usize = BOOTSTRAP_MIN_RING_SIZE;

/// Activation height for strict ring member validation.
///
/// Below this height, ring members not found in the output index are
/// logged as warnings but not rejected (backward compat for pre-existing blocks).
/// At and above this height, every ring member MUST exist in the permanent
/// output index — fabricated ring members are rejected.
pub const STRICT_RING_MEMBER_HEIGHT: u64 = 100;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supply_cap_is_100m() {
        assert_eq!(TOTAL_SUPPLY_TARGET, 100_000_000);
    }

    #[test]
    fn test_atomic_units_per_cync() {
        assert_eq!(ATOMIC_UNITS, 1_000_000_000_000);
    }

    #[test]
    fn test_min_ring_size_constitutional() {
        assert!(BOOTSTRAP_MIN_RING_SIZE >= 11);
    }

    #[test]
    fn test_ring_size_at_height() {
        assert_eq!(ring_size_at_height(0), BOOTSTRAP_MIN_RING_SIZE);
        assert_eq!(ring_size_at_height(9_999), BOOTSTRAP_MIN_RING_SIZE);
        assert_eq!(ring_size_at_height(10_000), 16);
        assert_eq!(ring_size_at_height(100_000), DEFAULT_RING_SIZE);
    }

    #[test]
    fn test_algorithm_is_randomx_only() {
        // CoinCync 1.0 is RandomX-only — `algorithm_at_height` MUST return
        // the RandomX index (0) at every height. If this test fails, a
        // multi-algorithm rotation has been re-introduced without explicit
        // audit, which is a consensus-impacting change.
        //
        // Pre-audit this test expected a pre-1.0 three-algo rotation
        // (RandomX / YescryptHeavy / YescryptLight) that was removed in
        // the 1.0 trim but the test was never updated — a stale test that
        // silently failed under any test run.
        for h in [0u64, 1, 2, 100, 1_000, 100_000, 10_000_000] {
            assert_eq!(
                algorithm_at_height(h),
                0,
                "CoinCync 1.0 is RandomX-only; height {} must use algorithm 0",
                h
            );
        }
    }

    #[test]
    fn test_no_surveillance_hooks() {
        assert!(!ADDRESS_BLACKLIST_ENABLED);
        assert!(!TX_CENSORSHIP_ENABLED);
        assert!(!SURVEILLANCE_HOOKS_ENABLED);
        assert_eq!(DEV_TAX_PERCENT, 0);
    }

    #[test]
    fn test_effective_ring_size_young_chain() {
        // Young chain with few outputs adapts down
        assert_eq!(effective_ring_size(5, 3), 3);
        // But never below 2
        assert_eq!(effective_ring_size(5, 1), 2);
        // With enough outputs, use target
        assert_eq!(effective_ring_size(5, 20), BOOTSTRAP_MIN_RING_SIZE);
    }
}

/// Calculate activity bonus rate based on blocks mined
pub fn activity_bonus_rate(blocks_mined: u64) -> u64 {
    // Simple linear scaling for now
    // More blocks mined = higher bonus (up to a cap)
    let base_bonus = 100; // 1% in basis points
    let max_bonus = 1000; // 10% max bonus
    let bonus = base_bonus + (blocks_mined / 1000);
    bonus.min(max_bonus)
}
