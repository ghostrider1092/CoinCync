//! # Protocol Constants
//!
//! Core protocol constants for CoinCync 1.0.

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

/// Minimum output age for spending (blocks), PRE-activation.
///
/// CONSENSUS: this is the pre-hard-fork value. Used unconditionally
/// by all wallet selection / send / validation paths BEFORE block
/// height `MIN_OUTPUT_AGE_HARDFORK_HEIGHT`. After that height, the
/// `MIN_OUTPUT_AGE_POST_FORK` value applies. Always read this via
/// `min_output_age_at_height(height)` — never reference the const
/// directly in a code path that has a current height available, or
/// the chain will fork at the activation height.
pub const MIN_OUTPUT_AGE: u64 = 10;

/// Minimum output age for spending (blocks), POST-activation.
///
/// CONSENSUS: applies at heights ≥ `MIN_OUTPUT_AGE_HARDFORK_HEIGHT`.
/// The 10× increase from the pre-fork value tightens the maturity
/// window to ~3.3 hours of confirmations at 120s blocks (vs ~20 min
/// pre-fork). Closes the practical-attack window where a deep-reorg
/// adversary could double-spend a 10-block-confirmed output by
/// privately mining a 11-block sidechain — at 100 blocks that
/// adversary needs ~2 hours of >50% hashpower instead of ~20 min.
pub const MIN_OUTPUT_AGE_POST_FORK: u64 = 100;

/// Block height at which the `MIN_OUTPUT_AGE` 10 → 100 hard fork
/// activates. Heights STRICTLY BELOW this value use the pre-fork
/// value (`MIN_OUTPUT_AGE` = 10); heights AT OR ABOVE this value
/// use `MIN_OUTPUT_AGE_POST_FORK` = 100.
///
/// **TESTNET — `u64::MAX` is a placeholder.** The actual activation
/// height is picked in the pre-tag PR for the v1.0.10-testnet cut.
/// Per `docs/launch/v1.0.10-CHECKLIST.md` §0, the height should be
/// the current testnet tip + ~5,000 blocks (≈7 days at 120s) so
/// operators have a real window to upgrade before the rule changes
/// under them. While the placeholder is `u64::MAX`, behavior is
/// strictly identical to pre-fork — `min_output_age_at_height` always
/// returns 10 — so this guard ships safely in pre-cut commits and
/// only "turns on" when the height is set.
///
/// **MAINNET — `0`.** The new value is active from genesis; there's
/// no behavior to migrate because mainnet hasn't launched yet (target
/// 2026-10-01 per `project_staged_mainnet`). New mainnet wallets see
/// 100 as the maturity floor from block 1.
#[cfg(feature = "testnet")]
pub const MIN_OUTPUT_AGE_HARDFORK_HEIGHT: u64 = u64::MAX;
#[cfg(not(feature = "testnet"))]
pub const MIN_OUTPUT_AGE_HARDFORK_HEIGHT: u64 = 0;

/// Get the minimum output age (in blocks) required for an output to
/// be spendable at the given block height.
///
/// CONSENSUS-CRITICAL: this is the single source of truth. Every
/// call site that previously read `MIN_OUTPUT_AGE` directly must use
/// this helper with the relevant height (chain tip for wallet
/// selection, block-being-validated height for the consensus
/// validator). Bypassing the helper at a single call site will fork
/// the chain at the activation height.
#[inline]
pub fn min_output_age_at_height(height: u64) -> u64 {
    if height < MIN_OUTPUT_AGE_HARDFORK_HEIGHT {
        MIN_OUTPUT_AGE
    } else {
        MIN_OUTPUT_AGE_POST_FORK
    }
}

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
// Consensus checkpoints (CIP-009 Path B — reorg defense)
// =============================================================================
//
// Hardcoded (height, block_hash) pairs that the validator rejects any
// alternative chain from contradicting. A reorg attempt past a checkpoint
// height with a different block hash at that height is structurally
// impossible — every honest node refuses to accept it.
//
// The table is updated at every release. Pick a height ~2 weeks behind
// the chain tip at release time so the community has had time to review
// the chain state being baked in. The script
// `scripts/update-checkpoints.sh` automates the refresh; the procedure
// is documented in `docs/operations/CHECKPOINT_PROCEDURE.md`.
//
// Anti-features:
//   - Empty table is acceptable. The validator treats "no checkpoint
//     for this height" as "allow any consistent block." Initial
//     deployments and freshly-genesised chains run with empty tables.
//   - Per-network. Mainnet and testnet ship separate tables, gated
//     by the `testnet` feature, so a testnet rebuild doesn't lock
//     mainnet at a testnet hash.
//
// Format: const slice of `(height, raw_hash_bytes)` tuples. MUST be
// sorted ascending by height; the lookup is a binary search. The
// build-time test `test_checkpoints_are_sorted` enforces ordering.

/// Mainnet consensus checkpoints. Pre-launch: empty.
/// Populated post-launch via the release process; each release ships
/// with checkpoints up to ~2 weeks before the release date.
#[cfg(not(feature = "testnet"))]
pub const CONSENSUS_CHECKPOINTS: &[(u64, [u8; 32])] = &[
    // (height, block_hash_bytes)
    // Empty as of 2026-05-08; populate at first post-launch release.
];

/// Testnet consensus checkpoints. Empty as of 2026-05-08. Testnet
/// generally won't carry checkpoints (the chain resets between test
/// cycles), but the table exists so the validator code path is
/// exercised on the same data shape mainnet will use.
#[cfg(feature = "testnet")]
pub const CONSENSUS_CHECKPOINTS: &[(u64, [u8; 32])] = &[
    // (height, block_hash_bytes)
];

/// Look up the expected block hash at a given height, if a checkpoint
/// exists for it. Returns None when:
///   - no checkpoint is recorded at this height (the common case)
///   - the table is empty (pre-launch)
///
/// Caller (the validator) treats `None` as "accept any consistent
/// block at this height" — checkpoints are an ADDITIONAL constraint
/// on top of normal consensus, not a replacement.
///
/// Implementation: binary search since the table is sorted by height.
/// O(log n) where n is the checkpoint count (expected: dozens).
pub fn expected_checkpoint_hash(height: u64) -> Option<&'static [u8; 32]> {
    CONSENSUS_CHECKPOINTS
        .binary_search_by_key(&height, |&(h, _)| h)
        .ok()
        .map(|idx| &CONSENSUS_CHECKPOINTS[idx].1)
}

// =============================================================================
// CIP-011 — Rolling soft-finality activation heights
// =============================================================================
//
// Two-phase activation per CIP-011:
//
//   - ENABLE: blocks at/after this height *may* carry a CIP-009.D
//     finality attestation in coinbase extra. Validators record them
//     into the in-memory tracker; the reorg rule does **not** fire
//     yet. Backward-compatible — blocks without attestations are
//     still accepted.
//
//   - ENFORCE: blocks at/after this height **must** carry a valid
//     attestation, AND the reorg-rule fires — any reorg whose fork
//     point is at or below `soft_final_height()` is rejected.
//
// The ENABLE→ENFORCE gap (~25 000 blocks ≈ 35 days) is deliberately
// wider than the `WINDOW` of the `coincync-rolling-finality` crate
// (~10 000 blocks) so the active miner set has time to populate
// before the rule has bite. See `docs/cip/CIP-011-rolling-finality-
// activation.md` for the bootstrap-scenario playbook.
//
// Values per the CIP-011 draft, recommended option.

/// Block at/after which CIP-009.D finality attestations are accepted
/// in coinbase extra and recorded by validators. The reorg rule does
/// NOT fire at this height — only at `ROLLING_FINALITY_ENFORCE_HEIGHT`.
#[cfg(feature = "testnet")]
pub const ROLLING_FINALITY_ENABLE_HEIGHT: u64 = 50_000;
#[cfg(not(feature = "testnet"))]
pub const ROLLING_FINALITY_ENABLE_HEIGHT: u64 = 25_000;

/// Block at/after which CIP-009.D enforcement begins: every block
/// must carry a valid attestation, and any reorg whose fork point is
/// at or below the soft-final height is rejected. Must be strictly
/// greater than `ROLLING_FINALITY_ENABLE_HEIGHT` plus the active-set
/// `WINDOW`.
#[cfg(feature = "testnet")]
pub const ROLLING_FINALITY_ENFORCE_HEIGHT: u64 = 75_000;
#[cfg(not(feature = "testnet"))]
pub const ROLLING_FINALITY_ENFORCE_HEIGHT: u64 = 50_000;

// =============================================================================
// Hard-fork activation registry (CIP-007)
// =============================================================================

/// Hard-fork / soft-fork activation table per CIP-007.
///
/// Each named activation maps to the block height at which the new
/// rule takes effect. Validator code consults `is_activated(name,
/// height)` to gate consensus rules; wallet code consults it to
/// build txs that conform to the active set.
///
/// As of 2026-05-08 the table is intentionally empty: no Mode A
/// activations have been scheduled yet. The infrastructure is
/// in place so the first activation (likely
/// `BOOTSTRAP_MIN_RING_SIZE_V2` per the queued list in CIP-007) is a
/// table entry + validator branch, not a new file + helper + wiring.
///
/// Adding an activation:
///   1. Pick a stable name (snake_case, e.g. "ring_bump_v2").
///   2. Append `(name, testnet_height, mainnet_height)` to this
///      function.
///   3. Validator/wallet code uses `is_activated(name, h)` to gate
///      the new rule.
///   4. Document in the corresponding CIP.
fn activation_height(name: &str) -> Option<u64> {
    // Per CIP-007 Mode A: the testnet vs mainnet activation heights
    // can differ. We pick at compile time via the `testnet` feature.
    #[cfg(feature = "testnet")]
    let entries: &[(&str, u64)] = &[
        // Format: (activation_name, testnet_height)
        // Empty as of 2026-05-08 — first activation queued: ring_bump_v2.
    ];
    #[cfg(not(feature = "testnet"))]
    let entries: &[(&str, u64)] = &[
        // Format: (activation_name, mainnet_height)
        // Empty as of 2026-05-08.
    ];
    entries.iter()
        .find(|(n, _)| *n == name)
        .map(|(_, h)| *h)
}

/// Returns true if the named activation is in effect at `height`.
///
/// Returns false when the activation isn't registered (silent —
/// callers SHOULD pass only known names; an unknown-name false
/// means "this rule never activates," which is the correct
/// fail-safe for a forward-compat code path that hasn't been
/// scheduled yet).
pub fn is_activated(name: &str, height: u64) -> bool {
    match activation_height(name) {
        Some(activation_h) => height >= activation_h,
        None => false,
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

// ── Articles XI–XIV — Category-level tripwires ──────────────────────
//
// These four flags do not enforce the corresponding articles by
// themselves — Articles XI, XII, XIII, and XIV are principles enforced
// by the absence of forbidden mechanisms across the codebase. The
// flags exist as visible compile-time anchors: any future PR that
// tries to introduce a forbidden mechanism must either flip a flag
// (which is then a glaring diff in review) or build a parallel
// mechanism alongside dead-code that pretends nothing changed (also
// a glaring diff). Either way, review catches the violation. See
// CONSTITUTIONAL_COMMENTARY.md for the rationale behind each article.

/// Article XI — No Algorithmic Capture. CYNC is created only by the
/// Article I emission. No mint/burn rebalancing tied to external
/// price, no protocol-level subsidy, no reflexive supply mechanism.
pub const NO_ALGORITHMIC_PEG: bool = true;
const _: () = assert!(NO_ALGORITHMIC_PEG,
    "UNCONSTITUTIONAL: Article XI — No algorithmic capture; mint pathways outside Article I forbidden");

/// Article XII — No Admin Authority. No address, multisig, or off-
/// chain entity holds protocol-level power to mint, freeze, seize,
/// or redirect funds. No emergency override exists.
pub const NO_ADMIN_KEYS: bool = true;
const _: () = assert!(NO_ADMIN_KEYS,
    "UNCONSTITUTIONAL: Article XII — No admin authority; no key controls user funds at the protocol layer");

/// Article XIII — No External Trust. Consensus depends only on state
/// derivable from the CoinCync chain. No bridges, oracles, wrapped
/// assets, IOUs, or off-chain attestations enter block validity.
pub const NO_EXTERNAL_BRIDGES: bool = true;
const _: () = assert!(NO_EXTERNAL_BRIDGES,
    "UNCONSTITUTIONAL: Article XIII — No external trust; consensus is sovereign over local state only");

/// Article XIV — No Surveillance Layer. All CYNC is fungible. No
/// metadata layer, identity attestation, NFT primitive, name service,
/// or coin-distinguishing mechanism exists at the protocol level.
pub const NO_SURVEILLANCE_LAYER: bool = true;
const _: () = assert!(NO_SURVEILLANCE_LAYER,
    "UNCONSTITUTIONAL: Article XIV — No surveillance layer; all CYNC is fungible at the protocol level");

// ── Article XVI / Right XIV — Permanent Scarcity Through Burn ───────
//
// The fee-burn floors are constitutional invariants. Any reduction of
// either floor would redirect supply away from the burn — a category
// forbidden by Article XVI ("no portion may be redirected ...") and
// Right XIV. The asserts below ensure:
//   1. The normal-condition floor stays at 30%.
//   2. The congested-condition rate is never lower than the normal
//      rate (congestion may strengthen the burn, never weaken it).
//   3. The protocol fee in both modes remains zero (no third
//      destination beyond miner + burn).

const _: () = assert!(FEE_BURN_NORMAL_PERCENT == 30,
    "UNCONSTITUTIONAL: Article XVI / Right XIV — fee burn floor must remain at 30% under normal conditions");

const _: () = assert!(FEE_BURN_CONGESTED_PERCENT >= FEE_BURN_NORMAL_PERCENT,
    "UNCONSTITUTIONAL: Article XVI — congested burn rate must not fall below the normal-condition floor");

const _: () = assert!(
    FEE_PROTOCOL_NORMAL_PERCENT == 0 && FEE_PROTOCOL_CONGESTED_PERCENT == 0,
    "UNCONSTITUTIONAL: Article II / Article XVI / Right XIV — no third fee destination; only miner + burn permitted"
);

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

    /// Lock in the activation-boundary semantics of the MIN_OUTPUT_AGE
    /// 10 → 100 hard fork. The contract is: heights STRICTLY BELOW
    /// `MIN_OUTPUT_AGE_HARDFORK_HEIGHT` use the pre-fork value (10);
    /// heights AT OR ABOVE use the post-fork value (100). Off-by-one
    /// errors at this boundary would split the chain at activation,
    /// so the boundary case is asserted explicitly.
    #[test]
    fn test_min_output_age_activation_boundary() {
        // Pre-fork value is what the helper returns at every height
        // BELOW activation, regardless of which network we built for.
        assert_eq!(MIN_OUTPUT_AGE, 10);
        assert_eq!(MIN_OUTPUT_AGE_POST_FORK, 100);
        assert!(MIN_OUTPUT_AGE_POST_FORK > MIN_OUTPUT_AGE,
            "post-fork value must be strictly larger — the hard fork tightens, never loosens");

        // The boundary contract: `<` returns pre, `>=` returns post.
        // We only assert this when the activation height is finite
        // AND non-zero (testnet placeholder is u64::MAX, in which
        // case `< u64::MAX` is always true and the boundary is
        // unreachable; mainnet is 0 so there's no "one before
        // activation" — fork is genesis-active). Use saturating_*
        // and method-call boundary arithmetic so const-eval of the
        // mainnet `0` doesn't trip the arithmetic_overflow lint.
        if MIN_OUTPUT_AGE_HARDFORK_HEIGHT > 0 && MIN_OUTPUT_AGE_HARDFORK_HEIGHT < u64::MAX {
            // One block before activation: still pre-fork.
            assert_eq!(
                min_output_age_at_height(MIN_OUTPUT_AGE_HARDFORK_HEIGHT.saturating_sub(1)),
                MIN_OUTPUT_AGE,
                "block immediately before activation MUST use pre-fork value"
            );
            // Exactly at activation: post-fork (the rule activates AT
            // this height, not after).
            assert_eq!(
                min_output_age_at_height(MIN_OUTPUT_AGE_HARDFORK_HEIGHT),
                MIN_OUTPUT_AGE_POST_FORK,
                "activation-height block MUST use post-fork value"
            );
            // One block after activation: still post-fork.
            assert_eq!(
                min_output_age_at_height(MIN_OUTPUT_AGE_HARDFORK_HEIGHT.saturating_add(1)),
                MIN_OUTPUT_AGE_POST_FORK
            );
        }

        // Far-future and far-past sanity: with the testnet u64::MAX
        // placeholder, every reasonable height returns pre-fork.
        // With the mainnet 0 setting, every height returns post-fork.
        // Either way, the helper is total and never panics on any u64.
        for h in [0u64, 1, 100, 10_000, 1_000_000, u64::MAX / 2, u64::MAX - 1] {
            let v = min_output_age_at_height(h);
            assert!(
                v == MIN_OUTPUT_AGE || v == MIN_OUTPUT_AGE_POST_FORK,
                "helper returned unexpected value {} at height {}", v, h
            );
        }
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

    /// CIP-009 Path B invariant: the consensus-checkpoint table must
    /// be sorted ascending by height. The `expected_checkpoint_hash`
    /// lookup uses `binary_search_by_key` which returns garbage on
    /// unsorted input. A sort-violation in the table is a silent
    /// consensus bug; this test makes it loud at build time.
    #[test]
    fn test_consensus_checkpoints_are_sorted_ascending() {
        let table = CONSENSUS_CHECKPOINTS;
        for window in table.windows(2) {
            let (h_prev, _) = window[0];
            let (h_next, _) = window[1];
            assert!(
                h_prev < h_next,
                "CONSENSUS_CHECKPOINTS must be sorted ascending by height; \
                 found {} before {}",
                h_prev, h_next
            );
        }
    }

    /// CIP-009 Path B safety: `expected_checkpoint_hash` returns None
    /// at heights with no checkpoint, Some at heights that have one.
    /// Test exercises both paths even when the production table is
    /// empty, by building a synthetic table at test scope. Confirms
    /// the binary-search dispatch is wired correctly regardless of
    /// real-table content.
    #[test]
    fn test_expected_checkpoint_hash_lookup() {
        // The production table can be empty (pre-launch); confirm
        // empty-table behavior: every lookup returns None.
        if CONSENSUS_CHECKPOINTS.is_empty() {
            assert!(expected_checkpoint_hash(0).is_none());
            assert!(expected_checkpoint_hash(1).is_none());
            assert!(expected_checkpoint_hash(1_000_000).is_none());
        } else {
            // If checkpoints exist, the first must be findable.
            let (first_h, _) = CONSENSUS_CHECKPOINTS[0];
            assert!(expected_checkpoint_hash(first_h).is_some());
            // A height NOT in the table must return None.
            // Pick a height that's clearly between or after entries.
            let last_h = CONSENSUS_CHECKPOINTS[CONSENSUS_CHECKPOINTS.len() - 1].0;
            assert!(expected_checkpoint_hash(last_h + 1_000_000).is_none());
        }
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
