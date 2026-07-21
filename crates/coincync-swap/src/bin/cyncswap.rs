//! `cyncswap` — command-line driver for the CYNC↔BTC atomic swap.
//!
//! ## Status: PROTOCOL STATE MACHINE WIRED, CRYPTO STILL SKELETON
//!
//! As of phase 2.5, the CLI runs a real swap state machine end-to-
//! end:
//!
//! - `alice` and `bob` subcommands construct a `Swap` and persist
//!   it to disk via `SwapStore`.
//! - `status` reloads the state file and reports current state +
//!   legal next transitions.
//! - `cancel` applies `Transition::Abort` and re-saves; the swap
//!   is now in the terminal `Aborted` state.
//!
//! What's still skeleton: the on-chain cryptographic operations
//! (CYNC lock, BTC lock, claims, refunds) — the CLI subcommands
//! that drive those still print a NOT-YET-IMPLEMENTED notice and
//! exit non-zero, so scripts can't mistake them for working
//! operations. The state-machine layer is real and tested today;
//! the cryptography lands in phase 3+ per CIP-001.
//!
//! ## State file
//!
//! Default path: `~/.coincync/swap.json`. Override with
//! `--state-file <path>`. The home-directory prefix is expanded
//! manually (no `dirs-next` dep) — `~` becomes `$HOME` on
//! Unix-like systems and `%USERPROFILE%` on Windows. If neither
//! variable is set, the swap state lands in the current working
//! directory.
//!
//! ## Bob's parameters during phase 2.5
//!
//! In the production protocol, Bob learns the swap parameters
//! from Alice's `HelloAck` message. Without a working coordinator
//! on the wire today, Bob's CLI takes the same `--cync-amount`
//! and `--btc-amount-sats` flags Alice used. This is a testnet
//! expedient: in production, Bob just passes `--connect` and
//! `--swap-id` and the negotiation phase fills in the rest.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use coincync_swap::protocol::{Role, State, Swap, SwapParameters, Transition};
use coincync_swap::SwapStore;

/// Default swap timeouts. Match the CIP-001 §"Timeout Safety"
/// recommendation: BTC ≈ 24h wall-clock, CYNC ≈ 24h * margin.
/// Phase 3 will let users override via flags; for phase 2.5 these
/// are baked in.
const DEFAULT_CYNC_TIMEOUT_BLOCKS: u32 = 720;
const DEFAULT_BTC_TIMEOUT_BLOCKS: u32 = 100;

#[derive(Parser)]
#[command(name = "cyncswap")]
#[command(version)]
#[command(
    about = "CYNC↔BTC atomic swap CLI. State machine real; on-chain crypto skeleton. See CIP-001."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Byte-order tag for adaptor-secret hex inputs that need to be
/// interpreted as a scalar. Used by `btc-adaptor-point-from-secret`
/// (and would be used by any future subcommand that takes a raw
/// adaptor-secret hex and needs to know how to read it).
///
/// Default everywhere is `ristretto` because that's the canonical
/// form across the CLI surface: `cync-adaptor-point-from-secret`,
/// `prove-dleq`, `cync-create-pre-sig`, etc. all take Ristretto-LE.
/// The only place secp256k1-BE shows up natively is the output of
/// `recover-secret-from-btc-sig` — operators dealing with that
/// path can pass `--encoding secp256k1` rather than detour through
/// `adaptor-secret-flip-endian` first.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum AdaptorSecretEncoding {
    /// Ristretto255 canonical (little-endian). The swap protocol's
    /// default encoding; matches `cync-adaptor-point-from-secret`
    /// and `prove-dleq`.
    Ristretto,
    /// secp256k1 big-endian. Matches the output of
    /// `recover-secret-from-btc-sig`.
    Secp256k1,
}

/// Operator-callable observation transitions for the `transition`
/// subcommand. Only the OBSERVATION half of [`coincync_swap::protocol::Transition`]
/// is exposed — action transitions live behind their bundled
/// broadcast-then-transition subcommands (`lock-cync`, `lock-btc`,
/// etc.) so the local state cannot drift out of sync with the chain
/// by operator typo.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum TransitionKind {
    /// Alice OBSERVES Bob's BTC lock arriving on-chain.
    /// `AliceLocked` → `BobLocked`. Alice's role.
    ObserveBobLocked,
    /// Bob OBSERVES Alice's CYNC lock arriving on-chain.
    /// `Negotiated` → `AliceLocked`. Bob's role.
    ObserveAliceLocked,
    /// Bob OBSERVES Alice's BTC claim arriving on-chain (which
    /// reveals the adaptor secret). `BobLocked` → `SecretRevealed`.
    /// Bob's role.
    ObserveSecretRevealed,
    /// Bob OBSERVES Alice's CYNC claim arriving on-chain — used
    /// only in recovery scenarios where Alice somehow finalizes the
    /// CYNC side independently. `SecretRevealed` → `Completed`.
    /// Bob's role.
    ObserveCompleted,
}

impl TransitionKind {
    /// Map to the protocol-layer [`coincync_swap::protocol::Transition`].
    fn to_protocol(self) -> coincync_swap::protocol::Transition {
        use coincync_swap::protocol::Transition;
        match self {
            Self::ObserveBobLocked => Transition::ObserveBobLocked,
            Self::ObserveAliceLocked => Transition::ObserveAliceLocked,
            Self::ObserveSecretRevealed => Transition::ObserveSecretRevealed,
            Self::ObserveCompleted => Transition::ObserveCompleted,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a new swap as Alice (sells CYNC, buys BTC).
    /// Persists initial state to the state file; a fresh swap_id
    /// is printed on stdout for out-of-band sharing with Bob.
    Alice {
        /// Listen endpoint Alice publishes for Bob to dial (e.g.
        /// `0.0.0.0:9000` for direct TCP, or the `.onion` host her
        /// Tor hidden-service maps to). Recorded in the state file
        /// but not bound at this step — Alice runs
        /// `Coordinator::listen*` separately when the wallet
        /// integration ships.
        #[arg(long)]
        listen: String,
        /// Amount of CYNC to lock, in atomic units.
        #[arg(long)]
        cync_amount: u64,
        /// Amount of satoshis Bob will lock in return.
        #[arg(long)]
        btc_amount_sats: u64,
        /// CYNC stealth address Alice will eventually be paid to.
        /// Placeholder until wallet integration validates real
        /// stealth addresses.
        #[arg(long, default_value = "alice-cync-addr-placeholder")]
        alice_cync_address: String,
        /// BTC P2WPKH address Bob will eventually be paid to.
        /// Placeholder until wallet integration validates real
        /// Bitcoin addresses.
        #[arg(long, default_value = "bob-btc-addr-placeholder")]
        bob_btc_address: String,
        /// State file. Defaults to `~/.coincync/swap.json`.
        #[arg(long)]
        state_file: Option<PathBuf>,
    },

    /// Initialize a new swap as Bob (sells BTC, buys CYNC).
    /// Persists initial state. Parameters must match Alice's
    /// exactly (out-of-band agreement); a future coordinator-
    /// driven negotiation will exchange them automatically.
    Bob {
        /// Connect to Alice's listening endpoint (e.g.
        /// `alice.example.com:9000` for direct TCP, or her
        /// `.onion` for Tor). Recorded in the state file but not
        /// dialed here — the wallet integration drives the
        /// actual connection separately.
        #[arg(long)]
        connect: String,
        /// The swap ID Alice has shared with you out-of-band.
        #[arg(long)]
        swap_id: String,
        /// Amount of CYNC Alice is locking. Must match Alice's value.
        #[arg(long)]
        cync_amount: u64,
        /// Amount of satoshis Bob will lock. Must match Alice's value.
        #[arg(long)]
        btc_amount_sats: u64,
        #[arg(long, default_value = "alice-cync-addr-placeholder")]
        alice_cync_address: String,
        #[arg(long, default_value = "bob-btc-addr-placeholder")]
        bob_btc_address: String,
        /// State file. Defaults to `~/.coincync/swap.json`.
        #[arg(long)]
        state_file: Option<PathBuf>,
    },

    /// Initialize a new swap as Alice (wallet-friendly JSON output).
    /// Exposes a single subcommand for the wallet wizard to call —
    /// same underlying logic as `Alice`, but the output is a single
    /// JSON line on stdout including an `invite_hex` blob the wallet
    /// hands to Bob's wallet to complete the join (see [`WalletInitBob`]).
    WalletInitAlice {
        /// Listen endpoint Alice publishes (recorded only at this step;
        /// the wallet binds at coordinator-handshake time).
        #[arg(long)]
        listen: String,
        /// Amount of CYNC to lock, in atomic units.
        #[arg(long)]
        cync_amount: u64,
        /// Amount of satoshis Bob will lock in return.
        #[arg(long)]
        btc_amount_sats: u64,
        #[arg(long, default_value = "alice-cync-addr-placeholder")]
        alice_cync_address: String,
        #[arg(long, default_value = "bob-btc-addr-placeholder")]
        bob_btc_address: String,
        /// State file. Defaults to `~/.coincync/swap.json`.
        #[arg(long)]
        state_file: Option<PathBuf>,
    },

    /// Join a swap as Bob by consuming Alice's invite blob.
    /// Same underlying logic as `Bob`, but takes a single
    /// `--invite-hex` argument (the hex-encoded JSON blob Alice's
    /// wallet emitted from `WalletInitAlice`) and produces JSON output.
    /// All amounts and the connect URL are decoded from the invite,
    /// so the wallet doesn't need to ask the operator to retype them.
    WalletInitBob {
        /// Hex-encoded invite blob received from Alice's wallet.
        #[arg(long)]
        invite_hex: String,
        #[arg(long, default_value = "alice-cync-addr-placeholder")]
        alice_cync_address: String,
        #[arg(long, default_value = "bob-btc-addr-placeholder")]
        bob_btc_address: String,
        /// State file. Defaults to `~/.coincync/swap.json`.
        #[arg(long)]
        state_file: Option<PathBuf>,
    },

    /// Read a swap state file and emit its contents as JSON.
    /// Wallet-friendly counterpart to `Status`. Returns Ok with the
    /// JSON payload on stdout if the state file exists; returns an
    /// Err (the wallet treats this as "no active swap") if it does
    /// not. The payload is { swap_id, role, state, terminal,
    /// cync_amount, btc_amount_sats, cync_timeout_blocks,
    /// btc_timeout_blocks, alice_cync_address, bob_btc_address,
    /// legal_transitions: [..] }.
    WalletStatus {
        /// State file. Defaults to `~/.coincync/swap.json`.
        #[arg(long)]
        state_file: Option<PathBuf>,
    },

    /// Show status of an active swap (loaded from the on-disk
    /// state file).
    Status {
        /// State file. Defaults to `~/.coincync/swap.json`.
        #[arg(long)]
        state_file: Option<PathBuf>,
    },

    /// Cancel an active swap by transitioning it to `Aborted`.
    /// Use this PRE-LOCK only — once a lock tx has been broadcast,
    /// you must use the refund path (`refund-btc` / `refund-cync`)
    /// after the timeout fires, not `cancel`.
    Cancel {
        /// State file. Defaults to `~/.coincync/swap.json`.
        #[arg(long)]
        state_file: Option<PathBuf>,
    },

    /// Drive Alice's CYNC lock — the
    /// state-machine-aware bundled command. Pre-checks the swap is
    /// in `Negotiated` state with `role=Alice`, broadcasts the
    /// supplied signed CYNC lock tx via `coincync-node`, applies
    /// the `AliceLocksCync` transition, saves the state file.
    /// Prints the broadcast txid + new state.
    ///
    /// This is Alice's first on-chain move. Until this command
    /// returns successfully, no swap-related funds have moved on
    /// either chain; after it returns, Alice's CYNC sits behind
    /// the adaptor pubkey waiting for Bob's BTC lock.
    ///
    /// For step-by-step debugging or non-bundled flows, prefer the
    /// granular `cync-broadcast` subcommand combined with whatever
    /// CYNC-side transaction-construction tooling the wallet
    /// provides.
    LockCync {
        /// State file. Defaults to `~/.coincync/swap.json`.
        #[arg(long)]
        state_file: Option<PathBuf>,
        /// CoinCync network. Same set as `cync-broadcast`.
        #[arg(long)]
        network: String,
        /// `coincync-node` JSON-RPC endpoint.
        #[arg(long)]
        rpc_url: String,
        /// Optional API key (header `X-API-Key`), if the node
        /// requires it. Same shape as `cync-broadcast`.
        #[arg(long)]
        api_key: Option<String>,
        /// The signed CYNC lock tx as hex.
        #[arg(long)]
        signed_tx_hex: String,
    },

    /// Drive Bob's BTC lock — the
    /// state-machine-aware bundled command. Pre-checks the swap
    /// is in `AliceLocked` state with `role=Bob`, broadcasts the
    /// supplied signed lock tx via `bitcoind`, applies the
    /// `BobLocksBtc` transition, saves the state file. Prints
    /// the broadcast txid + new state.
    ///
    /// Inputs: same RPC flag set as `btc-broadcast` plus the
    /// signed tx hex (typically the output of `construct-btc-lock`
    /// piped through your wallet's signer).
    ///
    /// For step-by-step debugging or non-bundled flows, prefer
    /// the granular `construct-btc-lock` + `btc-broadcast`
    /// subcommands.
    LockBtc {
        /// State file. Defaults to `~/.coincync/swap.json`.
        #[arg(long)]
        state_file: Option<PathBuf>,
        /// Bitcoin network. Same set as `btc-broadcast`.
        #[arg(long)]
        network: String,
        /// bitcoind JSON-RPC endpoint.
        #[arg(long)]
        rpc_url: String,
        /// Optional RPC user. Coupled with `--rpc-pass`.
        #[arg(long)]
        rpc_user: Option<String>,
        /// Optional RPC pass. Coupled with `--rpc-user`.
        #[arg(long)]
        rpc_pass: Option<String>,
        /// The signed lock tx as hex. From the wallet after
        /// `construct-btc-lock` + signing.
        #[arg(long)]
        signed_tx_hex: String,
    },

    /// Drive Alice's BTC claim — the
    /// state-machine-aware bundled command. Pre-checks the swap is
    /// in `BobLocked` state with `role=Alice`, broadcasts the
    /// supplied signed claim tx via `bitcoind`, applies the
    /// `AliceClaimsBtc` transition, saves the state file. Prints
    /// the broadcast txid + new state.
    ///
    /// This is the moment that puts the adaptor secret into the
    /// public mempool: Alice's claim signature, once on-chain,
    /// lets Bob compute `recover-secret-from-btc-sig` and then
    /// `claim-cync`. For step-by-step debugging or non-bundled
    /// flows, prefer the granular `construct-btc-claim` +
    /// `btc-broadcast` subcommands.
    ClaimBtc {
        /// State file. Defaults to `~/.coincync/swap.json`.
        #[arg(long)]
        state_file: Option<PathBuf>,
        /// Bitcoin network. Same set as `btc-broadcast`.
        #[arg(long)]
        network: String,
        /// bitcoind JSON-RPC endpoint.
        #[arg(long)]
        rpc_url: String,
        /// Optional RPC user. Coupled with `--rpc-pass`.
        #[arg(long)]
        rpc_user: Option<String>,
        /// Optional RPC pass. Coupled with `--rpc-user`.
        #[arg(long)]
        rpc_pass: Option<String>,
        /// Lock transaction's txid, 64-char lowercase hex.
        #[arg(long)]
        lock_txid: String,
        /// Lock UTXO's output index.
        #[arg(long, default_value_t = 0)]
        lock_vout: u32,
        /// 32-byte x-only Taproot internal key committed by the lock.
        #[arg(long)]
        lock_internal_key: String,
        /// Alice's negotiated BTC claim destination.
        #[arg(long)]
        dest_address: String,
        /// Claim fee in satoshis.
        #[arg(long, default_value_t = 1000)]
        fee_sats: u64,
        /// Bob's refund-branch x-only pubkey, when the lock has a
        /// script-path refund branch.
        #[arg(long)]
        refund_bob_pubkey: Option<String>,
        /// Refund CSV delay. Required iff `--refund-bob-pubkey` is set.
        #[arg(long)]
        refund_csv_blocks: Option<u16>,
        /// The signed claim tx as hex. From the wallet after
        /// `construct-btc-claim` + `decrypt-btc-adaptor` (which
        /// produces the BIP-340 signature) + witness assembly.
        #[arg(long)]
        signed_tx_hex: String,
    },

    /// Drive Bob's BTC refund — the
    /// state-machine-aware bundled command. Pre-checks the swap is
    /// in `BobLocked` state with `role=Bob`, broadcasts the
    /// supplied signed BTC refund tx via `bitcoind`, applies the
    /// `BobRefunds` transition, saves the state file. Prints the
    /// broadcast txid + new state (terminal: `Refunded`).
    ///
    /// **Timeout note**: the BTC refund tx commits to a CSV-delayed
    /// script-path output. Broadcasting before `btc_timeout_blocks`
    /// have passed since the lock confirmation will be rejected by
    /// the chain (non-final tx); the orchestration layer does NOT
    /// double-check this — bitcoind is the authority. The CIP-001
    /// timeout-safety invariant guarantees CYNC's timeout outlasts
    /// BTC's by a 20% margin, so Bob's refund opens BEFORE Alice's
    /// refund would expire her ability to retrieve CYNC.
    ///
    /// For step-by-step debugging or non-bundled flows, prefer the
    /// granular `construct-btc-refund` + `btc-broadcast`
    /// subcommands.
    RefundBtc {
        /// State file. Defaults to `~/.coincync/swap.json`.
        #[arg(long)]
        state_file: Option<PathBuf>,
        /// Bitcoin network. Same set as `btc-broadcast`.
        #[arg(long)]
        network: String,
        /// bitcoind JSON-RPC endpoint.
        #[arg(long)]
        rpc_url: String,
        /// Optional RPC user. Coupled with `--rpc-pass`.
        #[arg(long)]
        rpc_user: Option<String>,
        /// Optional RPC pass. Coupled with `--rpc-user`.
        #[arg(long)]
        rpc_pass: Option<String>,
        /// The signed refund tx as hex. From the wallet after
        /// `construct-btc-refund` + signing under Bob's refund key.
        #[arg(long)]
        signed_tx_hex: String,
    },

    /// Drive Alice's CYNC refund —
    /// the state-machine-aware bundled command. Pre-checks the
    /// swap is in `AliceLocked` OR `BobLocked` state with
    /// `role=Alice` (refunds are legal from BOTH non-terminal lock
    /// states for Alice — see CIP-001 §"Refund Paths"), broadcasts
    /// the supplied signed CYNC refund tx via `coincync-node`,
    /// applies the `AliceRefunds` transition, saves the state file.
    /// Prints the broadcast txid + new state (terminal: `Refunded`).
    ///
    /// **Timeout note**: Alice's refund tx commits to a CSV-delayed
    /// output (analogous to BTC's). Broadcasting before
    /// `cync_timeout_blocks` have passed since the CYNC lock
    /// confirmation will be rejected by `coincync-node` (non-final
    /// tx). The orchestration layer does NOT double-check this —
    /// the node is the authority.
    ///
    /// For step-by-step debugging or non-bundled flows, prefer the
    /// granular `cync-broadcast` subcommand.
    RefundCync {
        /// State file. Defaults to `~/.coincync/swap.json`.
        #[arg(long)]
        state_file: Option<PathBuf>,
        /// CoinCync network. Same set as `cync-broadcast`.
        #[arg(long)]
        network: String,
        /// `coincync-node` JSON-RPC endpoint.
        #[arg(long)]
        rpc_url: String,
        /// Optional API key (header `X-API-Key`).
        #[arg(long)]
        api_key: Option<String>,
        /// The signed CYNC refund tx as hex.
        #[arg(long)]
        signed_tx_hex: String,
    },

    /// Drive Bob's CYNC claim — the
    /// state-machine-aware bundled command. Pre-checks the swap is
    /// in `SecretRevealed` state with `role=Bob`, broadcasts the
    /// supplied signed CYNC claim tx via `coincync-node`, applies
    /// the `BobClaimsCync` transition, saves the state file.
    /// Prints the broadcast txid + new state.
    ///
    /// This is the swap's final on-chain move: after Alice's
    /// `claim-btc` revealed the adaptor secret, Bob runs
    /// `recover-secret-from-btc-sig`, derives the spender secret
    /// via `derive-cync-spender-secret`, signs the CYNC claim, and
    /// broadcasts it here. The transition advances Bob's local
    /// state to `Completed` — the swap's only success terminal.
    ///
    /// For step-by-step debugging or non-bundled flows, prefer the
    /// granular `cync-broadcast` subcommand.
    ClaimCync {
        /// State file. Defaults to `~/.coincync/swap.json`.
        #[arg(long)]
        state_file: Option<PathBuf>,
        /// CoinCync network. Same set as `cync-broadcast`.
        #[arg(long)]
        network: String,
        /// `coincync-node` JSON-RPC endpoint.
        #[arg(long)]
        rpc_url: String,
        /// Optional API key (header `X-API-Key`), if the node
        /// requires it. Same shape as `cync-broadcast`.
        #[arg(long)]
        api_key: Option<String>,
        /// The signed CYNC claim tx as hex.
        #[arg(long)]
        signed_tx_hex: String,
    },

    /// Print the version of CIP-001 this skeleton tracks.
    DesignVersion,

    /// Run a fast cryptographic
    /// self-test exercising every primitive in the swap crate.
    /// Prints PASS/FAIL + elapsed per check, exits 0 on all-green
    /// and 1 on any failure. Use after installing the binary to
    /// confirm the build is functional + the host's CPU works for
    /// the primitives.
    ///
    /// Default run: ~50 ms total (DLEQ, BTC adaptor round-trip,
    /// CYNC adaptor round-trip, CYNC key-derivation round-trip).
    /// With `--features strict-dleq`: adds a ~500 ms strict-DLEQ
    /// prove + verify cycle.
    ///
    /// Does NOT exercise the transport layer (which needs sockets);
    /// for that, run the dual-testnet smoke harness or one of the
    /// coordinator integration tests.
    Selftest,

    /// Generate a fresh 32-byte
    /// Curve25519 static key for the Noise XX coordinator transport
    /// (Bob's `connect_noise` / Alice's `listen_noise` constructors
    /// take this). Writes the 32 raw bytes to `--out` (or stdout if
    /// `--out` is omitted), and prints the derived 64-char-hex
    /// public-key fingerprint to stderr for out-of-band exchange.
    ///
    /// Replaces the openssl / PowerShell incantations in
    /// `docs/cyncswap-transport-setup.md` §2.1. Use this as the
    /// operator's standard keygen step:
    ///
    ///   cyncswap noise-keygen --out ~/.coincync/swap-noise-static.bin
    ///   chmod 0400 ~/.coincync/swap-noise-static.bin
    ///
    /// Re-deriving the public key later (e.g., to confirm a stored
    /// private still matches the published fingerprint): use
    /// `cyncswap noise-pubkey --secret-file <path>`.
    NoiseKeygen {
        /// Output path for the 32 raw private-key bytes. Omit to
        /// write to stdout (suitable for piping into another tool;
        /// the public-key fingerprint still goes to stderr).
        #[arg(long)]
        out: Option<PathBuf>,
        /// I-understand-this-is-a-secret guard. Required when `--out`
        /// is omitted (i.e. the secret would otherwise be printed to
        /// the terminal). Forces the operator to acknowledge they
        /// know what they're doing.
        #[arg(long)]
        i_understand_this_is_a_secret: bool,
    },

    /// Apply an OBSERVATION
    /// transition to the persisted swap state — the operator's
    /// stand-in for what a chain watcher would do automatically.
    ///
    /// Only observation transitions are exposed here. Action
    /// transitions (`AliceLocksCync`, `BobLocksBtc`, etc.) are
    /// reserved for the bundled `lock-cync` / `lock-btc` /
    /// `claim-{btc,cync}` / `refund-{btc,cync}` subcommands, which
    /// broadcast-then-transition atomically — exposing them raw
    /// would let an operator mark a swap as "Bob locked" without
    /// actually broadcasting Bob's BTC tx, drifting the local view
    /// out of sync with the chain.
    ///
    /// Use this when, in production, your chain watcher would have
    /// already advanced state: e.g., during a manual recovery, or
    /// in the dual-testnet smoke harness where the operator drives
    /// each chain manually.
    ///
    /// For `Abort`, use the dedicated `cancel` subcommand.
    Transition {
        /// State file. Defaults to `~/.coincync/swap.json`.
        #[arg(long)]
        state_file: Option<PathBuf>,
        /// Which observation transition to apply.
        #[arg(long, value_enum)]
        kind: TransitionKind,
    },

    /// Derive the Curve25519 public
    /// key (X25519 / Noise XX fingerprint) for a stored 32-byte
    /// private key. Use this to:
    ///
    /// - Verify a stored private still produces the published
    ///   fingerprint (`derived == published`).
    /// - Print the fingerprint for out-of-band exchange after
    ///   `noise-keygen` (the fingerprint goes to stderr at keygen
    ///   time, but if you've lost that output, re-derive here).
    ///
    /// The derivation follows RFC 7748 X25519 clamping — matches
    /// snow's internal derivation byte-for-byte, so the output is
    /// exactly what the peer's `NoiseTransport::remote_static()`
    /// will report after a successful XX handshake.
    NoisePubkey {
        /// Path to the 32-byte private-key file (as written by
        /// `noise-keygen --out`). Mutually exclusive with `--secret-hex`.
        #[arg(long)]
        secret_file: Option<PathBuf>,
        /// 64-char hex of the 32-byte private. Mutually exclusive with
        /// `--secret-file`. Use this when you're already shell-piping
        /// the key around and don't want a file round-trip.
        #[arg(long)]
        secret_hex: Option<String>,
    },

    /// Construct an UNSIGNED Bitcoin
    /// P2TR lock transaction from the supplied parameters.
    ///
    /// Mirrors the `derive-cync-*` utility pattern: takes all
    /// construction inputs as flags, calls
    /// [`coincync_swap::btc::build_lock_tx`], prints the
    /// consensus-encoded transaction bytes as hex on stdout. No
    /// state-file involvement; the caller's wallet signs each
    /// input separately and broadcasts via `bitcoind`'s
    /// `sendrawtransaction` (or `cyncswap btc-broadcast` once
    /// that subcommand lands).
    ///
    /// Single-UTXO surface; multi-UTXO support is a follow-up.
    ConstructBtcLock {
        /// Bitcoin network: `mainnet`, `testnet`, `regtest`, or `signet`.
        #[arg(long)]
        network: String,
        /// Funding UTXO's transaction id, 64-char lowercase hex.
        #[arg(long)]
        funding_txid: String,
        /// Funding UTXO's output index.
        #[arg(long)]
        funding_vout: u32,
        /// Funding UTXO's value in satoshis. Must cover
        /// `lock_amount_sats + fee_sats`.
        #[arg(long)]
        funding_value_sats: u64,
        /// Amount to lock into the P2TR output, in satoshis.
        /// Above the 330-sat dust threshold.
        #[arg(long)]
        lock_amount_sats: u64,
        /// 32-byte x-only Taproot internal key (the adaptor-bound
        /// spending key Alice will claim against), hex.
        #[arg(long)]
        adaptor_internal_key: String,
        /// Bech32m change address (Bob's). Must parse for `network`.
        /// Change after fee must clear the 330-sat dust threshold.
        #[arg(long)]
        change_address: String,
        /// Absolute fee in satoshis. Default 1000.
        #[arg(long, default_value_t = 1000)]
        fee_sats: u64,
        /// `nLockTime` value. Default 0 (immediate broadcast).
        #[arg(long, default_value_t = 0)]
        locktime: u32,
        /// **Optional refund branch.** Bob's 32-byte x-only refund
        /// pubkey. If set, the lock tx gets a single-leaf script
        /// tree with a CSV refund script; --refund-csv-blocks
        /// is then required.
        #[arg(long)]
        refund_bob_pubkey: Option<String>,
        /// CSV timeout in blocks for the refund branch (BIP-68
        /// blocks-relative). Required iff --refund-bob-pubkey is
        /// set. Capped at u16::MAX by BIP-68.
        #[arg(long)]
        refund_csv_blocks: Option<u16>,
    },

    /// Verify a BTC Schnorr adaptor
    /// pre-signature.
    ///
    /// Alice runs this on the pre-sig Bob sent her, BEFORE
    /// broadcasting her CYNC lock — confirms Bob's pre-sig is
    /// valid against the agreed-upon claim sighash + the
    /// adaptor point Alice committed to. If verify rejects,
    /// Alice aborts the swap without committing funds.
    ///
    /// Silent on success (exit 0, no output); clear error on
    /// failure.
    VerifyPreSigBtc {
        /// Pre-sig's R nonce-commitment: 33-byte compressed
        /// secp256k1 point, 66-char hex.
        #[arg(long)]
        pre_sig_r_point: String,
        /// Pre-sig's s_pre scalar, 64-char hex (big-endian
        /// secp256k1).
        #[arg(long)]
        pre_sig_s: String,
        /// Signer's x-only pubkey (32 bytes — the BIP-340
        /// form, what `create-pre-sig-btc`'s JSON output's
        /// `signer_x` field returns).
        #[arg(long)]
        signer_x: String,
        /// Adaptor point `T = t·G_btc`, 33-byte compressed
        /// secp256k1.
        #[arg(long)]
        adaptor_point: String,
        /// The 32-byte message the pre-sig commits to — typically
        /// Alice's claim sighash from `claim-sighash-btc`.
        #[arg(long)]
        msg: String,
    },

    /// Verify a CYNC Schnorr
    /// adaptor pre-signature (Ristretto255).
    ///
    /// Symmetric to `verify-pre-sig-btc`. The signer pubkey is
    /// the 32-byte compressed Ristretto point (no x-only
    /// convention on Ristretto — the field is `signer_pub` in
    /// `create-pre-sig-cync`'s output).
    VerifyPreSigCync {
        /// Pre-sig R-point: 32-byte compressed Ristretto255.
        #[arg(long)]
        pre_sig_r_point: String,
        /// Pre-sig s_pre scalar: 32-byte Ristretto canonical
        /// (little-endian).
        #[arg(long)]
        pre_sig_s: String,
        /// Signer's 32-byte compressed Ristretto255 pubkey
        /// (the `signer_pub` field from `create-pre-sig-cync`).
        #[arg(long)]
        signer_pub: String,
        /// Adaptor point `T = t·G_cync`, 32-byte compressed
        /// Ristretto255.
        #[arg(long)]
        adaptor_point: String,
        /// 32-byte message the pre-sig commits to.
        #[arg(long)]
        msg: String,
    },

    /// Compute the BTC adaptor
    /// point `T = t·G_btc` from an adaptor secret.
    ///
    /// Pure secp256k1 scalar multiplication. Output is the
    /// 33-byte compressed pubkey as hex — the form
    /// `prove-dleq`'s `--btc-pub` accepts, and what Alice
    /// publishes to Bob during negotiation.
    ///
    /// **Default input encoding is Ristretto-LE** (the swap
    /// protocol's canonical form, matching every other
    /// `--adaptor-secret` flag in this CLI). Pass `--encoding
    /// secp256k1` if you have the secret in BTC-native
    /// big-endian form (e.g., straight from
    /// `recover-secret-from-btc-sig`'s output).
    BtcAdaptorPointFromSecret {
        /// Adaptor secret `t`, 32-byte hex. Default encoding is
        /// Ristretto-LE (the swap protocol's canonical form).
        /// Set `--encoding secp256k1` if your bytes are in
        /// secp256k1 big-endian.
        #[arg(long)]
        adaptor_secret: String,
        /// Encoding of `--adaptor-secret`. Default `ristretto`
        /// matches every other CLI subcommand; `secp256k1`
        /// matches the output of `recover-secret-from-btc-sig`.
        #[arg(long, value_enum, default_value_t = AdaptorSecretEncoding::Ristretto)]
        encoding: AdaptorSecretEncoding,
    },

    /// Compute the CYNC adaptor
    /// point `T = t·G_cync` from an adaptor secret.
    ///
    /// Pure Ristretto255 scalar multiplication. Output is the
    /// 32-byte compressed point as hex — the form
    /// `prove-dleq`'s `--cync-pub` accepts.
    CyncAdaptorPointFromSecret {
        /// Adaptor secret `t`, 32-byte hex in Ristretto canonical
        /// (little-endian) form. Must satisfy `t < ℓ` (the
        /// stricter Ristretto field order — checked at parse).
        #[arg(long)]
        adaptor_secret: String,
    },

    /// Produce a cross-curve
    /// discrete-log-equality proof binding the BTC adaptor point
    /// to the CYNC adaptor point through the same scalar `t`.
    ///
    /// Run by the participant who holds `t` (typically Alice,
    /// during the negotiation phase). The proof goes to the
    /// counterparty who runs `verify-dleq` before committing
    /// any funds.
    ///
    /// Output is single-line JSON with the four proof fields:
    /// `{"a_btc": "<hex>", "a_cync": "<hex>", "s_btc": "<hex>", "s_cync": "<hex>"}`
    /// — feed each field into `verify-dleq`'s flags.
    ///
    /// **Soundness caveat reminder** (also in CIP-001 §4.x): the
    /// shipped construction is dual-response Schoenmakers — it
    /// proves knowledge of discrete logs on both curves with a
    /// shared nonce commitment, but does NOT directly prove
    /// the two discrete logs are the *same number*. The
    /// operational binding (Alice's BTC claim reveals `t`; Bob's
    /// CYNC spend secret = `bob + t` either opens the lock or
    /// fails) closes that gap in the swap protocol.
    ProveDleq {
        /// Adaptor secret `t`, 32-byte hex in Ristretto canonical
        /// (little-endian) form. Must satisfy `t < ℓ` (the
        /// stricter Ristretto field order — checked at parse).
        #[arg(long)]
        adaptor_secret: String,
        /// `T_btc = t·G_btc`, 33-byte compressed secp256k1 hex.
        #[arg(long)]
        btc_pub: String,
        /// `T_cync = t·G_cync`, 32-byte compressed Ristretto255 hex.
        #[arg(long)]
        cync_pub: String,
        /// 32-byte fresh nonce in Ristretto canonical form.
        /// MUST be fresh per proof; reuse breaks soundness.
        #[arg(long)]
        nonce: String,
    },

    /// Verify a cross-curve DL
    /// equality proof.
    ///
    /// Run by the participant who receives a proof from the
    /// counterparty during negotiation. Silent exit-0 on success;
    /// exit-non-zero with a clear error on failure.
    ///
    /// All four proof fields come from `prove-dleq`'s JSON output;
    /// pubkeys come from the negotiation handshake.
    VerifyDleq {
        /// `T_btc`, 33-byte compressed secp256k1 hex.
        #[arg(long)]
        btc_pub: String,
        /// `T_cync`, 32-byte compressed Ristretto255 hex.
        #[arg(long)]
        cync_pub: String,
        /// **Recommended.** Single-argument JSON form — pass the
        /// raw output of `prove-dleq` (which is a single-line JSON
        /// object with `a_btc`/`a_cync`/`s_btc`/`s_cync` fields).
        /// Mutually exclusive with the four `--proof-*` flags.
        ///
        /// Use this for shell-piping:
        ///
        /// ```text
        /// PROOF=$(cyncswap prove-dleq ...)
        /// cyncswap verify-dleq --proof-json "$PROOF" --btc-pub ... --cync-pub ...
        /// ```
        #[arg(long, conflicts_with_all = ["proof_a_btc", "proof_a_cync", "proof_s_btc", "proof_s_cync"])]
        proof_json: Option<String>,
        /// Proof field `a_btc`, 33-byte compressed secp256k1 hex.
        /// Use with the other three `--proof-*` flags as an
        /// alternative to `--proof-json` (e.g., when fields come
        /// from different sources).
        #[arg(long, required_unless_present = "proof_json")]
        proof_a_btc: Option<String>,
        /// Proof field `a_cync`, 32-byte compressed Ristretto255 hex.
        #[arg(long, required_unless_present = "proof_json")]
        proof_a_cync: Option<String>,
        /// Proof field `s_btc`, 32-byte big-endian secp256k1 hex.
        #[arg(long, required_unless_present = "proof_json")]
        proof_s_btc: Option<String>,
        /// Proof field `s_cync`, 32-byte Ristretto canonical hex.
        #[arg(long, required_unless_present = "proof_json")]
        proof_s_cync: Option<String>,
    },

    /// Flip the byte order of an
    /// adaptor secret between secp256k1 (big-endian) and
    /// Ristretto255 (little-endian) representations.
    ///
    /// Closes the secret-pipeline gap noted in the help text of
    /// `recover-secret-from-btc-sig` — its output is BE (the BTC
    /// curve's convention), but `derive-cync-spender-secret`
    /// expects LE (the CYNC curve's convention). Pipe through
    /// this subcommand to bridge:
    ///
    /// ```text
    /// SECRET_BE=$(cyncswap recover-secret-from-btc-sig ... --i-understand-this-is-a-secret)
    /// SECRET_LE=$(cyncswap adaptor-secret-flip-endian \
    ///               --secret-hex $SECRET_BE --from secp256k1 \
    ///               --i-understand-this-is-a-secret)
    /// cyncswap derive-cync-spender-secret --adaptor-secret $SECRET_LE ...
    /// ```
    ///
    /// **Security note:** prints a secret to stdout.
    AdaptorSecretFlipEndian {
        /// The 32-byte secret hex to flip.
        #[arg(long)]
        secret_hex: String,
        /// The encoding the input is currently in. Output will be
        /// the opposite encoding (the bytes get reversed). Pass
        /// `secp256k1` if the input came from a BTC-side helper
        /// (`recover-secret-from-btc-sig`); pass `ristretto` if it
        /// came from a CYNC-side helper.
        #[arg(long)]
        from: String,
        #[arg(long)]
        i_understand_this_is_a_secret: bool,
    },

    /// Create a Schnorr adaptor
    /// pre-signature on the CYNC side (Ristretto255).
    ///
    /// Symmetric to `create-pre-sig-btc` but on Ristretto255 —
    /// no parity dance needed (prime-order group). Output is the
    /// same JSON shape: `{"r_point": "<hex>", "s_pre": "<hex>",
    /// "signer_pub": "<hex>"}` (32-byte compressed Ristretto for
    /// the points).
    CreatePreSigCync {
        /// Signer's 32-byte secret in Ristretto canonical
        /// (little-endian) form.
        #[arg(long)]
        signer_secret: String,
        /// 32-byte message (sighash equivalent for the CYNC tx
        /// being signed).
        #[arg(long)]
        msg: String,
        /// 32-byte compressed Ristretto255 adaptor point
        /// `T = t·G_cync`.
        #[arg(long)]
        adaptor_point: String,
        /// 32 random bytes for the nonce. MUST be fresh per call;
        /// reuse leaks the signing key.
        #[arg(long)]
        nonce: String,
    },

    /// Decrypt a CYNC-side Schnorr
    /// adaptor pre-signature using the adaptor secret. Outputs
    /// the 64-byte final signature (32-byte `R + T` || 32-byte
    /// `s`) — Ed25519/CLSAG-shaped.
    DecryptCyncAdaptor {
        /// Pre-sig R-point: 32-byte compressed Ristretto255, hex.
        #[arg(long)]
        pre_sig_r_point: String,
        /// Pre-sig s_pre scalar: 32-byte Ristretto canonical
        /// (little-endian) form, hex.
        #[arg(long)]
        pre_sig_s: String,
        /// Adaptor secret in Ristretto canonical (little-endian)
        /// form. If you have a BTC-side recovered secret, pipe
        /// through `adaptor-secret-flip-endian` first.
        #[arg(long)]
        adaptor_secret: String,
        /// 32-byte compressed Ristretto255 adaptor point `T`.
        #[arg(long)]
        adaptor_point: String,
    },

    /// Recover the adaptor secret
    /// from a CYNC pre-sig + the published final signature.
    /// Symmetric to `recover-secret-from-btc-sig`.
    ///
    /// **Security note:** prints a secret to stdout. Output is in
    /// Ristretto canonical (little-endian) form.
    RecoverSecretFromCyncSig {
        /// Pre-sig s_pre scalar: 32-byte Ristretto canonical, hex.
        #[arg(long)]
        pre_sig_s: String,
        /// The 64-byte final signature Alice published on the
        /// CYNC chain (32-byte `R + T` || 32-byte `s`), hex.
        #[arg(long)]
        final_sig: String,
        #[arg(long)]
        i_understand_this_is_a_secret: bool,
    },

    /// Broadcast a signed CoinCync
    /// transaction via `coincync-node`'s JSON-RPC.
    ///
    /// Symmetric to `btc-broadcast`. The tx hex is borsh-encoded
    /// (the format `send_raw_transaction` accepts on the CYNC
    /// side — *not* Bitcoin consensus encoding). Prints the
    /// resulting CYNC txid (lowercase hex) on stdout.
    ///
    /// Auth: optional bearer token via `--api-key`. CYNC RPC
    /// uses `Authorization: Bearer <token>` rather than HTTP
    /// basic-auth.
    CyncBroadcast {
        /// CYNC network: `mainnet`, `testnet`, or `regtest`.
        #[arg(long)]
        network: String,
        /// coincync-node JSON-RPC endpoint. Typically
        /// `http://127.0.0.1:28085` (testnet RPC default).
        #[arg(long)]
        rpc_url: String,
        /// Optional bearer-token API key. Required only if the
        /// node has RPC auth enabled.
        #[arg(long)]
        api_key: Option<String>,
        /// Borsh-encoded transaction as hex.
        #[arg(long)]
        tx_hex: String,
    },

    /// Wait for a CYNC transaction
    /// to reach a confirmation depth on the chain `coincync-node`
    /// is following.
    ///
    /// Polls `get_transaction` every 10 seconds and computes
    /// confirmations as `tip - block_height + 1`. Silent on
    /// success; error message on timeout.
    CyncWatch {
        #[arg(long)]
        network: String,
        #[arg(long)]
        rpc_url: String,
        #[arg(long)]
        api_key: Option<String>,
        /// Transaction id to watch, 64-char lowercase hex. CYNC
        /// RPC accepts the natural byte order (no `0x` prefix
        /// required; the parser tolerates one if present).
        #[arg(long)]
        txid: String,
        #[arg(long, default_value_t = 1)]
        confirmations: u32,
        /// Polling timeout in seconds. Default 300 (5 min — fine
        /// for testnet; production callers waiting on mainnet
        /// confirmation depth should bump to 3600+).
        #[arg(long, default_value_t = 300)]
        timeout_secs: u64,
    },

    /// Compute the BIP-341 key-path
    /// sighash for a hypothetical claim transaction.
    ///
    /// Closes the usability gap in the pre-sig pipeline: Bob needs
    /// the sighash to feed into `create-pre-sig-btc --msg <hex>`,
    /// but the sighash itself comes from the not-yet-signed claim
    /// tx's structure. This subcommand computes it without
    /// requiring a (possibly fake) signature.
    ///
    /// Same flag set as `construct-btc-claim` minus
    /// `--claim-signature`. The refund-branch flags must match
    /// what the lock was built with — the sighash depends on the
    /// (possibly tweaked) output key.
    ClaimSighashBtc {
        #[arg(long)]
        network: String,
        #[arg(long)]
        lock_txid: String,
        #[arg(long, default_value_t = 0)]
        lock_vout: u32,
        #[arg(long)]
        lock_value_sats: u64,
        #[arg(long)]
        lock_internal_key: String,
        #[arg(long)]
        dest_address: String,
        #[arg(long, default_value_t = 1000)]
        fee_sats: u64,
        #[arg(long)]
        refund_bob_pubkey: Option<String>,
        #[arg(long)]
        refund_csv_blocks: Option<u16>,
    },

    /// Compute the BIP-341
    /// script-path sighash for a hypothetical refund transaction.
    ///
    /// What Bob signs over when producing his refund signature.
    /// Same flag set as `construct-btc-refund` minus
    /// `--refund-signature`.
    RefundSighashBtc {
        #[arg(long)]
        network: String,
        #[arg(long)]
        lock_txid: String,
        #[arg(long, default_value_t = 0)]
        lock_vout: u32,
        #[arg(long)]
        lock_value_sats: u64,
        #[arg(long)]
        lock_internal_key: String,
        #[arg(long)]
        refund_bob_pubkey: String,
        #[arg(long)]
        refund_csv_blocks: u16,
        #[arg(long)]
        dest_address: String,
        #[arg(long, default_value_t = 1000)]
        fee_sats: u64,
    },

    /// Create a BIP-340-conformant
    /// Schnorr adaptor pre-signature.
    ///
    /// This is what Bob runs during negotiation, after Alice has
    /// committed to her claim transaction's structure (so the
    /// sighash is known). The output goes back to Alice
    /// out-of-band; she'll later run `decrypt-btc-adaptor` to
    /// turn it into a broadcastable signature.
    ///
    /// Handles both BIP-340 parity adjustments internally
    /// (signer-key y-parity + nonce retry until `R+T` has even
    /// y). Caller supplies `aux_rand` as 32 fresh random bytes;
    /// production callers MUST source from a CSPRNG and never
    /// reuse per `(seckey, msg)` pair.
    ///
    /// Wraps [`coincync_swap::adaptor::create_pre_sig_bip340`].
    /// Output is a single line of JSON:
    /// `{"r_point": "<hex>", "s_pre": "<hex>", "signer_x": "<hex>"}` —
    /// `jq -r .s_pre`-style consumption.
    CreatePreSigBtc {
        /// Bob's signing secret key, 32-byte hex (secp256k1
        /// big-endian — the form `SecretKey::secret_bytes()`
        /// returns).
        #[arg(long)]
        signer_secret: String,
        /// 32-byte message to sign — typically Alice's BIP-341
        /// claim sighash, produced by some prior step (e.g.
        /// `cyncswap claim-sighash-btc` once that subcommand
        /// lands; until then the caller computes it externally
        /// or extracts from `construct-btc-claim`'s intermediate
        /// state).
        #[arg(long)]
        msg: String,
        /// 33-byte compressed secp256k1 adaptor point
        /// `T = t·G_btc`, hex.
        #[arg(long)]
        adaptor_point: String,
        /// 32 random bytes for nonce derivation. Each call MUST
        /// receive fresh bytes — reuse leaks the signing key
        /// (textbook Schnorr nonce-reuse attack). Production
        /// callers source from `OsRng`; tests can use a fixed
        /// value for determinism.
        #[arg(long)]
        aux_rand: String,
    },

    /// Decrypt a Schnorr adaptor
    /// pre-signature into a complete BIP-340 signature using the
    /// adaptor secret.
    ///
    /// This is what Alice runs after the swap negotiation completes
    /// and she's received Bob's adaptor pre-sig. The output is the
    /// 64-byte signature that goes into the BTC claim tx's
    /// witness — `cyncswap construct-btc-claim --claim-signature
    /// $(cyncswap decrypt-btc-adaptor ...) ...`.
    ///
    /// Wraps [`coincync_swap::adaptor::decrypt_btc_adaptor`].
    /// Pure local arithmetic; no RPC traffic, no state-file
    /// involvement.
    DecryptBtcAdaptor {
        /// Pre-sig's R nonce-commitment: 33-byte compressed
        /// secp256k1 point, 66-char hex.
        #[arg(long)]
        pre_sig_r_point: String,
        /// Pre-sig's s_pre scalar, 64-char hex (big-endian
        /// secp256k1 secret-key form).
        #[arg(long)]
        pre_sig_s: String,
        /// Alice's adaptor secret `t`, 64-char hex (secp256k1
        /// big-endian — this is the `Secp256k1BigEndian` form
        /// `AdaptorSecret` uses internally for BTC operations).
        #[arg(long)]
        adaptor_secret: String,
        /// Adaptor point `T = t·G_btc`, 66-char hex (33-byte
        /// compressed secp256k1).
        #[arg(long)]
        adaptor_point: String,
    },

    /// Recover the adaptor secret
    /// from a pre-sig + the published final signature.
    ///
    /// This is what Bob runs after watching Alice publish her BTC
    /// claim tx on-chain. The extracted secret is the cross-chain
    /// link: with `t` recovered, Bob can derive his effective CYNC
    /// spend secret via `derive-cync-spender-secret` and claim
    /// Alice's CYNC lock.
    ///
    /// Wraps [`coincync_swap::adaptor::recover_secret_from_btc_sig`].
    /// Pure local arithmetic.
    ///
    /// **Security note:** prints a secret to stdout — pipe directly
    /// to the next pipeline stage, do not log.
    RecoverSecretFromBtcSig {
        /// Pre-sig's s_pre scalar, 64-char hex (the same value
        /// that was passed to `decrypt-btc-adaptor`'s
        /// `--pre-sig-s`). The R-point isn't needed for
        /// recovery — the math is `t = s_real - s_pre`.
        #[arg(long)]
        pre_sig_s: String,
        /// The 64-byte final BIP-340 signature Alice published on
        /// the BTC chain, 128-char hex. Format: `R_x (32) || s
        /// (32)`. Only the trailing `s` half is used; the R_x
        /// half is implicitly trusted by being on-chain.
        #[arg(long)]
        final_sig: String,
        /// Acknowledge that the output is a secret printed to
        /// stdout. Same posture as `derive-cync-spender-secret`.
        #[arg(long)]
        i_understand_this_is_a_secret: bool,
    },

    /// Broadcast a signed Bitcoin
    /// transaction via `bitcoind`'s JSON-RPC.
    ///
    /// Pipes a `construct-btc-*` output through to bitcoind in
    /// one command: `cyncswap construct-btc-lock ... | xargs cyncswap btc-broadcast ...`.
    /// Prints the resulting txid (lowercase hex) on stdout.
    ///
    /// Auth: if `--rpc-user` is set, `--rpc-pass` is required and
    /// HTTP basic-auth is used. Bitcoin Core's `.cookie` file
    /// contents (after the `:` separator) work as the password
    /// against `__cookie__` as the user.
    BtcBroadcast {
        /// Bitcoin network. Used only for sanity-checking the URL
        /// shape via `BtcConfig`; doesn't alter the broadcast.
        #[arg(long)]
        network: String,
        /// bitcoind JSON-RPC endpoint. Typically
        /// `http://127.0.0.1:8332` (mainnet) / `:18332` (testnet) /
        /// `:18443` (regtest).
        #[arg(long)]
        rpc_url: String,
        /// Optional RPC username. Required iff `--rpc-pass` is set.
        #[arg(long)]
        rpc_user: Option<String>,
        /// Optional RPC password. Required iff `--rpc-user` is set.
        #[arg(long)]
        rpc_pass: Option<String>,
        /// Signed transaction as hex. Hand the output of
        /// `construct-btc-*` to your wallet for signing, then
        /// pipe the result here.
        #[arg(long)]
        tx_hex: String,
    },

    /// Wait for a Bitcoin
    /// transaction to reach a confirmation depth on the chain
    /// `bitcoind` is following.
    ///
    /// Polls `getrawtransaction` every 10 seconds. Returns 0 once
    /// the configured confirmation depth is reached; returns
    /// non-zero on timeout. Prints nothing on success (silent so
    /// scripts can chain on `&&`); prints the error reason on
    /// failure.
    BtcWatch {
        /// Bitcoin network (sanity-check only; see `btc-broadcast`).
        #[arg(long)]
        network: String,
        /// bitcoind JSON-RPC endpoint.
        #[arg(long)]
        rpc_url: String,
        /// Optional RPC username. Required iff `--rpc-pass` is set.
        #[arg(long)]
        rpc_user: Option<String>,
        /// Optional RPC password. Required iff `--rpc-user` is set.
        #[arg(long)]
        rpc_pass: Option<String>,
        /// Transaction id to watch, 64-char lowercase hex (the
        /// form bitcoind's RPC uses — already byte-reversed
        /// from internal hash order).
        #[arg(long)]
        txid: String,
        /// Confirmation depth to wait for. 1 = "included in any
        /// block"; 6 = the conventional finality threshold for
        /// ordinary-value Bitcoin payments.
        #[arg(long, default_value_t = 1)]
        confirmations: u32,
        /// Polling timeout in seconds. Default 300 (5 minutes —
        /// fine for regtest / fast-block scenarios; production
        /// callers waiting for 6 confirms on mainnet should bump
        /// this to 3600+).
        #[arg(long, default_value_t = 300)]
        timeout_secs: u64,
    },

    /// Assemble Bob's BIP-341
    /// script-path refund transaction from the lock UTXO + his
    /// destination + a 64-byte signature under his refund
    /// pubkey.
    ///
    /// Bob runs this after the CSV timeout has elapsed AND Alice
    /// has failed to claim. The script-path witness reveals the
    /// CSV refund script, the control block proving it's a leaf
    /// of the lock's script tree, and Bob's signature over the
    /// script-path sighash.
    ///
    /// [`coincync_swap::btc::build_refund_tx`] runs full BIP-340
    /// verification at construction time — same pattern as the
    /// claim subcommand.
    ///
    /// The refund-branch flags are **required** (not optional like
    /// in lock/claim): a refund only makes sense if the lock was
    /// built with a script tree.
    ConstructBtcRefund {
        /// Bitcoin network: `mainnet`, `testnet`, `regtest`, or `signet`.
        #[arg(long)]
        network: String,
        /// Lock transaction's txid, 64-char lowercase hex.
        #[arg(long)]
        lock_txid: String,
        /// Lock UTXO's output index.
        #[arg(long, default_value_t = 0)]
        lock_vout: u32,
        /// Lock UTXO's value in satoshis.
        #[arg(long)]
        lock_value_sats: u64,
        /// 32-byte x-only Taproot internal key the lock was bound
        /// to (Alice's claim key — needed to reconstruct the
        /// merkle root + control block, not for signing).
        #[arg(long)]
        lock_internal_key: String,
        /// Bob's 32-byte x-only refund pubkey, hex. Must match
        /// what was passed to `construct-btc-lock`.
        #[arg(long)]
        refund_bob_pubkey: String,
        /// CSV timeout in blocks. Must match what was passed to
        /// `construct-btc-lock`. The refund tx's input sequence
        /// will encode this in BIP-68 blocks-relative form.
        #[arg(long)]
        refund_csv_blocks: u16,
        /// Bob's destination address (where the refund flows).
        /// Must parse for `network`.
        #[arg(long)]
        dest_address: String,
        /// Fee in satoshis. Output value = lock_value - fee.
        #[arg(long, default_value_t = 1000)]
        fee_sats: u64,
        /// The 64-byte BIP-340 Schnorr signature under
        /// `refund_bob_pubkey` over the script-path sighash,
        /// 128-char hex. No tweak — script-path signatures are
        /// against the leaf script's keys, not the output key.
        #[arg(long)]
        refund_signature: String,
    },

    /// Assemble Alice's BIP-340
    /// key-path claim transaction from the lock UTXO + her
    /// destination + the 64-byte adaptor-decrypted signature.
    ///
    /// [`coincync_swap::btc::build_claim_tx`] runs **full BIP-340
    /// verification** at construction time against the lock's
    /// (tweaked, if refund-branch present) output key + the
    /// computed sighash. A signature that doesn't verify is
    /// rejected here with a clear error rather than producing a
    /// tx that bitcoind would reject with
    /// `non-mandatory-script-verify-flag` on broadcast.
    ///
    /// The refund-branch flags MUST match what was passed to
    /// `construct-btc-lock` for this same lock (the tweaked
    /// output key depends on the script-tree merkle root).
    ConstructBtcClaim {
        /// Bitcoin network: `mainnet`, `testnet`, `regtest`, or `signet`.
        #[arg(long)]
        network: String,
        /// Lock transaction's txid, 64-char lowercase hex.
        #[arg(long)]
        lock_txid: String,
        /// Lock UTXO's output index (typically 0 — the P2TR lock
        /// output is the first output of a standard
        /// `construct-btc-lock` result).
        #[arg(long, default_value_t = 0)]
        lock_vout: u32,
        /// Lock UTXO's value in satoshis. Needed for the BIP-341
        /// sighash (which commits to the spent amount).
        #[arg(long)]
        lock_value_sats: u64,
        /// 32-byte x-only Taproot internal key the lock was bound
        /// to (NOT the tweaked output key — the tweak is recomputed
        /// internally from the refund-branch flags). Must match
        /// what was passed to `construct-btc-lock`.
        #[arg(long)]
        lock_internal_key: String,
        /// Alice's destination address. P2PKH / P2WPKH / P2TR all
        /// supported; must parse for `network`.
        #[arg(long)]
        dest_address: String,
        /// Fee in satoshis. Output value = lock_value - fee.
        #[arg(long, default_value_t = 1000)]
        fee_sats: u64,
        /// The 64-byte BIP-340 Schnorr signature, 128-char hex.
        /// This is the output of
        /// [`coincync_swap::adaptor::decrypt_btc_adaptor`] —
        /// Alice's pre-sig combined with her adaptor secret.
        #[arg(long)]
        claim_signature: String,
        /// **Optional refund branch.** If the lock was built with
        /// a script-tree refund branch, pass the same Bob refund
        /// pubkey here; --refund-csv-blocks is then required.
        /// Omitting both produces a sighash that matches a
        /// key-path-only lock.
        #[arg(long)]
        refund_bob_pubkey: Option<String>,
        /// CSV timeout in blocks for the refund branch. Required
        /// iff --refund-bob-pubkey is set. Must match the value
        /// passed to `construct-btc-lock`.
        #[arg(long)]
        refund_csv_blocks: Option<u16>,
    },

    /// Derive a CYNC swap-recipient
    /// spend pubkey from the counterparty's wallet spend pubkey
    /// and the adaptor point: `out = P + T` on Ristretto255.
    ///
    /// Exposes [`coincync_swap::cync::derive_swap_recipient_spend_pub`]
    /// so an external wallet (no Rust integration) can compute
    /// the modified address bytes via subprocess. Hex IO; no
    /// state file involvement.
    DeriveCyncRecipientPubkey {
        /// Counterparty's 32-byte compressed Ristretto255 spend pubkey, hex.
        #[arg(long)]
        counterparty_spend_pub: String,
        /// 32-byte compressed Ristretto255 adaptor point T = t·G_cync, hex.
        #[arg(long)]
        adaptor_point: String,
    },

    /// Derive the CYNC swap-spender
    /// effective secret from the counterparty's wallet spend
    /// secret and the adaptor secret: `out = s + t` mod ℓ on
    /// Ristretto255.
    ///
    /// **Security note:** prints a secret to stdout. Pipe directly
    /// into a wallet's stdin or write to a tmpfs file; do not
    /// log. Exposes [`coincync_swap::cync::derive_swap_spender_secret`].
    DeriveCyncSpenderSecret {
        /// Counterparty's 32-byte canonical Ristretto255 spend secret, hex.
        #[arg(long)]
        counterparty_spend_secret: String,
        /// 32-byte canonical Ristretto255 adaptor secret, hex.
        #[arg(long)]
        adaptor_secret: String,
        /// Acknowledge that you understand the output is a secret
        /// being printed to stdout. Required to avoid scripts
        /// accidentally logging the result.
        #[arg(long)]
        i_understand_this_is_a_secret: bool,
    },
}

// ──────────────────────────────────────────────────────────────────
// Main
// ──────────────────────────────────────────────────────────────────

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Alice {
            listen,
            cync_amount,
            btc_amount_sats,
            alice_cync_address,
            bob_btc_address,
            state_file,
        } => alice_cmd(
            &listen,
            cync_amount,
            btc_amount_sats,
            alice_cync_address,
            bob_btc_address,
            resolve_state_path(state_file)?,
        ),
        Command::Bob {
            connect,
            swap_id,
            cync_amount,
            btc_amount_sats,
            alice_cync_address,
            bob_btc_address,
            state_file,
        } => bob_cmd(
            &connect,
            swap_id,
            cync_amount,
            btc_amount_sats,
            alice_cync_address,
            bob_btc_address,
            resolve_state_path(state_file)?,
        ),
        Command::WalletInitAlice {
            listen,
            cync_amount,
            btc_amount_sats,
            alice_cync_address,
            bob_btc_address,
            state_file,
        } => wallet_init_alice_cmd(
            &listen,
            cync_amount,
            btc_amount_sats,
            alice_cync_address,
            bob_btc_address,
            resolve_state_path(state_file)?,
        ),
        Command::WalletInitBob {
            invite_hex,
            alice_cync_address,
            bob_btc_address,
            state_file,
        } => wallet_init_bob_cmd(
            &invite_hex,
            alice_cync_address,
            bob_btc_address,
            resolve_state_path(state_file)?,
        ),
        Command::WalletStatus { state_file } => wallet_status_cmd(resolve_state_path(state_file)?),
        Command::Status { state_file } => status_cmd(resolve_state_path(state_file)?),
        Command::Cancel { state_file } => cancel_cmd(resolve_state_path(state_file)?),
        Command::LockCync {
            state_file,
            network,
            rpc_url,
            api_key,
            signed_tx_hex,
        } => lock_cync_orchestration_cmd(
            resolve_state_path(state_file)?,
            network,
            rpc_url,
            api_key,
            signed_tx_hex,
        ),
        Command::LockBtc {
            state_file,
            network,
            rpc_url,
            rpc_user,
            rpc_pass,
            signed_tx_hex,
        } => lock_btc_orchestration_cmd(
            resolve_state_path(state_file)?,
            network,
            rpc_url,
            rpc_user,
            rpc_pass,
            signed_tx_hex,
        ),
        Command::ClaimBtc {
            state_file,
            network,
            rpc_url,
            rpc_user,
            rpc_pass,
            lock_txid,
            lock_vout,
            lock_internal_key,
            dest_address,
            fee_sats,
            refund_bob_pubkey,
            refund_csv_blocks,
            signed_tx_hex,
        } => claim_btc_orchestration_cmd(
            resolve_state_path(state_file)?,
            network,
            rpc_url,
            rpc_user,
            rpc_pass,
            lock_txid,
            lock_vout,
            lock_internal_key,
            dest_address,
            fee_sats,
            refund_bob_pubkey,
            refund_csv_blocks,
            signed_tx_hex,
        ),
        Command::ClaimCync {
            state_file,
            network,
            rpc_url,
            api_key,
            signed_tx_hex,
        } => claim_cync_orchestration_cmd(
            resolve_state_path(state_file)?,
            network,
            rpc_url,
            api_key,
            signed_tx_hex,
        ),
        Command::RefundBtc {
            state_file,
            network,
            rpc_url,
            rpc_user,
            rpc_pass,
            signed_tx_hex,
        } => refund_btc_orchestration_cmd(
            resolve_state_path(state_file)?,
            network,
            rpc_url,
            rpc_user,
            rpc_pass,
            signed_tx_hex,
        ),
        Command::RefundCync {
            state_file,
            network,
            rpc_url,
            api_key,
            signed_tx_hex,
        } => refund_cync_orchestration_cmd(
            resolve_state_path(state_file)?,
            network,
            rpc_url,
            api_key,
            signed_tx_hex,
        ),
        Command::DesignVersion => {
            println!("CIP-001 (atomic-swap) — cryptographic + transport perimeter complete");
            println!("Implementation status (refreshed 2026-05-18):");
            println!("  - protocol state machine:       shipped");
            println!("  - handshake state machine:      shipped");
            println!("  - state persistence:            shipped");
            println!("  - adaptor signatures (BTC):     shipped (BIP-340 parity-correct)");
            println!("  - adaptor signatures (CYNC):    shipped (Ristretto255)");
            println!("  - cross-curve DLEQ:             shipped (dual-response Schoenmakers)");
            println!(
                "  - BTC tx construction:          shipped (lock + claim + refund w/ script tree)"
            );
            println!("  - BTC RPC client:               shipped (Bitcoin Core JSON-RPC)");
            println!("  - CYNC RPC client:              shipped (coincync-node JSON-RPC)");
            println!(
                "  - CYNC swap key-derivation:     shipped (CLI-accessible via `derive-cync-*`)"
            );
            println!("  - end-to-end composition test:  shipped (17-step Alice/Bob walkthrough)");
            println!("  - CLI orchestration of crypto:  shipped (lock/claim/refund — 6 bundled commands)");
            println!("  - transport (Plain/Noise XX/Tor): shipped (3 composable layers + DoS-hardened listen)");
            println!("See docs/cip/CIP-001-atomic-swap.md for the design spec.");
            Ok(())
        }
        Command::Selftest => selftest_cmd(),
        Command::Transition { state_file, kind } => {
            transition_cmd(resolve_state_path(state_file)?, kind)
        }
        Command::NoiseKeygen {
            out,
            i_understand_this_is_a_secret,
        } => noise_keygen_cmd(out, i_understand_this_is_a_secret),
        Command::NoisePubkey {
            secret_file,
            secret_hex,
        } => noise_pubkey_cmd(secret_file, secret_hex),
        Command::ConstructBtcLock {
            network,
            funding_txid,
            funding_vout,
            funding_value_sats,
            lock_amount_sats,
            adaptor_internal_key,
            change_address,
            fee_sats,
            locktime,
            refund_bob_pubkey,
            refund_csv_blocks,
        } => construct_btc_lock_cmd(
            network,
            funding_txid,
            funding_vout,
            funding_value_sats,
            lock_amount_sats,
            adaptor_internal_key,
            change_address,
            fee_sats,
            locktime,
            refund_bob_pubkey,
            refund_csv_blocks,
        ),
        Command::VerifyPreSigBtc {
            pre_sig_r_point,
            pre_sig_s,
            signer_x,
            adaptor_point,
            msg,
        } => verify_pre_sig_btc_cmd(pre_sig_r_point, pre_sig_s, signer_x, adaptor_point, msg),
        Command::VerifyPreSigCync {
            pre_sig_r_point,
            pre_sig_s,
            signer_pub,
            adaptor_point,
            msg,
        } => verify_pre_sig_cync_cmd(pre_sig_r_point, pre_sig_s, signer_pub, adaptor_point, msg),
        Command::BtcAdaptorPointFromSecret {
            adaptor_secret,
            encoding,
        } => btc_adaptor_point_from_secret_cmd(adaptor_secret, encoding),
        Command::CyncAdaptorPointFromSecret { adaptor_secret } => {
            cync_adaptor_point_from_secret_cmd(adaptor_secret)
        }
        Command::ProveDleq {
            adaptor_secret,
            btc_pub,
            cync_pub,
            nonce,
        } => prove_dleq_cmd(adaptor_secret, btc_pub, cync_pub, nonce),
        Command::VerifyDleq {
            btc_pub,
            cync_pub,
            proof_json,
            proof_a_btc,
            proof_a_cync,
            proof_s_btc,
            proof_s_cync,
        } => {
            // Resolve the 4 proof fields: either from a single JSON
            // blob (the recommended pipe-friendly path) or from
            // four individual flags (the explicit path). Clap's
            // `required_unless_present` ensures one of the two
            // paths is populated; we still pattern-match here so
            // unreachable cases panic loudly rather than silently
            // proceed with empty strings.
            let (a_btc, a_cync, s_btc, s_cync) = match proof_json {
                Some(json) => parse_dleq_proof_json(&json)?,
                None => (
                    proof_a_btc.expect("clap required_unless_present"),
                    proof_a_cync.expect("clap required_unless_present"),
                    proof_s_btc.expect("clap required_unless_present"),
                    proof_s_cync.expect("clap required_unless_present"),
                ),
            };
            verify_dleq_cmd(btc_pub, cync_pub, a_btc, a_cync, s_btc, s_cync)
        }
        Command::AdaptorSecretFlipEndian {
            secret_hex,
            from,
            i_understand_this_is_a_secret,
        } => adaptor_secret_flip_endian_cmd(secret_hex, from, i_understand_this_is_a_secret),
        Command::CreatePreSigCync {
            signer_secret,
            msg,
            adaptor_point,
            nonce,
        } => create_pre_sig_cync_cmd(signer_secret, msg, adaptor_point, nonce),
        Command::DecryptCyncAdaptor {
            pre_sig_r_point,
            pre_sig_s,
            adaptor_secret,
            adaptor_point,
        } => decrypt_cync_adaptor_cmd(pre_sig_r_point, pre_sig_s, adaptor_secret, adaptor_point),
        Command::RecoverSecretFromCyncSig {
            pre_sig_s,
            final_sig,
            i_understand_this_is_a_secret,
        } => recover_secret_from_cync_sig_cmd(pre_sig_s, final_sig, i_understand_this_is_a_secret),
        Command::CyncBroadcast {
            network,
            rpc_url,
            api_key,
            tx_hex,
        } => cync_broadcast_cmd(network, rpc_url, api_key, tx_hex),
        Command::CyncWatch {
            network,
            rpc_url,
            api_key,
            txid,
            confirmations,
            timeout_secs,
        } => cync_watch_cmd(network, rpc_url, api_key, txid, confirmations, timeout_secs),
        Command::ClaimSighashBtc {
            network,
            lock_txid,
            lock_vout,
            lock_value_sats,
            lock_internal_key,
            dest_address,
            fee_sats,
            refund_bob_pubkey,
            refund_csv_blocks,
        } => claim_sighash_btc_cmd(
            network,
            lock_txid,
            lock_vout,
            lock_value_sats,
            lock_internal_key,
            dest_address,
            fee_sats,
            refund_bob_pubkey,
            refund_csv_blocks,
        ),
        Command::RefundSighashBtc {
            network,
            lock_txid,
            lock_vout,
            lock_value_sats,
            lock_internal_key,
            refund_bob_pubkey,
            refund_csv_blocks,
            dest_address,
            fee_sats,
        } => refund_sighash_btc_cmd(
            network,
            lock_txid,
            lock_vout,
            lock_value_sats,
            lock_internal_key,
            refund_bob_pubkey,
            refund_csv_blocks,
            dest_address,
            fee_sats,
        ),
        Command::CreatePreSigBtc {
            signer_secret,
            msg,
            adaptor_point,
            aux_rand,
        } => create_pre_sig_btc_cmd(signer_secret, msg, adaptor_point, aux_rand),
        Command::DecryptBtcAdaptor {
            pre_sig_r_point,
            pre_sig_s,
            adaptor_secret,
            adaptor_point,
        } => decrypt_btc_adaptor_cmd(pre_sig_r_point, pre_sig_s, adaptor_secret, adaptor_point),
        Command::RecoverSecretFromBtcSig {
            pre_sig_s,
            final_sig,
            i_understand_this_is_a_secret,
        } => recover_secret_from_btc_sig_cmd(pre_sig_s, final_sig, i_understand_this_is_a_secret),
        Command::BtcBroadcast {
            network,
            rpc_url,
            rpc_user,
            rpc_pass,
            tx_hex,
        } => btc_broadcast_cmd(network, rpc_url, rpc_user, rpc_pass, tx_hex),
        Command::BtcWatch {
            network,
            rpc_url,
            rpc_user,
            rpc_pass,
            txid,
            confirmations,
            timeout_secs,
        } => btc_watch_cmd(
            network,
            rpc_url,
            rpc_user,
            rpc_pass,
            txid,
            confirmations,
            timeout_secs,
        ),
        Command::ConstructBtcRefund {
            network,
            lock_txid,
            lock_vout,
            lock_value_sats,
            lock_internal_key,
            refund_bob_pubkey,
            refund_csv_blocks,
            dest_address,
            fee_sats,
            refund_signature,
        } => construct_btc_refund_cmd(
            network,
            lock_txid,
            lock_vout,
            lock_value_sats,
            lock_internal_key,
            refund_bob_pubkey,
            refund_csv_blocks,
            dest_address,
            fee_sats,
            refund_signature,
        ),
        Command::ConstructBtcClaim {
            network,
            lock_txid,
            lock_vout,
            lock_value_sats,
            lock_internal_key,
            dest_address,
            fee_sats,
            claim_signature,
            refund_bob_pubkey,
            refund_csv_blocks,
        } => construct_btc_claim_cmd(
            network,
            lock_txid,
            lock_vout,
            lock_value_sats,
            lock_internal_key,
            dest_address,
            fee_sats,
            claim_signature,
            refund_bob_pubkey,
            refund_csv_blocks,
        ),
        Command::DeriveCyncRecipientPubkey {
            counterparty_spend_pub,
            adaptor_point,
        } => derive_cync_recipient_pubkey_cmd(counterparty_spend_pub, adaptor_point),
        Command::DeriveCyncSpenderSecret {
            counterparty_spend_secret,
            adaptor_secret,
            i_understand_this_is_a_secret,
        } => derive_cync_spender_secret_cmd(
            counterparty_spend_secret,
            adaptor_secret,
            i_understand_this_is_a_secret,
        ),
    }
}

// ──────────────────────────────────────────────────────────────────
// Subcommand handlers
// ──────────────────────────────────────────────────────────────────

fn alice_cmd(
    listen: &str,
    cync_amount: u64,
    btc_amount_sats: u64,
    alice_cync_address: String,
    bob_btc_address: String,
    state_path: PathBuf,
) -> Result<(), String> {
    // Zero-amount swap is nonsense — Alice locks nothing → no swap.
    // Pedersen value commitments also leak the value when blinded
    // commits include zero. Reject at the front door so the operator
    // gets a clear error rather than a downstream cryptographic
    // surprise.
    if cync_amount == 0 {
        return Err("--cync-amount must be > 0 (zero-amount swap is meaningless)".into());
    }
    if btc_amount_sats == 0 {
        return Err("--btc-amount-sats must be > 0 (zero-amount swap is meaningless)".into());
    }

    let store = SwapStore::new(&state_path);
    if store.exists() {
        return Err(format!(
            "state file {} already exists; refusing to overwrite. Run `cyncswap status` to inspect, or `cyncswap cancel` first.",
            state_path.display()
        ));
    }

    let id = generate_swap_id();
    let params = SwapParameters {
        cync_amount,
        btc_amount_sats,
        cync_timeout_blocks: DEFAULT_CYNC_TIMEOUT_BLOCKS,
        btc_timeout_blocks: DEFAULT_BTC_TIMEOUT_BLOCKS,
        alice_cync_address,
        bob_btc_address,
        cync_network: "unknown".to_string(),
        btc_network: "unknown".to_string(),
    };
    let swap = Swap::negotiate(id.clone(), Role::Alice, params)
        .map_err(|e| format!("swap construction failed: {e}"))?;
    store.save(&swap).map_err(|e| format!("save failed: {e}"))?;

    println!("Swap initialized as Alice.");
    println!("  swap_id:    {id}");
    println!("  state:      {}", state_string(swap.state));
    println!("  state file: {}", state_path.display());
    println!("  listen:     {listen} (recorded only; bind happens at coordinator handshake time)");
    println!();
    println!("Share the swap_id with Bob out-of-band so he can join. Bob will run:");
    println!("  cyncswap bob \\");
    println!("    --connect <your-endpoint> \\");
    println!("    --swap-id {id} \\");
    println!("    --cync-amount {cync_amount} \\");
    println!("    --btc-amount-sats {btc_amount_sats}");
    Ok(())
}

fn bob_cmd(
    connect: &str,
    swap_id: String,
    cync_amount: u64,
    btc_amount_sats: u64,
    alice_cync_address: String,
    bob_btc_address: String,
    state_path: PathBuf,
) -> Result<(), String> {
    if cync_amount == 0 {
        return Err("--cync-amount must be > 0 (zero-amount swap is meaningless)".into());
    }
    if btc_amount_sats == 0 {
        return Err("--btc-amount-sats must be > 0 (zero-amount swap is meaningless)".into());
    }

    let store = SwapStore::new(&state_path);
    if store.exists() {
        return Err(format!(
            "state file {} already exists; refusing to overwrite.",
            state_path.display()
        ));
    }

    let params = SwapParameters {
        cync_amount,
        btc_amount_sats,
        cync_timeout_blocks: DEFAULT_CYNC_TIMEOUT_BLOCKS,
        btc_timeout_blocks: DEFAULT_BTC_TIMEOUT_BLOCKS,
        alice_cync_address,
        bob_btc_address,
        cync_network: "unknown".to_string(),
        btc_network: "unknown".to_string(),
    };
    let swap = Swap::negotiate(swap_id.clone(), Role::Bob, params)
        .map_err(|e| format!("swap construction failed: {e}"))?;
    store.save(&swap).map_err(|e| format!("save failed: {e}"))?;

    println!("Swap joined as Bob.");
    println!("  swap_id:    {swap_id}");
    println!("  state:      {}", state_string(swap.state));
    println!("  state file: {}", state_path.display());
    println!("  connect:    {connect} (phase-3 placeholder; not yet active)");
    Ok(())
}

/// Wallet-friendly Alice init. Same flow as [`alice_cmd`] but emits a
/// single JSON line on stdout (so the Tauri layer can parse it without
/// scraping human-readable strings) and produces an `invite_hex` blob
/// that carries everything Bob's wallet needs to join.
///
/// The invite blob is hex-encoded JSON `{ v, role, swap_id, listen,
/// cync_amount, btc_amount_sats, alice_cync_address, bob_btc_address }`.
/// `v` is a wire-version integer (currently 1) so a future schema
/// change can be detected and refused; ALL other fields are required.
fn wallet_init_alice_cmd(
    listen: &str,
    cync_amount: u64,
    btc_amount_sats: u64,
    alice_cync_address: String,
    bob_btc_address: String,
    state_path: PathBuf,
) -> Result<(), String> {
    if cync_amount == 0 {
        return Err("--cync-amount must be > 0 (zero-amount swap is meaningless)".into());
    }
    if btc_amount_sats == 0 {
        return Err("--btc-amount-sats must be > 0 (zero-amount swap is meaningless)".into());
    }

    let store = SwapStore::new(&state_path);
    if store.exists() {
        return Err(format!(
            "state file {} already exists; refusing to overwrite. Run `cyncswap status` to inspect, or `cyncswap cancel` first.",
            state_path.display()
        ));
    }

    let id = generate_swap_id();
    let params = SwapParameters {
        cync_amount,
        btc_amount_sats,
        cync_timeout_blocks: DEFAULT_CYNC_TIMEOUT_BLOCKS,
        btc_timeout_blocks: DEFAULT_BTC_TIMEOUT_BLOCKS,
        alice_cync_address: alice_cync_address.clone(),
        bob_btc_address: bob_btc_address.clone(),
        cync_network: "unknown".to_string(),
        btc_network: "unknown".to_string(),
    };
    let swap = Swap::negotiate(id.clone(), Role::Alice, params)
        .map_err(|e| format!("swap construction failed: {e}"))?;
    store.save(&swap).map_err(|e| format!("save failed: {e}"))?;

    let invite_json = serde_json::json!({
        "v": 1,
        "role": "alice",
        "swap_id": id,
        "listen": listen,
        "cync_amount": cync_amount,
        "btc_amount_sats": btc_amount_sats,
        "alice_cync_address": alice_cync_address,
        "bob_btc_address": bob_btc_address,
    });
    let invite_hex = hex::encode(invite_json.to_string().as_bytes());

    let out = serde_json::json!({
        "swap_id": id,
        "role": "alice",
        "state": state_string(swap.state),
        "state_file": state_path.display().to_string(),
        "invite_hex": invite_hex,
    });
    println!(
        "{}",
        serde_json::to_string(&out).map_err(|e| format!("json encode: {e}"))?
    );
    Ok(())
}

/// Wallet-friendly Bob init. Same flow as [`bob_cmd`] but takes a
/// single `--invite-hex` blob (output of [`wallet_init_alice_cmd`])
/// and emits a single JSON line on stdout.
fn wallet_init_bob_cmd(
    invite_hex: &str,
    alice_cync_address: String,
    bob_btc_address: String,
    state_path: PathBuf,
) -> Result<(), String> {
    let invite_bytes =
        hex::decode(invite_hex).map_err(|e| format!("invite_hex is not valid hex: {e}"))?;
    let invite: serde_json::Value = serde_json::from_slice(&invite_bytes)
        .map_err(|e| format!("invite is not valid JSON: {e}"))?;

    // Refuse unknown wire versions so a future schema change doesn't
    // silently downgrade by ignoring new fields.
    let v = invite.get("v").and_then(|v| v.as_u64()).unwrap_or(0);
    if v != 1 {
        return Err(format!(
            "invite wire version {} not supported by this build (expected 1)",
            v
        ));
    }
    let role = invite.get("role").and_then(|v| v.as_str()).unwrap_or("?");
    if role != "alice" {
        return Err(format!("expected invite from role=alice, got role={role}"));
    }

    let swap_id = invite
        .get("swap_id")
        .and_then(|v| v.as_str())
        .ok_or("invite missing swap_id")?
        .to_string();
    let cync_amount = invite
        .get("cync_amount")
        .and_then(|v| v.as_u64())
        .ok_or("invite missing cync_amount")?;
    let btc_amount_sats = invite
        .get("btc_amount_sats")
        .and_then(|v| v.as_u64())
        .ok_or("invite missing btc_amount_sats")?;
    let connect = invite
        .get("listen")
        .and_then(|v| v.as_str())
        .ok_or("invite missing listen")?
        .to_string();

    if cync_amount == 0 {
        return Err("invite has zero cync_amount (Alice's wallet rejected this earlier; refusing to proceed)".into());
    }
    if btc_amount_sats == 0 {
        return Err("invite has zero btc_amount_sats (Alice's wallet rejected this earlier; refusing to proceed)".into());
    }

    let store = SwapStore::new(&state_path);
    if store.exists() {
        return Err(format!(
            "state file {} already exists; refusing to overwrite.",
            state_path.display()
        ));
    }

    let params = SwapParameters {
        cync_amount,
        btc_amount_sats,
        cync_timeout_blocks: DEFAULT_CYNC_TIMEOUT_BLOCKS,
        btc_timeout_blocks: DEFAULT_BTC_TIMEOUT_BLOCKS,
        alice_cync_address,
        bob_btc_address,
        cync_network: "unknown".to_string(),
        btc_network: "unknown".to_string(),
    };
    let swap = Swap::negotiate(swap_id.clone(), Role::Bob, params)
        .map_err(|e| format!("swap construction failed: {e}"))?;
    store.save(&swap).map_err(|e| format!("save failed: {e}"))?;

    let out = serde_json::json!({
        "swap_id": swap_id,
        "role": "bob",
        "state": state_string(swap.state),
        "state_file": state_path.display().to_string(),
        "connect": connect,
        "cync_amount": cync_amount,
        "btc_amount_sats": btc_amount_sats,
    });
    println!(
        "{}",
        serde_json::to_string(&out).map_err(|e| format!("json encode: {e}"))?
    );
    Ok(())
}

/// Machine-readable counterpart to [`status_cmd`]. Returns a single
/// JSON line on stdout. The wallet's `swap_list` Tauri command
/// invokes this to populate the "Active swaps" panel.
fn wallet_status_cmd(state_path: PathBuf) -> Result<(), String> {
    let store = SwapStore::new(&state_path);
    let swap = match store.load().map_err(|e| format!("load failed: {e}"))? {
        Some(s) => s,
        None => {
            return Err(format!(
                "no swap state at {}; nothing to show.",
                state_path.display()
            ));
        }
    };

    let legal: Vec<String> = swap
        .legal_transitions()
        .into_iter()
        .map(|t| format!("{t:?}"))
        .collect();

    let out = serde_json::json!({
        "swap_id":             swap.id,
        "role":                format!("{:?}", swap.role),
        "state":               state_string(swap.state),
        "terminal":            swap.is_terminal(),
        "state_file":          state_path.display().to_string(),
        "cync_amount":         swap.parameters.cync_amount,
        "btc_amount_sats":     swap.parameters.btc_amount_sats,
        "cync_timeout_blocks": swap.parameters.cync_timeout_blocks,
        "btc_timeout_blocks":  swap.parameters.btc_timeout_blocks,
        "alice_cync_address":  swap.parameters.alice_cync_address,
        "bob_btc_address":     swap.parameters.bob_btc_address,
        "legal_transitions":   legal,
    });
    println!(
        "{}",
        serde_json::to_string(&out).map_err(|e| format!("json encode: {e}"))?
    );
    Ok(())
}

fn status_cmd(state_path: PathBuf) -> Result<(), String> {
    let store = SwapStore::new(&state_path);
    let swap = match store.load().map_err(|e| format!("load failed: {e}"))? {
        Some(s) => s,
        None => {
            return Err(format!(
                "no swap state at {}; nothing to show.",
                state_path.display()
            ));
        }
    };

    println!("Swap status:");
    println!("  swap_id:    {}", swap.id);
    println!("  role:       {:?}", swap.role);
    println!("  state:      {}", state_string(swap.state));
    println!("  cync_amount:        {}", swap.parameters.cync_amount);
    println!("  btc_amount_sats:    {}", swap.parameters.btc_amount_sats);
    println!(
        "  cync_timeout_blocks: {}",
        swap.parameters.cync_timeout_blocks
    );
    println!(
        "  btc_timeout_blocks:  {}",
        swap.parameters.btc_timeout_blocks
    );

    let legal = swap.legal_transitions();
    if legal.is_empty() {
        println!();
        println!("(terminal state — no further actions available)");
    } else {
        println!();
        println!("Legal next transitions for {:?}:", swap.role);
        for t in legal {
            println!("  - {t:?}{}", transition_hint(t));
        }
    }
    Ok(())
}

fn cancel_cmd(state_path: PathBuf) -> Result<(), String> {
    let store = SwapStore::new(&state_path);
    let mut swap = match store.load().map_err(|e| format!("load failed: {e}"))? {
        Some(s) => s,
        None => {
            return Err(format!(
                "no swap state at {}; nothing to cancel.",
                state_path.display()
            ));
        }
    };

    if swap.is_terminal() {
        return Err(format!(
            "swap is already in terminal state ({:?}); cannot cancel.",
            swap.state
        ));
    }

    // Apply on a clone first, persist, then commit to in-memory only
    // on save success. Reverse order would leave memory ahead of disk
    // if save fails — fine for a one-shot CLI that exits, but the
    // pattern is reused by the upcoming daemon and the safety is free.
    let prior_state = swap.state;
    let mut next = swap.clone();
    next.apply(Transition::Abort)
        .map_err(|e| format!("abort transition rejected: {e}"))?;
    store.save(&next).map_err(|e| format!("save failed: {e}"))?;
    swap = next;

    println!("Swap cancelled.");
    println!("  prior state: {}", state_string(prior_state));
    println!("  new state:   {}", state_string(swap.state));
    if matches!(prior_state, State::AliceLocked | State::BobLocked) {
        println!();
        println!("Note: an on-chain lock was active at cancel time. The local state");
        println!("is now Aborted, but your locked funds are NOT released until the");
        println!("on-chain timeout fires. Once it does, broadcast your pre-signed");
        println!("refund tx via `cyncswap refund-btc` (Bob) or `cyncswap refund-cync`");
        println!("(Alice) to reclaim the funds.");
    }
    Ok(())
}

// ── Derive helpers (real wiring, no state-file involvement) ──────

fn parse_hex_32(label: &str, hex_in: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_in.trim()).map_err(|e| format!("{label}: not valid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "{label}: expected 32 bytes ({}-char hex string), got {}",
            64,
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hex_33(label: &str, hex_in: &str) -> Result<[u8; 33], String> {
    let bytes = hex::decode(hex_in.trim()).map_err(|e| format!("{label}: not valid hex: {e}"))?;
    if bytes.len() != 33 {
        return Err(format!(
            "{label}: expected 33 bytes ({}-char hex string for compressed secp256k1 point), got {}",
            66,
            bytes.len()
        ));
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hex_64(label: &str, hex_in: &str) -> Result<[u8; 64], String> {
    let bytes = hex::decode(hex_in.trim()).map_err(|e| format!("{label}: not valid hex: {e}"))?;
    if bytes.len() != 64 {
        return Err(format!(
            "{label}: expected 64 bytes ({}-char hex string), got {}",
            128,
            bytes.len()
        ));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Parse the coupled `--refund-bob-pubkey` / `--refund-csv-blocks`
/// flag pair into an Option<RefundBranch>. Both-or-neither is
/// enforced; either-but-not-both is rejected with a clear message
/// for both directions.
fn parse_refund_branch_flags(
    bob_pubkey_hex: Option<String>,
    csv_blocks: Option<u16>,
) -> Result<Option<coincync_swap::btc::RefundBranch>, String> {
    match (bob_pubkey_hex, csv_blocks) {
        (Some(pk_hex), Some(csv)) => {
            let bob_pubkey = parse_hex_32("refund-bob-pubkey", &pk_hex)?;
            Ok(Some(coincync_swap::btc::RefundBranch {
                bob_pubkey,
                csv_blocks: csv,
            }))
        }
        (Some(_), None) => Err("--refund-bob-pubkey supplied without --refund-csv-blocks; \
             both are required to enable the script-tree refund branch."
            .into()),
        (None, Some(_)) => Err("--refund-csv-blocks supplied without --refund-bob-pubkey; \
             both are required to enable the script-tree refund branch."
            .into()),
        (None, None) => Ok(None),
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_claim_tx_base(
    lock_txid_hex: &str,
    lock_vout: u32,
    lock_value_sats: u64,
    lock_internal_key_hex: &str,
    dest_address: String,
    fee_sats: u64,
    refund_bob_pubkey_hex: Option<String>,
    refund_csv_blocks: Option<u16>,
) -> Result<coincync_swap::btc::ClaimTxBase, String> {
    use coincync_swap::btc::{ClaimTxBase, Txid};

    Ok(ClaimTxBase {
        lock_txid: Txid(parse_hex_32("lock-txid", lock_txid_hex)?),
        lock_vout,
        lock_value_sats,
        lock_internal_key: parse_hex_32("lock-internal-key", lock_internal_key_hex)?,
        refund_branch: parse_refund_branch_flags(refund_bob_pubkey_hex, refund_csv_blocks)?,
        dest_address,
        fee_sats,
    })
}

fn derive_cync_recipient_pubkey_cmd(
    counterparty_spend_pub_hex: String,
    adaptor_point_hex: String,
) -> Result<(), String> {
    let counterparty_spend_pub =
        parse_hex_32("counterparty-spend-pub", &counterparty_spend_pub_hex)?;
    let adaptor_point = parse_hex_32("adaptor-point", &adaptor_point_hex)?;

    let derived = coincync_swap::cync::derive_swap_recipient_spend_pub(
        &counterparty_spend_pub,
        &adaptor_point,
    )
    .map_err(|e| format!("derive_swap_recipient_spend_pub: {e}"))?;

    // Stdout is the recipient pubkey hex — only thing printed,
    // so scripts can pipe directly into a wallet's address
    // construction without parsing structured output.
    println!("{}", hex::encode(derived));
    Ok(())
}

fn derive_cync_spender_secret_cmd(
    counterparty_spend_secret_hex: String,
    adaptor_secret_hex: String,
    acknowledged: bool,
) -> Result<(), String> {
    if !acknowledged {
        return Err(format!(
            "this subcommand prints a secret to stdout. \
             Pass --i-understand-this-is-a-secret to acknowledge \
             you have safe stdout handling (pipe to wallet stdin, \
             write to a tmpfs file, etc.) and won't log the output."
        ));
    }
    let counterparty_spend_secret =
        parse_hex_32("counterparty-spend-secret", &counterparty_spend_secret_hex)?;
    let adaptor_secret = parse_hex_32("adaptor-secret", &adaptor_secret_hex)?;

    let derived = coincync_swap::cync::derive_swap_spender_secret(
        &counterparty_spend_secret,
        &adaptor_secret,
    )
    .map_err(|e| format!("derive_swap_spender_secret: {e}"))?;

    // Same minimal-output posture as the recipient-pubkey variant
    // — hex on stdout, nothing else, so scripts can pipe directly.
    println!("{}", hex::encode(derived));
    Ok(())
}

fn construct_btc_lock_cmd(
    network: String,
    funding_txid_hex: String,
    funding_vout: u32,
    funding_value_sats: u64,
    lock_amount_sats: u64,
    adaptor_internal_key_hex: String,
    change_address: String,
    fee_sats: u64,
    locktime: u32,
    refund_bob_pubkey_hex: Option<String>,
    refund_csv_blocks: Option<u16>,
) -> Result<(), String> {
    use coincync_swap::btc::{build_lock_tx, BtcConfig, FundingUtxo, LockTxRequest, Txid};

    // ── Parse + validate inputs ──────────────────────────────────
    let funding_txid_bytes = parse_hex_32("funding-txid", &funding_txid_hex)?;
    let adaptor_internal_key = parse_hex_32("adaptor-internal-key", &adaptor_internal_key_hex)?;
    let refund_branch = parse_refund_branch_flags(refund_bob_pubkey_hex, refund_csv_blocks)?;

    let config = BtcConfig {
        network,
        // build_lock_tx is purely construction; it doesn't talk
        // to bitcoind, so the RPC URL is unused at this stage.
        // Pass a placeholder; the value gets validated for URL
        // shape regardless, so use a sensible default.
        rpc_url: "http://127.0.0.1:18443".into(),
        rpc_auth: None,
    };

    let request = LockTxRequest {
        utxos: vec![FundingUtxo {
            txid: Txid(funding_txid_bytes),
            vout: funding_vout,
            value_sats: funding_value_sats,
        }],
        lock_amount_sats,
        adaptor_internal_key,
        change_address,
        fee_sats,
        locktime,
        refund_branch,
    };

    // ── Construct + emit ─────────────────────────────────────────
    let bytes = build_lock_tx(&config, &request).map_err(|e| format!("build_lock_tx: {e}"))?;

    // Stdout is the hex of the unsigned consensus-encoded tx —
    // ready for the caller's wallet to sign each input and pass
    // to `sendrawtransaction`. Single line, no other output.
    println!("{}", hex::encode(&bytes));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn claim_sighash_btc_cmd(
    network: String,
    lock_txid_hex: String,
    lock_vout: u32,
    lock_value_sats: u64,
    lock_internal_key_hex: String,
    dest_address: String,
    fee_sats: u64,
    refund_bob_pubkey_hex: Option<String>,
    refund_csv_blocks: Option<u16>,
) -> Result<(), String> {
    use coincync_swap::btc::{claim_sighash, BtcConfig, ClaimTxBase, Txid};

    let lock_txid_bytes = parse_hex_32("lock-txid", &lock_txid_hex)?;
    let lock_internal_key = parse_hex_32("lock-internal-key", &lock_internal_key_hex)?;
    let refund_branch = parse_refund_branch_flags(refund_bob_pubkey_hex, refund_csv_blocks)?;

    let config = BtcConfig {
        network,
        rpc_url: "http://127.0.0.1:18443".into(),
        rpc_auth: None,
    };
    let base = ClaimTxBase {
        lock_txid: Txid(lock_txid_bytes),
        lock_vout,
        lock_value_sats,
        lock_internal_key,
        refund_branch,
        dest_address,
        fee_sats,
    };

    let sighash = claim_sighash(&config, &base).map_err(|e| format!("claim_sighash: {e}"))?;
    println!("{}", hex::encode(sighash));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn refund_sighash_btc_cmd(
    network: String,
    lock_txid_hex: String,
    lock_vout: u32,
    lock_value_sats: u64,
    lock_internal_key_hex: String,
    refund_bob_pubkey_hex: String,
    refund_csv_blocks: u16,
    dest_address: String,
    fee_sats: u64,
) -> Result<(), String> {
    use coincync_swap::btc::{refund_sighash, BtcConfig, RefundBranch, RefundTxBase, Txid};

    let lock_txid_bytes = parse_hex_32("lock-txid", &lock_txid_hex)?;
    let lock_internal_key = parse_hex_32("lock-internal-key", &lock_internal_key_hex)?;
    let bob_pubkey = parse_hex_32("refund-bob-pubkey", &refund_bob_pubkey_hex)?;

    let config = BtcConfig {
        network,
        rpc_url: "http://127.0.0.1:18443".into(),
        rpc_auth: None,
    };
    let base = RefundTxBase {
        lock_txid: Txid(lock_txid_bytes),
        lock_vout,
        lock_value_sats,
        lock_internal_key,
        refund_branch: RefundBranch {
            bob_pubkey,
            csv_blocks: refund_csv_blocks,
        },
        dest_address,
        fee_sats,
    };

    let sighash = refund_sighash(&config, &base).map_err(|e| format!("refund_sighash: {e}"))?;
    println!("{}", hex::encode(sighash));
    Ok(())
}

fn verify_pre_sig_btc_cmd(
    pre_sig_r_point_hex: String,
    pre_sig_s_hex: String,
    signer_x_hex: String,
    adaptor_point_hex: String,
    msg_hex: String,
) -> Result<(), String> {
    use coincync_swap::adaptor::{verify_pre_sig, BtcAdaptorSig};

    let r_point_bytes = parse_hex_33("pre-sig-r-point", &pre_sig_r_point_hex)?;
    let s_pre = parse_hex_32("pre-sig-s", &pre_sig_s_hex)?;
    let signer_x_bytes = parse_hex_32("signer-x", &signer_x_hex)?;
    let adaptor_point_bytes = parse_hex_33("adaptor-point", &adaptor_point_hex)?;
    let msg = parse_hex_32("msg", &msg_hex)?;

    let r_point = bitcoin::secp256k1::PublicKey::from_slice(&r_point_bytes)
        .map_err(|e| format!("pre-sig-r-point: not a valid compressed secp256k1 point: {e}"))?;
    let adaptor_pt = bitcoin::secp256k1::PublicKey::from_slice(&adaptor_point_bytes)
        .map_err(|e| format!("adaptor-point: not a valid compressed secp256k1 point: {e}"))?;
    let signer_x = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&signer_x_bytes)
        .map_err(|e| format!("signer-x: not a valid x-only pubkey: {e}"))?;

    let adaptor = BtcAdaptorSig { r_point, s_pre };
    verify_pre_sig(&adaptor, &signer_x, &adaptor_pt, &msg)
        .map_err(|e| format!("verify_pre_sig: {e}"))?;
    Ok(())
}

fn verify_pre_sig_cync_cmd(
    pre_sig_r_point_hex: String,
    pre_sig_s_hex: String,
    signer_pub_hex: String,
    adaptor_point_hex: String,
    msg_hex: String,
) -> Result<(), String> {
    use coincync_swap::adaptor::{cync_verify_pre_sig, CyncAdaptorSig};

    let r_point = parse_hex_32("pre-sig-r-point", &pre_sig_r_point_hex)?;
    let s_pre = parse_hex_32("pre-sig-s", &pre_sig_s_hex)?;
    let signer_pub = parse_hex_32("signer-pub", &signer_pub_hex)?;
    let adaptor_point = parse_hex_32("adaptor-point", &adaptor_point_hex)?;
    let msg = parse_hex_32("msg", &msg_hex)?;

    let adaptor = CyncAdaptorSig { r_point, s_pre };
    cync_verify_pre_sig(&adaptor, &signer_pub, &adaptor_point, &msg)
        .map_err(|e| format!("cync_verify_pre_sig: {e}"))?;
    Ok(())
}

fn btc_adaptor_point_from_secret_cmd(
    adaptor_secret_hex: String,
    encoding: AdaptorSecretEncoding,
) -> Result<(), String> {
    use coincync_swap::adaptor::AdaptorSecret;
    let raw_bytes = parse_hex_32("adaptor-secret", &adaptor_secret_hex)?;

    // Resolve to a canonical `AdaptorSecret` regardless of the
    // wire encoding. The struct internally tracks which encoding
    // it stores + transparently reverses bytes when the consumer
    // curve disagrees — so the same `AdaptorSecret.secp256k1_bytes()`
    // call below works whether the operator passed Ristretto-LE
    // (default, matches every other CLI subcommand) or
    // secp256k1-BE (matches `recover-secret-from-btc-sig` output).
    let secret = match encoding {
        AdaptorSecretEncoding::Ristretto => AdaptorSecret::from_ristretto_bytes(raw_bytes)
            .map_err(|e| format!("adaptor-secret (ristretto encoding): {e:?}"))?,
        AdaptorSecretEncoding::Secp256k1 => AdaptorSecret::from_secp256k1_bytes(raw_bytes)
            .map_err(|e| format!("adaptor-secret (secp256k1 encoding): {e:?}"))?,
    };

    let secret_be = secret.secp256k1_bytes();
    let secret_key = bitcoin::secp256k1::SecretKey::from_slice(&secret_be)
        .map_err(|e| format!("adaptor-secret: not a valid secp256k1 scalar: {e}"))?;
    let pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(
        &bitcoin::secp256k1::Secp256k1::new(),
        &secret_key,
    );
    println!("{}", hex::encode(pubkey.serialize()));
    Ok(())
}

fn cync_adaptor_point_from_secret_cmd(adaptor_secret_hex: String) -> Result<(), String> {
    use coincync_swap::adaptor::{cync_adaptor_point, AdaptorSecret};

    let secret_bytes = parse_hex_32("adaptor-secret", &adaptor_secret_hex)?;
    let secret = AdaptorSecret::from_ristretto_bytes(secret_bytes)
        .map_err(|e| format!("adaptor-secret: {e}"))?;
    let point = cync_adaptor_point(&secret).map_err(|e| format!("cync_adaptor_point: {e}"))?;
    println!("{}", hex::encode(point));
    Ok(())
}

fn prove_dleq_cmd(
    adaptor_secret_hex: String,
    btc_pub_hex: String,
    cync_pub_hex: String,
    nonce_hex: String,
) -> Result<(), String> {
    use coincync_swap::adaptor::{prove_cross_curve, AdaptorSecret};

    let secret_bytes = parse_hex_32("adaptor-secret", &adaptor_secret_hex)?;
    let btc_pub = parse_hex_33("btc-pub", &btc_pub_hex)?;
    let cync_pub = parse_hex_32("cync-pub", &cync_pub_hex)?;
    let nonce = parse_hex_32("nonce", &nonce_hex)?;

    // prove_cross_curve reads via `ristretto_bytes()`, so the
    // AdaptorSecret must be tagged RistrettoLittleEndian. Use
    // from_ristretto_bytes which also enforces canonical-as-
    // Ristretto-scalar (< ℓ) — the stricter check the DLEQ math
    // requires.
    let secret = AdaptorSecret::from_ristretto_bytes(secret_bytes)
        .map_err(|e| format!("adaptor-secret: {e}"))?;

    let proof = prove_cross_curve(&secret, &btc_pub, &cync_pub, &nonce)
        .map_err(|e| format!("prove_cross_curve: {e}"))?;

    // Single-line JSON with all four proof components. Caller
    // pipes each field into `verify-dleq`'s matching flag via
    // `jq -r .a_btc` / `.a_cync` / `.s_btc` / `.s_cync`.
    println!(
        r#"{{"a_btc":"{}","a_cync":"{}","s_btc":"{}","s_cync":"{}"}}"#,
        hex::encode(proof.a_btc),
        hex::encode(proof.a_cync),
        hex::encode(proof.s_btc),
        hex::encode(proof.s_cync),
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
/// Parse the JSON output of `prove-dleq` into the 4 proof fields.
/// Accepts the exact byte-for-byte single-line shape `prove-dleq`
/// emits — `{"a_btc":"<hex>","a_cync":"<hex>","s_btc":"<hex>","s_cync":"<hex>"}`.
/// Tolerates whitespace + key ordering since `serde_json` is
/// permissive. Returns the 4 hex strings in `(a_btc, a_cync,
/// s_btc, s_cync)` order matching `verify_dleq_cmd`'s parameter
/// list.
fn parse_dleq_proof_json(json: &str) -> Result<(String, String, String, String), String> {
    let parsed: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("--proof-json: invalid JSON: {e}"))?;
    let extract = |k: &str| -> Result<String, String> {
        parsed
            .get(k)
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("--proof-json: missing or non-string field `{k}`"))
            .map(|s| s.to_string())
    };
    Ok((
        extract("a_btc")?,
        extract("a_cync")?,
        extract("s_btc")?,
        extract("s_cync")?,
    ))
}

fn verify_dleq_cmd(
    btc_pub_hex: String,
    cync_pub_hex: String,
    proof_a_btc_hex: String,
    proof_a_cync_hex: String,
    proof_s_btc_hex: String,
    proof_s_cync_hex: String,
) -> Result<(), String> {
    use coincync_swap::adaptor::{verify_cross_curve_proof, CrossCurveDlProof};

    let btc_pub = parse_hex_33("btc-pub", &btc_pub_hex)?;
    let cync_pub = parse_hex_32("cync-pub", &cync_pub_hex)?;
    let proof = CrossCurveDlProof {
        a_btc: parse_hex_33("proof-a-btc", &proof_a_btc_hex)?,
        a_cync: parse_hex_32("proof-a-cync", &proof_a_cync_hex)?,
        s_btc: parse_hex_32("proof-s-btc", &proof_s_btc_hex)?,
        s_cync: parse_hex_32("proof-s-cync", &proof_s_cync_hex)?,
    };

    verify_cross_curve_proof(&proof, &btc_pub, &cync_pub)
        .map_err(|e| format!("verify_cross_curve_proof: {e}"))?;
    // Silent success — scripts chain on `&&` without parsing.
    Ok(())
}

fn adaptor_secret_flip_endian_cmd(
    secret_hex: String,
    from: String,
    acknowledged: bool,
) -> Result<(), String> {
    if !acknowledged {
        return Err("this subcommand prints a secret to stdout. Pass \
             --i-understand-this-is-a-secret to acknowledge you have safe \
             stdout handling."
            .into());
    }
    let from = from.trim().to_lowercase();
    if from != "secp256k1" && from != "ristretto" {
        return Err(format!(
            "--from must be `secp256k1` or `ristretto`, got `{from}`"
        ));
    }
    let mut bytes = parse_hex_32("secret-hex", &secret_hex)?;
    // The flip is the same operation in both directions — reverse
    // the byte order. The --from flag exists for documentation /
    // future-proofing if we ever add encoding-specific validation,
    // not because the byte operation differs.
    bytes.reverse();
    println!("{}", hex::encode(bytes));
    Ok(())
}

fn create_pre_sig_cync_cmd(
    signer_secret_hex: String,
    msg_hex: String,
    adaptor_point_hex: String,
    nonce_hex: String,
) -> Result<(), String> {
    use coincync_swap::adaptor::cync_create_pre_sig;

    let signer_secret = parse_hex_32("signer-secret", &signer_secret_hex)?;
    let msg = parse_hex_32("msg", &msg_hex)?;
    let adaptor_point = parse_hex_32("adaptor-point", &adaptor_point_hex)?;
    let nonce = parse_hex_32("nonce", &nonce_hex)?;

    let (pre_sig, signer_pub) = cync_create_pre_sig(&signer_secret, &msg, &adaptor_point, &nonce)
        .map_err(|e| format!("cync_create_pre_sig: {e}"))?;

    // Same JSON shape as create-pre-sig-btc, with field name
    // `signer_pub` rather than `signer_x` — Ristretto has no
    // x-only convention so the full compressed point IS the
    // wire form.
    println!(
        r#"{{"r_point":"{}","s_pre":"{}","signer_pub":"{}"}}"#,
        hex::encode(pre_sig.r_point),
        hex::encode(pre_sig.s_pre),
        hex::encode(signer_pub),
    );
    Ok(())
}

fn decrypt_cync_adaptor_cmd(
    pre_sig_r_point_hex: String,
    pre_sig_s_hex: String,
    adaptor_secret_hex: String,
    adaptor_point_hex: String,
) -> Result<(), String> {
    use coincync_swap::adaptor::{cync_decrypt_adaptor, AdaptorSecret, CyncAdaptorSig};

    let r_point = parse_hex_32("pre-sig-r-point", &pre_sig_r_point_hex)?;
    let s_pre = parse_hex_32("pre-sig-s", &pre_sig_s_hex)?;
    let adaptor_secret_bytes = parse_hex_32("adaptor-secret", &adaptor_secret_hex)?;
    let adaptor_point = parse_hex_32("adaptor-point", &adaptor_point_hex)?;

    let adaptor = CyncAdaptorSig { r_point, s_pre };
    let adaptor_secret = AdaptorSecret::from_ristretto_bytes(adaptor_secret_bytes)
        .map_err(|e| format!("adaptor-secret: {e}"))?;

    let final_sig = cync_decrypt_adaptor(&adaptor, &adaptor_secret, &adaptor_point)
        .map_err(|e| format!("cync_decrypt_adaptor: {e}"))?;

    println!("{}", hex::encode(final_sig));
    Ok(())
}

fn recover_secret_from_cync_sig_cmd(
    pre_sig_s_hex: String,
    final_sig_hex: String,
    acknowledged: bool,
) -> Result<(), String> {
    if !acknowledged {
        return Err("this subcommand prints a secret to stdout. Pass \
             --i-understand-this-is-a-secret to acknowledge you have safe \
             stdout handling."
            .into());
    }
    use coincync_swap::adaptor::{cync_recover_secret, CyncAdaptorSig};

    let s_pre = parse_hex_32("pre-sig-s", &pre_sig_s_hex)?;
    let final_sig = parse_hex_64("final-sig", &final_sig_hex)?;

    // r_point isn't used in the recovery math (`t = s_real - s_pre`).
    // Synthesize the Ristretto basepoint (32 bytes encoding of G)
    // as a valid placeholder so we can build a CyncAdaptorSig.
    let dummy_r_point = {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        let mut out = [0u8; 32];
        out.copy_from_slice(RISTRETTO_BASEPOINT_POINT.compress().as_bytes());
        out
    };
    let adaptor = CyncAdaptorSig {
        r_point: dummy_r_point,
        s_pre,
    };

    let recovered = cync_recover_secret(&adaptor, &final_sig)
        .map_err(|e| format!("cync_recover_secret: {e}"))?;

    // `cync_recover_secret` returns AdaptorSecret in
    // RistrettoLittleEndian encoding. Print LE bytes directly —
    // operators piping into `derive-cync-spender-secret` get the
    // right form without needing to flip.
    println!("{}", hex::encode(recovered.ristretto_bytes()));
    Ok(())
}

fn create_pre_sig_btc_cmd(
    signer_secret_hex: String,
    msg_hex: String,
    adaptor_point_hex: String,
    aux_rand_hex: String,
) -> Result<(), String> {
    use coincync_swap::adaptor::create_pre_sig_bip340;

    let signer_secret_bytes = parse_hex_32("signer-secret", &signer_secret_hex)?;
    let msg = parse_hex_32("msg", &msg_hex)?;
    let adaptor_point_bytes = parse_hex_33("adaptor-point", &adaptor_point_hex)?;
    let aux_rand = parse_hex_32("aux-rand", &aux_rand_hex)?;

    // signer_secret → SecretKey (validates in-range; rejects
    // zero + values ≥ n with a clear from_slice error).
    let signer_secret = bitcoin::secp256k1::SecretKey::from_slice(&signer_secret_bytes)
        .map_err(|e| format!("signer-secret: not a valid secp256k1 scalar: {e}"))?;

    // adaptor_point → PublicKey (validates compressed encoding +
    // on-curve).
    let adaptor_pt = bitcoin::secp256k1::PublicKey::from_slice(&adaptor_point_bytes)
        .map_err(|e| format!("adaptor-point: not a valid compressed secp256k1 point: {e}"))?;

    let (pre_sig, signer_x) = create_pre_sig_bip340(&signer_secret, &msg, &adaptor_pt, &aux_rand)
        .map_err(|e| format!("create_pre_sig_bip340: {e}"))?;

    // JSON output — three logically-distinct outputs (R-point,
    // s_pre scalar, signer's x-only pubkey) wrapped so consumers
    // can `jq -r .field`. Hand-rolled to avoid pulling in
    // serde-derive boilerplate for a 3-field struct.
    println!(
        r#"{{"r_point":"{}","s_pre":"{}","signer_x":"{}"}}"#,
        hex::encode(pre_sig.r_point.serialize()),
        hex::encode(pre_sig.s_pre),
        hex::encode(signer_x.serialize()),
    );
    Ok(())
}

fn decrypt_btc_adaptor_cmd(
    pre_sig_r_point_hex: String,
    pre_sig_s_hex: String,
    adaptor_secret_hex: String,
    adaptor_point_hex: String,
) -> Result<(), String> {
    use coincync_swap::adaptor::{decrypt_btc_adaptor, AdaptorSecret, BtcAdaptorSig};

    let r_point_bytes = parse_hex_33("pre-sig-r-point", &pre_sig_r_point_hex)?;
    let s_pre = parse_hex_32("pre-sig-s", &pre_sig_s_hex)?;
    let adaptor_secret_bytes = parse_hex_32("adaptor-secret", &adaptor_secret_hex)?;
    let adaptor_point_bytes = parse_hex_33("adaptor-point", &adaptor_point_hex)?;

    // Reconstruct the BtcAdaptorSig from its byte components.
    // PublicKey::from_slice validates the compressed-secp256k1
    // encoding (parity prefix byte + 32-byte x-coord).
    let r_point = bitcoin::secp256k1::PublicKey::from_slice(&r_point_bytes)
        .map_err(|e| format!("pre-sig-r-point: not a valid compressed secp256k1 point: {e}"))?;
    let adaptor = BtcAdaptorSig { r_point, s_pre };

    let adaptor_pt = bitcoin::secp256k1::PublicKey::from_slice(&adaptor_point_bytes)
        .map_err(|e| format!("adaptor-point: not a valid compressed secp256k1 point: {e}"))?;

    let adaptor_secret = AdaptorSecret::from_secp256k1_bytes(adaptor_secret_bytes)
        .map_err(|e| format!("adaptor-secret: {e}"))?;

    let final_sig = decrypt_btc_adaptor(&adaptor, &adaptor_secret, &adaptor_pt)
        .map_err(|e| format!("decrypt_btc_adaptor: {e}"))?;

    println!("{}", hex::encode(final_sig));
    Ok(())
}

fn recover_secret_from_btc_sig_cmd(
    pre_sig_s_hex: String,
    final_sig_hex: String,
    acknowledged: bool,
) -> Result<(), String> {
    if !acknowledged {
        return Err("this subcommand prints a secret to stdout. Pass \
             --i-understand-this-is-a-secret to acknowledge you have safe stdout \
             handling (pipe directly to derive-cync-spender-secret, etc.) and \
             won't log the output."
            .into());
    }
    use coincync_swap::adaptor::{recover_secret_from_btc_sig, BtcAdaptorSig};

    let s_pre = parse_hex_32("pre-sig-s", &pre_sig_s_hex)?;
    let final_sig = parse_hex_64("final-sig", &final_sig_hex)?;

    // recover_secret_from_btc_sig only consumes adaptor.s_pre —
    // the r_point field is unused in the math (`t = s_real - s_pre`).
    // Synthesize a dummy r_point so we can build a BtcAdaptorSig
    // without requiring the caller to pass it; the secp256k1
    // generator is a valid compressed point and the cheapest
    // value that won't fail the from-slice check.
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    let one_secret = {
        let mut b = [0u8; 32];
        b[31] = 1;
        SecretKey::from_slice(&b).expect("hardcoded non-zero scalar")
    };
    let dummy_r_point = PublicKey::from_secret_key(&Secp256k1::new(), &one_secret);

    let adaptor = BtcAdaptorSig {
        r_point: dummy_r_point,
        s_pre,
    };

    let recovered = recover_secret_from_btc_sig(&adaptor, &final_sig)
        .map_err(|e| format!("recover_secret_from_btc_sig: {e}"))?;

    // `recover_secret_from_btc_sig` returns the AdaptorSecret in
    // Secp256k1BigEndian encoding — the natural form for BTC-side
    // operations. Output hex is BE. If the caller pipes into
    // `derive-cync-spender-secret`, that subcommand will need
    // the LE form — pipe through a byte-reverse stage, or wait
    // for a future `adaptor-secret-flip-endian` utility.
    println!("{}", hex::encode(recovered.secp256k1_bytes()));
    Ok(())
}

/// Apply an OBSERVATION transition to the persisted swap state.
/// Loads → applies → saves. Errors surface as `Error::Rpc` with
/// the underlying state-machine message (out-of-order transition,
/// role mismatch, terminal state).
/// Run the cryptographic self-test suite. Each check is a single
/// closure that returns `Result<(), String>`; we time it, print a
/// PASS/FAIL line, and accumulate failures. Returns Ok iff every
/// check passed.
fn selftest_cmd() -> Result<(), String> {
    use std::time::Instant;

    println!("cyncswap selftest — running cryptographic primitives…");
    println!();

    let mut failures = 0usize;
    let suite_start = Instant::now();

    macro_rules! check {
        ($label:expr, $body:expr) => {{
            let start = Instant::now();
            let result: std::result::Result<(), String> = (|| $body)();
            let elapsed = start.elapsed();
            match result {
                Ok(()) => {
                    println!(
                        "  PASS  [{:>6.2} ms]  {}",
                        elapsed.as_secs_f64() * 1000.0,
                        $label
                    );
                }
                Err(e) => {
                    println!(
                        "  FAIL  [{:>6.2} ms]  {}",
                        elapsed.as_secs_f64() * 1000.0,
                        $label
                    );
                    println!("        → {}", e);
                    failures += 1;
                }
            }
        }};
    }

    // ── 1. Fast cross-curve DLEQ round-trip ──
    check!("fast cross-curve DLEQ (dual-response Schoenmakers)", {
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        use coincync_swap::adaptor::{
            cync_adaptor_point, prove_cross_curve, verify_cross_curve_proof, AdaptorSecret,
        };
        let mut secret_le = [0u8; 32];
        secret_le[0] = 0x42;
        let secret = AdaptorSecret::from_ristretto_bytes(secret_le)
            .map_err(|e| format!("AdaptorSecret: {e:?}"))?;
        let secp = Secp256k1::new();
        let t_btc = PublicKey::from_secret_key(
            &secp,
            &SecretKey::from_slice(&secret.secp256k1_bytes())
                .map_err(|e| format!("SecretKey: {e}"))?,
        )
        .serialize();
        let t_cync = cync_adaptor_point(&secret).map_err(|e| format!("t_cync: {e:?}"))?;
        let mut nonce = [0u8; 32];
        nonce[0] = 0x11;
        let proof = prove_cross_curve(&secret, &t_btc, &t_cync, &nonce)
            .map_err(|e| format!("prove: {e:?}"))?;
        verify_cross_curve_proof(&proof, &t_btc, &t_cync).map_err(|e| format!("verify: {e:?}"))?;
        Ok(())
    });

    // ── 2. BTC Schnorr adaptor pre-sig → decrypt → recover round-trip ──
    check!("BTC Schnorr adaptor (pre-sig → decrypt → recover)", {
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        use coincync_swap::adaptor::{
            create_pre_sig_bip340, decrypt_btc_adaptor, recover_secret_from_btc_sig, AdaptorSecret,
        };
        let mut secret_le = [0u8; 32];
        secret_le[0] = 0x55;
        let secret = AdaptorSecret::from_ristretto_bytes(secret_le)
            .map_err(|e| format!("AdaptorSecret: {e:?}"))?;
        let secp = Secp256k1::new();
        let t_btc_pk = PublicKey::from_secret_key(
            &secp,
            &SecretKey::from_slice(&secret.secp256k1_bytes())
                .map_err(|e| format!("SecretKey for T: {e}"))?,
        );
        let mut signer_bytes = [0u8; 32];
        signer_bytes[31] = 1;
        signer_bytes[30] = 1;
        let signer_sk =
            SecretKey::from_slice(&signer_bytes).map_err(|e| format!("SecretKey signer: {e}"))?;
        let msg = [0x77u8; 32];
        let aux = [0xAAu8; 32];
        let (pre_sig, _signer_x) = create_pre_sig_bip340(&signer_sk, &msg, &t_btc_pk, &aux)
            .map_err(|e| format!("create_pre_sig_bip340: {e:?}"))?;
        let final_sig = decrypt_btc_adaptor(&pre_sig, &secret, &t_btc_pk)
            .map_err(|e| format!("decrypt: {e:?}"))?;
        let recovered = recover_secret_from_btc_sig(&pre_sig, &final_sig)
            .map_err(|e| format!("recover: {e:?}"))?;
        let _ = t_btc_pk; // not needed by recover; silence unused
        if recovered != secret {
            return Err("recovered secret does not equal original".into());
        }
        Ok(())
    });

    // ── 3. CYNC (Ristretto) adaptor round-trip ──
    check!("CYNC Ristretto adaptor (pre-sig → decrypt → recover)", {
        use coincync_swap::adaptor::{
            cync_adaptor_point, cync_create_pre_sig, cync_decrypt_adaptor, cync_recover_secret,
            AdaptorSecret,
        };
        let mut secret_le = [0u8; 32];
        secret_le[0] = 0x33;
        let secret = AdaptorSecret::from_ristretto_bytes(secret_le)
            .map_err(|e| format!("AdaptorSecret: {e:?}"))?;
        let t_cync = cync_adaptor_point(&secret).map_err(|e| format!("t_cync: {e:?}"))?;
        let mut signer_bytes = [0u8; 32];
        signer_bytes[0] = 0x88;
        let mut nonce_bytes = [0u8; 32];
        nonce_bytes[0] = 0x99;
        let msg = [0x66u8; 32];
        let (pre_sig, _signer_pub) =
            cync_create_pre_sig(&signer_bytes, &msg, &t_cync, &nonce_bytes)
                .map_err(|e| format!("cync_create_pre_sig: {e:?}"))?;
        let final_sig = cync_decrypt_adaptor(&pre_sig, &secret, &t_cync)
            .map_err(|e| format!("cync_decrypt: {e:?}"))?;
        let recovered = cync_recover_secret(&pre_sig, &final_sig)
            .map_err(|e| format!("cync_recover: {e:?}"))?;
        if recovered != secret {
            return Err("recovered secret does not equal original".into());
        }
        Ok(())
    });

    // ── 4. CYNC swap key-derivation round-trip ──
    check!("CYNC swap key-derivation (joint key ↔ joint secret)", {
        use coincync_swap::cync::{
            cync_adaptor_point_from_secret, derive_swap_recipient_spend_pub,
            derive_swap_spender_secret,
        };
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
        use curve25519_dalek::scalar::Scalar;

        // Bob's spend key share.
        let mut bob_secret = [0u8; 32];
        bob_secret[0] = 0x11;
        let bob_scalar = Scalar::from_canonical_bytes(bob_secret)
            .into_option()
            .ok_or("bob scalar canonical".to_string())?;
        let bob_pub = (&bob_scalar * RISTRETTO_BASEPOINT_TABLE)
            .compress()
            .to_bytes();

        // Alice's key share (the "adaptor secret t" in our framing).
        let mut t = [0u8; 32];
        t[0] = 0x22;
        let t_pub = cync_adaptor_point_from_secret(&t).map_err(|e| format!("t_pub: {e:?}"))?;

        // Joint key: S = bob_pub + t_pub
        let joint_pub = derive_swap_recipient_spend_pub(&bob_pub, &t_pub)
            .map_err(|e| format!("derive_swap_recipient: {e:?}"))?;

        // Joint secret: s = bob_secret + t. Must equal dlog of joint_pub.
        let joint_secret = derive_swap_spender_secret(&bob_secret, &t)
            .map_err(|e| format!("derive_swap_spender: {e:?}"))?;
        let joint_secret_scalar = Scalar::from_canonical_bytes(joint_secret)
            .into_option()
            .ok_or("joint_secret canonical".to_string())?;
        let joint_pub_from_secret = (&joint_secret_scalar * RISTRETTO_BASEPOINT_TABLE)
            .compress()
            .to_bytes();
        if joint_pub != joint_pub_from_secret {
            return Err("joint_secret · G ≠ joint_pub — derivation inconsistent".into());
        }
        Ok(())
    });

    // ── 5. Noise static pubkey derivation ──
    check!("Noise XX static-pubkey derivation (RFC 7748 clamping)", {
        let private = [0x42u8; 32];
        let pub1 = coincync_swap::coordinator::derive_noise_static_public(&private);
        let pub2 = coincync_swap::coordinator::derive_noise_static_public(&private);
        if pub1 != pub2 {
            return Err("derivation not deterministic".into());
        }
        if pub1 == [0u8; 32] {
            return Err("derivation produced identity point (likely bug)".into());
        }
        Ok(())
    });

    // ── 6. Strict-DLEQ round-trip (feature-gated) ──
    #[cfg(feature = "strict-dleq")]
    check!("strict cross-curve DLEQ (Noether 2018, ~81 KB proof)", {
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        use coincync_swap::adaptor::{cync_adaptor_point, AdaptorSecret};
        use coincync_swap::strict_dleq::{prove_cross_curve_strict, verify_cross_curve_strict};
        let mut secret_le = [0u8; 32];
        secret_le[0] = 0x42;
        let secret = AdaptorSecret::from_ristretto_bytes(secret_le)
            .map_err(|e| format!("AdaptorSecret: {e:?}"))?;
        let secp = Secp256k1::new();
        let t_btc = PublicKey::from_secret_key(
            &secp,
            &SecretKey::from_slice(&secret.secp256k1_bytes())
                .map_err(|e| format!("SecretKey: {e}"))?,
        )
        .serialize();
        let t_cync = cync_adaptor_point(&secret).map_err(|e| format!("t_cync: {e:?}"))?;
        let seed = [0x77u8; 32];
        let proof = prove_cross_curve_strict(&secret, &t_btc, &t_cync, &seed)
            .map_err(|e| format!("prove_strict: {e:?}"))?;
        verify_cross_curve_strict(&proof, &t_btc, &t_cync)
            .map_err(|e| format!("verify_strict: {e:?}"))?;
        Ok(())
    });

    println!();
    let total_ms = suite_start.elapsed().as_secs_f64() * 1000.0;
    if failures == 0 {
        println!("All checks PASSED ({:.2} ms total)", total_ms);
        Ok(())
    } else {
        println!("{} check(s) FAILED ({:.2} ms total)", failures, total_ms);
        Err(format!("selftest: {failures} failure(s)"))
    }
}

fn transition_cmd(state_path: PathBuf, kind: TransitionKind) -> Result<(), String> {
    let store = SwapStore::new(&state_path);
    let mut swap = match store.load().map_err(|e| format!("load failed: {e}"))? {
        Some(s) => s,
        None => {
            return Err(format!(
                "no swap state at {}. Run `cyncswap alice` or `cyncswap bob` first.",
                state_path.display()
            ));
        }
    };

    let before = swap.state;
    swap.apply(kind.to_protocol())
        .map_err(|e| format!("apply {:?}: {}", kind, e))?;
    let after = swap.state;
    store.save(&swap).map_err(|e| format!("save failed: {e}"))?;

    println!(
        "transition applied: {} → {}",
        state_string(before),
        state_string(after)
    );
    Ok(())
}

/// Generate a fresh 32-byte Curve25519 static key for the Noise XX
/// coordinator transport. Writes the raw bytes to `out` (or stdout
/// if `out` is None), and prints the derived public-key fingerprint
/// to stderr.
fn noise_keygen_cmd(out: Option<PathBuf>, i_understand: bool) -> Result<(), String> {
    use rand::RngCore;

    // If writing to stdout, force operator acknowledgment — the raw
    // private key would be visible in the terminal scrollback.
    if out.is_none() && !i_understand {
        return Err(
            "writing the private key to stdout requires --i-understand-this-is-a-secret \
             (or pass --out <path>)"
                .into(),
        );
    }

    let mut private = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut private);
    let public = coincync_swap::coordinator::derive_noise_static_public(&private);

    match out {
        Some(path) => {
            // Write the raw bytes to file. The operator is responsible
            // for chmod 0400 / icacls — we don't try to set perms
            // here because Windows vs Unix divergence isn't worth
            // the surface area for a single file.
            let path_display = path.display().to_string();
            std::fs::write(&path, private)
                .map_err(|e| format!("write private key to {path_display}: {e}"))?;
            eprintln!("wrote 32-byte Noise static private to {path_display}");
            eprintln!("REMEMBER to restrict permissions (chmod 0400 / icacls).");
            eprintln!(
                "public-key fingerprint (share out-of-band): {}",
                hex::encode(public)
            );
            println!("{}", hex::encode(public));
        }
        None => {
            // Stdout for both halves; operator already acknowledged.
            eprintln!(
                "public-key fingerprint (share out-of-band): {}",
                hex::encode(public)
            );
            println!("private:{}", hex::encode(private));
            println!("public:{}", hex::encode(public));
        }
    }
    Ok(())
}

/// Derive the Curve25519 public key from a stored 32-byte private.
/// Reads the private from either a file or a hex string, applies the
/// RFC 7748 X25519 clamping, prints the 64-char-hex public key on
/// stdout.
fn noise_pubkey_cmd(
    secret_file: Option<PathBuf>,
    secret_hex: Option<String>,
) -> Result<(), String> {
    let private: [u8; 32] = match (secret_file, secret_hex) {
        (Some(path), None) => {
            let path_display = path.display().to_string();
            let bytes = std::fs::read(&path)
                .map_err(|e| format!("read private key from {path_display}: {e}"))?;
            if bytes.len() != 32 {
                return Err(format!(
                    "private-key file {path_display} has length {} bytes, expected 32",
                    bytes.len()
                ));
            }
            bytes.try_into().expect("length-checked above")
        }
        (None, Some(hex)) => {
            let bytes =
                hex::decode(hex.trim()).map_err(|e| format!("secret-hex: not valid hex: {e}"))?;
            if bytes.len() != 32 {
                return Err(format!(
                    "secret-hex: decoded length {} bytes, expected 32",
                    bytes.len()
                ));
            }
            bytes.try_into().expect("length-checked above")
        }
        (Some(_), Some(_)) => {
            return Err("pass exactly one of --secret-file or --secret-hex (got both)".into());
        }
        (None, None) => {
            return Err("must pass one of --secret-file or --secret-hex".into());
        }
    };

    let public = coincync_swap::coordinator::derive_noise_static_public(&private);
    println!("{}", hex::encode(public));
    Ok(())
}

/// Build a `BtcConfig` from the CLI's RPC flag set. The two
/// auth flags are coupled: both or neither. Either-but-not-both
/// is rejected here rather than at the bitcoind-error layer.
fn build_btc_rpc_config(
    network: String,
    rpc_url: String,
    rpc_user: Option<String>,
    rpc_pass: Option<String>,
) -> Result<coincync_swap::btc::BtcConfig, String> {
    let rpc_auth = match (rpc_user, rpc_pass) {
        (Some(u), Some(p)) => Some((u, p)),
        (None, None) => None,
        (Some(_), None) => {
            return Err(
                "--rpc-user supplied without --rpc-pass; both required for basic-auth, \
                 or omit both for cookie-less / no-auth setups."
                    .into(),
            );
        }
        (None, Some(_)) => {
            return Err(
                "--rpc-pass supplied without --rpc-user; both required for basic-auth.".into(),
            );
        }
    };
    Ok(coincync_swap::btc::BtcConfig {
        network,
        rpc_url,
        rpc_auth,
    })
}

/// Build a `CyncConfig` from the CLI's RPC flag set. Simpler than
/// the BTC counterpart — CYNC RPC uses bearer-token auth, so there's
/// just one optional `--api-key` flag rather than a coupled pair.
fn build_cync_rpc_config(
    network: String,
    rpc_url: String,
    api_key: Option<String>,
) -> coincync_swap::cync::CyncConfig {
    coincync_swap::cync::CyncConfig {
        network,
        rpc_url,
        api_key,
    }
}

fn cync_broadcast_cmd(
    network: String,
    rpc_url: String,
    api_key: Option<String>,
    tx_hex: String,
) -> Result<(), String> {
    let config = build_cync_rpc_config(network, rpc_url, api_key);

    // tx_hex must be valid hex AND non-empty. Borsh decoding
    // happens on the node side; client-side we only enforce
    // hex-shape.
    let tx_bytes = hex::decode(tx_hex.trim()).map_err(|e| format!("tx-hex: not valid hex: {e}"))?;
    if tx_bytes.is_empty() {
        return Err("tx-hex: empty transaction bytes".into());
    }

    let txid_hex = coincync_swap::cync::broadcast(&config, &tx_bytes)
        .map_err(|e| format!("cync broadcast: {e}"))?;
    println!("{txid_hex}");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cync_watch_cmd(
    network: String,
    rpc_url: String,
    api_key: Option<String>,
    txid: String,
    confirmations: u32,
    timeout_secs: u64,
) -> Result<(), String> {
    let config = build_cync_rpc_config(network, rpc_url, api_key);

    // CyncTxid::from_hex tolerates an optional `0x` prefix; do
    // the same length check the BTC counterpart does for early
    // rejection of obviously-wrong input.
    let trimmed = txid.trim_start_matches("0x");
    if trimmed.len() != 64 {
        return Err(format!(
            "txid: expected 64-char hex string (optionally `0x`-prefixed), got {} chars after stripping prefix",
            trimmed.len()
        ));
    }

    coincync_swap::cync::wait_for_confirmations(&config, &txid, confirmations, timeout_secs)
        .map_err(|e| format!("cync watch: {e}"))?;
    Ok(())
}

fn btc_broadcast_cmd(
    network: String,
    rpc_url: String,
    rpc_user: Option<String>,
    rpc_pass: Option<String>,
    tx_hex: String,
) -> Result<(), String> {
    let config = build_btc_rpc_config(network, rpc_url, rpc_user, rpc_pass)?;

    // tx_hex must be valid hex AND non-empty. We don't validate
    // the consensus encoding here — bitcoind's
    // `sendrawtransaction` will reject malformed bytes with a
    // clear error, and validating client-side would duplicate
    // the bitcoin crate's deserialization that the construct-*
    // subcommands already exercised. The sync `broadcast`
    // wrapper takes raw bytes; decode from hex first.
    let tx_bytes = hex::decode(tx_hex.trim()).map_err(|e| format!("tx-hex: not valid hex: {e}"))?;
    if tx_bytes.is_empty() {
        return Err("tx-hex: empty transaction bytes".into());
    }

    // Sync wrapper in btc.rs spins up its own tokio runtime —
    // fine for one-shot CLI invocations. The swap state-machine
    // daemon (future) would use the async BtcChain trait
    // directly to avoid runtime per call.
    let txid_hex = coincync_swap::btc::broadcast(&config, &tx_bytes)
        .map_err(|e| format!("btc broadcast: {e}"))?;
    println!("{txid_hex}");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn btc_watch_cmd(
    network: String,
    rpc_url: String,
    rpc_user: Option<String>,
    rpc_pass: Option<String>,
    txid: String,
    confirmations: u32,
    timeout_secs: u64,
) -> Result<(), String> {
    let config = build_btc_rpc_config(network, rpc_url, rpc_user, rpc_pass)?;

    // Bitcoin Core's RPC uses byte-reversed-from-internal-hash
    // order for txids; we pass the user-supplied string through
    // as-is because the sync `wait_for_confirmations` wrapper
    // accepts the same display form (Txid::from_hex internally).
    if txid.len() != 64 {
        return Err(format!(
            "txid: expected 64-char hex string, got {} chars",
            txid.len()
        ));
    }

    coincync_swap::btc::wait_for_confirmations(&config, &txid, confirmations, timeout_secs)
        .map_err(|e| format!("btc watch: {e}"))?;
    // Silent success — scripts can chain on `&&` without parsing
    // structured output.
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn construct_btc_refund_cmd(
    network: String,
    lock_txid_hex: String,
    lock_vout: u32,
    lock_value_sats: u64,
    lock_internal_key_hex: String,
    refund_bob_pubkey_hex: String,
    refund_csv_blocks: u16,
    dest_address: String,
    fee_sats: u64,
    refund_signature_hex: String,
) -> Result<(), String> {
    use coincync_swap::btc::{build_refund_tx, BtcConfig, RefundBranch, RefundTxBase, Txid};

    // ── Parse + validate inputs ──────────────────────────────────
    let lock_txid_bytes = parse_hex_32("lock-txid", &lock_txid_hex)?;
    let lock_internal_key = parse_hex_32("lock-internal-key", &lock_internal_key_hex)?;
    let bob_pubkey = parse_hex_32("refund-bob-pubkey", &refund_bob_pubkey_hex)?;
    let refund_signature = parse_hex_64("refund-signature", &refund_signature_hex)?;

    let config = BtcConfig {
        network,
        rpc_url: "http://127.0.0.1:18443".into(),
        rpc_auth: None,
    };

    let base = RefundTxBase {
        lock_txid: Txid(lock_txid_bytes),
        lock_vout,
        lock_value_sats,
        lock_internal_key,
        refund_branch: RefundBranch {
            bob_pubkey,
            csv_blocks: refund_csv_blocks,
        },
        dest_address,
        fee_sats,
    };

    // ── Construct (with full BIP-340 verification) + emit ────────
    //
    // build_refund_tx's verification fires on:
    //   - signature under the wrong key (Bob signed with not-his-
    //     pubkey, or operator supplied a wrong refund_bob_pubkey);
    //   - signature over a different sighash (operator supplied
    //     wrong base parameters — wrong dest, fee, csv_blocks, etc);
    //   - malformed signature bytes.
    // Witness assembly produces the standard 3-element script-path
    // shape: [sig, refund_script, control_block].
    let bytes = build_refund_tx(&config, &base, &refund_signature)
        .map_err(|e| format!("build_refund_tx: {e}"))?;

    println!("{}", hex::encode(&bytes));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn construct_btc_claim_cmd(
    network: String,
    lock_txid_hex: String,
    lock_vout: u32,
    lock_value_sats: u64,
    lock_internal_key_hex: String,
    dest_address: String,
    fee_sats: u64,
    claim_signature_hex: String,
    refund_bob_pubkey_hex: Option<String>,
    refund_csv_blocks: Option<u16>,
) -> Result<(), String> {
    use coincync_swap::btc::{build_claim_tx, BtcConfig};

    let claim_signature = parse_hex_64("claim-signature", &claim_signature_hex)?;
    let base = parse_claim_tx_base(
        &lock_txid_hex,
        lock_vout,
        lock_value_sats,
        &lock_internal_key_hex,
        dest_address,
        fee_sats,
        refund_bob_pubkey_hex,
        refund_csv_blocks,
    )?;

    let config = BtcConfig {
        network,
        // build_claim_tx is pure construction + verification; no
        // RPC traffic. Placeholder URL gets the BtcConfig
        // constructor's URL-shape check past.
        rpc_url: "http://127.0.0.1:18443".into(),
        rpc_auth: None,
    };

    // ── Construct (with full BIP-340 verification) + emit ────────
    //
    // build_claim_tx's internal BIP-340 verify against the lock's
    // (possibly tweaked) output key + the BIP-341 sighash catches:
    //   - signature over a different sighash (caller passed wrong
    //     base parameters);
    //   - signature under a non-tweaked secret when the lock had
    //     a refund branch (caller forgot tweaked_claim_secret);
    //   - malformed / non-BIP-340 signature bytes;
    //   - mismatched refund-branch flags vs. the lock's actual tree.
    // All four collapse into one Verification error here rather
    // than a downstream `sendrawtransaction` rejection.
    let bytes = build_claim_tx(&config, &base, &claim_signature)
        .map_err(|e| format!("build_claim_tx: {e}"))?;

    println!("{}", hex::encode(&bytes));
    Ok(())
}

/// State-machine-aware orchestration: Bob broadcasts his BTC lock tx
/// and the swap transitions `AliceLocked → BobLocked`. Save-after-
/// broadcast posture: we apply the in-memory state transition and
/// then persist; if the persist fails, the swap is still on-chain
/// but the state file lags — operator runs `cyncswap status` to
/// recover. (The alternative — persist first, broadcast second —
/// would mean a save success followed by a broadcast failure
/// leaves the state file claiming a lock that doesn't exist on
/// chain, which is the strictly worse failure mode.)
#[allow(clippy::too_many_arguments)]
fn lock_btc_orchestration_cmd(
    state_path: PathBuf,
    network: String,
    rpc_url: String,
    rpc_user: Option<String>,
    rpc_pass: Option<String>,
    signed_tx_hex: String,
) -> Result<(), String> {
    use coincync_swap::protocol::{Role, State, Transition};

    let store = SwapStore::new(&state_path);
    let mut swap = match store.load().map_err(|e| format!("load failed: {e}"))? {
        Some(s) => s,
        None => {
            return Err(format!(
                "no swap state at {}. Run `cyncswap alice` or `cyncswap bob` first.",
                state_path.display()
            ));
        }
    };

    // Pre-check role + state. `Swap::apply` would catch these with
    // clear errors too, but pre-checking lets us bail BEFORE the
    // broadcast hits the network — preserving the "no on-chain
    // side-effect if the operator ran the wrong subcommand" invariant.
    if swap.role != Role::Bob {
        return Err(format!(
            "lock-btc is Bob's transition; this swap was initialized as {:?}",
            swap.role
        ));
    }
    if swap.state != State::AliceLocked {
        return Err(format!(
            "lock-btc requires state AliceLocked (after Alice broadcasts CYNC + Bob observes); \
             current state is {}",
            state_string(swap.state)
        ));
    }

    // Validate flag inputs early. Hex parse + non-empty check.
    let tx_bytes = hex::decode(signed_tx_hex.trim())
        .map_err(|e| format!("signed-tx-hex: not valid hex: {e}"))?;
    if tx_bytes.is_empty() {
        return Err("signed-tx-hex: empty transaction bytes".into());
    }
    let config = build_btc_rpc_config(network, rpc_url, rpc_user, rpc_pass)?;

    // Broadcast first, then transition + save. If broadcast fails,
    // state file is untouched; operator retries. If broadcast
    // succeeds but transition or save fails, the swap is on-chain
    // already and `cyncswap status` will surface the divergence.
    let txid_hex = coincync_swap::btc::broadcast(&config, &tx_bytes)
        .map_err(|e| format!("btc broadcast: {e}"))?;

    swap.apply(Transition::BobLocksBtc)
        .map_err(|e| format!("apply BobLocksBtc transition: {e}"))?;
    store
        .save(&swap)
        .map_err(|e| format!("save failed (NOTE: tx is on-chain, txid {txid_hex}): {e}"))?;

    println!(
        "lock-btc complete:\n  broadcast txid: {txid_hex}\n  new state:      {}",
        state_string(swap.state)
    );
    Ok(())
}

/// Drive Alice's BTC claim. State-machine-aware bundled command:
/// pre-checks `role=Alice` + `state=BobLocked`, broadcasts the
/// supplied signed claim tx, applies `AliceClaimsBtc`
/// (`BobLocked` → `SecretRevealed`), saves the state file.
///
/// Posture matches `lock_btc_orchestration_cmd`: broadcast first,
/// then transition + save. A broadcast failure leaves the state
/// file untouched; a save failure after a successful broadcast is
/// surfaced via `cyncswap status` (the chain has moved but the
/// local state hasn't). The `cancel` subcommand can rebuild the
/// local view from the state file the operator should now treat
/// as `SecretRevealed`.
///
/// Implication for Bob: once this command returns successfully,
/// the adaptor secret is reconstructable from Alice's witness via
/// `recover-secret-from-btc-sig`. Bob's chain watcher catches the
/// claim, advances his own swap to `SecretRevealed`, and the
/// `claim-cync` step becomes available to him.
#[allow(clippy::too_many_arguments)]
fn claim_btc_orchestration_cmd(
    state_path: PathBuf,
    network: String,
    rpc_url: String,
    rpc_user: Option<String>,
    rpc_pass: Option<String>,
    lock_txid_hex: String,
    lock_vout: u32,
    lock_internal_key_hex: String,
    dest_address: String,
    fee_sats: u64,
    refund_bob_pubkey_hex: Option<String>,
    refund_csv_blocks: Option<u16>,
    signed_tx_hex: String,
) -> Result<(), String> {
    use coincync_swap::protocol::{Role, State, Transition};

    let store = SwapStore::new(&state_path);
    let mut swap = match store.load().map_err(|e| format!("load failed: {e}"))? {
        Some(s) => s,
        None => {
            return Err(format!(
                "no swap state at {}. Run `cyncswap alice` or `cyncswap bob` first.",
                state_path.display()
            ));
        }
    };

    if swap.role != Role::Alice {
        return Err(format!(
            "claim-btc is Alice's transition; this swap was initialized as {:?}",
            swap.role
        ));
    }
    if swap.state != State::BobLocked {
        return Err(format!(
            "claim-btc requires state BobLocked (after Alice observes Bob's BTC lock); \
             current state is {}",
            state_string(swap.state)
        ));
    }

    let tx_bytes = hex::decode(signed_tx_hex.trim())
        .map_err(|e| format!("signed-tx-hex: not valid hex: {e}"))?;
    if tx_bytes.is_empty() {
        return Err("signed-tx-hex: empty transaction bytes".into());
    }
    // A second CLI amount would let one operator input validate another;
    // the persisted swap amount is the independent authority here.
    let base = parse_claim_tx_base(
        &lock_txid_hex,
        lock_vout,
        swap.parameters.btc_amount_sats,
        &lock_internal_key_hex,
        dest_address,
        fee_sats,
        refund_bob_pubkey_hex,
        refund_csv_blocks,
    )?;
    let config = build_btc_rpc_config(network, rpc_url, rpc_user, rpc_pass)?;
    coincync_swap::btc::validate_claim_tx(&config, &base, &tx_bytes)
        .map_err(|e| format!("signed claim does not match this swap: {e}"))?;

    let txid_hex = coincync_swap::btc::broadcast(&config, &tx_bytes)
        .map_err(|e| format!("btc broadcast: {e}"))?;

    swap.apply(Transition::AliceClaimsBtc)
        .map_err(|e| format!("apply AliceClaimsBtc transition: {e}"))?;
    store
        .save(&swap)
        .map_err(|e| format!("save failed (NOTE: tx is on-chain, txid {txid_hex}): {e}"))?;

    println!(
        "claim-btc complete:\n  broadcast txid: {txid_hex}\n  new state:      {}\n\
         note: the adaptor secret is now extractable from Alice's witness; Bob's chain\n\
         watcher will pick this up and advance Bob's swap to SecretRevealed.",
        state_string(swap.state)
    );
    Ok(())
}

/// Drive Alice's CYNC lock. State-machine-aware bundled command:
/// pre-checks `role=Alice` + `state=Negotiated`, broadcasts the
/// supplied signed CYNC lock tx, applies `AliceLocksCync`
/// (`Negotiated` → `AliceLocked`), saves the state file.
///
/// Posture matches `lock_btc_orchestration_cmd` /
/// `claim_btc_orchestration_cmd`: broadcast first, then transition
/// + save. A broadcast failure leaves the state file untouched;
/// a save failure after a successful broadcast is surfaced via
/// `cyncswap status` (the chain has moved but the local state
/// hasn't).
///
/// Implication for Bob: once this command returns successfully,
/// Bob's chain watcher catches the CYNC lock at the agreed
/// confirmation depth and advances Bob's swap to `AliceLocked`,
/// after which `lock-btc` becomes available to him.
fn lock_cync_orchestration_cmd(
    state_path: PathBuf,
    network: String,
    rpc_url: String,
    api_key: Option<String>,
    signed_tx_hex: String,
) -> Result<(), String> {
    use coincync_swap::protocol::{Role, State, Transition};

    let store = SwapStore::new(&state_path);
    let mut swap = match store.load().map_err(|e| format!("load failed: {e}"))? {
        Some(s) => s,
        None => {
            return Err(format!(
                "no swap state at {}. Run `cyncswap alice` or `cyncswap bob` first.",
                state_path.display()
            ));
        }
    };

    if swap.role != Role::Alice {
        return Err(format!(
            "lock-cync is Alice's transition; this swap was initialized as {:?}",
            swap.role
        ));
    }
    if swap.state != State::Negotiated {
        return Err(format!(
            "lock-cync requires state Negotiated (the freshly-initialized state); \
             current state is {}",
            state_string(swap.state)
        ));
    }

    let tx_bytes = hex::decode(signed_tx_hex.trim())
        .map_err(|e| format!("signed-tx-hex: not valid hex: {e}"))?;
    if tx_bytes.is_empty() {
        return Err("signed-tx-hex: empty transaction bytes".into());
    }
    let config = build_cync_rpc_config(network, rpc_url, api_key);

    let txid_hex = coincync_swap::cync::broadcast(&config, &tx_bytes)
        .map_err(|e| format!("cync broadcast: {e}"))?;

    swap.apply(Transition::AliceLocksCync)
        .map_err(|e| format!("apply AliceLocksCync transition: {e}"))?;
    store
        .save(&swap)
        .map_err(|e| format!("save failed (NOTE: tx is on-chain, txid {txid_hex}): {e}"))?;

    println!(
        "lock-cync complete:\n  broadcast txid: {txid_hex}\n  new state:      {}",
        state_string(swap.state)
    );
    Ok(())
}

/// Drive Bob's CYNC claim — the swap's final on-chain move.
/// State-machine-aware bundled command: pre-checks `role=Bob` +
/// `state=SecretRevealed`, broadcasts the supplied signed CYNC
/// claim tx, applies `BobClaimsCync` (`SecretRevealed` →
/// `Completed`), saves the state file.
///
/// Posture matches the other three orchestration handlers:
/// broadcast first, then transition + save. A broadcast failure
/// leaves the state file untouched; a save failure after a
/// successful broadcast is surfaced via `cyncswap status` (the
/// chain has moved but the local state hasn't).
///
/// Because `Completed` is a terminal state, no further
/// transitions are legal after this command returns successfully.
/// The operator's next move is `cyncswap status` to confirm the
/// swap is at `Completed` and the CYNC claim has reached the
/// agreed confirmation depth (`cync-watch` is the granular tool
/// for that).
fn claim_cync_orchestration_cmd(
    state_path: PathBuf,
    network: String,
    rpc_url: String,
    api_key: Option<String>,
    signed_tx_hex: String,
) -> Result<(), String> {
    use coincync_swap::protocol::{Role, State, Transition};

    let store = SwapStore::new(&state_path);
    let mut swap = match store.load().map_err(|e| format!("load failed: {e}"))? {
        Some(s) => s,
        None => {
            return Err(format!(
                "no swap state at {}. Run `cyncswap alice` or `cyncswap bob` first.",
                state_path.display()
            ));
        }
    };

    if swap.role != Role::Bob {
        return Err(format!(
            "claim-cync is Bob's transition; this swap was initialized as {:?}",
            swap.role
        ));
    }
    if swap.state != State::SecretRevealed {
        return Err(format!(
            "claim-cync requires state SecretRevealed (after Bob observes Alice's BTC claim \
             and recovers the adaptor secret); current state is {}",
            state_string(swap.state)
        ));
    }

    let tx_bytes = hex::decode(signed_tx_hex.trim())
        .map_err(|e| format!("signed-tx-hex: not valid hex: {e}"))?;
    if tx_bytes.is_empty() {
        return Err("signed-tx-hex: empty transaction bytes".into());
    }
    let config = build_cync_rpc_config(network, rpc_url, api_key);

    let txid_hex = coincync_swap::cync::broadcast(&config, &tx_bytes)
        .map_err(|e| format!("cync broadcast: {e}"))?;

    swap.apply(Transition::BobClaimsCync)
        .map_err(|e| format!("apply BobClaimsCync transition: {e}"))?;
    store
        .save(&swap)
        .map_err(|e| format!("save failed (NOTE: tx is on-chain, txid {txid_hex}): {e}"))?;

    println!(
        "claim-cync complete:\n  broadcast txid: {txid_hex}\n  new state:      {}\n\
         swap COMPLETED — no further transitions legal. Confirm finality with `cync-watch`.",
        state_string(swap.state)
    );
    Ok(())
}

/// Drive Bob's BTC refund. State-machine-aware bundled command:
/// pre-checks `role=Bob` + `state=BobLocked`, broadcasts the
/// supplied signed refund tx, applies `BobRefunds`
/// (`BobLocked` → `Refunded`), saves the state file.
///
/// Posture matches the other orchestration handlers: broadcast
/// first, then transition + save. Timeout enforcement is the
/// chain's job — bitcoind will reject the broadcast if the CSV
/// timeout has not yet elapsed; the orchestration layer does not
/// double-check.
///
/// `Refunded` is terminal: no further transitions are legal after
/// this command returns successfully.
fn refund_btc_orchestration_cmd(
    state_path: PathBuf,
    network: String,
    rpc_url: String,
    rpc_user: Option<String>,
    rpc_pass: Option<String>,
    signed_tx_hex: String,
) -> Result<(), String> {
    use coincync_swap::protocol::{Role, State, Transition};

    let store = SwapStore::new(&state_path);
    let mut swap = match store.load().map_err(|e| format!("load failed: {e}"))? {
        Some(s) => s,
        None => {
            return Err(format!(
                "no swap state at {}. Run `cyncswap alice` or `cyncswap bob` first.",
                state_path.display()
            ));
        }
    };

    if swap.role != Role::Bob {
        return Err(format!(
            "refund-btc is Bob's transition; this swap was initialized as {:?}",
            swap.role
        ));
    }
    if swap.state != State::BobLocked {
        return Err(format!(
            "refund-btc requires state BobLocked (after Bob's BTC lock confirmed); \
             current state is {}",
            state_string(swap.state)
        ));
    }

    let tx_bytes = hex::decode(signed_tx_hex.trim())
        .map_err(|e| format!("signed-tx-hex: not valid hex: {e}"))?;
    if tx_bytes.is_empty() {
        return Err("signed-tx-hex: empty transaction bytes".into());
    }
    let config = build_btc_rpc_config(network, rpc_url, rpc_user, rpc_pass)?;

    let txid_hex = coincync_swap::btc::broadcast(&config, &tx_bytes)
        .map_err(|e| format!("btc broadcast: {e}"))?;

    swap.apply(Transition::BobRefunds)
        .map_err(|e| format!("apply BobRefunds transition: {e}"))?;
    store
        .save(&swap)
        .map_err(|e| format!("save failed (NOTE: tx is on-chain, txid {txid_hex}): {e}"))?;

    println!(
        "refund-btc complete:\n  broadcast txid: {txid_hex}\n  new state:      {}\n\
         swap REFUNDED — no further transitions legal. Confirm finality with `btc-watch`.",
        state_string(swap.state)
    );
    Ok(())
}

/// Drive Alice's CYNC refund. State-machine-aware bundled
/// command: pre-checks `role=Alice` + state ∈ {`AliceLocked`,
/// `BobLocked`}, broadcasts the supplied signed refund tx,
/// applies `AliceRefunds` (any-of-{AliceLocked,BobLocked} →
/// `Refunded`), saves the state file.
///
/// Why two source states? CIP-001 §"Refund Paths": Alice can
/// refund whether Bob locked or not. If Bob never locked, Alice's
/// timeout on her CYNC lock fires and she reclaims directly. If
/// Bob locked but then disappeared (Alice never broadcast her
/// claim), the same refund path is available — Bob's BTC sits
/// dormant until his own (shorter) timeout fires and he reclaims
/// independently.
///
/// Posture matches the other orchestration handlers; timeout
/// enforcement is the chain's job.
///
/// `Refunded` is terminal.
fn refund_cync_orchestration_cmd(
    state_path: PathBuf,
    network: String,
    rpc_url: String,
    api_key: Option<String>,
    signed_tx_hex: String,
) -> Result<(), String> {
    use coincync_swap::protocol::{Role, State, Transition};

    let store = SwapStore::new(&state_path);
    let mut swap = match store.load().map_err(|e| format!("load failed: {e}"))? {
        Some(s) => s,
        None => {
            return Err(format!(
                "no swap state at {}. Run `cyncswap alice` or `cyncswap bob` first.",
                state_path.display()
            ));
        }
    };

    if swap.role != Role::Alice {
        return Err(format!(
            "refund-cync is Alice's transition; this swap was initialized as {:?}",
            swap.role
        ));
    }
    if !matches!(swap.state, State::AliceLocked | State::BobLocked) {
        return Err(format!(
            "refund-cync requires state AliceLocked or BobLocked (per CIP-001 §Refund Paths); \
             current state is {}",
            state_string(swap.state)
        ));
    }

    let tx_bytes = hex::decode(signed_tx_hex.trim())
        .map_err(|e| format!("signed-tx-hex: not valid hex: {e}"))?;
    if tx_bytes.is_empty() {
        return Err("signed-tx-hex: empty transaction bytes".into());
    }
    let config = build_cync_rpc_config(network, rpc_url, api_key);

    let txid_hex = coincync_swap::cync::broadcast(&config, &tx_bytes)
        .map_err(|e| format!("cync broadcast: {e}"))?;

    swap.apply(Transition::AliceRefunds)
        .map_err(|e| format!("apply AliceRefunds transition: {e}"))?;
    store
        .save(&swap)
        .map_err(|e| format!("save failed (NOTE: tx is on-chain, txid {txid_hex}): {e}"))?;

    println!(
        "refund-cync complete:\n  broadcast txid: {txid_hex}\n  new state:      {}\n\
         swap REFUNDED — no further transitions legal. Confirm finality with `cync-watch`.",
        state_string(swap.state)
    );
    Ok(())
}

// `on_chain_skeleton` was the NOT-YET-IMPLEMENTED placeholder for
// the four on-chain bundled commands. All four (`lock-cync`,
// `lock-btc`, `claim-btc`, `claim-cync`) are now wired through to
// real orchestration handlers, joined by `refund-btc` and
// `refund-cync` for the two refund-path transitions — the helper
// is gone with them.

// ──────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────

/// Resolve the state-file path. If the user provided one, use it
/// (after expanding any leading `~`). Otherwise fall back to
/// `<home>/.coincync/swap.json`, falling back further to
/// `./swap.json` if `$HOME` / `%USERPROFILE%` are unset.
fn resolve_state_path(opt: Option<PathBuf>) -> Result<PathBuf, String> {
    match opt {
        Some(path) => Ok(expand_tilde(path)),
        None => {
            let home = std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(PathBuf::from);
            match home {
                Some(h) => Ok(h.join(".coincync").join("swap.json")),
                None => {
                    eprintln!("warning: HOME / USERPROFILE not set; using ./swap.json");
                    Ok(PathBuf::from("swap.json"))
                }
            }
        }
    }
}

/// Expand a leading `~` to the user's home directory. POSIX +
/// Windows compatible. Other tilde patterns (e.g. `~user`) are
/// left as-is.
fn expand_tilde(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/").or_else(|| s.strip_prefix("~\\")) {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return PathBuf::from(home).join(rest);
        }
    }
    if s == "~" {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return PathBuf::from(home);
        }
    }
    path
}

/// Generate a fresh swap_id. UUID-style would be ideal, but the
/// crate currently has no `uuid` dep; pick a `time-secs +
/// process-id + small-random` form that's unique enough for
/// practical purposes (collision probability is functionally
/// zero unless two binaries start in the same second on the
/// same PID).
fn generate_swap_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let pid = std::process::id();
    // A tiny stir so two parallel CLI starts don't collide.
    let mut entropy = [0u8; 4];
    let _ = read_random(&mut entropy);
    let suffix = u32::from_le_bytes(entropy);
    format!("cyncswap-{secs:x}-{pid:x}-{suffix:x}")
}

fn read_random(buf: &mut [u8]) -> std::io::Result<()> {
    use std::io::Read;
    // /dev/urandom on Unix; CryptGenRandom-equivalent on Windows
    // would need winapi. Best-effort: try /dev/urandom; on
    // failure, fall back to a less-good source. Phase 2.5
    // doesn't need cryptographic randomness — swap_id collisions
    // are an operator inconvenience, not a security risk.
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        f.read_exact(buf)?;
        return Ok(());
    }
    // Fallback: derive from system time nanoseconds.
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    for (i, b) in buf.iter_mut().enumerate() {
        *b = ((nanos >> (i * 8)) & 0xff) as u8;
    }
    Ok(())
}

fn state_string(s: State) -> &'static str {
    match s {
        State::Negotiated => "Negotiated",
        State::AliceLocked => "AliceLocked",
        State::BobLocked => "BobLocked",
        State::SecretRevealed => "SecretRevealed",
        State::Completed => "Completed (terminal)",
        State::Refunded => "Refunded (terminal)",
        State::Aborted => "Aborted (terminal)",
    }
}

fn transition_hint(t: Transition) -> &'static str {
    match t {
        Transition::AliceLocksCync => "  (broadcast Alice's CYNC lock — `cyncswap lock-cync`)",
        Transition::BobLocksBtc => "  (broadcast Bob's BTC lock — `cyncswap lock-btc`)",
        Transition::AliceClaimsBtc => "  (broadcast Alice's BTC claim — `cyncswap claim-btc`)",
        Transition::BobClaimsCync => "  (broadcast Bob's CYNC claim — `cyncswap claim-cync`)",
        Transition::AliceRefunds => "  (Alice broadcasts CYNC refund)",
        Transition::BobRefunds => "  (Bob broadcasts BTC refund)",
        Transition::ObserveBobLocked => "  (auto on Bob's BTC lock confirming)",
        Transition::ObserveAliceLocked => "  (auto on Alice's CYNC lock confirming)",
        Transition::ObserveSecretRevealed => "  (auto on Alice's BTC claim confirming)",
        Transition::ObserveCompleted => "  (auto on Bob's CYNC claim confirming)",
        Transition::Abort => "  (`cyncswap cancel`)",
    }
}
