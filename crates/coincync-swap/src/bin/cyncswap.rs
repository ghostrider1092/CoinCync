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

use clap::{Parser, Subcommand};

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

#[derive(Subcommand)]
enum Command {
    /// Initialize a new swap as Alice (sells CYNC, buys BTC).
    /// Persists initial state to the state file; a fresh swap_id
    /// is printed on stdout for out-of-band sharing with Bob.
    Alice {
        /// Listen endpoint for Bob to connect (placeholder for
        /// phase 3; not used in phase 2.5).
        #[arg(long)]
        listen: String,
        /// Amount of CYNC to lock, in atomic units.
        #[arg(long)]
        cync_amount: u64,
        /// Amount of satoshis Bob will lock in return.
        #[arg(long)]
        btc_amount_sats: u64,
        /// CYNC stealth address Alice will eventually be paid to.
        /// Placeholder string in phase 2.5 — phase 3 will validate.
        #[arg(long, default_value = "alice-cync-addr-placeholder")]
        alice_cync_address: String,
        /// BTC P2WPKH address Bob will eventually be paid to.
        /// Placeholder in phase 2.5.
        #[arg(long, default_value = "bob-btc-addr-placeholder")]
        bob_btc_address: String,
        /// State file. Defaults to `~/.coincync/swap.json`.
        #[arg(long)]
        state_file: Option<PathBuf>,
    },

    /// Initialize a new swap as Bob (sells BTC, buys CYNC).
    /// Persists initial state. In phase 2.5, parameters must
    /// match Alice's exactly (out-of-band agreement); in
    /// production, Bob receives them via the negotiation
    /// handshake.
    Bob {
        /// Connect to Alice's listening endpoint (placeholder for
        /// phase 3; not used in phase 2.5).
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

    /// Show status of an active swap (loaded from the on-disk
    /// state file).
    Status {
        /// State file. Defaults to `~/.coincync/swap.json`.
        #[arg(long)]
        state_file: Option<PathBuf>,
    },

    /// Cancel an active swap by transitioning it to `Aborted`.
    /// This works only PRE-LOCK in phase 2.5 (no on-chain
    /// activity to walk back yet); post-lock cancel becomes
    /// "broadcast the pre-signed refund tx" in phase 3.
    Cancel {
        /// State file. Defaults to `~/.coincync/swap.json`.
        #[arg(long)]
        state_file: Option<PathBuf>,
    },

    /// Drive Alice's CYNC lock. **SKELETON in phase 2.5** —
    /// constructs no on-chain transaction. Phase 3 wires
    /// `cync.rs` in.
    LockCync {
        #[arg(long)]
        state_file: Option<PathBuf>,
    },

    /// Drive Bob's BTC lock. **SKELETON in phase 2.5.**
    LockBtc {
        #[arg(long)]
        state_file: Option<PathBuf>,
    },

    /// Drive Alice's BTC claim. **SKELETON in phase 2.5.**
    ClaimBtc {
        #[arg(long)]
        state_file: Option<PathBuf>,
    },

    /// Drive Bob's CYNC claim. **SKELETON in phase 2.5.**
    ClaimCync {
        #[arg(long)]
        state_file: Option<PathBuf>,
    },

    /// Print the version of CIP-001 this skeleton tracks.
    DesignVersion,
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
        Command::Status { state_file } => status_cmd(resolve_state_path(state_file)?),
        Command::Cancel { state_file } => cancel_cmd(resolve_state_path(state_file)?),
        Command::LockCync { state_file } => on_chain_skeleton(
            "LockCync (Alice)",
            "broadcast Alice's CYNC lock tx",
            resolve_state_path(state_file)?,
        ),
        Command::LockBtc { state_file } => on_chain_skeleton(
            "LockBtc (Bob)",
            "broadcast Bob's BTC lock tx",
            resolve_state_path(state_file)?,
        ),
        Command::ClaimBtc { state_file } => on_chain_skeleton(
            "ClaimBtc (Alice)",
            "broadcast Alice's BTC claim",
            resolve_state_path(state_file)?,
        ),
        Command::ClaimCync { state_file } => on_chain_skeleton(
            "ClaimCync (Bob)",
            "broadcast Bob's CYNC claim",
            resolve_state_path(state_file)?,
        ),
        Command::DesignVersion => {
            println!("CIP-001 (atomic-swap) — phase 2.5 (state machine + persistence)");
            println!("Implementation status:");
            println!("  - protocol state machine: shipped");
            println!("  - handshake state machine: shipped");
            println!("  - state persistence:       shipped");
            println!("  - adaptor signatures:      not yet (phase 3)");
            println!("  - BTC + CYNC tx construction: not yet (phase 3)");
            println!("  - transport (Tor/Noise):   not yet (phase 3)");
            println!("See docs/cip/CIP-001-atomic-swap.md for the design spec.");
            Ok(())
        }
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
    };
    let swap = Swap::negotiate(id.clone(), Role::Alice, params)
        .map_err(|e| format!("swap construction failed: {e}"))?;
    store.save(&swap).map_err(|e| format!("save failed: {e}"))?;

    println!("Swap initialized as Alice.");
    println!("  swap_id:    {id}");
    println!("  state:      {}", state_string(swap.state));
    println!("  state file: {}", state_path.display());
    println!("  listen:     {listen} (phase-3 placeholder; not yet active)");
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
    store
        .save(&next)
        .map_err(|e| format!("save failed: {e}"))?;
    swap = next;

    println!("Swap cancelled.");
    println!("  prior state: {}", state_string(prior_state));
    println!("  new state:   {}", state_string(swap.state));
    if matches!(prior_state, State::AliceLocked | State::BobLocked) {
        println!();
        println!("Note: an on-chain lock was active at cancel time. In phase 3 (when");
        println!("the cryptographic primitives ship), this CLI will broadcast the");
        println!("pre-signed refund transaction automatically. Until then, you must");
        println!("manually broadcast your refund tx using the wallet binary once the");
        println!("chain timeout has elapsed.");
    }
    Ok(())
}

fn on_chain_skeleton(
    cmd_name: &str,
    what_it_would_do: &str,
    state_path: PathBuf,
) -> Result<(), String> {
    let store = SwapStore::new(&state_path);
    let swap = match store.load().map_err(|e| format!("load failed: {e}"))? {
        Some(s) => s,
        None => {
            return Err(format!(
                "no swap state at {}. Run `cyncswap alice` or `cyncswap bob` first.",
                state_path.display()
            ));
        }
    };

    eprintln!("┌─ cyncswap: {cmd_name} (skeleton in phase 2.5) ────────────");
    eprintln!("│ swap_id:  {}", swap.id);
    eprintln!("│ role:     {:?}", swap.role);
    eprintln!("│ state:    {}", state_string(swap.state));
    eprintln!("│ status:   on-chain operations NOT YET IMPLEMENTED");
    eprintln!("│");
    eprintln!("│ This subcommand will eventually:");
    eprintln!("│   - {what_it_would_do}");
    eprintln!("│   - Apply the corresponding state transition");
    eprintln!("│   - Re-save the state file");
    eprintln!("│");
    eprintln!("│ Phase 3 (post-launch) wires `adaptor.rs`, `btc.rs`, and");
    eprintln!("│ `cync.rs` into this code path. Until then, this binary");
    eprintln!("│ exits non-zero so scripts cannot mistake the skeleton");
    eprintln!("│ for a working operation.");
    eprintln!("└────────────────────────────────────────────────────────────");
    Err("on-chain operation not yet implemented (phase 3 work)".into())
}

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
