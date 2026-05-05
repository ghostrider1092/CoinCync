//! `cyncswap` — command-line driver for the CYNC↔BTC atomic swap.
//!
//! ## Status: SKELETON
//!
//! Every subcommand prints a human-readable explanation of what it
//! *will* do once the protocol implementation lands, then exits with
//! a non-zero status so scripts don't accidentally treat the skeleton
//! as a working tool. This keeps the CLI surface stable for the
//! eventual wallet UI integration while making it impossible to
//! mistake the skeleton for a real swap.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cyncswap")]
#[command(version)]
#[command(about = "CYNC↔BTC atomic swap (skeleton — not yet functional). See CIP-001 for design.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a new swap as Alice (sells CYNC, buys BTC).
    Alice {
        /// Listen endpoint for Bob to connect (e.g. `0.0.0.0:9999`).
        #[arg(long)]
        listen: String,
        /// Amount of CYNC to lock, in atomic units.
        #[arg(long)]
        cync_amount: u64,
        /// Amount of satoshis Bob will lock in return.
        #[arg(long)]
        btc_amount_sats: u64,
    },

    /// Initialize a new swap as Bob (sells BTC, buys CYNC).
    Bob {
        /// Connect to Alice's listening endpoint.
        #[arg(long)]
        connect: String,
        /// The swap ID Alice has shared with you out-of-band.
        #[arg(long)]
        swap_id: String,
    },

    /// Show status of an active swap (loaded from the on-disk state file).
    Status {
        /// Path to the swap-state JSON file (default: `~/.coincync/swap.json`).
        #[arg(long)]
        state_file: Option<String>,
    },

    /// Cancel an active swap and walk it through the refund path.
    /// Refund is always available before the chain timeout fires;
    /// after the timeout, refund is automatic.
    Cancel {
        /// Path to the swap-state JSON file.
        #[arg(long)]
        state_file: Option<String>,
    },

    /// Print the version of CIP-001 this skeleton tracks. Useful for
    /// verifying the binary matches the design doc on disk.
    DesignVersion,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Alice { listen, cync_amount, btc_amount_sats } => {
            print_skeleton_notice(
                "alice",
                &format!(
                    "Would listen on {listen} for Bob, offering {cync_amount} atomic CYNC \
                     in exchange for {btc_amount_sats} sats."
                ),
            );
        }
        Command::Bob { connect, swap_id } => {
            print_skeleton_notice(
                "bob",
                &format!(
                    "Would connect to Alice at {connect} and join swap session {swap_id}."
                ),
            );
        }
        Command::Status { state_file } => {
            let path = state_file.unwrap_or_else(|| "~/.coincync/swap.json".into());
            print_skeleton_notice(
                "status",
                &format!("Would load swap state from {path} and print current state + legal next transitions."),
            );
        }
        Command::Cancel { state_file } => {
            let path = state_file.unwrap_or_else(|| "~/.coincync/swap.json".into());
            print_skeleton_notice(
                "cancel",
                &format!("Would walk swap at {path} through the refund path. Funds are recoverable in all states."),
            );
        }
        Command::DesignVersion => {
            // Tracks the CIP this skeleton implements against. Bump
            // when the implementation moves to a newer CIP revision.
            println!("CIP-001 (atomic-swap) — skeleton revision");
            println!("Implementation status: NONE. See docs/cip/CIP-001-atomic-swap.md for the design spec.");
        }
    }
}

fn print_skeleton_notice(stage: &str, what_it_would_do: &str) {
    eprintln!("┌─ cyncswap: skeleton mode ─────────────────────────────────");
    eprintln!("│ stage:  {stage}");
    eprintln!("│ status: NOT YET IMPLEMENTED");
    eprintln!("│");
    eprintln!("│ {what_it_would_do}");
    eprintln!("│");
    eprintln!("│ Working swaps are a v1.0 mainnet launch blocker, not a");
    eprintln!("│ testnet feature. See docs/cip/CIP-001-atomic-swap.md");
    eprintln!("│ for the protocol design and implementation roadmap.");
    eprintln!("└───────────────────────────────────────────────────────────");
    std::process::exit(2);
}
