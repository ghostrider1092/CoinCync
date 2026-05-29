//! `cynchubd` — CyncHub daemon CLI (skeleton).
//!
//! ## Status: SKELETON
//!
//! Every subcommand currently prints "not implemented yet" and exits
//! non-zero. The CLI surface is declared so operators can write their
//! systemd units / ansible / docker-compose files against stable
//! command shapes while the chain implementation lands in slices.
//!
//! Subcommands (provisional, will be tightened against CIP-002 §"Wallet
//! UX" and the eventual operator docs):
//!
//! - `cynchubd start` — start the daemon: SPV light clients, consensus
//!   node, orderbook sync, RPC server.
//! - `cynchubd status` — print current tip height + sync status.
//! - `cynchubd orderbook` — dump the current orderbook to stdout.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cynchubd")]
#[command(about = "CyncHub daemon — merge-mined PoW liquidity layer for CYNC↔BTC trades (skeleton)")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the CyncHub daemon (consensus + SPV + orderbook + RPC).
    Start,
    /// Print current sync status: CyncHub tip height, BTC tip height,
    /// CYNC tip height.
    Status,
    /// Dump the current CyncHub orderbook to stdout (JSON).
    Orderbook,
    /// Print the crate-level `is_implemented()` sentinel. Returns 0
    /// once the full V1 implementation has shipped + been audited.
    /// Lets ops scripts gate user-facing features on real readiness.
    SkeletonStatus,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Start => {
            eprintln!("cynchubd: start — not implemented yet (CIP-002 skeleton).");
            std::process::exit(2);
        }
        Commands::Status => {
            eprintln!("cynchubd: status — not implemented yet (CIP-002 skeleton).");
            std::process::exit(2);
        }
        Commands::Orderbook => {
            eprintln!("cynchubd: orderbook — not implemented yet (CIP-002 skeleton).");
            std::process::exit(2);
        }
        Commands::SkeletonStatus => {
            if cynchub::is_implemented() {
                println!("cynchub: implemented = true");
                std::process::exit(0);
            } else {
                println!("cynchub: implemented = false (skeleton — see CIP-002)");
                std::process::exit(1);
            }
        }
    }
}
