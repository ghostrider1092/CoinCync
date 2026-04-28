//! Stratum banlist inspector/maintenance utility.
//!
//! Usage examples:
//!   cargo run --bin stratum_ban_tool -- list --file stratum_bans.json
//!   cargo run --bin stratum_ban_tool -- clear-ip --file stratum_bans.json --ip 203.0.113.10
//!   cargo run --bin stratum_ban_tool -- clear-expired --file stratum_bans.json
//!   cargo run --bin stratum_ban_tool -- clear-all --file stratum_bans.json

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedBanEntry {
    score: u32,
    banned_until: u64,
    last_seen: u64,
}

#[derive(Parser)]
#[command(name = "stratum_ban_tool")]
#[command(about = "Inspect and clear CoinCync persistent Stratum bans")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List all ban entries.
    List {
        #[arg(long, default_value = "stratum_bans.json")]
        file: PathBuf,
    },
    /// Remove one IP entry from banlist.
    ClearIp {
        #[arg(long, default_value = "stratum_bans.json")]
        file: PathBuf,
        #[arg(long)]
        ip: String,
    },
    /// Remove all entries whose ban has expired.
    ClearExpired {
        #[arg(long, default_value = "stratum_bans.json")]
        file: PathBuf,
    },
    /// Remove all entries.
    ClearAll {
        #[arg(long, default_value = "stratum_bans.json")]
        file: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::List { file } => {
            let bans = load_banlist(&file)?;
            if bans.is_empty() {
                println!("No Stratum ban entries.");
                return Ok(());
            }
            let now = now_secs();
            let mut entries: Vec<_> = bans.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            for (ip, e) in entries {
                let state = if e.banned_until > now { "BANNED" } else { "not-banned" };
                println!(
                    "{}  state={}  score={}  banned_until={}  last_seen={}",
                    ip, state, e.score, e.banned_until, e.last_seen
                );
            }
        }
        Command::ClearIp { file, ip } => {
            let mut bans = load_banlist(&file)?;
            let existed = bans.remove(&ip).is_some();
            save_banlist(&file, &bans)?;
            if existed {
                println!("Removed entry for {}", ip);
            } else {
                println!("No entry for {}", ip);
            }
        }
        Command::ClearExpired { file } => {
            let mut bans = load_banlist(&file)?;
            let before = bans.len();
            let now = now_secs();
            bans.retain(|_, v| v.banned_until > now);
            let removed = before.saturating_sub(bans.len());
            save_banlist(&file, &bans)?;
            println!("Removed {} expired entries", removed);
        }
        Command::ClearAll { file } => {
            save_banlist(&file, &HashMap::new())?;
            println!("Cleared all Stratum ban entries.");
        }
    }
    Ok(())
}

fn load_banlist(path: &PathBuf) -> Result<HashMap<String, PersistedBanEntry>, Box<dyn std::error::Error>> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let raw = fs::read_to_string(path)?;
    let parsed = serde_json::from_str(&raw)?;
    Ok(parsed)
}

fn save_banlist(
    path: &PathBuf,
    bans: &HashMap<String, PersistedBanEntry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let raw = serde_json::to_string_pretty(bans)?;
    fs::write(path, raw)?;
    Ok(())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
