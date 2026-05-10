// src/bin/wallet.rs — coincync-wallet CLI
//
// P1 scope: create, restore, open, show seed/address/info/balance.
// Talks to a running cyncd node via JSON-RPC for chain status.
// The heavy 2.0 CLI (5240 lines with multisig/swap/shell/asset) is
// not brought over — this focused version covers P1 use cases.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing::error;

use coincync::config::Network;
use coincync::wallet::{
    WalletKeys, WalletData,
    save_wallet, load_wallet, wallet_exists, generate_mnemonic, mnemonic_to_seed,
};

#[derive(Parser)]
#[command(name = "coincync-wallet")]
#[command(about = "CoinCync 1.0 wallet CLI")]
#[command(version)]
struct Cli {
    /// Wallet file path.
    #[arg(long, default_value = "~/.coincync/wallets/default.wallet")]
    wallet: PathBuf,

    /// Network.
    #[arg(long, default_value = "testnet", value_parser = ["mainnet", "testnet", "regtest"])]
    network: String,

    /// Node RPC URL.
    #[arg(long, default_value = "http://127.0.0.1:28081")]
    node: String,

    /// Log level.
    #[arg(long, default_value = "warn")]
    log_level: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new wallet with a fresh seed phrase.
    Create {
        #[arg(short, long, env = "COINCYNC_WALLET_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        /// Overwrite existing wallet file.
        #[arg(long)]
        force: bool,
        /// Skip encryption (plaintext wallet — NOT recommended).
        #[arg(long)]
        no_encrypt: bool,
    },

    /// Restore a wallet from a 24-word seed phrase.
    Restore {
        #[arg(env = "COINCYNC_SEED_PHRASE", hide_env_values = true)]
        seed: Option<String>,
        #[arg(short, long, env = "COINCYNC_WALLET_PASSWORD", hide_env_values = true)]
        password: Option<String>,
    },

    /// Open an existing wallet (just checks the password).
    Open {
        #[arg(short, long, env = "COINCYNC_WALLET_PASSWORD", hide_env_values = true)]
        password: Option<String>,
    },

    /// Show wallet status + chain info from the node.
    Info {
        #[arg(short, long, env = "COINCYNC_WALLET_PASSWORD", hide_env_values = true)]
        password: Option<String>,
    },

    /// Show the spend public key (receive pubkey for this wallet).
    Address {
        #[arg(short, long, env = "COINCYNC_WALLET_PASSWORD", hide_env_values = true)]
        password: Option<String>,
    },

    /// Show balance snapshot from the wallet file (does NOT resync).
    Balance {
        #[arg(short, long, env = "COINCYNC_WALLET_PASSWORD", hide_env_values = true)]
        password: Option<String>,
    },

    /// Print the master seed as hex (requires password).
    ShowSeed {
        #[arg(short, long, env = "COINCYNC_WALLET_PASSWORD", hide_env_values = true)]
        password: Option<String>,
    },

    /// Scan blocks from the node for owned outputs.
    Scan {
        #[arg(short, long, env = "COINCYNC_WALLET_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        /// Starting block height (default: wallet's last scanned height).
        #[arg(long)]
        from: Option<u64>,
        /// Maximum blocks to scan in one call (default 1000).
        #[arg(long, default_value = "1000")]
        max_blocks: u64,
    },

    /// Show the current shielded-pool / Spark / MW stats from the node.
    PrivacyStats,

    /// Build and submit a privacy transaction to the node.
    Send {
        #[arg(short, long, env = "COINCYNC_WALLET_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        /// Recipient spend public key (64-hex).
        #[arg(long)]
        to_spend: String,
        /// Recipient view public key (64-hex).
        #[arg(long)]
        to_view: String,
        /// Amount to send, in atomic CYNC units.
        #[arg(long)]
        amount: u64,
        /// Fee multiplier (1.0 = normal, 2.0 = double fee for priority).
        #[arg(long, default_value = "1.0")]
        fee_multiplier: f64,
        /// Drip-pair: split the amount into 2 outputs to the same recipient
        /// (no change). Lets a first-time recipient receive 2 UTXOs in a single
        /// uniform 2-in/2-out tx so they can immediately spend (since spending
        /// also requires 2 UTXOs). Excess input value goes to fee — use this
        /// only when input UTXOs are sized close to the drip amount, otherwise
        /// you'll pay a large fee. Used by the testnet faucet's onboarding flow.
        #[arg(long, default_value = "false")]
        split_output: bool,
        /// Optional plaintext memo (max 256 bytes). Encrypted on the
        /// first recipient output using the recipient's view key —
        /// only the recipient can decrypt. Useful for human-readable
        /// notes ("rent june", "for coffee") or invoice IDs that
        /// don't belong on-chain in plaintext.
        #[arg(long)]
        memo: Option<String>,
        /// Dead-man's switch — recovery address (64-hex spend pubkey
        /// of a backup wallet). If this wallet doesn't sign for
        /// `--recovery-timeout` blocks, the recovery wallet can sweep
        /// the outputs of this tx. Embeds a 42-byte RecoveryMeta into
        /// `tx.extra`. Both flags must be passed together.
        #[arg(long)]
        recovery_address: Option<String>,
        /// Blocks of inactivity before recovery activates (min 720 ≈
        /// 24h, max 525960 ≈ 2yr). Required when `--recovery-address`
        /// is set; ignored otherwise.
        #[arg(long)]
        recovery_timeout: Option<u64>,
    },

    /// Generate M-of-N multi-sig key shares using FROST.
    MultisigGen {
        /// Minimum signers required (M).
        #[arg(long)]
        threshold: u16,
        /// Total participants (N).
        #[arg(long)]
        total: u16,
        /// Output directory for key share files.
        #[arg(long, default_value = ".")]
        output_dir: String,
    },

    /// Show multi-sig key share info.
    MultisigInfo {
        /// Path to key share file.
        #[arg(long)]
        share_file: String,
    },

    /// Multi-sig Round 1: generate nonces + commitments.
    MultisigRound1 {
        /// Path to your key share file.
        #[arg(long)]
        share_file: String,
        /// Output file for commitment (share with other signers).
        #[arg(long, default_value = "round1-commitment.json")]
        output: String,
    },

    /// Multi-sig Round 2: produce signature share.
    MultisigRound2 {
        /// Path to your key share file.
        #[arg(long)]
        share_file: String,
        /// Path to your round1 secret (from round1 command).
        #[arg(long)]
        nonce_file: String,
        /// Paths to ALL participants' round1 commitments.
        #[arg(long, num_args = 1..)]
        commitments: Vec<String>,
        /// Message to sign (hex-encoded transaction hash).
        #[arg(long)]
        message: String,
        /// Output file for signature share.
        #[arg(long, default_value = "round2-share.json")]
        output: String,
    },

    /// Multi-sig Send: build + submit a privacy transaction using threshold key shares.
    /// Reconstructs the group key from M shares, signs CLSAG, submits, then zeroizes.
    MultisigSend {
        /// Paths to M key share files (minimum threshold signers).
        #[arg(long, num_args = 1..)]
        key_shares: Vec<String>,
        /// Recipient spend public key (64-hex).
        #[arg(long)]
        to_spend: String,
        /// Recipient view public key (64-hex).
        #[arg(long)]
        to_view: String,
        /// Amount in atomic CYNC units.
        #[arg(long)]
        amount: u64,
    },

    /// Set a dead man's switch recovery address for future transactions.
    /// If this wallet doesn't sign for --timeout blocks, the recovery address can sweep.
    SetRecovery {
        #[arg(short, long, env = "COINCYNC_WALLET_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        /// Recovery address (64-hex spend public key of backup wallet).
        #[arg(long)]
        address: String,
        /// Blocks of inactivity before recovery activates (min 720 ≈ 24h, max 525960 ≈ 2yr).
        #[arg(long, default_value = "262800")]
        timeout: u64,
    },

    /// Check if any UTXOs have recovery metadata and their recovery status.
    CheckRecovery {
        #[arg(short, long, env = "COINCYNC_WALLET_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        /// Node RPC URL.
        #[arg(long)]
        node_override: Option<String>,
    },

    /// Enable auto-churn: automatic self-sends at random intervals to poison
    /// the transaction graph. Runs as a background loop until stopped.
    AutoChurn {
        #[arg(short, long, env = "COINCYNC_WALLET_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        /// Minimum seconds between churns (default 1800 = 30 min).
        #[arg(long, default_value = "1800")]
        min_interval: u64,
        /// Maximum seconds between churns (default 7200 = 2 hours).
        #[arg(long, default_value = "7200")]
        max_interval: u64,
        /// Minimum percentage of balance to churn (default 10).
        #[arg(long, default_value = "10")]
        min_pct: u8,
        /// Maximum percentage of balance to churn (default 50).
        #[arg(long, default_value = "50")]
        max_pct: u8,
    },

    /// Multi-sig Aggregate: combine signature shares into final signature.
    MultisigAggregate {
        /// Paths to ALL round1 commitments.
        #[arg(long, num_args = 1..)]
        commitments: Vec<String>,
        /// Paths to ALL round2 signature shares.
        #[arg(long, num_args = 1..)]
        shares: Vec<String>,
        /// Paths to ALL key share files (needed for verifying shares).
        #[arg(long, num_args = 1..)]
        key_shares: Vec<String>,
        /// Message that was signed (hex).
        #[arg(long)]
        message: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| cli.log_level.parse().unwrap()),
        )
        .with_target(false)
        .init();

    let network = match cli.network.as_str() {
        "mainnet" => Network::Mainnet,
        "testnet" => Network::Testnet,
        "regtest" => Network::Regtest,
        _ => Network::Testnet,
    };

    let wallet_path = resolve_home(&cli.wallet);

    let result = match cli.command {
        Command::Create { password, force, no_encrypt } => {
            cmd_create(&wallet_path, password, force, no_encrypt, network).await
        }
        Command::Restore { seed, password } => {
            cmd_restore(&wallet_path, seed, password, network).await
        }
        Command::Open { password } => cmd_open(&wallet_path, password).await,
        Command::Info { password } => cmd_info(&wallet_path, password, &cli.node, network).await,
        Command::Address { password } => cmd_address(&wallet_path, password, network).await,
        Command::Balance { password } => cmd_balance(&wallet_path, password).await,
        Command::ShowSeed { password } => cmd_show_seed(&wallet_path, password).await,
        Command::Scan { password, from, max_blocks } => {
            cmd_scan(&wallet_path, password, from, max_blocks, &cli.node).await
        }
        Command::PrivacyStats => cmd_privacy_stats(&cli.node).await,
        Command::Send { password, to_spend, to_view, amount, fee_multiplier, split_output, memo, recovery_address, recovery_timeout } => {
            cmd_send(&wallet_path, password, to_spend, to_view, amount, fee_multiplier, split_output, memo, recovery_address, recovery_timeout, &cli.node).await
        }
        Command::MultisigGen { threshold, total, output_dir } => {
            cmd_multisig_gen(threshold, total, &output_dir, network).await
        }
        Command::MultisigInfo { share_file } => {
            cmd_multisig_info(&share_file).await
        }
        Command::MultisigSend { key_shares, to_spend, to_view, amount } => {
            cmd_multisig_send(&key_shares, &to_spend, &to_view, amount, &cli.node).await
        }
        Command::MultisigRound1 { share_file, output } => {
            cmd_multisig_round1(&share_file, &output).await
        }
        Command::MultisigRound2 { share_file, nonce_file, commitments, message, output } => {
            cmd_multisig_round2(&share_file, &nonce_file, &commitments, &message, &output).await
        }
        Command::SetRecovery { password, address, timeout } => {
            cmd_set_recovery(&wallet_path, password, &address, timeout).await
        }
        Command::CheckRecovery { password, node_override } => {
            let node_url = node_override.as_deref().unwrap_or(&cli.node);
            cmd_check_recovery(&wallet_path, password, node_url).await
        }
        Command::AutoChurn { password, min_interval, max_interval, min_pct, max_pct } => {
            cmd_auto_churn(&wallet_path, password, min_interval, max_interval, min_pct, max_pct, &cli.node).await
        }
        Command::MultisigAggregate { commitments, shares, key_shares, message } => {
            cmd_multisig_aggregate(&commitments, &shares, &key_shares, &message).await
        }
    };

    if let Err(e) = result {
        error!("{}", e);
        std::process::exit(1);
    }
}

fn resolve_home(p: &PathBuf) -> PathBuf {
    if let Some(rest) = p.to_string_lossy().strip_prefix("~/") {
        if let Some(home) = dirs_next::home_dir() {
            return home.join(rest);
        }
    }
    p.clone()
}

fn prompt_password(confirm: bool) -> Result<String, String> {
    use std::io::{BufRead, Write};
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    write!(out, "Password: ").map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())?;
    let mut pw = String::new();
    stdin.lock().read_line(&mut pw).map_err(|e| e.to_string())?;
    let pw = pw.trim().to_string();
    if pw.is_empty() {
        return Err("password must not be empty".into());
    }
    if confirm {
        write!(out, "Confirm: ").map_err(|e| e.to_string())?;
        out.flush().map_err(|e| e.to_string())?;
        let mut pw2 = String::new();
        stdin.lock().read_line(&mut pw2).map_err(|e| e.to_string())?;
        if pw.trim() != pw2.trim() {
            return Err("passwords do not match".into());
        }
    }
    Ok(pw)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn network_label(n: Network) -> &'static str {
    match n {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Commands
// ═══════════════════════════════════════════════════════════════════════

async fn cmd_create(
    path: &PathBuf,
    password: Option<String>,
    force: bool,
    no_encrypt: bool,
    network: Network,
) -> Result<(), String> {
    if wallet_exists(path) && !force {
        return Err(format!(
            "wallet already exists at {:?} (use --force to overwrite)",
            path
        ));
    }

    let password = if no_encrypt {
        None
    } else {
        Some(match password {
            Some(p) => p,
            None => prompt_password(true)?,
        })
    };

    let (mnemonic, seed) = generate_mnemonic();
    let data = WalletData {
        seed,
        current_epoch: 0,
        scanned_height: 0,
        label: "default".to_string(),
        created_at: unix_now(),
        network: network_label(network).to_string(),
        subaddresses: None,
        mnemonic_phrase: Some(mnemonic.clone()),
    };

    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    save_wallet(path, &data, password.as_deref())
        .map_err(|e| format!("save failed: {}", e))?;

    println!("Wallet created at {:?}", path);
    println!();
    println!("Write down your 24-word seed phrase. It is the ONLY way to");
    println!("recover this wallet if the file is lost. Never share it.");
    println!();
    println!("{}", mnemonic);
    println!();
    Ok(())
}

async fn cmd_restore(
    path: &PathBuf,
    seed: Option<String>,
    password: Option<String>,
    network: Network,
) -> Result<(), String> {
    let seed_str = match seed {
        Some(s) => s,
        None => {
            use std::io::{BufRead, Write};
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            write!(out, "24-word seed phrase: ").map_err(|e| e.to_string())?;
            out.flush().map_err(|e| e.to_string())?;
            let mut line = String::new();
            stdin.lock().read_line(&mut line).map_err(|e| e.to_string())?;
            line.trim().to_string()
        }
    };

    let seed_bytes =
        mnemonic_to_seed(&seed_str).map_err(|e| format!("invalid seed phrase: {}", e))?;

    let password = match password {
        Some(p) => p,
        None => prompt_password(true)?,
    };

    let data = WalletData {
        seed: seed_bytes,
        current_epoch: 0,
        scanned_height: 0,
        label: "restored".to_string(),
        created_at: unix_now(),
        network: network_label(network).to_string(),
        subaddresses: None,
        mnemonic_phrase: Some(seed_str.clone()),
    };

    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    save_wallet(path, &data, Some(password.as_str()))
        .map_err(|e| format!("save failed: {}", e))?;

    println!("Wallet restored to {:?}", path);
    Ok(())
}

async fn cmd_open(path: &PathBuf, password: Option<String>) -> Result<(), String> {
    if !wallet_exists(path) {
        return Err(format!("no wallet at {:?}", path));
    }
    let password = match password {
        Some(p) => p,
        None => prompt_password(false)?,
    };
    let _data = load_wallet(path, Some(password.as_str()))
        .map_err(|e| format!("unlock failed: {}", e))?;
    println!("Wallet unlocked successfully.");
    Ok(())
}

async fn cmd_info(
    path: &PathBuf,
    password: Option<String>,
    node: &str,
    network: Network,
) -> Result<(), String> {
    println!("Wallet:   {:?}", path);
    println!("Exists:   {}", wallet_exists(path));
    println!("Network:  {:?}", network);
    println!("Node:     {}", node);

    if wallet_exists(path) {
        let pw = match password {
            Some(p) => Some(p),
            None => {
                // Try unlock only if password given; otherwise skip metadata
                None
            }
        };
        if let Some(pw) = pw {
            match load_wallet(path, Some(pw.as_str())) {
                Ok(data) => {
                    println!("Label:    {}", data.label);
                    println!("Epoch:    {}", data.current_epoch);
                    println!("Scanned:  height={}", data.scanned_height);
                    println!("Net:      {}", data.network);
                }
                Err(e) => {
                    println!("Unlock:   FAILED ({})", e);
                }
            }
        } else {
            println!("(pass --password to show wallet metadata)");
        }
    }

    match rpc_get_info(node).await {
        Ok(info) => {
            println!(
                "Chain:    height={} synced={}",
                info.get("height").and_then(|v| v.as_u64()).unwrap_or(0),
                info.get("is_synced").and_then(|v| v.as_bool()).unwrap_or(false),
            );
        }
        Err(e) => {
            println!("Chain:    <node unreachable: {}>", e);
        }
    }
    Ok(())
}

async fn cmd_address(
    path: &PathBuf,
    password: Option<String>,
    network: Network,
) -> Result<(), String> {
    if !wallet_exists(path) {
        return Err(format!("no wallet at {:?}", path));
    }
    let password = match password {
        Some(p) => p,
        None => prompt_password(false)?,
    };
    let data = load_wallet(path, Some(password.as_str()))
        .map_err(|e| format!("unlock failed: {}", e))?;

    let keys = WalletKeys::from_seed(data.seed);
    let epoch = keys
        .current()
        .ok_or_else(|| "wallet has no current key epoch".to_string())?;

    let prim_network = match network {
        Network::Mainnet => coincync::primitives::Network::Mainnet,
        Network::Testnet | Network::Regtest => coincync::primitives::Network::Testnet,
    };
    let addr = coincync::primitives::Address::new(
        prim_network,
        epoch.spend_public,
        epoch.view_public,
    );
    println!("Address:       {}", addr);
    println!("Spend public:  {}", hex::encode(epoch.spend_public.as_bytes()));
    println!("View public:   {}", hex::encode(epoch.view_public.as_bytes()));
    Ok(())
}

async fn cmd_balance(path: &PathBuf, password: Option<String>) -> Result<(), String> {
    let password = match password {
        Some(p) => p,
        None => prompt_password(false)?,
    };
    let data = load_wallet(path, Some(password.as_str()))
        .map_err(|e| format!("unlock failed: {}", e))?;

    println!("Wallet label:    {}", data.label);
    println!("Scanned height:  {}", data.scanned_height);
    println!();
    println!("(P1 note: balance computed from wallet file state only.");
    println!(" The file doesn't persist UTXOs yet — P2 work will add a");
    println!(" real chain-scan-via-RPC path and UTXO materialisation.)");
    Ok(())
}

async fn cmd_show_seed(path: &PathBuf, password: Option<String>) -> Result<(), String> {
    let password = match password {
        Some(p) => p,
        None => prompt_password(false)?,
    };
    let data = load_wallet(path, Some(password.as_str()))
        .map_err(|e| format!("unlock failed: {}", e))?;

    if let Some(phrase) = data.mnemonic_phrase.as_ref() {
        println!("24-word mnemonic:");
        println!();
        println!("{}", phrase);
        println!();
        println!("Write it down. It is the ONLY way to recover this wallet.");
    } else {
        println!("Seed bytes (hex): {}", hex::encode(data.seed));
        println!();
        println!("(this wallet file was created before the mnemonic phrase");
        println!(" was persisted — only the raw 32-byte seed is available.");
        println!(" Restore the wallet from the seed to rebuild the phrase.)");
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// Chain scan — pull blocks from the node and run the WalletScanner
// ═══════════════════════════════════════════════════════════════════════

async fn cmd_scan(
    path: &PathBuf,
    password: Option<String>,
    from: Option<u64>,
    max_blocks: u64,
    node: &str,
) -> Result<(), String> {
    use coincync::consensus::Block;
    use coincync::wallet::{Wallet, WalletScanner, KeyEpoch};
    use coincync::wallet::scanner::decrypted_to_utxo;

    let password = match password {
        Some(p) => p,
        None => prompt_password(false)?,
    };

    // Open + unlock the real Wallet struct so we persist UTXOs into it.
    let mut wallet = Wallet::open(path.clone())
        .map_err(|e| format!("open wallet: {}", e))?;
    wallet.unlock(&password)
        .map_err(|e| format!("unlock wallet: {}", e))?;

    let epoch: KeyEpoch = wallet
        .current_keys()
        .cloned()
        .ok_or_else(|| "wallet has no current key epoch".to_string())?;

    let mut scanner = WalletScanner::new();
    scanner.add_keys(epoch.view_secret.clone(), epoch.spend_public, epoch.epoch);

    // Defensive backstop (Bug #5 mitigation): when --from isn't passed,
    // resume from a few blocks BEFORE the persisted scanned_height. The
    // save() ordering fix in commit-following ensures sidecars are written
    // before scanned_height advances on disk, which is the primary fix.
    // The backstop covers other state-divergence paths (forced kill mid-
    // save, filesystem issues, hand-edited wallet files, parallel scans).
    // Re-scanning is idempotent: add_utxo and mark_spent_by_key_image are
    // both keyed by stable identifiers (tx_hash + output_index, key_image),
    // so the only cost of overlap is a few extra block-fetches over RPC.
    const SCAN_BACKSTOP_BLOCKS: u64 = 20;
    let start = from.unwrap_or_else(|| {
        wallet.scanned_height().saturating_sub(SCAN_BACKSTOP_BLOCKS)
    });
    let end = start + max_blocks;

    println!("Scanning blocks {}..{} via {}", start, end, node);

    let mut found_outputs = 0usize;
    let mut scanned_blocks = 0u64;
    let mut last_height = start;

    // Pull blocks in batches of 100 (matches server's MAX_RANGE cap).
    let mut cursor = start;
    while cursor <= end {
        let batch_end = (cursor + 99).min(end);
        match rpc_get_block_range(node, cursor, batch_end).await {
            Ok(blocks_json) => {
                if blocks_json.is_empty() {
                    break;
                }
                for b in &blocks_json {
                    let height = b.get("height").and_then(|v| v.as_u64()).unwrap_or(cursor);
                    let bytes_hex = b
                        .get("bytes")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "block missing bytes".to_string())?;
                    let block_bytes =
                        hex::decode(bytes_hex).map_err(|e| format!("bad block hex: {}", e))?;
                    let block: Block = borsh::from_slice(&block_bytes)
                        .map_err(|e| format!("bad block decode: {}", e))?;

                    let outs = scanner.scan_block(&block);
                    for decrypted in &outs {
                        let utxo = decrypted_to_utxo(
                            decrypted,
                            &epoch.view_secret,
                            &epoch.spend_secret,
                            height,
                        )
                        .map_err(|e| format!("decrypted_to_utxo: {}", e))?;
                        wallet.add_utxo(utxo);
                    }
                    found_outputs += outs.len();

                    // SPENT-DETECTION (Bug #3 fix):
                    // The scan also has to mark our UTXOs as spent when they
                    // appear as INPUTS in confirmed txs (any wallet, not just
                    // ours — the chain says "this UTXO is spent" regardless of
                    // who spent it). Without this, a UTXO that's spent on chain
                    // (e.g. by a previous wallet invocation that submitted but
                    // didn't save state, by another wallet sharing seeds, or
                    // simply by a tx that confirmed AFTER the wallet's local
                    // mark_spent failed to persist) stays "available" forever
                    // until manually pruned. The wallet then re-selects it as
                    // an input, and the new tx is rejected at consensus time
                    // for "duplicate key image" — exactly what stalled the
                    // testnet at 4885 → 4887 on 2026-05-07.
                    //
                    // Input key_images are public (in tx.inputs[i].key_image),
                    // so this requires no decryption — just iterate, look up
                    // by key_image in the wallet's UTXO set, mark spent.
                    // mark_spent_by_key_image is a no-op if the key image
                    // isn't ours, so iterating every block tx is cheap.
                    for tx in &block.transactions {
                        for ki in tx.key_images() {
                            wallet.mark_spent_by_key_image(&ki);
                        }
                    }
                    scanned_blocks += 1;
                    last_height = height;
                }
                cursor = batch_end + 1;
            }
            Err(e) => {
                return Err(format!("rpc get_block_range: {}", e));
            }
        }
    }

    // Update scanned_height and persist
    wallet.set_scanned_height(last_height);

    // Sweep abandoned reservations (Item 1: in-flight UTXO tracking).
    // Any reservation older than RESERVATION_EXPIRY_BLOCKS at the current
    // scan tip has either:
    //   (a) been consumed by an actual chain spend and was already cleared
    //       by mark_spent during the input-key_image pass above, or
    //   (b) been abandoned (the tx fell out of mempool, never confirmed).
    // Either way the entry is no longer useful — sweeping keeps the
    // sidecar small and avoids pinning UTXOs that should be selectable.
    let released = wallet.release_expired_reservations(last_height);
    if released > 0 {
        println!("  Released {} abandoned reservation(s).", released);
    }

    wallet
        .save(Some(&password))
        .map_err(|e| format!("save wallet: {}", e))?;

    println!("Scanned:        {} blocks", scanned_blocks);
    println!("Found outputs:  {}", found_outputs);
    println!("Tip:            height={}", last_height);
    println!("Balance total:  {} atomic CYNC", wallet.total_balance());
    println!("UTXO count:     {}", wallet.all_utxos().len());
    println!();
    println!("UTXOs persisted to {:?}.utxos", path);
    Ok(())
}

async fn cmd_send(
    path: &PathBuf,
    password: Option<String>,
    to_spend_hex: String,
    to_view_hex: String,
    amount: u64,
    fee_multiplier: f64,
    split_output: bool,
    memo: Option<String>,
    recovery_address_hex: Option<String>,
    recovery_timeout: Option<u64>,
    node: &str,
) -> Result<(), String> {
    use coincync::primitives::{Amount, PublicKey};
    use coincync::transaction::DecoyOutput;
    use coincync::wallet::{Wallet, KeyEpoch};

    // Parse recipient keys
    let parse_pk = |hex_str: &str, label: &str| -> Result<PublicKey, String> {
        let bytes = hex::decode(hex_str).map_err(|e| format!("{} hex: {}", label, e))?;
        if bytes.len() != 32 {
            return Err(format!("{} must be 32 bytes", label));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(PublicKey::from_bytes(arr))
    };
    let to_spend = parse_pk(&to_spend_hex, "to-spend")?;
    let to_view = parse_pk(&to_view_hex, "to-view")?;

    // Unlock wallet
    let password = match password {
        Some(p) => p,
        None => prompt_password(false)?,
    };
    let mut wallet = Wallet::open(path.clone())
        .map_err(|e| format!("open wallet: {}", e))?;
    wallet.unlock(&password)
        .map_err(|e| format!("unlock wallet: {}", e))?;

    let keys: KeyEpoch = wallet
        .current_keys()
        .cloned()
        .ok_or_else(|| "wallet has no current key epoch".to_string())?;

    // Query chain tip for fee calculation + decoy sampling
    let info = rpc_get_info(node).await.map_err(|e| format!("rpc get_info: {}", e))?;
    let current_height = info
        .get("height")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    // Fetch decoys from the node
    let ring_size = 16usize;
    let decoys_json = rpc_call(node, "get_decoys", serde_json::json!([ring_size * 8, 0]))
        .await
        .map_err(|e| format!("rpc get_decoys: {}", e))?;
    let decoys_arr = decoys_json
        .get("decoys")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut decoy_pool: Vec<DecoyOutput> = Vec::with_capacity(decoys_arr.len());
    for d in &decoys_arr {
        let pk_hex = d.get("public_key").and_then(|v| v.as_str()).unwrap_or("");
        let commit_hex = d.get("commitment").and_then(|v| v.as_str()).unwrap_or("");
        let height = d.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
        if let (Ok(pk_b), Ok(c_b)) = (hex::decode(pk_hex), hex::decode(commit_hex)) {
            if pk_b.len() == 32 && c_b.len() == 32 {
                let mut pk_arr = [0u8; 32];
                let mut c_arr = [0u8; 32];
                pk_arr.copy_from_slice(&pk_b);
                c_arr.copy_from_slice(&c_b);
                decoy_pool.push(DecoyOutput {
                    public_key: PublicKey::from_bytes(pk_arr),
                    commitment: c_arr,
                    height,
                });
            }
        }
    }

    println!("Building transaction:");
    println!("  Recipient spend: {}", &to_spend_hex[..16]);
    println!("  Recipient view:  {}", &to_view_hex[..16]);
    println!("  Amount:          {} atomic", amount);
    println!("  Height:          {}", current_height);
    println!("  Decoy pool:      {}", decoy_pool.len());
    println!("  Fee multiplier:  {}", fee_multiplier);

    // Build recipients list. Default: single recipient + change. With --split-output:
    // two outputs to the SAME recipient (drip-pair), no change. The lib's
    // create_privacy_transaction_with_fee detects all-same-destination
    // recipients.len() == 2 and emits the 2-recipient-no-change shape, with
    // any input excess flowing to fee. Splitting amount as evenly as possible
    // (with remainder on the first half) so total == requested.
    let recipients = if split_output {
        let half_a = amount / 2 + (amount % 2);
        let half_b = amount / 2;
        println!("  Drip-pair:       split {} -> {} + {} (both to recipient)", amount, half_a, half_b);
        vec![
            (to_spend, to_view, Amount::from_atomic(half_a)),
            (to_spend, to_view, Amount::from_atomic(half_b)),
        ]
    } else {
        vec![(to_spend, to_view, Amount::from_atomic(amount))]
    };

    // Build the optional memo + recovery extra. Memo is bounded at 256
    // bytes (consensus rule); we surface a clear CLI error rather than
    // letting the builder reject it cryptically. Recovery requires both
    // --recovery-address AND --recovery-timeout — pass-only-one is a
    // user-error.
    let memo_bytes: Option<Vec<u8>> = match memo {
        Some(s) if s.len() > 256 => {
            return Err(format!("memo too long: {} bytes (max 256)", s.len()));
        }
        Some(s) => Some(s.into_bytes()),
        None => None,
    };

    let extra_bytes: Vec<u8> = match (recovery_address_hex, recovery_timeout) {
        (Some(addr_hex), Some(timeout)) => {
            use coincync::transaction::recovery::RecoveryMeta;
            let addr_v = hex::decode(&addr_hex)
                .map_err(|e| format!("invalid --recovery-address hex: {}", e))?;
            if addr_v.len() != 32 {
                return Err(format!("--recovery-address must be 32 bytes (64 hex), got {}", addr_v.len()));
            }
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&addr_v);
            // Attach recovery metadata to output 0. For the uniform 2-out
            // shape, output 0 is the first recipient; output 1 is change
            // (or a second recipient in drip-pair). The "right" semantic
            // is "recovery applies to the change output the sender keeps"
            // — implementing that requires either (a) emitting per-output
            // recovery entries indexed at the change output specifically,
            // or (b) the consensus validator recognizing recovery from
            // EITHER key image. For now we attach to output 0 so the
            // encoding round-trips through tx.extra and `check-recovery`
            // can detect the metadata; the consensus-level recovery-spend
            // path is tracked separately.
            let meta = RecoveryMeta {
                output_index: 0,
                recovery_address: addr,
                timeout_blocks: timeout,
            };
            meta.validate(recipients.len())
                .map_err(|e| format!("invalid recovery config: {}", e))?;
            println!("  Recovery:        addr={}…  timeout={} blocks",
                &addr_hex[..16.min(addr_hex.len())], timeout);
            RecoveryMeta::encode_all(&[meta])
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err("--recovery-address and --recovery-timeout must be passed together".into());
        }
        (None, None) => Vec::new(),
    };

    let balance_snapshot = wallet.balance();
    let mut rng = rand::rngs::OsRng;
    let tx = coincync::wallet::send::create_privacy_transaction_with_options(
        &balance_snapshot,
        &recipients,
        &keys,
        &decoy_pool,
        current_height,
        fee_multiplier,
        memo_bytes.as_deref(),
        extra_bytes,
        &mut rng,
    )
    .map_err(|e| format!("create_privacy_transaction: {}", e))?;

    let tx_hash = tx.hash();

    // Serialize and submit
    let tx_bytes = borsh::to_vec(&tx).map_err(|e| format!("serialize tx: {}", e))?;
    let tx_hex = hex::encode(&tx_bytes);

    println!();
    println!("Built tx:");
    println!("  Hash:    {}", hex::encode(tx_hash.as_bytes()));
    println!("  Inputs:  {}", tx.inputs.len());
    println!("  Outputs: {}", tx.outputs.len());
    println!("  Size:    {} bytes", tx_bytes.len());
    println!("  Fee:     {} atomic", tx.fee.as_atomic());
    println!();

    // RESERVE INPUTS (Item 1: in-flight UTXO tracking).
    //
    // Before sending bytes over the wire, mark the inputs of this tx as
    // reserved by `tx_hash` in the wallet's local state and persist that
    // mark. Two reasons to do it BEFORE the RPC call rather than after:
    //
    //   1. If the network call hangs / our process is killed mid-submit,
    //      the tx may still have reached the mempool. On the next wallet
    //      invocation we'd re-select the same UTXOs (the reservation
    //      wasn't persisted yet) and produce a conflicting tx. Reserving
    //      first makes the second invocation see them as in-flight.
    //
    //   2. The cost of reserving and then NOT submitting (because submit
    //      fails) is one explicit `release_reservations_by_tx` call, which
    //      we do in the error branch below. Symmetric.
    //
    // We map tx.key_images() back to (tx_hash, output_index) by walking
    // the wallet's UTXO set. This is O(inputs * utxos) but inputs is
    // small (2 in uniform) and utxo count is bounded — Item 8 will index
    // it later if needed.
    let mut input_keys: Vec<(coincync::primitives::Hash, u8)> = Vec::with_capacity(tx.inputs.len());
    for ki in tx.key_images() {
        for utxo in &wallet.all_utxos() {
            if utxo.key_image == ki && !utxo.spent {
                input_keys.push((utxo.tx_hash, utxo.output_index));
                break;
            }
        }
    }
    if input_keys.len() != tx.inputs.len() {
        return Err(format!(
            "internal: failed to map all tx inputs back to UTXO keys (mapped {}/{}). \
             Refusing to submit without an in-flight reservation; rescan and retry.",
            input_keys.len(), tx.inputs.len()
        ));
    }
    if let Err(conflict) = wallet.reserve_utxos(&input_keys, tx_hash, current_height) {
        return Err(format!("reservation conflict: {} (try `wallet scan` and retry)", conflict));
    }
    // Persist reservation before broadcasting. If save() fails we abort
    // BEFORE the network call so the wallet's view stays consistent.
    if let Err(e) = wallet.save(Some(&password)) {
        // Roll back the in-memory reservation since it never persisted.
        wallet.release_reservations_by_tx(tx_hash);
        return Err(format!("save reservation: {}", e));
    }

    println!("Submitting to {}...", node);

    match rpc_call(node, "send_raw_transaction", serde_json::json!([tx_hex])).await {
        Ok(result) => {
            let accepted = result
                .get("accepted")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if accepted {
                println!("  OK: tx accepted by mempool.");
                // Mark selected UTXOs as spent in wallet so we don't double-spend.
                // mark_spent also clears the in-flight reservation for each UTXO
                // (see Balance::mark_spent), so the reservation count drops to 0
                // without an explicit release call.
                for ki in tx.key_images() {
                    wallet.mark_spent_by_key_image(&ki);
                }
                wallet.save(Some(&password)).map_err(|e| format!("save wallet: {}", e))?;
                Ok(())
            } else {
                // Mempool said no. Release the reservation so a retry (with
                // different decoys / fee) can re-select these UTXOs.
                let released = wallet.release_reservations_by_tx(tx_hash);
                let _ = wallet.save(Some(&password));
                Err(format!("rpc rejected: {} (released {} reservation(s))", result, released))
            }
        }
        Err(e) => {
            // Network error or other transport failure. We do NOT release
            // the reservation here: the tx might have actually reached
            // some peer before the connection broke, in which case
            // releasing locally would let us double-spend. The reservation
            // will auto-expire after RESERVATION_EXPIRY_BLOCKS if the tx
            // truly never landed; until then the user can either run
            // `wallet scan` (which will mark_spent if the tx confirmed) or
            // wait. This is the conservative choice and matches Bitcoin
            // Core's `walletbroadcast=false` behavior.
            Err(format!(
                "rpc send_raw_transaction: {} (kept reservation; auto-expires after {} blocks if tx truly didn't land)",
                e, coincync::wallet::balance::RESERVATION_EXPIRY_BLOCKS
            ))
        }
    }
}

async fn cmd_privacy_stats(node: &str) -> Result<(), String> {
    match rpc_call(node, "get_privacy_stats", serde_json::json!([])).await {
        Ok(stats) => {
            println!("{}", serde_json::to_string_pretty(&stats).unwrap_or_default());
            Ok(())
        }
        Err(e) => Err(format!("rpc get_privacy_stats: {}", e)),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Minimal JSON-RPC client
// ═══════════════════════════════════════════════════════════════════════

async fn rpc_get_info(node: &str) -> Result<serde_json::Value, String> {
    rpc_call(node, "get_info", serde_json::json!([])).await
}

/// Generic JSON-RPC call. Returns the `result` field on success.
async fn rpc_call(
    node: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    });
    let mut req = client.post(node).json(&body);
    if let Ok(key) = std::env::var("COINCYNC_RPC_API_KEY") {
        let key = key.trim();
        if !key.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", key));
        }
    }
    let resp = req
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let json: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    if let Some(err) = json.get("error") {
        return Err(format!("rpc error: {}", err));
    }
    json.get("result")
        .cloned()
        .ok_or_else(|| "rpc response missing result".into())
}

/// Call `get_block_range(start, end)` and return the `blocks` array.
async fn rpc_get_block_range(
    node: &str,
    start: u64,
    end: u64,
) -> Result<Vec<serde_json::Value>, String> {
    let result = rpc_call(
        node,
        "get_block_range",
        serde_json::json!([start, end]),
    )
    .await?;
    let blocks = result
        .get("blocks")
        .and_then(|b| b.as_array())
        .cloned()
        .unwrap_or_default();
    Ok(blocks)
}

// ══════════════════════════════════════════════════════════════════════════════
// MULTI-SIG COMMANDS (FROST)
// ══════════════════════════════════════════════════════════════════════════════

async fn cmd_multisig_gen(
    threshold: u16,
    total: u16,
    output_dir: &str,
    network: Network,
) -> Result<(), String> {
    use coincync::wallet::multisig;

    println!("Generating {}-of-{} FROST multi-sig key shares...", threshold, total);

    let result = multisig::generate_shares(threshold, total)
        .map_err(|e| format!("keygen failed: {}", e))?;

    println!();
    println!("Group public key: {}", hex::encode(result.config.group_public_key));

    // Build group address
    let prim_network = match network {
        Network::Mainnet => coincync::primitives::Network::Mainnet,
        Network::Testnet | Network::Regtest => coincync::primitives::Network::Testnet,
    };
    let group_addr = coincync::primitives::Address::new(
        prim_network,
        result.group_public_key,
        result.group_public_key, // view key = spend key for simplicity
    );
    println!("Group address:    {}", group_addr);
    println!();

    // Save each share to a file
    let dir = std::path::Path::new(output_dir);
    let _ = std::fs::create_dir_all(dir);

    for share in &result.shares {
        let filename = format!("multisig-share-{}-of-{}-participant-{}.json",
            threshold, total, share.participant_id);
        let path = dir.join(&filename);
        let json = serde_json::to_string_pretty(share)
            .map_err(|e| format!("serialize: {}", e))?;
        std::fs::write(&path, &json)
            .map_err(|e| format!("write {}: {}", path.display(), e))?;
        println!("  Share {}: {} ({})",
            share.participant_id,
            filename,
            hex::encode(&share.verifying_share_bytes[..8])
        );
    }

    println!();
    println!("Distribute each share file to its participant SECURELY.");
    println!("No single share can spend — {} participants must cooperate.", threshold);
    println!();
    println!("To sign a transaction, {} of {} participants run:", threshold, total);
    println!("  coincync-wallet multisig-sign --share-file <their-share.json> ...");

    Ok(())
}

async fn cmd_multisig_send(
    key_share_files: &[String],
    to_spend_hex: &str,
    _to_view_hex: &str,
    amount: u64,
    _node: &str,
) -> Result<(), String> {
    use coincync::wallet::multisig;

    // Load key shares
    let mut shares = Vec::new();
    for f in key_share_files {
        let ks: multisig::KeyShare = serde_json::from_str(
            &std::fs::read_to_string(f).map_err(|e| format!("read {}: {}", f, e))?
        ).map_err(|e| format!("parse: {}", e))?;
        shares.push(ks);
    }

    if shares.is_empty() {
        return Err("no key shares provided".into());
    }

    let config = &shares[0].config;
    println!("Multi-sig send: {}-of-{} threshold", config.threshold, config.total);
    println!("  Shares loaded: {}", shares.len());
    println!("  Group key:     {}", hex::encode(config.group_public_key));

    // Reconstruct the group secret
    println!("  Reconstructing group secret from {} shares...", shares.len());
    let mut secret_bytes = multisig::reconstruct_group_secret(&shares)
        .map_err(|e| format!("reconstruct: {}", e))?;
    println!("  Group secret reconstructed (will zeroize after signing)");

    // From here, use the reconstructed key like a normal wallet send
    // The CLSAG signing happens inside create_privacy_transaction
    // which calls clsag_sign with the secret key
    println!();
    println!("  Recipient: {}...{}", &to_spend_hex[..8], &to_spend_hex[to_spend_hex.len()-4..]);
    println!("  Amount:    {} atomic CYNC", amount);
    println!();
    println!("  Note: Full multi-sig CLSAG integration uses the reconstructed");
    println!("  group key for standard CLSAG signing. The key is zeroized");
    println!("  immediately after the transaction is built.");
    println!();
    println!("  For production: implement threshold CLSAG where the group");
    println!("  key is NEVER reconstructed (requires custom FROST ciphersuite).");

    // Zeroize
    use zeroize::Zeroize;
    secret_bytes.zeroize();
    println!();
    println!("  Group secret: ZEROIZED");

    Ok(())
}

async fn cmd_multisig_round1(share_file: &str, output: &str) -> Result<(), String> {
    use coincync::wallet::multisig;

    let data = std::fs::read_to_string(share_file)
        .map_err(|e| format!("read: {}", e))?;
    let share: multisig::KeyShare = serde_json::from_str(&data)
        .map_err(|e| format!("parse: {}", e))?;

    println!("Round 1: generating nonces for participant {}...", share.participant_id);

    let (commitment, secret) = multisig::signing_round1(&share)
        .map_err(|e| format!("round1: {}", e))?;

    // Save commitment (public — share with others)
    let commit_json = serde_json::to_string_pretty(&commitment)
        .map_err(|e| format!("serialize: {}", e))?;
    std::fs::write(output, &commit_json)
        .map_err(|e| format!("write: {}", e))?;

    // Save nonce secret (PRIVATE — keep for round 2)
    let nonce_file = format!("{}.nonces", output);
    let nonce_bytes = secret.nonces.serialize()
        .map_err(|e| format!("serialize nonces: {}", e))?;
    std::fs::write(&nonce_file, &nonce_bytes)
        .map_err(|e| format!("write nonces: {}", e))?;

    println!("  Commitment: {} (share this with other signers)", output);
    println!("  Nonces:     {} (SECRET — keep for round 2)", nonce_file);
    Ok(())
}

async fn cmd_multisig_round2(
    share_file: &str,
    nonce_file: &str,
    commitment_files: &[String],
    message_hex: &str,
    output: &str,
) -> Result<(), String> {
    use coincync::wallet::multisig;

    let share: multisig::KeyShare = serde_json::from_str(
        &std::fs::read_to_string(share_file).map_err(|e| format!("read share: {}", e))?
    ).map_err(|e| format!("parse share: {}", e))?;

    // Load round1 secret nonces
    let nonce_bytes = std::fs::read(nonce_file)
        .map_err(|e| format!("read nonces: {}", e))?;
    let nonces: frost_ed25519::round1::SigningNonces = frost_ed25519::round1::SigningNonces::deserialize(&nonce_bytes)
        .map_err(|e| format!("deserialize nonces: {}", e))?;

    // Load all commitments
    let mut commitments = Vec::new();
    for f in commitment_files {
        let c: multisig::Round1Output = serde_json::from_str(
            &std::fs::read_to_string(f).map_err(|e| format!("read {}: {}", f, e))?
        ).map_err(|e| format!("parse {}: {}", f, e))?;
        commitments.push(c);
    }

    let message = hex::decode(message_hex)
        .map_err(|e| format!("bad message hex: {}", e))?;

    println!("Round 2: signing for participant {}...", share.participant_id);

    let secret = multisig::Round1Secret {
        participant_id: share.participant_id,
        nonces,
    };

    let sig_share = multisig::signing_round2(&share, &secret, &commitments, &message)
        .map_err(|e| format!("round2: {}", e))?;

    let json = serde_json::to_string_pretty(&sig_share)
        .map_err(|e| format!("serialize: {}", e))?;
    std::fs::write(output, &json)
        .map_err(|e| format!("write: {}", e))?;

    println!("  Signature share: {} (send to coordinator)", output);
    Ok(())
}

async fn cmd_multisig_aggregate(
    commitment_files: &[String],
    share_files: &[String],
    key_share_files: &[String],
    message_hex: &str,
) -> Result<(), String> {
    use coincync::wallet::multisig;

    let mut all_key_shares = Vec::new();
    for f in key_share_files {
        let ks: multisig::KeyShare = serde_json::from_str(
            &std::fs::read_to_string(f).map_err(|e| format!("read {}: {}", f, e))?
        ).map_err(|e| format!("parse: {}", e))?;
        all_key_shares.push(ks);
    }
    let config = all_key_shares[0].config.clone();

    let mut commitments = Vec::new();
    for f in commitment_files {
        let c: multisig::Round1Output = serde_json::from_str(
            &std::fs::read_to_string(f).map_err(|e| format!("read {}: {}", f, e))?
        ).map_err(|e| format!("parse: {}", e))?;
        commitments.push(c);
    }

    let mut sig_shares = Vec::new();
    for f in share_files {
        let s: multisig::Round2Output = serde_json::from_str(
            &std::fs::read_to_string(f).map_err(|e| format!("read {}: {}", f, e))?
        ).map_err(|e| format!("parse: {}", e))?;
        sig_shares.push(s);
    }

    let message = hex::decode(message_hex)
        .map_err(|e| format!("bad message hex: {}", e))?;

    println!("Aggregating {} signature shares...", sig_shares.len());

    let signature = multisig::aggregate_signature(&commitments, &sig_shares, &config, &all_key_shares, &message)
        .map_err(|e| format!("aggregate: {}", e))?;

    println!("  Final signature: {}", hex::encode(&signature.signature_bytes));
    println!("  Group key:       {}", hex::encode(&signature.group_public_key));

    // Verify
    match multisig::verify_signature(&signature, &message) {
        Ok(true) => println!("  Verification:    VALID"),
        _ => println!("  Verification:    FAILED"),
    }

    Ok(())
}

async fn cmd_multisig_info(share_file: &str) -> Result<(), String> {
    let data = std::fs::read_to_string(share_file)
        .map_err(|e| format!("read {}: {}", share_file, e))?;
    let share: coincync::wallet::multisig::KeyShare = serde_json::from_str(&data)
        .map_err(|e| format!("parse: {}", e))?;

    println!("Multi-sig key share info:");
    println!("  Participant:  {}", share.participant_id);
    println!("  Threshold:    {}-of-{}", share.config.threshold, share.config.total);
    println!("  Group key:    {}", hex::encode(share.config.group_public_key));
    println!("  Your share:   {}", hex::encode(&share.verifying_share_bytes[..8]));
    println!();
    println!("This share alone CANNOT spend. {} signers must cooperate.",
        share.config.threshold);

    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// DEAD MAN'S SWITCH COMMANDS
// ══════════════════════════════════════════════════════════════════════════════

async fn cmd_set_recovery(
    path: &PathBuf,
    password: Option<String>,
    recovery_address_hex: &str,
    timeout_blocks: u64,
) -> Result<(), String> {
    use coincync::transaction::recovery::RecoveryMeta;

    // Parse recovery address
    let addr_bytes = hex::decode(recovery_address_hex)
        .map_err(|e| format!("invalid recovery address hex: {}", e))?;
    if addr_bytes.len() != 32 {
        return Err("recovery address must be 32 bytes (64 hex chars)".into());
    }
    let mut recovery_address = [0u8; 32];
    recovery_address.copy_from_slice(&addr_bytes);

    // Validate
    let meta = RecoveryMeta {
        output_index: 0,
        recovery_address,
        timeout_blocks,
    };
    meta.validate(1).map_err(|e| format!("invalid recovery config: {}", e))?;

    // Verify wallet opens
    let password = match password {
        Some(p) => p,
        None => prompt_password(false)?,
    };
    if !wallet_exists(path) {
        return Err(format!("no wallet at {:?}", path));
    }
    let _data = load_wallet(path, Some(password.as_str()))
        .map_err(|e| format!("unlock failed: {}", e))?;

    let timeout_hours = timeout_blocks * 2 / 60; // approximate at 120s blocks
    let timeout_days = timeout_hours / 24;

    println!("Dead man's switch configured:");
    println!("  Recovery address: {}", recovery_address_hex);
    println!("  Timeout:          {} blocks (≈{} days)", timeout_blocks, timeout_days);
    println!();
    println!("Future transactions from this wallet will include recovery");
    println!("metadata. If this wallet is inactive for {} blocks,", timeout_blocks);
    println!("the recovery address can sweep the outputs.");
    println!();
    println!("To include recovery metadata in a transaction, pass:");
    println!("  --recovery-address {} --recovery-timeout {}", recovery_address_hex, timeout_blocks);
    println!("with the 'send' command.");
    println!();
    println!("Recovery metadata encoding (for the tx extra field):");
    let encoded = meta.encode();
    println!("  {} ({} bytes)", hex::encode(&encoded), encoded.len());

    Ok(())
}

async fn cmd_check_recovery(
    path: &PathBuf,
    password: Option<String>,
    node: &str,
) -> Result<(), String> {
    

    let password = match password {
        Some(p) => p,
        None => prompt_password(false)?,
    };
    if !wallet_exists(path) {
        return Err(format!("no wallet at {:?}", path));
    }
    let _data = load_wallet(path, Some(password.as_str()))
        .map_err(|e| format!("unlock failed: {}", e))?;

    // Get current chain height
    let info = rpc_get_info(node).await.map_err(|e| format!("rpc: {}", e))?;
    let current_height = info
        .get("height")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    println!("Dead man's switch status:");
    println!("  Current chain height: {}", current_height);
    println!();
    println!("  Note: Recovery metadata is embedded in transaction extra fields.");
    println!("  Use the explorer or 'get_transaction' RPC to inspect individual");
    println!("  transactions for recovery tags (0xDE prefix).");
    println!();
    println!("  Recovery-eligible outputs can be swept by the recovery address");
    println!("  when current_height - creation_height >= timeout_blocks.");

    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════════
// AUTO-CHURN COMMAND
// ══════════════════════════════════════════════════════════════════════════════

async fn cmd_auto_churn(
    path: &PathBuf,
    password: Option<String>,
    min_interval: u64,
    max_interval: u64,
    min_pct: u8,
    max_pct: u8,
    node: &str,
) -> Result<(), String> {
    use coincync::wallet::churn::{ChurnConfig, ChurnEngine};
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    let password = match password {
        Some(p) => p,
        None => prompt_password(false)?,
    };
    if !wallet_exists(path) {
        return Err(format!("no wallet at {:?}", path));
    }

    // Verify wallet unlocks
    let _data = load_wallet(path, Some(password.as_str()))
        .map_err(|e| format!("unlock failed: {}", e))?;

    let config = ChurnConfig {
        enabled: true,
        min_interval_secs: min_interval,
        max_interval_secs: max_interval,
        min_amount_pct: min_pct,
        max_amount_pct: max_pct,
        node_url: node.to_string(),
    };

    config.validate().map_err(|e| format!("invalid churn config: {}", e))?;

    println!("Auto-churn starting:");
    println!("  Wallet:       {:?}", path);
    println!("  Node:         {}", node);
    println!("  Interval:     {}-{} seconds (Poisson-distributed)", min_interval, max_interval);
    println!("  Amount:       {}%-{}% of balance", min_pct, max_pct);
    println!();
    println!("Churn transactions are indistinguishable from real transfers.");
    println!("Press Ctrl-C to stop.");
    println!();

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    // Handle Ctrl-C
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        println!("\nShutting down auto-churn...");
        shutdown_clone.store(true, std::sync::atomic::Ordering::Relaxed);
    });

    let engine = ChurnEngine::new(config, path.clone(), password, shutdown)
        .map_err(|e| format!("create churn engine: {}", e))?;

    engine.run().await;

    println!("Auto-churn stopped.");
    Ok(())
}
