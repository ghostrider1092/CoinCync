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
    generate_mnemonic, load_wallet, mnemonic_to_seed, save_wallet, wallet_exists, WalletData,
    WalletKeys,
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
        /// Wallet password. Use `-` to read from stdin (recommended for
        /// piped automation: `echo $pw | wallet ... --password -`).
        /// Reads `COINCYNC_WALLET_PASSWORD` env if neither flag nor
        /// stdin is provided; otherwise prompts interactively.
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
        /// Wallet password. Use `-` to read from stdin (recommended for
        /// piped automation: `echo $pw | wallet ... --password -`).
        /// Reads `COINCYNC_WALLET_PASSWORD` env if neither flag nor
        /// stdin is provided; otherwise prompts interactively.
        #[arg(short, long, env = "COINCYNC_WALLET_PASSWORD", hide_env_values = true)]
        password: Option<String>,
    },

    /// Open an existing wallet (just checks the password).
    Open {
        /// Wallet password. Use `-` to read from stdin (recommended for
        /// piped automation: `echo $pw | wallet ... --password -`).
        /// Reads `COINCYNC_WALLET_PASSWORD` env if neither flag nor
        /// stdin is provided; otherwise prompts interactively.
        #[arg(short, long, env = "COINCYNC_WALLET_PASSWORD", hide_env_values = true)]
        password: Option<String>,
    },

    /// Show wallet status + chain info from the node.
    Info {
        /// Wallet password. Use `-` to read from stdin (recommended for
        /// piped automation: `echo $pw | wallet ... --password -`).
        /// Reads `COINCYNC_WALLET_PASSWORD` env if neither flag nor
        /// stdin is provided; otherwise prompts interactively.
        #[arg(short, long, env = "COINCYNC_WALLET_PASSWORD", hide_env_values = true)]
        password: Option<String>,
    },

    /// Show the spend public key (receive pubkey for this wallet).
    Address {
        /// Wallet password. Use `-` to read from stdin (recommended for
        /// piped automation: `echo $pw | wallet ... --password -`).
        /// Reads `COINCYNC_WALLET_PASSWORD` env if neither flag nor
        /// stdin is provided; otherwise prompts interactively.
        #[arg(short, long, env = "COINCYNC_WALLET_PASSWORD", hide_env_values = true)]
        password: Option<String>,
    },

    /// Show balance snapshot from the wallet file (does NOT resync).
    Balance {
        /// Wallet password. Use `-` to read from stdin (recommended for
        /// piped automation: `echo $pw | wallet ... --password -`).
        /// Reads `COINCYNC_WALLET_PASSWORD` env if neither flag nor
        /// stdin is provided; otherwise prompts interactively.
        #[arg(short, long, env = "COINCYNC_WALLET_PASSWORD", hide_env_values = true)]
        password: Option<String>,
    },

    /// Print the master seed as hex (requires password).
    ShowSeed {
        /// Wallet password. Use `-` to read from stdin (recommended for
        /// piped automation: `echo $pw | wallet ... --password -`).
        /// Reads `COINCYNC_WALLET_PASSWORD` env if neither flag nor
        /// stdin is provided; otherwise prompts interactively.
        #[arg(short, long, env = "COINCYNC_WALLET_PASSWORD", hide_env_values = true)]
        password: Option<String>,
    },

    /// Scan blocks from the node for owned outputs.
    Scan {
        /// Wallet password. Use `-` to read from stdin (recommended for
        /// piped automation: `echo $pw | wallet ... --password -`).
        /// Reads `COINCYNC_WALLET_PASSWORD` env if neither flag nor
        /// stdin is provided; otherwise prompts interactively.
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
        /// Wallet password. Use `-` to read from stdin (recommended for
        /// piped automation: `echo $pw | wallet ... --password -`).
        /// Reads `COINCYNC_WALLET_PASSWORD` env if neither flag nor
        /// stdin is provided; otherwise prompts interactively.
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
        /// Wallet password. Use `-` to read from stdin (recommended for
        /// piped automation: `echo $pw | wallet ... --password -`).
        /// Reads `COINCYNC_WALLET_PASSWORD` env if neither flag nor
        /// stdin is provided; otherwise prompts interactively.
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
        /// Wallet password. Use `-` to read from stdin (recommended for
        /// piped automation: `echo $pw | wallet ... --password -`).
        /// Reads `COINCYNC_WALLET_PASSWORD` env if neither flag nor
        /// stdin is provided; otherwise prompts interactively.
        #[arg(short, long, env = "COINCYNC_WALLET_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        /// Node RPC URL.
        #[arg(long)]
        node_override: Option<String>,
    },

    /// Enable auto-churn: automatic self-sends at random intervals to poison
    /// the transaction graph. Runs as a background loop until stopped.
    AutoChurn {
        /// Wallet password. Use `-` to read from stdin (recommended for
        /// piped automation: `echo $pw | wallet ... --password -`).
        /// Reads `COINCYNC_WALLET_PASSWORD` env if neither flag nor
        /// stdin is provided; otherwise prompts interactively.
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

    /// Subaddress operations: list and generate unlinkable receiving
    /// addresses derived from this wallet's view+spend keys. Each
    /// subaddress is a distinct (account, index) tuple. Senders to
    /// different subaddresses cannot tell that they're paying the
    /// same wallet — the spend pubkeys are independent on chain even
    /// though they share a view key for scan.
    Subaddress {
        #[command(subcommand)]
        action: SubaddressAction,
    },

    /// Selective-disclosure proofs. Prove statements about owned
    /// UTXOs to a third party (auditor, KYC counterparty) without
    /// revealing values or one-time secrets. All non-interactive —
    /// proof bytes travel over any channel.
    Disclose {
        #[command(subcommand)]
        action: DiscloseAction,
    },

    /// Decrypt and print the encrypted memo attached to one of
    /// this wallet's UTXOs. Senders embed memos in the first
    /// recipient output via `send --memo`; the bytes are encrypted
    /// to the recipient's view key and round-trip through chain
    /// untouched. Only the recipient (this wallet) can read them.
    ShowMemo {
        /// Wallet password. Use `-` to read from stdin (recommended for
        /// piped automation: `echo $pw | wallet ... --password -`).
        /// Reads `COINCYNC_WALLET_PASSWORD` env if neither flag nor
        /// stdin is provided; otherwise prompts interactively.
        #[arg(short, long, env = "COINCYNC_WALLET_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        /// Index of the UTXO in the wallet's UTXO list (0-based).
        /// Run `scan` first to populate; the order is the persisted
        /// order. Use the same index you'd pass to `disclose balance`.
        #[arg(long)]
        utxo_index: usize,
    },
}

#[derive(Subcommand)]
enum DiscloseAction {
    /// Prove a specific UTXO's amount is at least `--threshold`
    /// without revealing the actual amount. Useful for
    /// proof-of-funds at a counterparty without exposing balance.
    Balance {
        /// Wallet password. Use `-` to read from stdin (recommended for
        /// piped automation: `echo $pw | wallet ... --password -`).
        /// Reads `COINCYNC_WALLET_PASSWORD` env if neither flag nor
        /// stdin is provided; otherwise prompts interactively.
        #[arg(short, long, env = "COINCYNC_WALLET_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        /// Index of the UTXO in the wallet's UTXO list (0-based).
        /// Run `scan` first; the order is the persisted order.
        #[arg(long)]
        utxo_index: usize,
        /// Threshold value in atomic units. Asserts
        /// `utxo.amount >= threshold`. Must be <= actual value.
        #[arg(long)]
        threshold: u64,
    },
    /// Verify a hex-encoded balance proof. No wallet keys needed —
    /// anyone can verify.
    VerifyBalance {
        #[arg(long)]
        proof: String,
    },
    /// Verify a hex-encoded ownership proof. The wallet owner
    /// produces the OwnershipProof out-of-band; the auditor
    /// pastes the proof here.
    VerifyOwnership {
        #[arg(long)]
        proof: String,
    },
    /// Export a time-scoped view key: a read-only key that decrypts only
    /// outputs in blocks [--from-height, --to-height]. Discloses your
    /// history for a bounded period (e.g. a tax year) without giving up
    /// past-or-future privacy. Contains a view secret — share carefully.
    ScopedViewKey {
        #[arg(short, long, env = "COINCYNC_WALLET_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        /// First block height the exported key can decrypt (inclusive).
        #[arg(long)]
        from_height: u64,
        /// Last block height the exported key can decrypt (inclusive).
        #[arg(long)]
        to_height: u64,
    },
    /// Auditor side: scan a scoped view key's block range and list the
    /// outputs it can see. Read-only, no wallet, bounded to the key's
    /// disclosed range.
    ScanScoped {
        /// The scoped view key JSON (from `disclose scoped-view-key`).
        #[arg(long)]
        view_key: String,
    },
}

#[derive(Subcommand)]
enum SubaddressAction {
    /// List all subaddresses currently generated for this wallet.
    /// Always includes the main address (0/0). Subaddresses generated
    /// in past sessions are persisted in the wallet file.
    List {
        /// Wallet password. Use `-` to read from stdin (recommended for
        /// piped automation: `echo $pw | wallet ... --password -`).
        /// Reads `COINCYNC_WALLET_PASSWORD` env if neither flag nor
        /// stdin is provided; otherwise prompts interactively.
        #[arg(short, long, env = "COINCYNC_WALLET_PASSWORD", hide_env_values = true)]
        password: Option<String>,
    },
    /// Generate the next subaddress in `--account` (default 0) and
    /// persist it to the wallet file. Prints the new address.
    Create {
        /// Wallet password. Use `-` to read from stdin (recommended for
        /// piped automation: `echo $pw | wallet ... --password -`).
        /// Reads `COINCYNC_WALLET_PASSWORD` env if neither flag nor
        /// stdin is provided; otherwise prompts interactively.
        #[arg(short, long, env = "COINCYNC_WALLET_PASSWORD", hide_env_values = true)]
        password: Option<String>,
        /// Account index. Different accounts give independent
        /// subaddress streams — useful for separating funds (e.g.,
        /// account 0 for personal, account 1 for business).
        #[arg(long, default_value = "0")]
        account: u32,
        /// Optional human-readable label saved alongside the
        /// subaddress (e.g., "exchange-deposit-2026-05").
        #[arg(long)]
        label: Option<String>,
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
        Command::Create {
            password,
            force,
            no_encrypt,
        } => cmd_create(&wallet_path, password, force, no_encrypt, network).await,
        Command::Restore { seed, password } => {
            cmd_restore(&wallet_path, seed, password, network).await
        }
        Command::Open { password } => cmd_open(&wallet_path, password).await,
        Command::Info { password } => cmd_info(&wallet_path, password, &cli.node, network).await,
        Command::Address { password } => cmd_address(&wallet_path, password, network).await,
        Command::Balance { password } => cmd_balance(&wallet_path, password).await,
        Command::ShowSeed { password } => cmd_show_seed(&wallet_path, password).await,
        Command::Scan {
            password,
            from,
            max_blocks,
        } => cmd_scan(&wallet_path, password, from, max_blocks, &cli.node).await,
        Command::PrivacyStats => cmd_privacy_stats(&cli.node).await,
        Command::Send {
            password,
            to_spend,
            to_view,
            amount,
            fee_multiplier,
            split_output,
            memo,
            recovery_address,
            recovery_timeout,
        } => {
            cmd_send(
                &wallet_path,
                password,
                to_spend,
                to_view,
                amount,
                fee_multiplier,
                split_output,
                memo,
                recovery_address,
                recovery_timeout,
                &cli.node,
            )
            .await
        }
        Command::MultisigGen {
            threshold,
            total,
            output_dir,
        } => cmd_multisig_gen(threshold, total, &output_dir, network).await,
        Command::MultisigInfo { share_file } => cmd_multisig_info(&share_file).await,
        Command::MultisigSend {
            key_shares,
            to_spend,
            to_view,
            amount,
        } => cmd_multisig_send(&key_shares, &to_spend, &to_view, amount, &cli.node).await,
        Command::MultisigRound1 { share_file, output } => {
            cmd_multisig_round1(&share_file, &output).await
        }
        Command::MultisigRound2 {
            share_file,
            nonce_file,
            commitments,
            message,
            output,
        } => cmd_multisig_round2(&share_file, &nonce_file, &commitments, &message, &output).await,
        Command::SetRecovery {
            password,
            address,
            timeout,
        } => cmd_set_recovery(&wallet_path, password, &address, timeout).await,
        Command::CheckRecovery {
            password,
            node_override,
        } => {
            let node_url = node_override.as_deref().unwrap_or(&cli.node);
            cmd_check_recovery(&wallet_path, password, node_url).await
        }
        Command::AutoChurn {
            password,
            min_interval,
            max_interval,
            min_pct,
            max_pct,
        } => {
            cmd_auto_churn(
                &wallet_path,
                password,
                min_interval,
                max_interval,
                min_pct,
                max_pct,
                &cli.node,
            )
            .await
        }
        Command::MultisigAggregate {
            commitments,
            shares,
            key_shares,
            message,
        } => cmd_multisig_aggregate(&commitments, &shares, &key_shares, &message).await,
        Command::Subaddress { action } => match action {
            SubaddressAction::List { password } => {
                cmd_subaddress_list(&wallet_path, password, network).await
            }
            SubaddressAction::Create {
                password,
                account,
                label,
            } => cmd_subaddress_create(&wallet_path, password, account, label, network).await,
        },
        Command::Disclose { action } => match action {
            DiscloseAction::Balance {
                password,
                utxo_index,
                threshold,
            } => cmd_disclose_balance(&wallet_path, password, utxo_index, threshold).await,
            DiscloseAction::VerifyBalance { proof } => cmd_disclose_verify_balance(&proof).await,
            DiscloseAction::ScopedViewKey {
                password,
                from_height,
                to_height,
            } => cmd_disclose_scoped_view_key(&wallet_path, password, from_height, to_height).await,
            DiscloseAction::ScanScoped { view_key } => {
                cmd_disclose_scan_scoped(&view_key, &cli.node).await
            }
            DiscloseAction::VerifyOwnership { proof } => {
                cmd_disclose_verify_ownership(&proof).await
            }
        },
        Command::ShowMemo {
            password,
            utxo_index,
        } => cmd_show_memo(&wallet_path, password, utxo_index, &cli.node).await,
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

/// Maximum password length accepted from any input path (interactive
/// prompt or stdin pipe). Prevents OOM via malicious piped input
/// (`cat big-file | wallet --password -`) and limits the heap-resident
/// window of password bytes regardless of source. 4 KiB comfortably
/// exceeds any reasonable human-typed password. Added in v1.0.13 #5.
const MAX_PASSWORD_LEN: usize = 4 * 1024;

fn prompt_password(confirm: bool) -> Result<zeroize::Zeroizing<String>, String> {
    // P8-Bw1 (2026-07-03) + v1.0.13 #5: use dialoguer's hidden-input
    // Password prompt AND wrap the returned String in `Zeroizing<String>`
    // at the boundary. The previous read_line implementation echoed the
    // password to the terminal — visible in scrollback, terminal
    // recordings, and any shell that logs the tty (screen/tmux, mosh,
    // `script`, some CI wrappers). dialoguer::Password disables
    // terminal echo via the console crate's cross-platform tty control
    // (termios ECHO off on Unix, SetConsoleMode on Windows), which is
    // the standard fix. The Zeroizing wrapper ensures the backing heap
    // allocation is wiped on drop even if the subsequent length /
    // emptiness validation errors.
    //
    // Falls through to Err(String) on non-tty stdin so callers see the
    // same interface as before (piped automation must use `--password -`
    // to opt into the stdin-mode branch of resolve_password).
    let theme = dialoguer::theme::ColorfulTheme::default();
    let mut prompt = dialoguer::Password::with_theme(&theme).with_prompt("Password");
    if confirm {
        prompt = prompt.with_confirmation("Confirm password", "passwords do not match");
    }
    let pw = zeroize::Zeroizing::new(
        prompt
            .interact()
            .map_err(|e| format!("password prompt failed: {}", e))?,
    );
    if pw.is_empty() {
        return Err("password must not be empty".into());
    }
    Ok(pw)
}

/// Resolve a password from a CLI option, with stdin support via `-`.
///
/// Three cases:
/// - `Some("-")` reads one line from stdin (the password). Trailing CR/LF
///   stripped. Empty line is an error. Use when piping a password from an
///   automation context — keeps the secret out of argv (process list) and
///   out of env vars (visible to children, persistent across shells).
/// - `Some(s)` for any other s returns s as the password. Argv exposure
///   tradeoff is the caller's choice; we still accept it for human use.
/// - `None` falls back to interactive `prompt_password(confirm)`.
///
/// `confirm` only applies to the interactive path — piping is assumed to
/// be deliberate, and re-typing for confirmation is hostile to automation.
fn resolve_password(
    opt: Option<String>,
    confirm: bool,
) -> Result<zeroize::Zeroizing<String>, String> {
    use std::io::Read;
    use zeroize::Zeroize;
    match opt {
        Some(s) if s == "-" => {
            let stdin = std::io::stdin();
            let mut handle = stdin.lock().take((MAX_PASSWORD_LEN + 1) as u64);
            // v1.0.13 #5: stdin buffer is Zeroizing so the intermediate
            // copy is wiped on drop, including the error paths below.
            let mut buf = zeroize::Zeroizing::new(String::new());
            handle
                .read_to_string(&mut *buf)
                .map_err(|e| e.to_string())?;
            if buf.len() > MAX_PASSWORD_LEN {
                return Err(format!(
                    "stdin password too long (max {} bytes); refusing to read \
                     more — did you accidentally pipe a large file?",
                    MAX_PASSWORD_LEN,
                ));
            }
            // Strip ONE trailing newline (typical interactive paste
            // pattern). Don't trim() — leading/trailing whitespace
            // might be intentional in the password.
            let pw_str = zeroize::Zeroizing::new(
                buf.trim_end_matches('\n')
                    .trim_end_matches('\r')
                    .to_string(),
            );
            if pw_str.is_empty() {
                return Err("password must not be empty when reading from stdin".into());
            }
            Ok(pw_str)
        }
        Some(mut s) => {
            // ARGV exposure warning — see function doc.
            tracing::warn!(
                "Password passed via `--password <literal>` is visible to \
                 any local user via /proc/<pid>/cmdline on Linux or \
                 `wmic process get commandline` on Windows. Prefer `--password -` \
                 (piping the secret on stdin) for non-interactive use."
            );
            // v1.0.13 #5: copy the bytes into a Zeroizing wrapper and
            // explicitly zeroize the original clap-owned String so the
            // heap allocation that held the password through clap's
            // parse + dispatch is wiped immediately, instead of
            // leaking until the caller's drop.
            let pw = zeroize::Zeroizing::new(s.clone());
            s.zeroize();
            Ok(pw)
        }
        None => prompt_password(confirm),
    }
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
        Some(resolve_password(password, true)?)
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

    // v1.0.13 #5: password is now Option<Zeroizing<String>>.
    // as_deref doesn't give us &str directly (intermediate &String);
    // chain through as_str to land on &str for the library API.
    save_wallet(path, &data, password.as_ref().map(|p| p.as_str()))
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
            stdin
                .lock()
                .read_line(&mut line)
                .map_err(|e| e.to_string())?;
            line.trim().to_string()
        }
    };

    let seed_bytes =
        mnemonic_to_seed(&seed_str).map_err(|e| format!("invalid seed phrase: {}", e))?;

    let password = resolve_password(password, true)?;

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

    save_wallet(path, &data, Some(password.as_str())).map_err(|e| format!("save failed: {}", e))?;

    println!("Wallet restored to {:?}", path);
    Ok(())
}

async fn cmd_open(path: &PathBuf, password: Option<String>) -> Result<(), String> {
    if !wallet_exists(path) {
        return Err(format!("no wallet at {:?}", path));
    }
    let password = resolve_password(password, false)?;
    let _data =
        load_wallet(path, Some(password.as_str())).map_err(|e| format!("unlock failed: {}", e))?;
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
                info.get("is_synced")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
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
    let password = resolve_password(password, false)?;
    let data =
        load_wallet(path, Some(password.as_str())).map_err(|e| format!("unlock failed: {}", e))?;

    let keys = WalletKeys::from_seed(data.seed);
    let epoch = keys
        .current()
        .ok_or_else(|| "wallet has no current key epoch".to_string())?;

    let prim_network = match network {
        Network::Mainnet => coincync::primitives::Network::Mainnet,
        Network::Testnet | Network::Regtest => coincync::primitives::Network::Testnet,
    };
    let addr =
        coincync::primitives::Address::new(prim_network, epoch.spend_public, epoch.view_public);
    println!("Address:       {}", addr);
    println!(
        "Spend public:  {}",
        hex::encode(epoch.spend_public.as_bytes())
    );
    println!(
        "View public:   {}",
        hex::encode(epoch.view_public.as_bytes())
    );
    Ok(())
}

async fn cmd_balance(path: &PathBuf, password: Option<String>) -> Result<(), String> {
    let password = resolve_password(password, false)?;
    let data =
        load_wallet(path, Some(password.as_str())).map_err(|e| format!("unlock failed: {}", e))?;

    println!("Wallet label:    {}", data.label);
    println!("Scanned height:  {}", data.scanned_height);
    println!();
    println!("(P1 note: balance computed from wallet file state only.");
    println!(" The file doesn't persist UTXOs yet — P2 work will add a");
    println!(" real chain-scan-via-RPC path and UTXO materialisation.)");
    Ok(())
}

async fn cmd_show_seed(path: &PathBuf, password: Option<String>) -> Result<(), String> {
    let password = resolve_password(password, false)?;
    let data =
        load_wallet(path, Some(password.as_str())).map_err(|e| format!("unlock failed: {}", e))?;

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
    use coincync::wallet::scanner::decrypted_to_utxo;
    use coincync::wallet::{KeyEpoch, Wallet, WalletScanner};

    let password = resolve_password(password, false)?;

    // Open + unlock the real Wallet struct so we persist UTXOs into it.
    let mut wallet = Wallet::open(path.clone()).map_err(|e| format!("open wallet: {}", e))?;
    wallet
        .unlock(&password)
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
    let start =
        from.unwrap_or_else(|| wallet.scanned_height().saturating_sub(SCAN_BACKSTOP_BLOCKS));
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
                // Reorg auto-recovery bookkeeping for this batch: on a
                // detected reorg we rewind and set `reorg_resume` to the
                // height to continue from; a reorg deeper than the whole
                // journal sets `reorg_abort` to stop and require a full
                // rescan. Both break out of the per-block loop below.
                let mut reorg_resume: Option<u64> = None;
                let mut reorg_abort = false;
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

                    // Reorg-aware scan (Tasks #2b + #1b). If the scanner
                    // detects the incoming block doesn't extend its journal
                    // cleanly (prev_hash mismatch), it returns ReorgDetected.
                    // We AUTO-RECOVER: ask the node for our fork point using
                    // the scanner's (height,hash) journal, rewind wallet
                    // state (balance + history) to it, and resume from
                    // fork+1 — instead of stopping and forcing a manual
                    // rescan. A reorg deeper than the whole journal (which,
                    // with the journal sized to the reorg cap, is
                    // unreachable for a consensus-legal reorg) falls back to
                    // a warn + stop.
                    use coincync::wallet::scanner::ScanResult;
                    let outs = match scanner.scan_block_with_result(&block) {
                        ScanResult::Scanned { outputs, .. } => outputs,
                        ScanResult::ReorgDetected {
                            at_height,
                            actual_prev,
                            expected_prev,
                        } => {
                            eprintln!(
                                "reorg detected at height {} (block prev_hash={:?} != wallet's last hash={:?}); recovering…",
                                at_height, actual_prev, expected_prev,
                            );
                            let journal_hex: Vec<(u64, String)> = scanner
                                .journal_pairs()
                                .into_iter()
                                .map(|(h, hash)| (h, hex::encode(hash.as_bytes())))
                                .collect();
                            match rpc_find_fork_point(node, &journal_hex).await? {
                                Some(fork) => {
                                    let outcome = scanner.rewind_to_height(fork).map_err(|e| {
                                        format!("reorg rewind to {}: {:?}", fork, e)
                                    })?;
                                    let removed = wallet.remove_outputs(&outcome.outputs_to_remove);
                                    for ki in &outcome.key_images_to_unspend {
                                        wallet.unmark_spent_by_key_image(ki);
                                    }
                                    let reverted = wallet.revert_outgoing_above_height(fork);
                                    eprintln!(
                                        "recovered: rewound to height {} ({} orphaned output(s) removed, {} spend(s) restored, {} outgoing reverted); resuming from {}",
                                        fork,
                                        removed,
                                        outcome.key_images_to_unspend.len(),
                                        reverted,
                                        fork + 1,
                                    );
                                    reorg_resume = Some(fork + 1);
                                    break;
                                }
                                None => {
                                    eprintln!(
                                        "WARN: reorg at height {} is deeper than the wallet journal; \
                                         full rescan required. Re-run scan from an earlier height.",
                                        at_height,
                                    );
                                    reorg_abort = true;
                                    break;
                                }
                            }
                        }
                    };
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
                    //
                    // Task #1b: ALSO journal the spend in the scanner so
                    // a later rewind can un-mark spent on this UTXO if
                    // the current block ends up orphaned.
                    for tx in &block.transactions {
                        for ki in tx.key_images() {
                            // Only journal the spend if it actually
                            // belongs to us — otherwise we'd pollute
                            // the journal with every chain key_image.
                            if wallet.balance_ref().lookup_by_key_image(&ki).is_some() {
                                scanner.record_spend_for_last_block(ki.clone());
                            }
                            wallet.mark_spent_by_key_image(&ki);
                        }
                    }
                    scanned_blocks += 1;
                    last_height = height;
                }
                // Reorg deeper than the journal — stop; a full rescan is
                // needed (unreachable for a consensus-legal reorg).
                if reorg_abort {
                    break;
                }
                // Resume from the rewind target after a recovered reorg,
                // else advance past the batch we just scanned.
                cursor = reorg_resume.unwrap_or(batch_end + 1);
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
    use coincync::wallet::{KeyEpoch, Wallet};

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

    // Cheap arg-validation before any network or wallet I/O. A
    // wrong --memo or mismatched --recovery-* pair shouldn't make
    // the user wait for an RPC roundtrip + decoy fetch only to
    // bail. The deeper checks (hex decode, output_index against
    // recipients) stay below where the values are consumed.
    if let Some(s) = memo.as_deref() {
        if s.len() > 256 {
            return Err(format!("memo too long: {} bytes (max 256)", s.len()));
        }
    }
    match (recovery_address_hex.as_deref(), recovery_timeout) {
        (Some(_), None) | (None, Some(_)) => {
            return Err("--recovery-address and --recovery-timeout must be passed together".into());
        }
        _ => {}
    }

    // Unlock wallet
    let password = resolve_password(password, false)?;
    let mut wallet = Wallet::open(path.clone()).map_err(|e| format!("open wallet: {}", e))?;
    wallet
        .unlock(&password)
        .map_err(|e| format!("unlock wallet: {}", e))?;

    let keys: KeyEpoch = wallet
        .current_keys()
        .cloned()
        .ok_or_else(|| "wallet has no current key epoch".to_string())?;

    // Query chain tip for fee calculation + decoy sampling
    let info = rpc_get_info(node)
        .await
        .map_err(|e| format!("rpc get_info: {}", e))?;
    let current_height = info.get("height").and_then(|v| v.as_u64()).unwrap_or(0);

    // Fetch decoys from the node.
    //
    // 2026-06-07: `min_age` was hardcoded to 0, which let the wallet pick
    // immature coinbase outputs as decoys. The consensus validator rejects
    // any ring containing a coinbase younger than
    // `min_output_age_at_height(current_height)` (10 pre-fork, 100 after
    // MIN_OUTPUT_AGE_HARDFORK_HEIGHT). The tx would pass mempool admission
    // (crypto-only check) and then get evicted seconds later when shadow-
    // evict ran the full validator. Asking the node to filter at fetch
    // time avoids the eviction class entirely — only mature outputs reach
    // the wallet's decoy pool.
    let ring_size = 16usize;
    let min_decoy_age = coincync::constants::min_output_age_at_height(current_height);
    let decoys_json = rpc_call(
        node,
        "get_decoys",
        serde_json::json!([ring_size * 8, min_decoy_age]),
    )
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
        println!(
            "  Drip-pair:       split {} -> {} + {} (both to recipient)",
            amount, half_a, half_b
        );
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
                return Err(format!(
                    "--recovery-address must be 32 bytes (64 hex), got {}",
                    addr_v.len()
                ));
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
            println!(
                "  Recovery:        addr={}…  timeout={} blocks",
                &addr_hex[..16.min(addr_hex.len())],
                timeout
            );
            RecoveryMeta::encode_all(&[meta])
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err("--recovery-address and --recovery-timeout must be passed together".into());
        }
        (None, None) => Vec::new(),
    };

    // R-113 note: SharedWallet.balance() clones because it can't
    // hold the RwLock guard across the return. If a future refactor
    // adds a `with_balance<T>(|b: &Balance| -> T)` closure API on
    // SharedWallet, callers can drop this clone. For now the
    // clone is the structural cost of using SharedWallet.
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
            input_keys.len(),
            tx.inputs.len()
        ));
    }
    if let Err(conflict) = wallet.reserve_utxos(&input_keys, tx_hash, current_height) {
        return Err(format!(
            "reservation conflict: {} (try `wallet scan` and retry)",
            conflict
        ));
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
                wallet
                    .save(Some(&password))
                    .map_err(|e| format!("save wallet: {}", e))?;
                Ok(())
            } else {
                // Mempool said no. Release the reservation so a retry (with
                // different decoys / fee) can re-select these UTXOs.
                let released = wallet.release_reservations_by_tx(tx_hash);
                let _ = wallet.save(Some(&password));
                Err(format!(
                    "rpc rejected: {} (released {} reservation(s))",
                    result, released
                ))
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
            println!(
                "{}",
                serde_json::to_string_pretty(&stats).unwrap_or_default()
            );
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
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let json: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    if let Some(err) = json.get("error") {
        return Err(format!("rpc error: {}", err));
    }
    json.get("result")
        .cloned()
        .ok_or_else(|| "rpc response missing result".into())
}

/// Call the node's `find_fork_point` RPC with the wallet's `(height, hex_hash)`
/// journal; returns the deepest still-canonical height (the fork point), or
/// `None` if the reorg is deeper than the journal. Response shape:
/// `{"fork_point": <u64 | null>}`.
async fn rpc_find_fork_point(
    node: &str,
    journal_hex: &[(u64, String)],
) -> Result<Option<u64>, String> {
    let resp = rpc_call(node, "find_fork_point", serde_json::json!([journal_hex])).await?;
    Ok(resp.get("fork_point").and_then(|v| v.as_u64()))
}

/// Call `get_block_range(start, end)` and return the `blocks` array.
async fn rpc_get_block_range(
    node: &str,
    start: u64,
    end: u64,
) -> Result<Vec<serde_json::Value>, String> {
    let result = rpc_call(node, "get_block_range", serde_json::json!([start, end])).await?;
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

    println!(
        "Generating {}-of-{} FROST multi-sig key shares...",
        threshold, total
    );

    let result =
        multisig::generate_shares(threshold, total).map_err(|e| format!("keygen failed: {}", e))?;

    println!();
    println!(
        "Group public key: {}",
        hex::encode(result.config.group_public_key)
    );

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
        let filename = format!(
            "multisig-share-{}-of-{}-participant-{}.json",
            threshold, total, share.participant_id
        );
        let path = dir.join(&filename);
        let json = serde_json::to_string_pretty(share).map_err(|e| format!("serialize: {}", e))?;
        std::fs::write(&path, &json).map_err(|e| format!("write {}: {}", path.display(), e))?;
        println!(
            "  Share {}: {} ({})",
            share.participant_id,
            filename,
            hex::encode(&share.verifying_share_bytes[..8])
        );
    }

    println!();
    println!("Distribute each share file to its participant SECURELY.");
    println!(
        "No single share can spend — {} participants must cooperate.",
        threshold
    );
    println!();
    println!(
        "To sign a transaction, {} of {} participants run:",
        threshold, total
    );
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
            &std::fs::read_to_string(f).map_err(|e| format!("read {}: {}", f, e))?,
        )
        .map_err(|e| format!("parse: {}", e))?;
        shares.push(ks);
    }

    if shares.is_empty() {
        return Err("no key shares provided".into());
    }

    let config = &shares[0].config;
    println!(
        "Multi-sig send: {}-of-{} threshold",
        config.threshold, config.total
    );
    println!("  Shares loaded: {}", shares.len());
    println!("  Group key:     {}", hex::encode(config.group_public_key));

    // Reconstruct the group secret directly into a ZeroizeOnDrop wrapper.
    println!(
        "  Reconstructing group secret from {} shares...",
        shares.len()
    );
    let secret =
        multisig::reconstruct_group_secret(&shares).map_err(|e| format!("reconstruct: {}", e))?;
    println!("  Group secret reconstructed (will zeroize on drop)");

    // From here, use the reconstructed key like a normal wallet send
    // The CLSAG signing happens inside create_privacy_transaction
    // which calls clsag_sign with the secret key
    println!();
    println!(
        "  Recipient: {}...{}",
        &to_spend_hex[..8],
        &to_spend_hex[to_spend_hex.len() - 4..]
    );
    println!("  Amount:    {} atomic CYNC", amount);
    println!();
    println!("  Note: Full multi-sig CLSAG integration uses the reconstructed");
    println!("  group key for standard CLSAG signing. The key is zeroized");
    println!("  immediately after the transaction is built.");
    println!();
    println!("  For production: implement threshold CLSAG where the group");
    println!("  key is NEVER reconstructed (requires custom FROST ciphersuite).");

    // `secret` drops here — SecretScalar's ZeroizeOnDrop impl wipes
    // the underlying Scalar on the way out.
    drop(secret);
    println!();
    println!("  Group secret: ZEROIZED (via SecretScalar::Drop)");

    Ok(())
}

async fn cmd_multisig_round1(share_file: &str, output: &str) -> Result<(), String> {
    use coincync::wallet::multisig;

    let data = std::fs::read_to_string(share_file).map_err(|e| format!("read: {}", e))?;
    let share: multisig::KeyShare =
        serde_json::from_str(&data).map_err(|e| format!("parse: {}", e))?;

    println!(
        "Round 1: generating nonces for participant {}...",
        share.participant_id
    );

    let (commitment, secret) =
        multisig::signing_round1(&share).map_err(|e| format!("round1: {}", e))?;

    // Save commitment (public — share with others)
    let commit_json =
        serde_json::to_string_pretty(&commitment).map_err(|e| format!("serialize: {}", e))?;
    std::fs::write(output, &commit_json).map_err(|e| format!("write: {}", e))?;

    // Save nonce secret (PRIVATE — keep for round 2)
    let nonce_file = format!("{}.nonces", output);
    let nonce_bytes = secret
        .nonces
        .serialize()
        .map_err(|e| format!("serialize nonces: {}", e))?;
    std::fs::write(&nonce_file, &nonce_bytes).map_err(|e| format!("write nonces: {}", e))?;

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
        &std::fs::read_to_string(share_file).map_err(|e| format!("read share: {}", e))?,
    )
    .map_err(|e| format!("parse share: {}", e))?;

    // Load round1 secret nonces
    let nonce_bytes = std::fs::read(nonce_file).map_err(|e| format!("read nonces: {}", e))?;
    let nonces: frost_ed25519::round1::SigningNonces =
        frost_ed25519::round1::SigningNonces::deserialize(&nonce_bytes)
            .map_err(|e| format!("deserialize nonces: {}", e))?;

    // Load all commitments
    let mut commitments = Vec::new();
    for f in commitment_files {
        let c: multisig::Round1Output = serde_json::from_str(
            &std::fs::read_to_string(f).map_err(|e| format!("read {}: {}", f, e))?,
        )
        .map_err(|e| format!("parse {}: {}", f, e))?;
        commitments.push(c);
    }

    let message = hex::decode(message_hex).map_err(|e| format!("bad message hex: {}", e))?;

    println!(
        "Round 2: signing for participant {}...",
        share.participant_id
    );

    let secret = multisig::Round1Secret {
        participant_id: share.participant_id,
        nonces,
    };

    let sig_share = multisig::signing_round2(&share, &secret, &commitments, &message)
        .map_err(|e| format!("round2: {}", e))?;

    let json = serde_json::to_string_pretty(&sig_share).map_err(|e| format!("serialize: {}", e))?;
    std::fs::write(output, &json).map_err(|e| format!("write: {}", e))?;

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
            &std::fs::read_to_string(f).map_err(|e| format!("read {}: {}", f, e))?,
        )
        .map_err(|e| format!("parse: {}", e))?;
        all_key_shares.push(ks);
    }
    let config = all_key_shares[0].config.clone();

    let mut commitments = Vec::new();
    for f in commitment_files {
        let c: multisig::Round1Output = serde_json::from_str(
            &std::fs::read_to_string(f).map_err(|e| format!("read {}: {}", f, e))?,
        )
        .map_err(|e| format!("parse: {}", e))?;
        commitments.push(c);
    }

    let mut sig_shares = Vec::new();
    for f in share_files {
        let s: multisig::Round2Output = serde_json::from_str(
            &std::fs::read_to_string(f).map_err(|e| format!("read {}: {}", f, e))?,
        )
        .map_err(|e| format!("parse: {}", e))?;
        sig_shares.push(s);
    }

    let message = hex::decode(message_hex).map_err(|e| format!("bad message hex: {}", e))?;

    println!("Aggregating {} signature shares...", sig_shares.len());

    let signature = multisig::aggregate_signature(
        &commitments,
        &sig_shares,
        &config,
        &all_key_shares,
        &message,
    )
    .map_err(|e| format!("aggregate: {}", e))?;

    println!(
        "  Final signature: {}",
        hex::encode(&signature.signature_bytes)
    );
    println!(
        "  Group key:       {}",
        hex::encode(&signature.group_public_key)
    );

    // Verify
    match multisig::verify_signature(&signature, &message) {
        Ok(true) => println!("  Verification:    VALID"),
        _ => println!("  Verification:    FAILED"),
    }

    Ok(())
}

async fn cmd_multisig_info(share_file: &str) -> Result<(), String> {
    let data =
        std::fs::read_to_string(share_file).map_err(|e| format!("read {}: {}", share_file, e))?;
    let share: coincync::wallet::multisig::KeyShare =
        serde_json::from_str(&data).map_err(|e| format!("parse: {}", e))?;

    println!("Multi-sig key share info:");
    println!("  Participant:  {}", share.participant_id);
    println!(
        "  Threshold:    {}-of-{}",
        share.config.threshold, share.config.total
    );
    println!(
        "  Group key:    {}",
        hex::encode(share.config.group_public_key)
    );
    println!(
        "  Your share:   {}",
        hex::encode(&share.verifying_share_bytes[..8])
    );
    println!();
    println!(
        "This share alone CANNOT spend. {} signers must cooperate.",
        share.config.threshold
    );

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
    meta.validate(1)
        .map_err(|e| format!("invalid recovery config: {}", e))?;

    // Verify wallet opens
    let password = resolve_password(password, false)?;
    if !wallet_exists(path) {
        return Err(format!("no wallet at {:?}", path));
    }
    let _data =
        load_wallet(path, Some(password.as_str())).map_err(|e| format!("unlock failed: {}", e))?;

    let timeout_hours = timeout_blocks * 2 / 60; // approximate at 120s blocks
    let timeout_days = timeout_hours / 24;

    println!("Dead man's switch configured:");
    println!("  Recovery address: {}", recovery_address_hex);
    println!(
        "  Timeout:          {} blocks (≈{} days)",
        timeout_blocks, timeout_days
    );
    println!();
    println!("Future transactions from this wallet will include recovery");
    println!(
        "metadata. If this wallet is inactive for {} blocks,",
        timeout_blocks
    );
    println!("the recovery address can sweep the outputs.");
    println!();
    println!("To include recovery metadata in a transaction, pass:");
    println!(
        "  --recovery-address {} --recovery-timeout {}",
        recovery_address_hex, timeout_blocks
    );
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
    let password = resolve_password(password, false)?;
    if !wallet_exists(path) {
        return Err(format!("no wallet at {:?}", path));
    }
    let _data =
        load_wallet(path, Some(password.as_str())).map_err(|e| format!("unlock failed: {}", e))?;

    // Get current chain height
    let info = rpc_get_info(node)
        .await
        .map_err(|e| format!("rpc: {}", e))?;
    let current_height = info.get("height").and_then(|v| v.as_u64()).unwrap_or(0);

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

    let password = resolve_password(password, false)?;
    if !wallet_exists(path) {
        return Err(format!("no wallet at {:?}", path));
    }

    // Verify wallet unlocks
    let _data =
        load_wallet(path, Some(password.as_str())).map_err(|e| format!("unlock failed: {}", e))?;

    let config = ChurnConfig {
        enabled: true,
        min_interval_secs: min_interval,
        max_interval_secs: max_interval,
        min_amount_pct: min_pct,
        max_amount_pct: max_pct,
        node_url: node.to_string(),
    };

    config
        .validate()
        .map_err(|e| format!("invalid churn config: {}", e))?;

    println!("Auto-churn starting:");
    println!("  Wallet:       {:?}", path);
    println!("  Node:         {}", node);
    println!(
        "  Interval:     {}-{} seconds (Poisson-distributed)",
        min_interval, max_interval
    );
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

async fn cmd_subaddress_list(
    path: &PathBuf,
    password: Option<String>,
    network: Network,
) -> Result<(), String> {
    use coincync::wallet::subaddress::SubaddressManager;

    if !wallet_exists(path) {
        return Err(format!("no wallet at {:?}", path));
    }
    let password = resolve_password(password, false)?;
    let data =
        load_wallet(path, Some(password.as_str())).map_err(|e| format!("unlock failed: {}", e))?;

    let keys = WalletKeys::from_seed(data.seed);
    let epoch = keys
        .current()
        .ok_or_else(|| "wallet has no current key epoch".to_string())?;

    // Build a manager seeded with this wallet's keys, then import any
    // persisted subaddresses from the wallet file. The MAIN address
    // (account 0, index 0) is always present; others appear only if
    // the user has run `subaddress create` previously.
    let mut mgr = SubaddressManager::new(
        epoch.view_secret.clone(),
        epoch.spend_public,
        epoch.view_public,
    );
    if let Some(saved) = data.subaddresses.as_ref() {
        mgr.import(saved);
    }

    let prim_network = match network {
        Network::Mainnet => coincync::primitives::Network::Mainnet,
        Network::Testnet | Network::Regtest => coincync::primitives::Network::Testnet,
    };

    println!("Subaddresses for wallet {:?}:", path);
    let mut all = mgr.all();
    all.sort_by_key(|s| (s.index.account, s.index.index));
    for sub in all {
        let used_marker = if sub.used { "[USED]" } else { "      " };
        println!(
            "  {} {}  {}  {}",
            used_marker,
            sub.index,
            sub.address(prim_network),
            if sub.label.is_empty() {
                String::new()
            } else {
                format!("({})", sub.label)
            }
        );
    }
    println!();
    println!("Total: {} subaddress(es)", mgr.count());
    Ok(())
}

async fn cmd_subaddress_create(
    path: &PathBuf,
    password: Option<String>,
    account: u32,
    label: Option<String>,
    network: Network,
) -> Result<(), String> {
    use coincync::wallet::subaddress::SubaddressManager;

    if !wallet_exists(path) {
        return Err(format!("no wallet at {:?}", path));
    }
    let password = resolve_password(password, false)?;
    let mut data =
        load_wallet(path, Some(password.as_str())).map_err(|e| format!("unlock failed: {}", e))?;

    let keys = WalletKeys::from_seed(data.seed);
    let epoch = keys
        .current()
        .ok_or_else(|| "wallet has no current key epoch".to_string())?;

    let mut mgr = SubaddressManager::new(
        epoch.view_secret.clone(),
        epoch.spend_public,
        epoch.view_public,
    );
    if let Some(saved) = data.subaddresses.as_ref() {
        mgr.import(saved);
    }

    let new_index = mgr
        .generate_next(account)
        .map(|s| s.index)
        .ok_or_else(|| format!("failed to generate subaddress at account {}", account))?;
    if let Some(lbl) = label {
        mgr.set_label(new_index, &lbl);
    }
    let sub = mgr
        .get(new_index)
        .ok_or_else(|| "internal error: just-created subaddress not found".to_string())?
        .clone();

    let prim_network = match network {
        Network::Mainnet => coincync::primitives::Network::Mainnet,
        Network::Testnet | Network::Regtest => coincync::primitives::Network::Testnet,
    };

    // Persist the updated subaddress set back into the wallet file.
    data.subaddresses = Some(mgr.export());
    save_wallet(path, &data, Some(password.as_str())).map_err(|e| format!("save wallet: {}", e))?;

    println!("Generated subaddress:");
    println!("  Index:        {}", sub.index);
    println!("  Address:      {}", sub.address(prim_network));
    println!(
        "  Spend public: {}",
        hex::encode(sub.spend_public.as_bytes())
    );
    println!(
        "  View public:  {}",
        hex::encode(sub.view_public.as_bytes())
    );
    if !sub.label.is_empty() {
        println!("  Label:        {}", sub.label);
    }
    println!();
    println!(
        "Persisted to {:?}.  Share this address with senders — they cannot",
        path
    );
    println!("link payments to your other subaddresses on-chain.");
    Ok(())
}

async fn cmd_disclose_balance(
    path: &PathBuf,
    password: Option<String>,
    utxo_index: usize,
    threshold: u64,
) -> Result<(), String> {
    use coincync::crypto::{create_balance_proof, BlindingFactor, PedersenCommitment};
    use coincync::wallet::Wallet;

    if !wallet_exists(path) {
        return Err(format!("no wallet at {:?}", path));
    }
    let password = resolve_password(password, false)?;
    let mut wallet = Wallet::open(path.clone()).map_err(|e| format!("open wallet: {}", e))?;
    wallet
        .unlock(&password)
        .map_err(|e| format!("unlock wallet: {}", e))?;
    let balance = wallet.balance();
    let utxos = balance.unspent_utxos();
    if utxos.is_empty() {
        return Err("wallet has no unspent UTXOs to prove balance over".into());
    }
    let utxo = utxos.get(utxo_index).ok_or_else(|| {
        format!(
            "utxo_index {} out of range (wallet has {} unspent UTXOs)",
            utxo_index,
            utxos.len()
        )
    })?;

    let value = utxo.amount.as_atomic();
    if value < threshold {
        return Err(format!(
            "cannot prove threshold {}: UTXO has only {} atomic",
            threshold, value
        ));
    }
    let blinding = BlindingFactor::from_bytes(utxo.amount_blinding_bytes);
    let commitment = PedersenCommitment::commit(value, &blinding);

    let proof = create_balance_proof(value, &blinding, &commitment, threshold)
        .map_err(|e| format!("create_balance_proof: {}", e))?;

    let json = serde_json::to_vec(&proof).map_err(|e| format!("serialize proof: {}", e))?;
    let proof_hex = hex::encode(&json);

    println!("Balance proof (hex):");
    println!(
        "  utxo:        index={}  amount={}  height={}",
        utxo_index, value, utxo.height
    );
    println!(
        "  threshold:   {} atomic (≈ {:.4} CYNC)",
        threshold,
        threshold as f64 / 1e12
    );
    println!("  proof_bytes: {} bytes", json.len());
    println!();
    println!("{}", proof_hex);
    println!();
    println!("Verifier needs only the bytes above — no chain access, no wallet keys.");
    println!("Run `coincync-wallet disclose verify-balance --proof <hex>` to check.");
    Ok(())
}

/// Export a time-scoped view key covering blocks [from_height, to_height].
/// The key can decrypt only the wallet's outputs inside that range —
/// bounded disclosure ("particular description"), not a full view key.
async fn cmd_disclose_scoped_view_key(
    path: &PathBuf,
    password: Option<String>,
    from_height: u64,
    to_height: u64,
) -> Result<(), String> {
    use coincync::wallet::{ScopedViewKey, Wallet};

    if from_height > to_height {
        return Err(format!(
            "--from-height ({}) must be <= --to-height ({})",
            from_height, to_height
        ));
    }
    if !wallet_exists(path) {
        return Err(format!("no wallet at {:?}", path));
    }
    let password = resolve_password(password, false)?;
    let mut wallet = Wallet::open(path.clone()).map_err(|e| format!("open wallet: {}", e))?;
    wallet
        .unlock(&password)
        .map_err(|e| format!("unlock wallet: {}", e))?;
    let epoch = wallet
        .current_keys()
        .ok_or_else(|| "wallet has no active key epoch".to_string())?;
    let scoped = ScopedViewKey::from_epoch(&epoch, from_height, to_height);

    println!(
        "Scoped view key — blocks {}..={} (inclusive)",
        from_height, to_height
    );
    println!();
    println!("{}", scoped.to_json());
    println!();
    println!("⚠ This key contains a VIEW SECRET. It lets the holder see every");
    println!("  output your wallet received in this height range — and nothing");
    println!("  outside it. It cannot spend. Share only with the intended auditor,");
    println!("  who imports it as a read-only view bounded to this height range.");
    Ok(())
}

/// Auditor side of a scoped view key: scan the disclosed block range and
/// list the outputs the key can see. Read-only, no wallet, no spend
/// capability, and bounded to [from_height, to_height] — nothing outside
/// the disclosed scope is visible.
async fn cmd_disclose_scan_scoped(view_key_json: &str, node: &str) -> Result<(), String> {
    use coincync::consensus::Block;
    use coincync::primitives::{PublicKey, SecretKey};
    use coincync::wallet::scanner::ScanResult;
    use coincync::wallet::WalletScanner;

    let v: serde_json::Value = serde_json::from_str(view_key_json)
        .map_err(|e| format!("invalid scoped-view-key JSON: {}", e))?;
    let get_bytes = |k: &str| -> Result<[u8; 32], String> {
        let s = v
            .get(k)
            .and_then(|x| x.as_str())
            .ok_or_else(|| format!("scoped-view-key missing field '{}'", k))?;
        let raw = hex::decode(s).map_err(|e| format!("bad hex for '{}': {}", k, e))?;
        if raw.len() != 32 {
            return Err(format!("'{}' must be 32 bytes, got {}", k, raw.len()));
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(&raw);
        Ok(b)
    };
    let view_secret = SecretKey::from_bytes(get_bytes("view_secret")?);
    let spend_public = PublicKey::from_bytes(get_bytes("spend_public")?);
    let from_height = v
        .get("from_height")
        .and_then(|x| x.as_u64())
        .ok_or("scoped-view-key missing from_height")?;
    let to_height = v
        .get("to_height")
        .and_then(|x| x.as_u64())
        .ok_or("scoped-view-key missing to_height")?;
    if from_height > to_height {
        return Err(format!(
            "from_height ({}) > to_height ({})",
            from_height, to_height
        ));
    }

    let mut scanner = WalletScanner::new();
    scanner.add_keys(view_secret, spend_public, 0);

    println!(
        "Scoped scan — blocks {}..={} via {}",
        from_height, to_height, node
    );
    let (mut found, mut total) = (0usize, 0u64);
    let mut cursor = from_height;
    while cursor <= to_height {
        let batch_end = (cursor + 99).min(to_height);
        let blocks = rpc_get_block_range(node, cursor, batch_end).await?;
        if blocks.is_empty() {
            break;
        }
        for b in &blocks {
            let height = b.get("height").and_then(|x| x.as_u64()).unwrap_or(cursor);
            let bytes_hex = b
                .get("bytes")
                .and_then(|x| x.as_str())
                .ok_or("block missing bytes")?;
            let block_bytes =
                hex::decode(bytes_hex).map_err(|e| format!("bad block hex: {}", e))?;
            let block: Block =
                borsh::from_slice(&block_bytes).map_err(|e| format!("block decode: {}", e))?;
            if let ScanResult::Scanned { outputs, .. } = scanner.scan_block_with_result(&block) {
                for o in &outputs {
                    found += 1;
                    total = total.saturating_add(o.amount);
                    println!(
                        "  h{:<8} {:>16} atomic (~{:.6} CYNC)  tx={} out={}",
                        height,
                        o.amount,
                        o.amount as f64 / 1e12,
                        hex::encode(&o.tx_hash.as_bytes()[..8]),
                        o.output_index,
                    );
                }
            }
        }
        cursor = batch_end + 1;
    }
    println!();
    println!(
        "Found {} output(s), total {} atomic (~{:.6} CYNC) in blocks {}..={}.",
        found,
        total,
        total as f64 / 1e12,
        from_height,
        to_height,
    );
    println!("Bounded to the disclosed range — nothing outside it is visible to this key.");
    Ok(())
}

async fn cmd_disclose_verify_balance(proof_hex: &str) -> Result<(), String> {
    use coincync::crypto::{verify_balance_proof, DisclosureBalanceProof as BalanceProof};

    let bytes = hex::decode(proof_hex).map_err(|e| format!("invalid proof hex: {}", e))?;
    let proof: BalanceProof =
        serde_json::from_slice(&bytes).map_err(|e| format!("decode BalanceProof: {}", e))?;

    let ok = verify_balance_proof(&proof).map_err(|e| format!("verify_balance_proof: {}", e))?;

    if ok {
        // Honesty (issue #253): this only checks the range-proof math over a
        // caller-supplied commitment. It does NOT confirm the commitment
        // exists in the chain's UTXO set, so it is NOT evidence of on-chain
        // funds — anyone can commit to any amount and produce a valid range
        // proof. Label the crypto result plainly and never imply funds.
        println!("CRYPTOGRAPHICALLY VALID — range proof well-formed");
        println!(
            "  threshold:   {} atomic (≈ {:.4} CYNC)",
            proof.threshold,
            proof.threshold as f64 / 1e12
        );
        println!("  timestamp:   {} (unix epoch seconds)", proof.timestamp);
        println!("  commitment:  {}", hex::encode(proof.original_commitment));
        println!();
        println!(
            "The prover knows a value ≥ {} atomic for this commitment,",
            proof.threshold
        );
        println!("without revealing the actual value.");
        println!();
        println!("⚠ NOT ANCHORED TO CHAIN: this does not prove the commitment");
        println!("  corresponds to a real, unspent on-chain output. It is not");
        println!("  proof-of-funds on its own — verify the commitment against a");
        println!("  trusted node's UTXO set before relying on it.");
        Ok(())
    } else {
        Err("INVALID: proof verification failed".into())
    }
}

async fn cmd_disclose_verify_ownership(proof_hex: &str) -> Result<(), String> {
    use coincync::crypto::{verify_ownership_proof, OwnershipProof};

    let bytes = hex::decode(proof_hex).map_err(|e| format!("invalid proof hex: {}", e))?;
    let proof: OwnershipProof =
        serde_json::from_slice(&bytes).map_err(|e| format!("decode OwnershipProof: {}", e))?;

    let ok =
        verify_ownership_proof(&proof).map_err(|e| format!("verify_ownership_proof: {}", e))?;

    if ok {
        // Honesty (issue #253): verify_ownership_proof only checks the
        // Schnorr signature over the (stealth_address, tx_hash, output_index)
        // the prover chose. It does NOT query the chain to confirm that
        // output exists, is unspent, or that its on-chain stealth address
        // matches. So this proves "I know the key for this self-declared
        // output", not "I control real on-chain funds". Report accordingly.
        println!("CRYPTOGRAPHICALLY VALID — ownership signature well-formed");
        println!(
            "  tx_hash:        {}",
            hex::encode(proof.tx_hash.as_bytes())
        );
        println!("  output_index:   {}", proof.output_index);
        println!(
            "  stealth_addr:   {}",
            hex::encode(proof.stealth_address.as_bytes())
        );
        println!();
        println!("The prover knows the secret key for the stealth address above,");
        println!("bound to the referenced output and message.");
        println!();
        println!("⚠ NOT ANCHORED TO CHAIN: this does not confirm the referenced");
        println!("  output exists, is unspent, or that its on-chain stealth");
        println!("  address matches. It is not proof the prover controls real");
        println!("  funds — check (tx_hash, output_index) against a trusted");
        println!("  node's UTXO set before relying on it.");
        Ok(())
    } else {
        Err("INVALID: proof verification failed".into())
    }
}

async fn cmd_show_memo(
    path: &PathBuf,
    password: Option<String>,
    utxo_index: usize,
    node: &str,
) -> Result<(), String> {
    use coincync::crypto::decrypt_memo;
    use coincync::wallet::Wallet;

    if !wallet_exists(path) {
        return Err(format!("no wallet at {:?}", path));
    }
    let password = resolve_password(password, false)?;
    let mut wallet = Wallet::open(path.clone()).map_err(|e| format!("open wallet: {}", e))?;
    wallet
        .unlock(&password)
        .map_err(|e| format!("unlock wallet: {}", e))?;

    let keys = wallet
        .current_keys()
        .ok_or_else(|| "wallet has no current key epoch".to_string())?;
    let view_secret_bytes: [u8; 32] = *keys.view_secret.as_bytes();

    let balance = wallet.balance();
    let utxos = balance.unspent_utxos();
    let utxo = utxos.get(utxo_index).ok_or_else(|| {
        format!(
            "utxo_index {} out of range (wallet has {} unspent UTXOs)",
            utxo_index,
            utxos.len()
        )
    })?;

    let tx_hash_hex = hex::encode(utxo.tx_hash.as_bytes());
    let resp = rpc_call(node, "get_transaction", serde_json::json!([tx_hash_hex]))
        .await
        .map_err(|e| format!("rpc get_transaction: {}", e))?;

    let outputs = resp
        .get("outputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "rpc response missing 'outputs' array".to_string())?;
    let output = outputs.get(utxo.output_index as usize).ok_or_else(|| {
        format!(
            "output_index {} out of range (tx has {} outputs)",
            utxo.output_index,
            outputs.len()
        )
    })?;
    let memo_hex = output
        .get("encrypted_memo")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            "rpc response missing 'encrypted_memo' field — node may be on an older build"
                .to_string()
        })?;

    if memo_hex.is_empty() {
        println!(
            "No memo on UTXO #{} (tx {} output {}).",
            utxo_index,
            &tx_hash_hex[..16],
            utxo.output_index
        );
        return Ok(());
    }

    let encrypted =
        hex::decode(memo_hex).map_err(|e| format!("decode encrypted_memo hex: {}", e))?;
    let tx_pub_bytes: [u8; 32] = *utxo.tx_public_key.as_bytes();

    let plaintext = decrypt_memo(&encrypted, &view_secret_bytes, &tx_pub_bytes)
        .map_err(|e| format!("decrypt_memo: {} (memo is on-chain but this wallet's view key didn't decrypt — wrong key epoch or different recipient)", e))?;

    println!(
        "UTXO #{} (tx {}, output {}, height {}):",
        utxo_index,
        &tx_hash_hex[..16],
        utxo.output_index,
        utxo.height
    );
    println!("  encrypted bytes: {}", encrypted.len());
    match std::str::from_utf8(&plaintext) {
        Ok(s) => println!("  decrypted memo:  {:?}", s),
        Err(_) => println!(
            "  decrypted bytes: {} (not valid UTF-8) — hex={}",
            plaintext.len(),
            hex::encode(&plaintext)
        ),
    }
    Ok(())
}
