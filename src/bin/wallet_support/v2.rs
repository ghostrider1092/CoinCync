/// Route spend-sensitive commands through the typed wallet application layer.
///
/// Other commands keep using the established CLI implementation while the
/// migration proceeds incrementally.  `wallet.rs` includes this file after
/// `wallet_support/legacy.rs`, so both implementations share the same private clap
/// types and password/path helpers without widening their public surface.
pub(super) fn dispatch_v2() {
    let cli = Cli::parse();

    if matches!(&cli.command, Command::Send { .. }) {
        run_send_command_v2(cli);
    } else {
        // The legacy entry point owns runtime and tracing initialization for
        // commands that have not moved to typed application services yet.
        main();
    }
}

fn run_send_command_v2(cli: Cli) {
    let Cli {
        wallet,
        node,
        log_level,
        command,
        ..
    } = cli;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| log_level.parse().unwrap()),
        )
        .with_target(false)
        .init();

    let Command::Send {
        password,
        to_spend,
        to_view,
        amount,
        fee_multiplier,
        split_output,
        subaddress,
        memo,
        recovery_address,
        recovery_timeout,
        policy,
    } = command
    else {
        unreachable!("send dispatcher called for a non-send command");
    };

    let arguments = SendCommandArguments {
        wallet_path: resolve_home(&wallet),
        password,
        to_spend,
        to_view,
        amount,
        fee_multiplier,
        split_output,
        subaddress,
        memo,
        recovery_address,
        recovery_timeout,
        policy,
        node,
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            error!("failed to create wallet runtime: {}", error);
            std::process::exit(1);
        }
    };

    let result = runtime.block_on(cmd_send_v2(arguments));

    if let Err(error) = result {
        error!("{}", error);
        std::process::exit(1);
    }
}

struct SendCommandArguments {
    wallet_path: PathBuf,
    password: Option<String>,
    to_spend: String,
    to_view: String,
    amount: u64,
    fee_multiplier: f64,
    split_output: bool,
    subaddress: bool,
    memo: Option<String>,
    recovery_address: Option<String>,
    recovery_timeout: Option<u64>,
    policy: Option<String>,
    node: String,
}

async fn cmd_send_v2(arguments: SendCommandArguments) -> Result<(), String> {
    let SendCommandArguments {
        wallet_path,
        password,
        to_spend: to_spend_hex,
        to_view: to_view_hex,
        amount,
        fee_multiplier,
        split_output,
        subaddress,
        memo,
        recovery_address: recovery_address_hex,
        recovery_timeout,
        policy,
        node,
    } = arguments;
    use coincync::wallet::spend::{SpendCoordinator, SpendIntent, SpendSubmission};
    use coincync::wallet::{KeyEpoch, Wallet};

    // Treasury policy: refuse before touching keys if the recipient is not
    // approved (redirect guard) or this send would exceed the per-window
    // outflow cap (velocity guard).
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Some(policy_file) = policy.as_deref() {
        enforce_send_policy(policy_file, &to_spend_hex, &to_view_hex)?;
        enforce_send_velocity(policy_file, amount, now_secs)?;
    }

    let to_spend = parse_public_key_v2(&to_spend_hex, "to-spend")?;
    let to_view = parse_public_key_v2(&to_view_hex, "to-view")?;
    let memo_bytes = validate_memo_v2(memo)?;

    if matches!(
        (recovery_address_hex.as_ref(), recovery_timeout),
        (Some(_), None) | (None, Some(_))
    ) {
        return Err(
            "--recovery-address and --recovery-timeout must be passed together".into(),
        );
    }
    let payments = payments_v2(to_spend, to_view, amount, split_output, subaddress);
    let extra = recovery_extra_v2(
        recovery_address_hex.as_deref(),
        recovery_timeout,
        payments.len(),
    )?;

    let password = resolve_password(password, false)?;
    let mut wallet = Wallet::open(wallet_path).map_err(|error| format!("open wallet: {error}"))?;
    wallet
        .unlock(password.as_str())
        .map_err(|error| format!("unlock wallet: {error}"))?;
    // W-1/W-B launch-safety: --subaddress sends are disabled on mainnet in this
    // release. This raw-pubkey path bypasses Address parsing (where the mainnet
    // subaddress gate lives), so it must be rejected here explicitly — a
    // subaddress-received output is currently unspendable (spend path omits the
    // per-subaddress offset). Available on testnet/regtest. See W-B / W-1.
    if subaddress && wallet.network_name() == "mainnet" {
        return Err(
            "subaddresses are disabled on mainnet in this release (funds received \
             at a subaddress would be permanently unspendable); omit --subaddress \
             and send to a standard address"
                .to_string(),
        );
    }
    let keys: KeyEpoch = wallet
        .current_keys()
        .cloned()
        .ok_or_else(|| "wallet has no current key epoch".to_string())?;

    let coordinator = SpendCoordinator::for_node(node)
        .map_err(|error| format!("create spend coordinator: {error}"))?;
    let session = coordinator
        .begin()
        .await
        .map_err(|error| format!("start spend session: {error}"))?;

    println!("Building transaction:");
    println!("  Recipient spend: {}", &to_spend_hex[..16]);
    println!("  Recipient view:  {}", &to_view_hex[..16]);
    println!("  Amount:          {} atomic", amount);
    println!("  Height:          {}", session.target_height());
    println!("  Fee multiplier:  {}", fee_multiplier);
    if split_output {
        println!(
            "  Drip-pair:       {} + {} (both to recipient)",
            payments[0].amount.as_atomic(),
            payments[1].amount.as_atomic()
        );
    }
    if let (Some(address), Some(timeout)) =
        (recovery_address_hex.as_deref(), recovery_timeout)
    {
        println!(
            "  Recovery:        addr={}…  timeout={} blocks",
            &address[..16],
            timeout
        );
    }

    let intent = SpendIntent::new(payments)
        .with_fee_multiplier(fee_multiplier)
        .with_memo(memo_bytes)
        .with_extra(extra);
    let mut rng = rand::rngs::OsRng;
    let built = coordinator
        .build_privacy_transaction(
            session,
            wallet.balance_ref(),
            &keys,
            intent,
            &mut rng,
        )
        .await
        .map_err(|error| format!("build privacy transaction: {error}"))?;

    let transaction = built.transaction();
    let tx_hash = built.tx_hash();
    let tx_size = built.serialized_size();

    println!();
    println!("Built tx:");
    println!("  Hash:    {}", hex::encode(tx_hash.as_bytes()));
    println!("  Inputs:  {}", transaction.inputs.len());
    println!("  Outputs: {}", transaction.outputs.len());
    println!("  Size:    {} bytes", tx_size);
    println!("  Fee:     {} atomic", transaction.fee.as_atomic());
    println!();
    println!("Submitting to {}...", coordinator.rpc().endpoint());

    match coordinator
        .submit_reserved(&mut wallet, password.as_str(), built)
        .await
        .map_err(|error| format!("submit transaction: {error}"))?
    {
        SpendSubmission::MempoolAccepted {
            tx_hash,
            retained_reservations,
            reservation_expires_at,
        } => {
            println!("  OK: tx {} accepted by mempool.", hex::encode(tx_hash.as_bytes()));
            println!(
                "  Inputs: {} reservation(s) retained until confirmation (expiry height {}).",
                retained_reservations, reservation_expires_at
            );
            // Record the outflow against the velocity ledger only after the send
            // is accepted, so a failed send never consumes budget. Best-effort.
            if let Some(policy_file) = policy.as_deref() {
                record_send_velocity(policy_file, amount, now_secs);
            }
            Ok(())
        }
        SpendSubmission::Rejected {
            tx_hash,
            reason,
            released_reservations,
            reservation_release_save_error,
        } => {
            let persistence_note = reservation_release_save_error
                .map(|error| {
                    format!(
                        "; reservation release was not persisted ({error}), so it may remain until expiry"
                    )
                })
                .unwrap_or_default();
            Err(format!(
                "node rejected transaction {}: {} (released {} reservation(s){})",
                hex::encode(tx_hash.as_bytes()),
                reason,
                released_reservations,
                persistence_note
            ))
        }
        SpendSubmission::Unknown {
            tx_hash,
            reason,
            retained_reservations,
            reservation_expires_at,
        } => Err(format!(
            "submission status for {} is unknown: {}. {} input reservation(s) were retained and \
             expire at height {} if the transaction did not land",
            hex::encode(tx_hash.as_bytes()),
            reason,
            retained_reservations,
            reservation_expires_at
        )),
    }
}

fn parse_public_key_v2(value: &str, label: &str) -> Result<coincync::primitives::PublicKey, String> {
    let bytes = hex::decode(value).map_err(|error| format!("{label} hex: {error}"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("{label} must be 32 bytes, got {}", bytes.len()))?;

    coincync::primitives::PublicKey::from_bytes_checked(bytes)
        .map_err(|error| format!("invalid {label}: {error}"))
}

fn validate_memo_v2(memo: Option<String>) -> Result<Option<Vec<u8>>, String> {
    match memo {
        Some(memo) if memo.len() > 256 => {
            Err(format!("memo too long: {} bytes (max 256)", memo.len()))
        }
        Some(memo) => Ok(Some(memo.into_bytes())),
        None => Ok(None),
    }
}

fn payments_v2(
    spend_public: coincync::primitives::PublicKey,
    view_public: coincync::primitives::PublicKey,
    amount: u64,
    split_output: bool,
    is_subaddress: bool,
) -> Vec<coincync::wallet::send::Payment> {
    use coincync::primitives::Amount;
    use coincync::wallet::send::Payment;

    // `is_subaddress` marks the destination as a subaddress (--subaddress): the
    // output then uses R = r*D_i so the recipient detects it against C_i = a*D_i.
    if split_output {
        let first = amount / 2 + amount % 2;
        let second = amount / 2;
        vec![
            Payment::new(spend_public, view_public, Amount::from_atomic(first))
                .with_subaddress(is_subaddress),
            Payment::new(spend_public, view_public, Amount::from_atomic(second))
                .with_subaddress(is_subaddress),
        ]
    } else {
        vec![
            Payment::new(spend_public, view_public, Amount::from_atomic(amount))
                .with_subaddress(is_subaddress),
        ]
    }
}

fn recovery_extra_v2(
    recovery_address_hex: Option<&str>,
    recovery_timeout: Option<u64>,
    output_count: usize,
) -> Result<Vec<u8>, String> {
    use coincync::transaction::recovery::RecoveryMeta;

    match (recovery_address_hex, recovery_timeout) {
        (Some(address), Some(timeout_blocks)) => {
            let bytes = hex::decode(address)
                .map_err(|error| format!("invalid --recovery-address hex: {error}"))?;
            let recovery_address: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
                format!(
                    "--recovery-address must be 32 bytes (64 hex), got {}",
                    bytes.len()
                )
            })?;
            let metadata = RecoveryMeta {
                output_index: 0,
                recovery_address,
                timeout_blocks,
            };
            metadata
                .validate(output_count)
                .map_err(|error| format!("invalid recovery config: {error}"))?;
            Ok(RecoveryMeta::encode_all(&[metadata]))
        }
        (None, None) => Ok(Vec::new()),
        _ => Err(
            "--recovery-address and --recovery-timeout must be passed together".into(),
        ),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests for the typed v2 dispatch path (wallet_support/v2.rs).
//
// This file is `include!`d into `mod app` alongside `legacy.rs`, so the
// module lives at `app::v2_support_tests` and reaches the private CLI
// types / helpers via `super::*`. A distinct module name avoids clashing
// with `legacy.rs`'s own `#[cfg(test)]` module in the same parent.
//
// Deferred (documented, not implemented) — cannot run without I/O the
// harness can't provide:
//   * dispatch_v2() / run_send_command_v2() end-to-end — read the process
//     argv, install a global tracing subscriber, spin a tokio runtime, and
//     `cmd_send_v2` then talks to a live node (SpendCoordinator::for_node /
//     get_decoy_distribution) against a funded wallet. Here we test the
//     routing predicate, arg parsing, and the pure `payments_v2` /
//     `parse_public_key_v2` / `validate_memo_v2` / `recovery_extra_v2`
//     builders that feed the SendRequest instead.
// ═══════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod v2_support_tests {
    use super::*;
    use clap::Parser as _;

    const HEX32: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    /// A real, on-curve (spend_public, view_public) pair derived from a
    /// freshly generated seed — needed wherever a helper actually validates
    /// the point (parse_public_key_v2 / Payment construction).
    fn real_key_pair() -> (coincync::primitives::PublicKey, coincync::primitives::PublicKey) {
        let (_phrase, seed) = coincync::wallet::generate_mnemonic();
        let keys = coincync::wallet::WalletKeys::from_seed(seed);
        let epoch = keys.current().expect("fresh wallet has a current epoch");
        (epoch.spend_public, epoch.view_public)
    }

    #[test]
    fn dispatch_v2_routes_send_to_typed_path_and_others_fall_through() {
        // Mirrors the exact `matches!` guard in `dispatch_v2`.
        let send = Cli::try_parse_from([
            "coincync-wallet",
            "send",
            "--to-spend",
            HEX32,
            "--to-view",
            HEX32,
            "--amount",
            "1000",
        ])
        .expect("send parses");
        assert!(
            matches!(&send.command, Command::Send { .. }),
            "Send must route to the typed v2 path"
        );

        for other in [
            vec!["coincync-wallet", "info"],
            vec!["coincync-wallet", "open"],
            vec!["coincync-wallet", "balance"],
            vec!["coincync-wallet", "privacy-stats"],
        ] {
            let cli = Cli::try_parse_from(other.clone()).expect("subcommand parses");
            assert!(
                !matches!(&cli.command, Command::Send { .. }),
                "{other:?} must fall through to legacy main()"
            );
        }
    }

    #[test]
    fn run_send_command_v2_parses_recipient_amount_and_password() {
        // The fields `run_send_command_v2` destructures out of the parsed Cli
        // to build SendCommandArguments.
        let cli = Cli::try_parse_from([
            "coincync-wallet",
            "send",
            "--password",
            "s3cret",
            "--to-spend",
            HEX32,
            "--to-view",
            HEX32,
            "--amount",
            "4242",
            "--fee-multiplier",
            "2.5",
        ])
        .expect("send parses");

        let Command::Send {
            password,
            to_spend,
            to_view,
            amount,
            fee_multiplier,
            split_output,
            subaddress,
            ..
        } = cli.command
        else {
            panic!("expected Send");
        };
        assert_eq!(password.as_deref(), Some("s3cret"));
        assert_eq!(to_spend, HEX32);
        assert_eq!(to_view, HEX32);
        assert_eq!(amount, 4242);
        assert_eq!(fee_multiplier, 2.5);
        assert!(!split_output);
        assert!(!subaddress);
    }

    #[test]
    fn payments_v2_single_output_carries_full_amount() {
        let (sp, vp) = real_key_pair();
        let payments = payments_v2(sp, vp, 1000, false, false);
        assert_eq!(payments.len(), 1);
        assert_eq!(payments[0].amount.as_atomic(), 1000);
        assert!(!payments[0].is_subaddress);
    }

    #[test]
    fn payments_v2_split_output_halves_sum_to_amount_with_odd_remainder_on_first() {
        let (sp, vp) = real_key_pair();
        let payments = payments_v2(sp, vp, 1001, true, false);
        assert_eq!(payments.len(), 2);
        // amount/2 + amount%2 on the first half, amount/2 on the second.
        assert_eq!(payments[0].amount.as_atomic(), 501);
        assert_eq!(payments[1].amount.as_atomic(), 500);
        assert_eq!(
            payments[0].amount.as_atomic() + payments[1].amount.as_atomic(),
            1001
        );
    }

    #[test]
    fn payments_v2_subaddress_flag_marks_every_payment() {
        let (sp, vp) = real_key_pair();
        let payments = payments_v2(sp, vp, 2000, true, true);
        assert_eq!(payments.len(), 2);
        assert!(payments.iter().all(|p| p.is_subaddress));
    }

    #[test]
    fn parse_public_key_v2_accepts_real_key_rejects_bad_hex_and_wrong_length() {
        let (sp, _vp) = real_key_pair();
        let good_hex = hex::encode(sp.as_bytes());
        assert!(parse_public_key_v2(&good_hex, "to-spend").is_ok());

        assert!(
            parse_public_key_v2("zznothex", "to-spend").is_err(),
            "non-hex must be rejected"
        );
        // 31 bytes (62 hex chars) — wrong length.
        let short = "00".repeat(31);
        assert!(
            parse_public_key_v2(&short, "to-spend").is_err(),
            "wrong-length key must be rejected"
        );
    }

    #[test]
    fn validate_memo_v2_accepts_within_limit_and_rejects_over_256() {
        assert!(validate_memo_v2(None).unwrap().is_none());
        let ok = "a".repeat(256);
        assert_eq!(validate_memo_v2(Some(ok.clone())).unwrap(), Some(ok.into_bytes()));
        let too_long = "a".repeat(257);
        assert!(validate_memo_v2(Some(too_long)).is_err());
    }

    #[test]
    fn recovery_extra_v2_requires_both_flags_or_neither() {
        // Neither set -> empty extra.
        assert!(recovery_extra_v2(None, None, 1).unwrap().is_empty());
        // Exactly one set -> error, in both directions.
        let addr = "00".repeat(32);
        assert!(recovery_extra_v2(Some(addr.as_str()), None, 1).is_err());
        assert!(recovery_extra_v2(None, Some(262800), 1).is_err());
    }

    #[test]
    fn recovery_extra_v2_encodes_metadata_when_both_present() {
        // Non-zero address: RecoveryMeta::validate rejects an all-zero one.
        let addr = "01".repeat(32);
        // 262800 blocks is within the RecoveryMeta min/max validity window.
        let extra = recovery_extra_v2(Some(addr.as_str()), Some(262800), 1)
            .expect("valid recovery config encodes");
        assert!(!extra.is_empty(), "recovery metadata must be encoded into extra");
    }
}
