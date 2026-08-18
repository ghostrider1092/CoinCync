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
        node,
    } = arguments;
    use coincync::wallet::spend::{SpendCoordinator, SpendIntent, SpendSubmission};
    use coincync::wallet::{KeyEpoch, Wallet};

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
