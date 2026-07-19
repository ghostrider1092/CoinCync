//! `coord-cli` — operator CLI for the FROST coordinator (phase 4.5).
//!
//! The `coord` server bin (phase 4) accepts WSS connections and
//! routes messages between participants. It does NOT expose
//! session-creation, invitation-minting, or admin operations over
//! the network — those are operator privileges. This CLI is the
//! local interface for them: it reads + writes the same
//! SessionStore the server reads, plus mints HMAC invitations
//! using the same per-session secret.
//!
//! ## Status: PHASE 4.5 — works, sync, no async runtime
//!
//! Subcommands:
//! - `gen-secret`     — generate a fresh 32-byte session secret
//! - `create-session` — add a new Session to the state store
//! - `mint-invitation` — issue an HMAC invitation token
//! - `list`           — list all sessions (id, state, threshold)
//! - `inspect`        — print full details of a single session
//! - `force-abort`    — admin: walk a session to Aborted
//! - `gc-terminal`    — purge sessions in terminal states past
//!   retention
//!
//! ## Workflow
//!
//! 1. Operator generates a secret on first install:
//!    ```
//!    coord-cli gen-secret > /etc/coincync/coord-secret
//!    chmod 600 /etc/coincync/coord-secret
//!    ```
//!
//! 2. Operator creates a session:
//!    ```
//!    coord-cli create-session --threshold 2 --total 3 \
//!        --group-pubkey <hex-32> --creator <hex-32>
//!    ```
//!    Prints the session_id; operator shares it out-of-band.
//!
//! 3. For each invited participant, operator mints a token:
//!    ```
//!    coord-cli mint-invitation --session <id> \
//!        --participant <hex-32> --expires-in-hours 168
//!    ```
//!    Prints the JSON-encoded token; operator delivers each
//!    token to the corresponding participant out-of-band
//!    (Signal / email / QR code).
//!
//! 4. The participants connect their wallets to the running
//!    `coord` WSS server, present their tokens, and the FROST
//!    signing flow proceeds.
//!
//! ## Coexistence with the coord server
//!
//! The `coord` server holds its own in-memory copy of the
//! SessionStore. If `coord-cli` modifies the store while the
//! server is running, the server WILL NOT see the change until
//! it's restarted (the server doesn't watch the file for
//! changes — that complexity isn't worth it pre-mainnet).
//!
//! Operator workflow:
//!   - run `coord-cli create-session` / `mint-invitation` BEFORE
//!     starting the server, OR
//!   - stop the server, run the CLI, restart the server.
//!
//! The server's atomic-write pattern means concurrent runs won't
//! corrupt the file — but the in-memory view divergence is
//! confusing, so the discipline above is the recommended path.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};

use coincync_frost_coordinator::invitations::{mint_token, SESSION_SECRET_LEN};
use coincync_frost_coordinator::session::{
    ParticipantId, Session, SessionId, SessionState, Transition,
};
use coincync_frost_coordinator::SessionStore;

#[derive(Parser)]
#[command(name = "coord-cli")]
#[command(version)]
#[command(about = "Operator CLI for the FROST coordinator (phase 4.5).")]
struct Cli {
    /// Path to the SessionStore JSON file. Defaults to
    /// `/var/lib/coincync-coord/sessions.json` (matches the
    /// coord server's default `COINCYNC_COORD_STATE`).
    #[arg(long, global = true)]
    state_file: Option<PathBuf>,

    /// Path to the session-secret file. Defaults to
    /// `/etc/coincync/coord-secret`. Used by `mint-invitation`.
    #[arg(long, global = true)]
    secret_file: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a fresh 32-byte session secret. Writes to stdout
    /// as 64 hex chars; pipe to a 0600 file owned by the
    /// coordinator service user.
    GenSecret,

    /// Create a new FROST session. Prints the session_id.
    CreateSession {
        /// Signing threshold M (must be >= 2).
        #[arg(long)]
        threshold: u16,
        /// Total participants N (must be >= threshold).
        #[arg(long)]
        total: u16,
        /// Group public key, 64 hex chars (= 32 bytes ed25519).
        #[arg(long)]
        group_pubkey: String,
        /// Creator's pubkey, 64 hex chars. The creator is
        /// distinguished as the participant who initiated the
        /// session; in production wallets, this is the operator's
        /// own pubkey.
        #[arg(long)]
        creator: String,
    },

    /// Mint an invitation token for a participant. Prints the
    /// JSON-encoded token on stdout.
    MintInvitation {
        /// Session ID (UUID format).
        #[arg(long)]
        session: String,
        /// Participant's pubkey, 64 hex chars.
        #[arg(long)]
        participant: String,
        /// Token expiry in hours from now. Default 168 (= 7
        /// days), matching `INVITED_TIMEOUT_SECS`.
        #[arg(long, default_value_t = 168)]
        expires_in_hours: u64,
    },

    /// List all sessions in the state store.
    List,

    /// Print full details of a single session.
    Inspect {
        /// Session ID.
        session: String,
    },

    /// Force a session into the Aborted state. Used when a
    /// session is stuck (a participant is unreachable, the
    /// operator decides to abandon it, etc.). The participant
    /// argument is the operator's own pubkey, used as the abort
    /// signaler.
    ForceAbort {
        /// Session ID.
        #[arg(long)]
        session: String,
        /// Operator's pubkey (the abort is recorded as coming
        /// from this pubkey).
        #[arg(long)]
        participant: String,
        /// Reason for the abort, recorded in operator logs.
        #[arg(long)]
        reason: String,
    },

    /// Garbage-collect sessions in terminal states whose
    /// retention has elapsed. Aggregated sessions are kept for
    /// AGGREGATED_RETENTION_SECS (30 days); Aborted and Expired
    /// have no fixed retention but are purged after the same
    /// 30-day window.
    GcTerminal {
        /// Dry-run: print what would be purged, don't modify the
        /// state file.
        #[arg(long)]
        dry_run: bool,
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
    let state_path = cli
        .state_file
        .unwrap_or_else(|| PathBuf::from("/var/lib/coincync-coord/sessions.json"));
    let secret_path = cli
        .secret_file
        .unwrap_or_else(|| PathBuf::from("/etc/coincync/coord-secret"));

    match cli.command {
        Command::GenSecret => gen_secret(),
        Command::CreateSession {
            threshold,
            total,
            group_pubkey,
            creator,
        } => create_session(state_path, threshold, total, &group_pubkey, &creator),
        Command::MintInvitation {
            session,
            participant,
            expires_in_hours,
        } => mint_invitation(secret_path, &session, &participant, expires_in_hours),
        Command::List => list_sessions(state_path),
        Command::Inspect { session } => inspect_session(state_path, &session),
        Command::ForceAbort {
            session,
            participant,
            reason,
        } => force_abort(state_path, &session, &participant, &reason),
        Command::GcTerminal { dry_run } => gc_terminal(state_path, dry_run),
    }
}

// ──────────────────────────────────────────────────────────────────
// Subcommand handlers
// ──────────────────────────────────────────────────────────────────

fn gen_secret() -> Result<(), String> {
    let mut secret = [0u8; SESSION_SECRET_LEN];
    read_random(&mut secret).map_err(|e| format!("random read failed: {e}"))?;
    println!("{}", hex::encode(secret));
    eprintln!("# 32-byte session secret. Write to a 0600 file owned by the");
    eprintln!("# coord service user, then start coord with");
    eprintln!("# COINCYNC_COORD_INVITE_SECRET=<this-hex>.");
    Ok(())
}

fn create_session(
    state_path: PathBuf,
    threshold: u16,
    total: u16,
    group_pubkey_hex: &str,
    creator_hex: &str,
) -> Result<(), String> {
    let group_pubkey =
        parse_32byte_hex(group_pubkey_hex).map_err(|e| format!("group_pubkey: {e}"))?;
    let creator_bytes = parse_32byte_hex(creator_hex).map_err(|e| format!("creator: {e}"))?;
    let now = unix_now();

    let session = Session::new(
        threshold,
        total,
        group_pubkey,
        ParticipantId(creator_bytes),
        now,
    )
    .map_err(|e| format!("session construction: {e}"))?;
    let session_id = session.id;

    let store = SessionStore::new(&state_path);
    let mut existing = store.load().map_err(|e| format!("load existing: {e}"))?;
    existing.push(session);
    store.save(&existing).map_err(|e| format!("save: {e}"))?;

    println!("Session created.");
    println!("  session_id: {}", uuid_format(session_id));
    println!("  threshold:  {threshold}");
    println!("  total:      {total}");
    println!("  state file: {}", state_path.display());
    println!();
    println!("Next steps:");
    println!("  - mint an invitation for each participant:");
    println!("      coord-cli mint-invitation \\");
    println!("        --session {} \\", uuid_format(session_id));
    println!("        --participant <participant-pubkey-hex>");
    println!("  - share each token out-of-band with the corresponding participant");
    println!("  - start (or restart) the coord server so it picks up this session");
    Ok(())
}

fn mint_invitation(
    secret_path: PathBuf,
    session_hex: &str,
    participant_hex: &str,
    expires_in_hours: u64,
) -> Result<(), String> {
    let secret = read_secret_file(&secret_path)?;
    let session_id = parse_session_id(session_hex)?;
    let participant_bytes =
        parse_32byte_hex(participant_hex).map_err(|e| format!("participant: {e}"))?;
    let participant = ParticipantId(participant_bytes);

    let expires_at = unix_now()
        .checked_add(
            expires_in_hours
                .checked_mul(3600)
                .ok_or_else(|| "expires_in_hours too large".to_string())?,
        )
        .ok_or_else(|| "expiry timestamp overflow".to_string())?;

    let token = mint_token(&secret, session_id, participant, expires_at)
        .map_err(|e| format!("mint failed: {e}"))?;
    let json = serde_json::to_string_pretty(&token).map_err(|e| format!("encode token: {e}"))?;
    println!("{json}");
    eprintln!();
    eprintln!("# Invitation token for participant {participant_hex}");
    eprintln!("# Expires at unix time {expires_at} (~{expires_in_hours}h from now).");
    eprintln!("# Deliver to the participant out-of-band.");
    Ok(())
}

fn list_sessions(state_path: PathBuf) -> Result<(), String> {
    let store = SessionStore::new(&state_path);
    let sessions = store.load().map_err(|e| format!("load: {e}"))?;
    if sessions.is_empty() {
        println!("(no sessions in {})", state_path.display());
        return Ok(());
    }
    println!(
        "{:<38}  {:<11}  {:>5}  {:>5}  {:>11}",
        "session_id", "state", "thld", "total", "age (s)"
    );
    println!("{}", "-".repeat(80));
    let now = unix_now();
    for s in &sessions {
        let age = now.saturating_sub(s.created_at);
        println!(
            "{:<38}  {:<11}  {:>5}  {:>5}  {:>11}",
            uuid_format(s.id),
            state_name(&s.state),
            s.threshold,
            s.total,
            age,
        );
    }
    Ok(())
}

fn inspect_session(state_path: PathBuf, session_hex: &str) -> Result<(), String> {
    let target_id = parse_session_id(session_hex)?;
    let store = SessionStore::new(&state_path);
    let sessions = store.load().map_err(|e| format!("load: {e}"))?;
    let session = sessions
        .iter()
        .find(|s| s.id == target_id)
        .ok_or_else(|| format!("session {session_hex} not found"))?;

    let now = unix_now();
    println!("Session details:");
    println!("  session_id:   {}", uuid_format(session.id));
    println!("  state:        {}", state_name(&session.state));
    println!("  threshold:    {}", session.threshold);
    println!("  total:        {}", session.total);
    println!("  group_pubkey: {}", hex::encode(session.group_pubkey));
    println!("  creator:      {}", hex::encode(session.creator.0));
    println!(
        "  created_at:   {} ({}s ago)",
        session.created_at,
        now.saturating_sub(session.created_at)
    );
    println!(
        "  state_entered: {} ({}s ago)",
        session.state_entered_at,
        now.saturating_sub(session.state_entered_at)
    );
    println!(
        "  message:      {}",
        match &session.message {
            Some(m) => format!("{} bytes", m.len()),
            None => "(not yet declared)".into(),
        }
    );
    println!("  participants ({}):", session.participants.len());
    for (pubkey, p_state) in &session.participants {
        println!(
            "    {} (attached={}, commitment={}, sig_share={})",
            hex::encode(pubkey.0),
            p_state.attached,
            if p_state.commitment.is_some() {
                "yes"
            } else {
                "no"
            },
            if p_state.sig_share.is_some() {
                "yes"
            } else {
                "no"
            },
        );
    }
    println!(
        "  aggregate_signature: {}",
        match &session.aggregate_signature {
            Some(s) => format!("{} bytes ({})", s.len(), hex::encode(&s[..s.len().min(8)])),
            None => "(not yet)".into(),
        }
    );
    Ok(())
}

fn force_abort(
    state_path: PathBuf,
    session_hex: &str,
    participant_hex: &str,
    reason: &str,
) -> Result<(), String> {
    let target_id = parse_session_id(session_hex)?;
    let participant_bytes =
        parse_32byte_hex(participant_hex).map_err(|e| format!("participant: {e}"))?;
    let store = SessionStore::new(&state_path);
    let mut sessions = store.load().map_err(|e| format!("load: {e}"))?;
    let session = sessions
        .iter_mut()
        .find(|s| s.id == target_id)
        .ok_or_else(|| format!("session {session_hex} not found"))?;
    let now = unix_now();
    let prior_state = state_name(&session.state).to_string();
    session
        .apply(
            Transition::Abort {
                participant: ParticipantId(participant_bytes),
            },
            now,
        )
        .map_err(|e| format!("abort transition: {e}"))?;
    let new_state = state_name(&session.state).to_string();
    store.save(&sessions).map_err(|e| format!("save: {e}"))?;

    eprintln!("Force-abort applied (operator-initiated).");
    eprintln!("  session:      {session_hex}");
    eprintln!("  prior state:  {prior_state}");
    eprintln!("  new state:    {new_state}");
    eprintln!("  participant:  {participant_hex}");
    eprintln!("  reason:       {reason}");
    eprintln!();
    eprintln!("Restart the coord server so it picks up the abort.");
    Ok(())
}

fn gc_terminal(state_path: PathBuf, dry_run: bool) -> Result<(), String> {
    const RETENTION_SECS: u64 = 30 * 24 * 60 * 60; // 30 days
    let store = SessionStore::new(&state_path);
    let sessions = store.load().map_err(|e| format!("load: {e}"))?;
    let now = unix_now();
    let mut keep: Vec<Session> = Vec::with_capacity(sessions.len());
    let mut purged: Vec<(SessionId, &'static str)> = Vec::new();
    for s in sessions {
        if !s.state.is_terminal() {
            keep.push(s);
            continue;
        }
        let age = now.saturating_sub(s.state_entered_at);
        if age >= RETENTION_SECS {
            purged.push((s.id, state_name(&s.state)));
        } else {
            keep.push(s);
        }
    }

    if purged.is_empty() {
        println!(
            "Nothing to purge ({} sessions, all within retention or non-terminal).",
            keep.len()
        );
        return Ok(());
    }

    if dry_run {
        println!("DRY RUN: would purge {} session(s):", purged.len());
    } else {
        println!("Purging {} session(s):", purged.len());
    }
    for (id, state) in &purged {
        println!("  {}  ({})", uuid_format(*id), state);
    }
    if dry_run {
        println!();
        println!("(dry run — state file not modified. Re-run without --dry-run to commit.)");
        return Ok(());
    }
    store.save(&keep).map_err(|e| format!("save: {e}"))?;
    println!();
    println!("Purge complete. {} session(s) retained.", keep.len());
    Ok(())
}

// ──────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn parse_32byte_hex(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("not valid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "expected 32 bytes (64 hex chars), got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_session_id(s: &str) -> Result<SessionId, String> {
    use uuid::Uuid;
    let uuid = Uuid::parse_str(s).map_err(|e| format!("not a valid UUID: {e}"))?;
    Ok(SessionId(uuid))
}

fn uuid_format(id: SessionId) -> String {
    id.0.to_string()
}

fn state_name(s: &SessionState) -> &'static str {
    match s {
        SessionState::Created => "Created",
        SessionState::Invited => "Invited",
        SessionState::Round1 => "Round1",
        SessionState::Round2 => "Round2",
        SessionState::Aggregated => "Aggregated",
        SessionState::Aborted => "Aborted",
        SessionState::Expired => "Expired",
    }
}

fn read_secret_file(path: &PathBuf) -> Result<[u8; SESSION_SECRET_LEN], String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("read secret file {}: {e}", path.display()))?;
    let trimmed = raw.trim();
    parse_32byte_hex(trimmed).map_err(|e| format!("secret file: {e}"))
}

fn read_random(buf: &mut [u8]) -> std::io::Result<()> {
    // CSPRNG: getrandom maps to the OS's secure-random syscall
    // on every platform we ship — Linux/macOS getrandom(2),
    // Windows BCryptGenRandom, WASI random_get. HMAC keys MUST
    // be unguessable; any fallback to weaker entropy here
    // would be a security defect, so we fail loudly instead.
    //
    // Earlier versions of this function fell back to an LCG
    // seeded from now()+pid on Windows. That was a critical
    // bug found in the May-8 aggressive-test pass: an attacker
    // who knew approximate process-start time and PID range
    // could brute-force the secret in seconds and forge attach
    // tokens. Replaced with getrandom — no fallback, fail-fast.
    getrandom::getrandom(buf).map_err(|e| std::io::Error::other(e.to_string()))
}

// ──────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_32byte_hex_accepts_64_chars() {
        let hex = "00".repeat(32);
        let parsed = parse_32byte_hex(&hex).unwrap();
        assert_eq!(parsed, [0u8; 32]);
    }

    #[test]
    fn parse_32byte_hex_rejects_wrong_length() {
        assert!(parse_32byte_hex("aabbcc").is_err());
        assert!(parse_32byte_hex(&"00".repeat(33)).is_err());
    }

    #[test]
    fn parse_32byte_hex_rejects_non_hex() {
        let bad = "z".repeat(64);
        assert!(parse_32byte_hex(&bad).is_err());
    }

    #[test]
    fn parse_session_id_round_trip() {
        use uuid::Uuid;
        // Use a fixed value rather than v4/v7 generators because
        // the workspace's uuid dep only enables `v7`. Any valid
        // UUID round-trips identically.
        let original = SessionId(Uuid::from_u128(0x0123456789abcdef_fedcba9876543210));
        let s = uuid_format(original);
        let parsed = parse_session_id(&s).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn state_name_is_distinct_per_variant() {
        let names: std::collections::HashSet<_> = [
            state_name(&SessionState::Created),
            state_name(&SessionState::Invited),
            state_name(&SessionState::Round1),
            state_name(&SessionState::Round2),
            state_name(&SessionState::Aggregated),
            state_name(&SessionState::Aborted),
            state_name(&SessionState::Expired),
        ]
        .into_iter()
        .collect();
        assert_eq!(names.len(), 7);
    }

    #[test]
    fn is_terminal_matches_state_machine() {
        assert!(!SessionState::Created.is_terminal());
        assert!(!SessionState::Invited.is_terminal());
        assert!(!SessionState::Round1.is_terminal());
        assert!(!SessionState::Round2.is_terminal());
        assert!(SessionState::Aggregated.is_terminal());
        assert!(SessionState::Aborted.is_terminal());
        assert!(SessionState::Expired.is_terminal());
    }
}
