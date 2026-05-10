//! Subprocess wrapper around the `coincync-wallet send` CLI.
//!
//! Why subprocess instead of in-process: the wallet's send path
//! depends on RocksDB / chain handles that aren't trivial to embed.
//! The faucet stays a thin HTTP service whose only job is to gate
//! requests, append drip-log rows, and shell out to a binary that's
//! already audited and known-correct.

use std::path::Path;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;

#[derive(thiserror::Error, Debug)]
pub enum WalletError {
    #[error("wallet subprocess timed out after {0:?}")]
    Timeout(Duration),

    #[error("wallet subprocess io: {0}")]
    Io(#[from] std::io::Error),

    #[error("wallet subprocess exited {code}: {stderr}")]
    Exit { code: i32, stderr: String },

    #[error("could not parse tx hash from wallet output")]
    ParseHash,
}

pub type WalletResult<T> = std::result::Result<T, WalletError>;

pub struct WalletSendResult {
    pub tx_hash: String,
}

/// Shell out to `coincync-wallet send` with the given args. Returns
/// the parsed transaction hash on success.
///
/// The wallet binary is expected to print a line of the form
/// `  Hash:    <64-hex>` on success (see src/bin/wallet.rs around
/// the cmd_send function).
pub async fn send(
    wallet_bin: &Path,
    wallet_path: &Path,
    network: &str,
    node_rpc: &str,
    password: &str,
    to_spend_hex: &str,
    to_view_hex: &str,
    amount_atomic: u64,
    timeout_d: Duration,
) -> WalletResult<WalletSendResult> {
    let mut cmd = Command::new(wallet_bin);
    cmd.arg("--network").arg(network)
        .arg("--wallet").arg(wallet_path)
        .arg("--node").arg(node_rpc)
        .arg("send")
        .arg("--password").arg(password)
        .arg("--to-spend").arg(to_spend_hex)
        .arg("--to-view").arg(to_view_hex)
        .arg("--amount").arg(amount_atomic.to_string());

    // No stdin needed; capture stdout + stderr so we can parse + log.
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let child = cmd.spawn()?;
    let out = match timeout(timeout_d, child.wait_with_output()).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Err(WalletError::Timeout(timeout_d)),
    };

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        return Err(WalletError::Exit {
            code: out.status.code().unwrap_or(-1),
            stderr: truncate(&stderr, 512),
        });
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let tx_hash = parse_tx_hash(&stdout).ok_or(WalletError::ParseHash)?;
    Ok(WalletSendResult { tx_hash })
}

/// Pull the first 64-hex token following a `Hash:` label out of the
/// wallet's stdout. Defensive: if the format ever changes, we'd
/// rather fail loud than silently report a stale or wrong hash.
fn parse_tx_hash(stdout: &str) -> Option<String> {
    for line in stdout.lines() {
        let lower = line.trim_start();
        if let Some(rest) = lower.strip_prefix("Hash:").or_else(|| lower.strip_prefix("hash:")) {
            let h: String = rest
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .take(64)
                .collect();
            if h.len() == 64 {
                return Some(h);
            }
        }
    }
    // Fallback: any 64-hex token in the output.
    let mut hex_run = String::new();
    for c in stdout.chars() {
        if c.is_ascii_hexdigit() {
            hex_run.push(c);
            if hex_run.len() == 64 {
                return Some(hex_run);
            }
        } else {
            hex_run.clear();
        }
    }
    None
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() } else { format!("{}…", &s[..max]) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hash_from_typical_wallet_output() {
        let out = "  Submitting transaction...\n  Hash:    abcd0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd0123\n  OK\n";
        let h = parse_tx_hash(out).expect("hash");
        assert_eq!(h.len(), 64);
        assert!(h.starts_with("abcd0123"));
    }

    #[test]
    fn parses_hash_from_lowercase_label() {
        let out = "ok\nhash: 1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff\n";
        let h = parse_tx_hash(out).expect("hash");
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn falls_back_to_any_64_hex_token() {
        let out = "tx broadcast: 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef\n";
        let h = parse_tx_hash(out).expect("hash");
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn rejects_short_hex() {
        let out = "no hash here. just abc123 short.\n";
        assert!(parse_tx_hash(out).is_none());
    }
}
