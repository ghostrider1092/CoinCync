//! First-run disclaimer that users must acknowledge before using CoinCync.
//!
//! Tracks acknowledgment history with timestamps in a JSON file.
//! Requires re-acknowledgment when DISCLAIMER_VERSION is bumped.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

/// Disclaimer version -- increment when terms change to require re-acknowledgment
pub const DISCLAIMER_VERSION: u32 = 1;

/// Acknowledgment record
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Acknowledgment {
    pub version: u32,
    pub timestamp: String,
}

/// Acknowledgment history stored on disk
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct AcknowledgmentHistory {
    pub acknowledgments: Vec<Acknowledgment>,
}

impl AcknowledgmentHistory {
    /// Load from disk or create new
    pub fn load(data_dir: &Path) -> Self {
        let path = data_dir.join("disclaimer_history.json");
        if path.exists() {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(history) = serde_json::from_str(&content) {
                    return history;
                }
            }
        }
        Self::default()
    }

    /// Save to disk
    pub fn save(&self, data_dir: &Path) -> io::Result<()> {
        fs::create_dir_all(data_dir)?;
        let path = data_dir.join("disclaimer_history.json");
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        fs::write(path, content)
    }

    /// Check if current version is acknowledged
    pub fn is_current_acknowledged(&self) -> bool {
        self.acknowledgments
            .iter()
            .any(|a| a.version == DISCLAIMER_VERSION)
    }

    /// Record new acknowledgment
    pub fn record(&mut self, version: u32) {
        self.acknowledgments.push(Acknowledgment {
            version,
            timestamp: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        });
    }
}

/// The disclaimer text shown to users on first run
pub const DISCLAIMER_TEXT: &str = r#"
+==============================================================================+
|                        COINCYNC DISCLAIMER & TERMS                           |
+==============================================================================+

BY USING THIS SOFTWARE, YOU ACKNOWLEDGE AND AGREE TO THE FOLLOWING:

1. NO WARRANTY
   This software is provided "AS IS" without warranty of any kind. CoinCync
   contributors are not liable for any loss of funds, data, or damages.

2. YOUR RESPONSIBILITY
   - You are solely responsible for securing your private keys and seed phrases
   - Lost keys CANNOT be recovered by anyone
   - Transactions are IRREVERSIBLE once confirmed

3. LEGAL COMPLIANCE
   - You are responsible for complying with all applicable laws
   - You must determine if cryptocurrency use is legal in your jurisdiction
   - You are responsible for any tax obligations

4. PROHIBITED USES
   CoinCync does NOT support and explicitly prohibits use for:
   - Money laundering or terrorist financing
   - Tax evasion or sanctions evasion
   - Purchasing illegal goods or services
   - Any activity that violates applicable law

5. PRIVACY LIMITATIONS
   - Privacy features are best-effort, not guaranteed
   - Network-level privacy (Tor/I2P) requires user configuration
   - Future cryptographic advances may weaken current protections

6. RISKS
   - CYNC may lose all value
   - Software bugs may cause unexpected behavior
   - The network may be subject to attacks or regulatory action

Full terms: DISCLAIMER.md in the CoinCync repository
"#;

/// Show disclaimer and require acknowledgment.
/// Returns true if acknowledged, false if declined.
/// Skips the prompt if already acknowledged or if --yes flag is set.
pub fn require_acknowledgment(data_dir: &Path, auto_accept: bool) -> io::Result<bool> {
    fs::create_dir_all(data_dir)?;

    let mut history = AcknowledgmentHistory::load(data_dir);

    if history.is_current_acknowledged() {
        return Ok(true);
    }

    // Auto-accept if --yes flag OR non-interactive (piped stdin, CI, background)
    use std::io::IsTerminal;
    if auto_accept || !io::stdin().is_terminal() {
        history.record(DISCLAIMER_VERSION);
        history.save(data_dir)?;
        return Ok(true);
    }

    // Interactive: show disclaimer and require typed acknowledgment
    println!("{}", DISCLAIMER_TEXT);
    println!("================================================================================");
    println!();
    print!("Type 'I AGREE' to acknowledge and continue, or 'quit' to exit: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();

    if input == "I AGREE" {
        history.record(DISCLAIMER_VERSION);
        history.save(data_dir)?;
        println!();
        println!("  Acknowledgment recorded.");
        println!();
        Ok(true)
    } else {
        println!();
        println!("  Disclaimer not acknowledged. Exiting.");
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acknowledgment_version_check() {
        let mut history = AcknowledgmentHistory::default();
        assert!(!history.is_current_acknowledged());

        history.acknowledgments.push(Acknowledgment {
            version: DISCLAIMER_VERSION,
            timestamp: "2026-01-01 00:00:00 UTC".to_string(),
        });
        assert!(history.is_current_acknowledged());
    }

    #[test]
    fn test_old_version_not_current() {
        let mut history = AcknowledgmentHistory::default();
        // Record an old version
        history.acknowledgments.push(Acknowledgment {
            version: 0,
            timestamp: "2025-01-01 00:00:00 UTC".to_string(),
        });
        // Current version is DISCLAIMER_VERSION (1), so this should be false
        // unless DISCLAIMER_VERSION happens to be 0
        if DISCLAIMER_VERSION > 0 {
            assert!(!history.is_current_acknowledged());
        }
    }

    #[test]
    fn test_disclaimer_text_not_empty() {
        assert!(!DISCLAIMER_TEXT.is_empty());
        assert!(DISCLAIMER_TEXT.contains("NO WARRANTY"));
    }
}

/// Print acknowledgment history to stdout
pub fn show_history(data_dir: &Path) {
    let history = AcknowledgmentHistory::load(data_dir);

    if history.acknowledgments.is_empty() {
        println!("No disclaimer acknowledgments recorded.");
        return;
    }

    println!();
    println!("+==============================================================+");
    println!("|            DISCLAIMER ACKNOWLEDGMENT HISTORY                 |");
    println!("+------+----------+-------------------------------------------+");
    for (i, ack) in history.acknowledgments.iter().enumerate() {
        println!("|  {:>2}  |    v{:<4} | {}  |", i + 1, ack.version, ack.timestamp);
    }
    println!("+------+----------+-------------------------------------------+");
    println!();
}
