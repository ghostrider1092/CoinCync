//! Colored output helpers for CLI

use colored::Colorize;

/// Print a success message with green checkmark
pub fn print_success(message: &str) {
    println!("{} {}", "✓".green().bold(), message.green());
}

/// Print an error message with red X
pub fn print_error(message: &str) {
    eprintln!("{} {}", "✗".red().bold(), message.red());
}

/// Print a warning message with yellow triangle
pub fn print_warning(message: &str) {
    println!("{} {}", "⚠".yellow().bold(), message.yellow());
}

/// Print an info message with blue info symbol
pub fn print_info(message: &str) {
    println!("{} {}", "ℹ".cyan().bold(), message);
}

/// Print a step in a process
pub fn print_step(step: usize, total: usize, message: &str) {
    println!(
        "{} {}",
        format!("[{}/{}]", step, total).dimmed(),
        message
    );
}

/// Print a labeled value
pub fn print_labeled(label: &str, value: &str) {
    println!("  {}: {}", label.dimmed(), value.bright_white());
}

/// Print a section header
pub fn print_header(title: &str) {
    println!();
    println!("{}", title.bright_white().bold().underline());
    println!();
}

/// Print a divider line
pub fn print_divider() {
    println!("{}", "─".repeat(60).dimmed());
}

/// Print a box around text
pub fn print_box(lines: &[&str]) {
    let max_len = lines.iter().map(|l| l.len()).max().unwrap_or(0);
    let border = "═".repeat(max_len + 2);

    println!("╔{}╗", border);
    for line in lines {
        println!("║ {:<width$} ║", line, width = max_len);
    }
    println!("╚{}╝", border);
}

/// Print a table row
pub fn print_table_row(columns: &[(&str, usize)]) {
    let formatted: Vec<String> = columns
        .iter()
        .map(|(text, width)| format!("{:<width$}", text, width = width))
        .collect();
    println!("  {}", formatted.join("  "));
}

/// Print balance with color based on amount
pub fn print_balance(label: &str, amount: &str, suffix: &str) {
    println!(
        "  {}: {} {}",
        label.dimmed(),
        amount.bright_green().bold(),
        suffix.dimmed()
    );
}

/// Format atomic units as human-readable CYNC amount
///
/// Examples:
/// - 1_000_000_000_000 -> "1.0 CYNC"
/// - 1_500_000_000_000 -> "1.5 CYNC"
/// - 100_000_000_000 -> "0.1 CYNC"
/// - 1_000_000 -> "0.000001 CYNC"
pub fn format_amount(atomic_units: u64) -> String {
    const ATOMIC_UNITS: u64 = 1_000_000_000_000;

    let whole = atomic_units / ATOMIC_UNITS;
    let frac = atomic_units % ATOMIC_UNITS;

    if frac == 0 {
        format!("{}.0 CYNC", whole)
    } else {
        // Find significant digits, trim trailing zeros
        let frac_str = format!("{:012}", frac);
        let trimmed = frac_str.trim_end_matches('0');
        format!("{}.{} CYNC", whole, trimmed)
    }
}

/// Format atomic units as human-readable CYNC amount (short version)
/// Uses K/M suffixes for large amounts
pub fn format_amount_short(atomic_units: u64) -> String {
    const ATOMIC_UNITS: u64 = 1_000_000_000_000;
    let cync = atomic_units as f64 / ATOMIC_UNITS as f64;

    if cync >= 1_000_000.0 {
        format!("{:.2}M CYNC", cync / 1_000_000.0)
    } else if cync >= 1_000.0 {
        format!("{:.2}K CYNC", cync / 1_000.0)
    } else if cync >= 1.0 {
        format!("{:.4} CYNC", cync)
    } else if cync >= 0.000001 {
        // Show micro-CYNC amounts (down to 1 sync)
        format!("{:.6} CYNC", cync)
    } else {
        format!("{} syncs", atomic_units)
    }
}

/// Print an address with truncation option
pub fn print_address(label: &str, address: &str, truncate: bool) {
    let display = if truncate && address.len() > 20 {
        format!("{}...{}", &address[..12], &address[address.len()-6..])
    } else {
        address.to_string()
    };
    println!("  {}: {}", label.dimmed(), display.cyan());
}

/// Print a hash value
pub fn print_hash(label: &str, hash: &str) {
    let short = if hash.len() > 16 {
        format!("{}...", &hash[..16])
    } else {
        hash.to_string()
    };
    println!("  {}: {}", label.dimmed(), short.magenta());
}

/// Print seed phrase in formatted grid (legacy — kept for tests).
///
/// L3 (audit fix): user-facing seed display should prefer
/// `print_seed_phrase_one_at_a_time` instead, which reduces forensic risk
/// from screenshots, scrollback, and shoulder-surfing.
pub fn print_seed_phrase(mnemonic: &str) {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();

    println!();
    println!("{}", "━".repeat(60).yellow());
    println!();

    for (i, word) in words.iter().enumerate() {
        let num = format!("{:2}.", i + 1);
        print!("{} {:<12}", num.dimmed(), word.bright_white());
        if (i + 1) % 4 == 0 {
            println!();
        }
    }

    println!();
    println!("{}", "━".repeat(60).yellow());
    println!();
}

/// L3 (audit fix): one-word-at-a-time seed phrase display.
///
/// Shows each word individually, waits for the user to press Enter, then
/// clears the screen before showing the next word. After the final word the
/// screen is cleared again so no full phrase is left in scrollback.
///
/// This is NOT a defense against memory forensics or screen capture by an
/// attacker who is already on the host. It's a defense against the much
/// more common case: a user with their phone camera, a screenshot, or a
/// terminal whose scrollback gets uploaded to a paste service. The phrase
/// never appears as a single visible block, so a single screenshot can only
/// leak one word.
///
/// Best-effort screen clear: works on any ANSI-capable terminal (everything
/// modern). Falls back to printing many newlines if escape codes are stripped.
pub fn print_seed_phrase_one_at_a_time(mnemonic: &str) {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    let total = words.len();

    println!();
    println!("{}", "Seed phrase display — ONE WORD AT A TIME".bright_yellow().bold());
    println!("{}", "Make sure no one can see your screen, then press Enter to begin.".dimmed());
    let _ = std::io::stdin().read_line(&mut String::new());
    clear_screen();

    for (i, word) in words.iter().enumerate() {
        println!();
        println!(
            "{} {} {}",
            "Word".dimmed(),
            format!("{}/{}", i + 1, total).bright_white().bold(),
            "— write it down, then press Enter for the next word.".dimmed()
        );
        println!();
        println!("    {}", word.bright_white().bold().on_black());
        println!();

        let _ = std::io::stdin().read_line(&mut String::new());
        clear_screen();
    }

    println!();
    println!("{}", "All words shown. Verify your written copy now.".bright_yellow());
    println!();
}

/// Best-effort terminal screen clear. Uses ANSI escape codes so it works on
/// every modern terminal (cmd.exe, PowerShell, Windows Terminal, all
/// xterm-compatible terminals on macOS / Linux). Falls back to many newlines
/// on terminals that strip escapes — that at least pushes the previous
/// output up out of the visible region.
fn clear_screen() {
    use std::io::Write;
    // ESC[2J  — clear entire screen
    // ESC[H   — cursor home
    print!("\x1B[2J\x1B[H");
    let _ = std::io::stdout().flush();
    // Defensive fallback for terminals that don't honour the escapes:
    // print enough blank lines to push the previous content above the
    // visible region. 80 lines covers any reasonable terminal height.
    for _ in 0..80 {
        println!();
    }
}

/// Print important warning box
pub fn print_important_warning(title: &str, lines: &[&str]) {
    println!();
    println!("{}", format!("⚠️  {} ⚠️", title).yellow().bold());
    println!();
    for line in lines {
        println!("   {}", line.yellow());
    }
    println!();
}

/// Format bytes as human readable
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Print an amount value with label (bright green for amounts)
pub fn print_amount_labeled(label: &str, amount: &str) {
    println!("  {}: {}", label.dimmed(), amount.bright_green());
}

/// Print a transaction hash with label (magenta for hashes)
pub fn print_tx_hash(label: &str, hash: &str) {
    println!("  {}: {}", label.dimmed(), hash.magenta());
}

/// Print a status value with label and semantic coloring
pub fn print_status(label: &str, status: &str, good: bool) {
    let colored = if good { status.green() } else { status.yellow() };
    println!("  {}: {}", label.dimmed(), colored);
}

/// Print a network-type label (bright cyan)
pub fn print_network(label: &str, network: &str) {
    println!("  {}: {}", label.dimmed(), network.bright_cyan());
}

/// Format duration in human readable form
pub fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else if seconds < 86400 {
        format!("{}h {}m", seconds / 3600, (seconds % 3600) / 60)
    } else {
        format!("{}d {}h", seconds / 86400, (seconds % 86400) / 3600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1_048_576), "1.00 MB");
        assert_eq!(format_bytes(1_073_741_824), "1.00 GB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(30), "30s");
        assert_eq!(format_duration(90), "1m 30s");
        assert_eq!(format_duration(3665), "1h 1m");
        assert_eq!(format_duration(90000), "1d 1h");
    }

    #[test]
    fn test_format_amount() {
        assert_eq!(format_amount(1_000_000_000_000), "1.0 CYNC");
        assert_eq!(format_amount(1_500_000_000_000), "1.5 CYNC");
        assert_eq!(format_amount(100_000_000_000), "0.1 CYNC");
        assert_eq!(format_amount(1_000_000), "0.000001 CYNC");
        assert_eq!(format_amount(0), "0.0 CYNC");
        assert_eq!(format_amount(10_000_000_000_000), "10.0 CYNC");
    }

    #[test]
    fn test_format_amount_short() {
        // 1_000_000_000_000_000_000 syncs = 1,000,000 CYNC = 1M CYNC
        assert_eq!(format_amount_short(1_000_000_000_000_000_000), "1.00M CYNC");
        // 1_000_000_000_000_000 syncs = 1,000 CYNC = 1K CYNC
        assert_eq!(format_amount_short(1_000_000_000_000_000), "1.00K CYNC");
        // 1_500_000_000_000 syncs = 1.5 CYNC
        assert_eq!(format_amount_short(1_500_000_000_000), "1.5000 CYNC");
        // 100_000_000 syncs = 0.0001 CYNC
        assert_eq!(format_amount_short(100_000_000), "0.000100 CYNC");
        // 100 syncs - too small for CYNC display
        assert_eq!(format_amount_short(100), "100 syncs");
    }
}
