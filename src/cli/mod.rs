//! # CLI Utilities for CoinCync 1.0
//!
//! Modern CLI experience with:
//! - Colored output
//! - Progress bars and spinners
//! - Interactive prompts
//! - Command suggestions
//! - REPL shell

pub mod disclaimer;
mod output;
mod progress;
// `prompts` depends on the optional `dialoguer` crate — wired in only
// when the `dialoguer` feature is enabled. Keeps the default build lean.
#[cfg(feature = "dialoguer")]
pub mod prompts;
mod shell;
mod suggest;

pub use output::*;
pub use progress::*;
pub use shell::*;
pub use suggest::*;

use colored::Colorize;

/// CLI theme colors
pub struct Theme;

impl Theme {
    /// Success color (green)
    pub fn success<S: AsRef<str>>(text: S) -> colored::ColoredString {
        text.as_ref().green()
    }

    /// Error color (red)
    pub fn error<S: AsRef<str>>(text: S) -> colored::ColoredString {
        text.as_ref().red()
    }

    /// Warning color (yellow)
    pub fn warning<S: AsRef<str>>(text: S) -> colored::ColoredString {
        text.as_ref().yellow()
    }

    /// Info color (cyan)
    pub fn info<S: AsRef<str>>(text: S) -> colored::ColoredString {
        text.as_ref().cyan()
    }

    /// Highlight color (bright white)
    pub fn highlight<S: AsRef<str>>(text: S) -> colored::ColoredString {
        text.as_ref().bright_white().bold()
    }

    /// Dimmed color (for secondary info)
    pub fn dimmed<S: AsRef<str>>(text: S) -> colored::ColoredString {
        text.as_ref().dimmed()
    }

    /// Amount color (green for positive)
    pub fn amount<S: AsRef<str>>(text: S) -> colored::ColoredString {
        text.as_ref().bright_green()
    }

    /// Address color (cyan)
    pub fn address<S: AsRef<str>>(text: S) -> colored::ColoredString {
        text.as_ref().cyan()
    }

    /// Hash color (magenta)
    pub fn hash<S: AsRef<str>>(text: S) -> colored::ColoredString {
        text.as_ref().magenta()
    }
}

/// Print CoinCync banner with logo
///
/// The logo shows a bold "C" arc inside an outer ring, with three
/// orbiting blockchain blocks — representing privacy, Layer 1, and
/// the chain's cryptographic ring signature foundation.
pub fn print_colored_banner() {
    
    println!();

    // ── Name ─────────────────────────────────────────────────────────
    let banner = r#"     ██████╗ ██████╗ ██╗███╗   ██╗ ██████╗██╗   ██╗███╗   ██╗ ██████╗
    ██╔════╝██╔═══██╗██║████╗  ██║██╔════╝╚██╗ ██╔╝████╗  ██║██╔════╝
    ██║     ██║   ██║██║██╔██╗ ██║██║      ╚████╔╝ ██╔██╗ ██║██║
    ██║     ██║   ██║██║██║╚██╗██║██║       ╚██╔╝  ██║╚██╗██║██║
    ╚██████╗╚██████╔╝██║██║ ╚████║╚██████╗   ██║   ██║ ╚████║╚██████╗
     ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝   ╚═╝   ╚═╝  ╚═══╝ ╚═════╝"#;

    println!("{}", banner.cyan());
    println!("                                                                 {}", "2.0".bright_cyan().bold());
    println!();
    println!("                    {}", "The privacy coin you can audit.".white());
    println!("                              {}{}", "v".dimmed(), env!("CARGO_PKG_VERSION").bright_white());
    println!();
}
