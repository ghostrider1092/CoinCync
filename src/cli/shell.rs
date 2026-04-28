//! REPL-style interactive wallet shell

use rustyline::error::ReadlineError;
use rustyline::{Editor, Config, EditMode, CompletionType};
use colored::Colorize;

use super::suggest::suggest_command;

/// Available shell commands
const COMMANDS: &[&str] = &[
    "help", "balance", "address", "send", "history", "sync",
    "info", "export", "import", "lock", "unlock", "quit", "exit",
    "clear", "version", "peers", "height", "mempool"
];

/// Command help text
const HELP_TEXT: &str = r#"
Available Commands:
  balance           Show wallet balance
  address           Show wallet address
  address new       Generate new subaddress
  send              Send CYNC (interactive)
  send <addr> <amt> Send CYNC to address
  history           Show transaction history
  history <n>       Show last n transactions
  sync              Sync wallet with blockchain
  info              Show wallet info
  export viewkey    Export view key
  export keyimages  Export key images
  lock              Lock wallet
  unlock            Unlock wallet
  peers             Show connected peers
  height            Show current block height
  mempool           Show mempool stats
  clear             Clear screen
  version           Show version info
  help              Show this help
  quit/exit         Exit wallet shell
"#;

/// Shell prompt configuration
pub struct ShellConfig {
    pub network: String,
    pub wallet_name: Option<String>,
    pub locked: bool,
}

impl ShellConfig {
    /// Get the prompt string
    pub fn prompt(&self) -> String {
        let network_indicator = if self.network == "testnet" {
            "[testnet]".yellow().to_string()
        } else {
            "".to_string()
        };

        let lock_indicator = if self.locked {
            "🔒".to_string()
        } else {
            "".to_string()
        };

        let name = self.wallet_name.as_deref().unwrap_or("wallet");

        format!(
            "{}:{}{}{} {} ",
            "CoinCync".cyan().bold(),
            name.white(),
            network_indicator,
            lock_indicator,
            ">".bright_white()
        )
    }
}

/// Parsed shell command
#[derive(Debug, Clone)]
pub enum ShellCommand {
    Help,
    Balance,
    Address { new: bool },
    Send { address: Option<String>, amount: Option<String> },
    History { limit: usize },
    Sync,
    Info,
    Export { what: String },
    Import { what: String, file: String },
    Lock,
    Unlock,
    Peers,
    Height,
    Mempool,
    Clear,
    Version,
    Quit,
    Unknown(String),
    Empty,
}

impl ShellCommand {
    /// Parse command from input string
    pub fn parse(input: &str) -> Self {
        let parts: Vec<&str> = input.trim().split_whitespace().collect();

        if parts.is_empty() {
            return ShellCommand::Empty;
        }

        match parts[0].to_lowercase().as_str() {
            "help" | "?" => ShellCommand::Help,
            "balance" | "bal" => ShellCommand::Balance,
            "address" | "addr" => {
                let new = parts.get(1).map(|s| *s == "new").unwrap_or(false);
                ShellCommand::Address { new }
            }
            "send" => {
                let address = parts.get(1).map(|s| s.to_string());
                let amount = parts.get(2).map(|s| s.to_string());
                ShellCommand::Send { address, amount }
            }
            "history" | "hist" | "txs" => {
                let limit = parts.get(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(10);
                ShellCommand::History { limit }
            }
            "sync" => ShellCommand::Sync,
            "info" => ShellCommand::Info,
            "export" => {
                let what = parts.get(1).unwrap_or(&"viewkey").to_string();
                ShellCommand::Export { what }
            }
            "import" => {
                let what = parts.get(1).unwrap_or(&"keyimages").to_string();
                let file = parts.get(2).unwrap_or(&"").to_string();
                ShellCommand::Import { what, file }
            }
            "lock" => ShellCommand::Lock,
            "unlock" => ShellCommand::Unlock,
            "peers" => ShellCommand::Peers,
            "height" => ShellCommand::Height,
            "mempool" | "pool" => ShellCommand::Mempool,
            "clear" | "cls" => ShellCommand::Clear,
            "version" | "ver" => ShellCommand::Version,
            "quit" | "exit" | "q" => ShellCommand::Quit,
            other => ShellCommand::Unknown(other.to_string()),
        }
    }
}

/// Interactive wallet shell
pub struct WalletShell {
    config: ShellConfig,
    editor: Editor<(), rustyline::history::DefaultHistory>,
}

impl WalletShell {
    /// Create new wallet shell
    pub fn new(config: ShellConfig) -> Result<Self, ReadlineError> {
        let rl_config = Config::builder()
            .edit_mode(EditMode::Emacs)
            .completion_type(CompletionType::List)
            .build();

        let editor = Editor::with_config(rl_config)?;

        Ok(Self { config, editor })
    }

    /// Run the shell loop
    pub fn run<F>(&mut self, mut handler: F) -> Result<(), ReadlineError>
    where
        F: FnMut(ShellCommand) -> bool,
    {
        println!();
        println!("{}", "CoinCync Interactive Wallet".bright_white().bold());
        println!("{}", "Type 'help' for available commands, 'quit' to exit.".dimmed());
        println!();

        loop {
            let prompt = self.config.prompt();

            match self.editor.readline(&prompt) {
                Ok(line) => {
                    let _ = self.editor.add_history_entry(line.as_str());
                    let cmd = ShellCommand::parse(&line);

                    // Handle unknown commands with suggestions
                    if let ShellCommand::Unknown(ref unknown) = cmd {
                        if let Some(suggestion) = suggest_command(unknown, COMMANDS) {
                            println!(
                                "{} Unknown command: '{}'. Did you mean '{}'?",
                                "?".yellow(),
                                unknown.red(),
                                suggestion.green()
                            );
                            continue;
                        }
                    }

                    // Call handler, quit if it returns true
                    if handler(cmd) {
                        break;
                    }
                }
                Err(ReadlineError::Interrupted) => {
                    println!("{}", "Use 'quit' or 'exit' to leave.".dimmed());
                }
                Err(ReadlineError::Eof) => {
                    println!("Goodbye!");
                    break;
                }
                Err(err) => {
                    println!("{} Error: {:?}", "✗".red(), err);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Update shell config
    pub fn set_locked(&mut self, locked: bool) {
        self.config.locked = locked;
    }
}

/// Print shell help
pub fn print_shell_help() {
    println!("{}", HELP_TEXT);
}

/// Clear terminal screen
pub fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_commands() {
        assert!(matches!(ShellCommand::parse("help"), ShellCommand::Help));
        assert!(matches!(ShellCommand::parse("balance"), ShellCommand::Balance));
        assert!(matches!(ShellCommand::parse("quit"), ShellCommand::Quit));
        assert!(matches!(ShellCommand::parse("exit"), ShellCommand::Quit));
        assert!(matches!(ShellCommand::parse(""), ShellCommand::Empty));

        match ShellCommand::parse("history 20") {
            ShellCommand::History { limit } => assert_eq!(limit, 20),
            _ => panic!("Expected History command"),
        }

        match ShellCommand::parse("address new") {
            ShellCommand::Address { new } => assert!(new),
            _ => panic!("Expected Address command"),
        }
    }
}
