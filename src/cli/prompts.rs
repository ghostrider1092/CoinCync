//! Interactive prompts for CLI

use dialoguer::{Confirm, Input, Password, Select, theme::ColorfulTheme};
use colored::Colorize;
use rand::seq::SliceRandom;

/// Result type for prompts
pub type PromptResult<T> = Result<T, dialoguer::Error>;

/// Get password input (hidden)
pub fn prompt_password(prompt: &str) -> PromptResult<String> {
    Password::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .interact()
}

/// Get password with confirmation
pub fn prompt_password_confirm(prompt: &str) -> PromptResult<String> {
    Password::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .with_confirmation("Confirm password", "Passwords don't match")
        .interact()
}

/// Get text input
pub fn prompt_input(prompt: &str) -> PromptResult<String> {
    Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .interact_text()
}

/// Get text input with default
pub fn prompt_input_default(prompt: &str, default: &str) -> PromptResult<String> {
    Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .default(default.to_string())
        .interact_text()
}

/// Get yes/no confirmation
pub fn prompt_confirm(prompt: &str, default: bool) -> PromptResult<bool> {
    Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .default(default)
        .interact()
}

/// Select from a list of options
pub fn prompt_select<T: ToString + std::fmt::Display>(prompt: &str, options: &[T]) -> PromptResult<usize> {
    Select::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .items(options)
        .default(0)
        .interact()
}

/// Seed phrase verification quiz
/// Returns true if user correctly verified their seed phrase
pub fn verify_seed_phrase(mnemonic: &str) -> PromptResult<bool> {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    let word_count = words.len();

    // Determine how many words to verify (3 for 24-word, 2 for 12-word)
    let verify_count = if word_count >= 24 { 3 } else { 2 };

    // Pick random word indices to verify.
    // SECURITY: use OsRng for anything that touches seed-phrase material,
    // even the verification quiz. This is the reflex discipline: seed bytes
    // never get near thread_rng.
    let mut rng = rand::rngs::OsRng;
    let mut indices: Vec<usize> = (0..word_count).collect();
    indices.shuffle(&mut rng);
    let verify_indices: Vec<usize> = indices.into_iter().take(verify_count).collect();

    println!();
    println!("{}", "SEED PHRASE VERIFICATION".bright_yellow().bold());
    println!("{}", "Please enter the following words to confirm you saved your seed phrase:".dimmed());
    println!();

    for &idx in &verify_indices {
        let word_num = idx + 1;
        let expected = words[idx].to_lowercase();

        let input: String = Input::<String>::with_theme(&ColorfulTheme::default())
            .with_prompt(format!("Word #{}", word_num))
            .interact_text()?;

        if input.trim().to_lowercase() != expected {
            println!();
            println!("{} Incorrect! Expected word #{} to be '{}'",
                "✗".red().bold(),
                word_num,
                expected.bright_white()
            );
            println!("{}", "Please write down your seed phrase and try again.".yellow());
            return Ok(false);
        }

        println!("{} Correct!", "✓".green());
    }

    println!();
    println!("{} Seed phrase verified successfully!", "✓".green().bold());
    Ok(true)
}

/// Display seed phrase with verification option.
///
/// L3 (audit fix): now uses the one-word-at-a-time display so a single
/// screenshot can leak at most one word, not the whole phrase.
pub fn display_and_verify_seed(mnemonic: &str) -> PromptResult<bool> {
    use super::output::print_seed_phrase_one_at_a_time;
    use super::output::print_important_warning;

    print_important_warning(
        "IMPORTANT: Write down your seed phrase!",
        &[
            "Anyone with this phrase can access your funds.",
            "Store it in a safe place offline.",
            "Never share it with anyone.",
            "CoinCync will NEVER ask for your seed phrase.",
            "The phrase will be shown ONE WORD AT A TIME.",
        ]
    );

    print_seed_phrase_one_at_a_time(mnemonic);

    // Verify
    verify_seed_phrase(mnemonic)
}

/// Prompt for wallet creation
pub struct WalletCreationPrompt {
    pub name: Option<String>,
    pub password: Option<String>,
    pub network: String,
}

impl WalletCreationPrompt {
    /// Run interactive wallet creation prompt
    pub fn run() -> PromptResult<Self> {
        println!();
        println!("{}", "Create New Wallet".bright_white().bold());
        println!("{}", "═".repeat(40).dimmed());
        println!();

        // Wallet name (optional)
        let name_input: String = Input::<String>::with_theme(&ColorfulTheme::default())
            .with_prompt("Wallet name (optional)")
            .allow_empty(true)
            .interact_text()?;
        let name = if name_input.is_empty() { None } else { Some(name_input) };

        // Network selection
        let networks = ["Mainnet", "Testnet"];
        let network_idx = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select network")
            .items(&networks)
            .default(0)
            .interact()?;
        let network = if network_idx == 0 { "mainnet" } else { "testnet" }.to_string();

        // Password
        let use_password = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Encrypt wallet with password?")
            .default(true)
            .interact()?;

        let password = if use_password {
            Some(prompt_password_confirm("Enter wallet password")?)
        } else {
            println!("{}", "⚠ Warning: Wallet will not be encrypted!".yellow());
            None
        };

        Ok(Self { name, password, network })
    }
}

/// Prompt for send transaction
pub struct SendPrompt {
    pub address: String,
    pub amount: String,
    pub payment_id: Option<String>,
    pub confirmed: bool,
}

impl SendPrompt {
    /// Run interactive send prompt
    pub fn run(balance: &str) -> PromptResult<Self> {
        println!();
        println!("{}", "Send CYNC".bright_white().bold());
        println!("{}", "═".repeat(40).dimmed());
        println!("Available balance: {}", balance.bright_green());
        println!();

        let address: String = Input::<String>::with_theme(&ColorfulTheme::default())
            .with_prompt("Recipient address")
            .interact_text()?;

        let amount: String = Input::<String>::with_theme(&ColorfulTheme::default())
            .with_prompt("Amount (CYNC)")
            .interact_text()?;

        let use_payment_id = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Add payment ID?")
            .default(false)
            .interact()?;

        let payment_id = if use_payment_id {
            Some(Input::<String>::with_theme(&ColorfulTheme::default())
                .with_prompt("Payment ID")
                .interact_text()?)
        } else {
            None
        };

        // Confirmation
        println!();
        println!("{}", "Transaction Summary".bright_white().bold());
        println!("  To:     {}", address.cyan());
        println!("  Amount: {} CYNC", amount.bright_green());
        if let Some(ref pid) = payment_id {
            println!("  Payment ID: {}", pid.dimmed());
        }
        println!();

        let confirmed = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Confirm transaction?")
            .default(false)
            .interact()?;

        Ok(Self {
            address,
            amount,
            payment_id,
            confirmed,
        })
    }
}

#[cfg(test)]
mod tests {
    // Interactive tests are difficult to automate
    // These would be integration tests
}
