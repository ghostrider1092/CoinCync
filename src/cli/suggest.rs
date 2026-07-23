//! Command suggestion for typos ("Did you mean...?")

use strsim::levenshtein;

/// Maximum edit distance for suggestions
const MAX_DISTANCE: usize = 3;

/// Find the best matching command for a typo
pub fn suggest_command<'a>(input: &str, commands: &[&'a str]) -> Option<&'a str> {
    let input_lower = input.to_lowercase();

    // First, try prefix matching
    let prefix_matches: Vec<_> = commands
        .iter()
        .filter(|cmd| cmd.starts_with(&input_lower))
        .collect();

    if prefix_matches.len() == 1 {
        return Some(prefix_matches[0]);
    }

    // Then try Levenshtein distance
    let mut best_match: Option<(&str, usize)> = None;

    for cmd in commands {
        let distance = levenshtein(&input_lower, cmd);

        if distance <= MAX_DISTANCE {
            match best_match {
                None => best_match = Some((cmd, distance)),
                Some((_, best_dist)) if distance < best_dist => {
                    best_match = Some((cmd, distance));
                }
                _ => {}
            }
        }
    }

    best_match.map(|(cmd, _)| cmd)
}

/// Find multiple suggestions (up to n)
pub fn suggest_commands<'a>(
    input: &str,
    commands: &[&'a str],
    max_suggestions: usize,
) -> Vec<&'a str> {
    let input_lower = input.to_lowercase();

    let mut scored: Vec<_> = commands
        .iter()
        .map(|cmd| {
            let distance = levenshtein(&input_lower, cmd);
            (*cmd, distance)
        })
        .filter(|(_, dist)| *dist <= MAX_DISTANCE + 1)
        .collect();

    scored.sort_by_key(|(_, dist)| *dist);

    scored
        .into_iter()
        .take(max_suggestions)
        .map(|(cmd, _)| cmd)
        .collect()
}

/// Suggest for CLI arguments
pub fn suggest_arg<'a>(input: &str, valid_args: &[&'a str]) -> Option<&'a str> {
    // Remove leading dashes for comparison
    let clean_input = input.trim_start_matches('-');

    let mut best_match: Option<(&str, usize)> = None;

    for arg in valid_args {
        let clean_arg = arg.trim_start_matches('-');
        let distance = levenshtein(clean_input, clean_arg);

        if distance <= 2 {
            match best_match {
                None => best_match = Some((arg, distance)),
                Some((_, best_dist)) if distance < best_dist => {
                    best_match = Some((arg, distance));
                }
                _ => {}
            }
        }
    }

    best_match.map(|(arg, _)| arg)
}

/// Format suggestion message
pub fn format_suggestion(input: &str, suggestion: &str) -> String {
    format!(
        "Unknown command '{}'. Did you mean '{}'?",
        input, suggestion
    )
}

/// Format multiple suggestions
pub fn format_suggestions(input: &str, suggestions: &[&str]) -> String {
    if suggestions.is_empty() {
        format!("Unknown command: '{}'", input)
    } else if suggestions.len() == 1 {
        format_suggestion(input, suggestions[0])
    } else {
        format!(
            "Unknown command '{}'. Did you mean one of: {}?",
            input,
            suggestions.join(", ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suggest_command() {
        let commands = &["balance", "send", "history", "help", "quit", "address"];

        // Exact prefix
        assert_eq!(suggest_command("bal", commands), Some("balance"));

        // Typos
        assert_eq!(suggest_command("blance", commands), Some("balance"));
        assert_eq!(suggest_command("halp", commands), Some("help"));
        assert_eq!(suggest_command("histroy", commands), Some("history"));

        // Too different
        assert_eq!(suggest_command("xyz", commands), None);
    }

    #[test]
    fn test_suggest_commands_multiple() {
        let commands = &["send", "set", "sync", "help", "history"];

        let suggestions = suggest_commands("sen", commands, 3);
        assert!(suggestions.contains(&"send"));
    }

    #[test]
    fn test_suggest_arg() {
        let args = &["--network", "--password", "--help", "--version"];

        assert_eq!(suggest_arg("--nework", args), Some("--network"));
        assert_eq!(suggest_arg("--pasword", args), Some("--password"));
    }
}
