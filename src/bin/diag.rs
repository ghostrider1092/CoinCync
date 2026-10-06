//! `coincync-diag` — explain CoinCync diagnostic codes, like `rustc --explain`.
//!
//! Usage:
//!   coincync-diag explain <CODE>     # full catalog entry for one code
//!   coincync-diag list               # one-line summary of every code
//!   coincync-diag list --markdown    # render DIAGNOSTICS.md
//!
//! The catalog is `coincync::diagnostics::CATALOG` — the single source of truth
//! shared with the runtime reporters and the generated docs.

use coincync::diagnostics::{lookup, Severity, CATALOG};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("explain") => {
            let Some(code) = args.get(1) else {
                eprintln!("usage: coincync-diag explain <CODE>");
                std::process::exit(2);
            };
            match lookup(code) {
                Some(d) => {
                    println!("{}", d.explain());
                    0
                }
                None => {
                    eprintln!(
                        "unknown diagnostic code {code:?}. Run `coincync-diag list` to see them all."
                    );
                    1
                }
            }
        }
        Some("list") if args.get(1).map(String::as_str) == Some("--markdown") => {
            print_markdown();
            0
        }
        Some("list") => {
            for d in CATALOG {
                let sev = match d.severity {
                    Severity::Error => "E",
                    Severity::Warning => "W",
                };
                println!("{:<14} [{}] {}", d.code, sev, d.title);
            }
            0
        }
        _ => {
            eprintln!(
                "coincync-diag — explain CoinCync diagnostic codes\n\n\
                 usage:\n  \
                 coincync-diag explain <CODE>\n  \
                 coincync-diag list [--markdown]"
            );
            2
        }
    };
    std::process::exit(code);
}

/// Render the whole catalog as `DIAGNOSTICS.md` (checked in / regenerated).
fn print_markdown() {
    println!("# CoinCync Diagnostics\n");
    println!(
        "Stable codes for runtime & consensus failures. Generated from \
         `src/diagnostics.rs` — do not edit by hand (`coincync-diag list --markdown`).\n"
    );
    println!("| Code | Sev | Title | Where | Spec |");
    println!("|------|-----|-------|-------|------|");
    for d in CATALOG {
        let sev = match d.severity {
            Severity::Error => "error",
            Severity::Warning => "warn",
        };
        println!(
            "| `{}` | {} | {} | `{}` | {} |",
            d.code, sev, d.title, d.location, d.spec
        );
    }
    println!("\n---\n");
    for d in CATALOG {
        println!("### `{}` — {}\n", d.code, d.title);
        println!("- **invariant:** {}", d.invariant);
        println!("- **where:** `{}`", d.location);
        println!("- **spec:** {}", d.spec);
        println!("- **help:** {}\n", d.help);
    }
}
