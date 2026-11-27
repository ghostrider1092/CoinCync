// Incremental CLI migration shell.
//
// The established command implementations remain in `wallet_support/legacy.rs` while
// spend-sensitive commands move to typed wallet services.  Keeping both files
// in one module lets the new dispatcher reuse the existing private parser and
// helpers without copying the rest of the CLI.
mod app {
    #![allow(dead_code)]
    // Enforce cast-lint cleanliness across the include!d CLI files (legacy.rs +
    // v2.rs) now that both are clean. They are `include!`d, so they cannot carry
    // their own module-level deny; the enforcement lives here on `mod app`.
    #![deny(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_lossless
    )]

    include!("wallet_support/legacy.rs");
    include!("wallet_support/v2.rs");
}

fn main() {
    app::dispatch_v2();
}
