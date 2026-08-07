// Incremental CLI migration shell.
//
// The established command implementations remain in `wallet_support/legacy.rs` while
// spend-sensitive commands move to typed wallet services.  Keeping both files
// in one module lets the new dispatcher reuse the existing private parser and
// helpers without copying the rest of the CLI.
mod app {
    #![allow(dead_code)]

    include!("wallet_support/legacy.rs");
    include!("wallet_support/v2.rs");
}

fn main() {
    app::dispatch_v2();
}
