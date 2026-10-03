//! coincync miner-top library: the miner display model (`miner`) and the
//! btop-style render layer (`ui`). Both the `miner-top` (live TUI) and `render`
//! (headless HTML) binaries build on these two modules.
// The `/data` response is a single large `serde_json::json!` object; its nested
// macro expansion needs a higher recursion limit than the default 128.
#![recursion_limit = "512"]

pub mod feed;
pub mod miner;
pub mod serve;
pub mod ui;
