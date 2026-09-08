//! coincync miner-top library: the miner display model (`miner`) and the
//! btop-style render layer (`ui`). Both the `miner-top` (live TUI) and `render`
//! (headless HTML) binaries build on these two modules.

pub mod feed;
pub mod miner;
pub mod serve;
pub mod ui;
