//! `coincync-dbg` — the CoinCync DAP adapter binary.
//!
//! Speaks DAP over stdin/stdout (how an IDE launches a DebugAdapterExecutable).
//! On launch it replays the built-in difficulty-collapse scenario; an IDE drives
//! it with standard debugging controls. Before running it writes the scenario
//! "disassembly" to a temp file so the IDE has a source to show the current line
//! against.

use std::io::{stdin, stdout, BufReader, BufWriter, Write};

use coincync_dbg::engine::ReplayEngine;
use coincync_dbg::session::Session;

fn main() -> std::io::Result<()> {
    let engine = ReplayEngine::demo_floor_scenario();

    // Write the scenario source so the IDE can open it and highlight the line
    // the stack frame points at. One line per replayed block.
    let source_path = std::env::temp_dir().join("coincync-dbg-scenario.ccscenario");
    {
        let mut f = std::fs::File::create(&source_path)?;
        for line in engine.source_lines() {
            writeln!(f, "{line}")?;
        }
    }

    let mut session = Session::new(engine, source_path.to_string_lossy().into_owned());

    let stdin = stdin();
    let mut reader = BufReader::new(stdin.lock());
    let stdout = stdout();
    let mut writer = BufWriter::new(stdout.lock());

    session.run(&mut reader, &mut writer)
}
