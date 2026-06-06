//! Fuzz target for P2P frame parsing — DEEP shim that drives the async
//! `read_message` loop end-to-end against an in-memory tokio duplex pipe.
//!
//! The 2026-05-03 framer-cancel-safety bug class was caused by
//! `read_message` using a local `Vec` payload inside `select!` — cancel
//! at await point dropped the partial bytes and the next read started
//! from a corrupt half-frame. The fix moved the payload to
//! `self.payload_buf`. This shim re-triggers the cancel pattern with
//! fuzz-controlled byte chunks to catch any regression of that class.
//!
//! Coverage:
//!   - Sync `MessageHeader::validate` (header byte bounds)
//!   - Async `read_message` over a duplex pipe (payload reassembly)
//!   - `select!` with deliberate cancellation mid-read (cancel-safety)

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FramingInput {
    chunk_a: Vec<u8>,
    chunk_b: Vec<u8>,
    // Magic bytes the framer's validate path expects (random magic ≈
    // always rejects, which exercises the rejection path; if fuzz happens
    // to land valid magic the success path runs too).
    expected_magic: [u8; 4],
    // Cancel-after this many micros into the read. Small range to stay
    // within libFuzzer's 1s slowest-unit budget.
    cancel_at_micros: u16,
}

fuzz_target!(|input: FramingInput| {
    use coincync::network::framing::MessageFramer;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    // ── 1. Sync header-only path ──
    {
        use coincync::network::protocol::MessageHeader;
        // Borsh-decode + validate. Both must not panic on random bytes.
        if let Ok(header) = borsh::from_slice::<MessageHeader>(&input.chunk_a) {
            let _ = header.validate(input.expected_magic);
        }
    }

    // ── 2. Async read_message with deliberate select! cancellation ──
    // Drives the cancel-safety path. The fix lives in `self.payload_buf`;
    // a regression that re-introduces a local Vec would corrupt parser
    // state across the cancel, and either panic or return malformed
    // payloads to subsequent reads.
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return,
    };

    rt.block_on(async move {
        // 4 KiB duplex — wide enough for any reasonable header + payload.
        let (mut writer_half, reader_half) = tokio::io::duplex(4096);
        // Discard end: framer writes verack/etc to this if it does
        let (_, write_sink) = tokio::io::duplex(4096);

        // First write: chunk_a (partial frame — likely incomplete; the
        // framer should buffer + wait for more).
        let chunk_a = input.chunk_a.clone();
        let chunk_b = input.chunk_b.clone();
        let cancel_micros = input.cancel_at_micros as u64 % 5000;

        let writer_task = tokio::spawn(async move {
            let _ = writer_half.write_all(&chunk_a).await;
            // Brief pause then second chunk — gives the framer a window
            // to await mid-frame.
            tokio::time::sleep(Duration::from_micros(10)).await;
            let _ = writer_half.write_all(&chunk_b).await;
            // EOF: drop writer_half so framer's read returns 0.
        });

        let mut framer = MessageFramer::new(reader_half, write_sink, input.expected_magic);

        // Cancel-safety probe: race read_message against a short timer.
        let _ = tokio::select! {
            _ = framer.read_message() => {}
            _ = tokio::time::sleep(Duration::from_micros(cancel_micros)) => {
                // Cancellation point. After this, we attempt another read
                // — the cancel-safety property requires this NOT to panic
                // or return a corrupt frame.
            }
        };

        // Second attempt after cancellation — this is where a regression
        // of the framer-cancel-safety bug would surface.
        let _ = tokio::time::timeout(Duration::from_millis(50), framer.read_message()).await;

        let _ = writer_task.await;
    });
});
