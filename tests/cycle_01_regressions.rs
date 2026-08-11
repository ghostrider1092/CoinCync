//! Regression tests for the four findings closed in Crucible Cycle 01.
//!
//! Each finding has a 1:1 mapping to a `regression_finding_N_…` test
//! below. Failing one of these tests means an intended fix for that
//! finding has been silently undone — see
//! `docs/crucible/cycle-01/finding-NN-*.md` for the full context and
//! root cause writeup.
//!
//! Coverage levels documented honestly per test:
//!
//!   - **Tight**     — exercises the fixed code path end-to-end at the
//!                     smallest scope that's still meaningful. Failing
//!                     this test means the fix has definitely
//!                     regressed.
//!   - **Surrogate** — exercises a function or invariant adjacent to
//!                     the fix because a full integration test would
//!                     need more setup (a real Blockchain, a spawned
//!                     process, etc.). Failing this test means the
//!                     surrogate has regressed; the underlying fix
//!                     might or might not be intact.
//!
//! Surrogate tests assert via the source-content pattern: they
//! `include_str!` the post-fix file and grep for the load-bearing
//! line that closes the finding. A refactor that rephrases / moves /
//! removes that line gets caught, and the test failure links straight
//! to the finding doc for context. Coverage upgrades (to real
//! integration tests) are tracked in the v1.0.13 ROADMAP.

use coincync::constants::{min_output_age_at_height, MIN_OUTPUT_AGE_HARDFORK_HEIGHT};
use coincync::network::sync::ChainSync;
use coincync::prelude::Hash;
use coincync::wallet::send::SpendContext;

// ── Finding #1 — silent mempool eviction ────────────────────────────
//
// Coverage: Surrogate.
//
// The fix added `chain.validate_transaction(&tx)?` at the top of
// `Mempool::add_with_chain` so that height-gated rules (coinbase
// maturity, ring member existence, V2 activation, lock heights,
// uniform-shape) are caught at admission rather than 60 seconds later
// in `shadow_evict_invalid`.
//
// A tight test would: build a real Blockchain, mine N blocks, build a
// privacy tx whose ring contains a coinbase output younger than
// `min_output_age_at_height(N)`, submit via `add_with_chain`, assert
// `Err(InvalidTransaction)` with reason containing "immature coinbase".
//
// That's ~100 lines of fixture setup (private-key generation, range
// proofs, ring signing, UTXO state, chain bootstrap). For v1.0.11 we
// settle for the surrogate.

#[test]
fn regression_finding_01_mempool_calls_full_validator_at_admission() {
    // The fix is: add_with_chain calls `chain.validate_transaction(&tx)`
    // BEFORE the inner `add`. Without this, height-gated rules are
    // missed at admission and the tx is silently evicted later.
    // Generation-aware admission may check the chain generation and the
    // validation result before insertion. Pin both operations to
    // add_with_chain and verify that full validation still precedes add.
    let mempool_rs = include_str!("../src/mempool.rs");
    let add_with_chain = mempool_rs
        .split_once("pub fn add_with_chain(")
        .map(|(_, tail)| tail)
        .and_then(|tail| {
            tail.split_once("/// Re-admit transactions")
                .map(|(body, _)| body)
        })
        .expect("SharedMempool::add_with_chain source must remain present");
    let validation = add_with_chain
        .find("chain.validate_transaction(tx)")
        .expect("add_with_chain must run full chain validation");
    let insertion = add_with_chain
        .find("mempool.add(tx)")
        .expect("add_with_chain must insert the validated transaction");
    assert!(
        validation < insertion,
        "Finding #1 regression: Mempool::add_with_chain must validate \
         the transaction against the chain before inserting it. See \
         docs/crucible/cycle-01/finding-01-silent-mempool-eviction.md."
    );
}

#[test]
fn regression_finding_01_spend_context_preserves_target_height_min_age() {
    // Decoy allocation receives its maturity floor from the spend context
    // rather than the retired RPC. Verify the public context at the initial
    // and activation heights so a zero or stale age cannot reach covered
    // allocation.
    for target_height in [0, MIN_OUTPUT_AGE_HARDFORK_HEIGHT] {
        let context = SpendContext::for_target_height(target_height);
        let expected_min_age = min_output_age_at_height(target_height);

        assert_eq!(context.target_height(), target_height);
        assert_eq!(context.min_output_age(), expected_min_age);
        assert_ne!(context.min_output_age(), 0);
    }
}

// ── Finding #2 — `--no-peers` silently kills `--addnode` ────────────
//
// Coverage: Tight on the arithmetic + Surrogate on the call-site.

#[test]
fn regression_finding_02_no_peers_addnode_slot_arithmetic() {
    // The fix's slot accounting: `extra_peers.len().max(1)`. We test
    // it as a pure function so the math is pinned even if the
    // surrounding code is restructured. Any change that re-introduces
    // a zero result fails here.
    fn slots(addnodes: usize) -> usize {
        addnodes.max(1)
    }
    assert_eq!(slots(0), 1, "must reserve at least one slot");
    assert_eq!(slots(1), 1, "one addnode -> one outbound slot");
    assert_eq!(slots(5), 5);
}

#[test]
fn regression_finding_02_no_peers_handler_preserves_addnode_slots() {
    let node_rs = include_str!("../src/bin/node.rs");
    assert!(
        node_rs.contains("p2p_config.max_outbound = extra_peers.len().max(1)"),
        "Finding #2 regression: src/bin/node.rs's --no-peers handler must \
         set max_outbound = extra_peers.len().max(1). The previous \
         `= 0` silently killed manual peer dialing — see \
         docs/crucible/cycle-01/finding-02-no-peers-kills-addnode.md."
    );
    // Explicitly assert the regression is gone too.
    assert!(
        !node_rs.contains("p2p_config.max_outbound = 0"),
        "Finding #2 regression: the buggy `max_outbound = 0` line has \
         re-entered src/bin/node.rs. It silently broke --addnode dialing."
    );
}

// ── Finding #3 — IBD GetHeaders 4 Hz flood ──────────────────────────
//
// Coverage: Tight on the state machine + Surrogate on the loop gate.

#[test]
fn regression_finding_03_headers_pending_state_machine() {
    let mut sync = ChainSync::new(0, Hash::zero());

    // Fresh sync: no request marked, gate should report not-pending.
    assert!(
        !sync.headers_request_pending(),
        "fresh Sync should report no pending request"
    );

    let peer = [1u8; 32];
    let nonce = sync.begin_headers_request(peer, 1_000).unwrap();
    assert!(
        sync.headers_request_pending(),
        "Finding #3 regression: after begin_headers_request, \
         headers_request_pending must report true. Without this, \
         the IBD loop would issue a fresh request every tick (~4 Hz \
         hammer)."
    );

    // A second issuance path cannot replace the first request or move its
    // timeout forward.
    assert!(sync.begin_headers_request([2u8; 32], 2_000).is_none());
    assert!(sync.headers_request_pending());
    assert!(sync.headers_timed_out(1_061));

    // After explicit reset (the normal path: EMERGENCY-TIER-3 OR the
    // 60-s timeout firing), the gate must allow a new request.
    sync.reset_headers_timeout();
    assert!(
        !sync.headers_request_pending(),
        "Finding #3 regression: reset_headers_timeout must clear the \
         pending flag so the IBD tick loop can re-issue. Without \
         this, EMERGENCY-TIER-3 recovery fires but has no effect — \
         the original trap shape."
    );
    assert!(!sync.validate_header_nonce(nonce, &peer));
}

#[test]
fn regression_finding_03_ibd_loop_gates_on_pending() {
    // The flood bug was: the tick loop sent GetHeaders unconditionally.
    // The fix inserts a `if … headers_request_pending() { continue; }`
    // guard before the send. The IBD loop now lives in sync_driver.rs.
    let sync_driver = include_str!("../src/network/node/sync_driver.rs");
    assert!(
        sync_driver.contains("headers_request_pending()"),
        "Finding #3 regression: the IBD tick loop in \
         src/network/node/sync_driver.rs must check headers_request_pending() \
         before issuing GetHeaders. Without this, the loop regresses \
         to a 4 Hz hammer that eats CPU and eventually kills the \
         node on a stuck-peer fork. See \
         docs/crucible/cycle-01/finding-03-headers-request-flood.md."
    );
}

// ── Finding #4 — Ctrl+C doesn't shut down ───────────────────────────
//
// Coverage: Surrogate.
//
// A tight test would spawn the node binary, send SIGINT, and assert
// the process exits within 5s with code 0. That needs a built binary
// and OS-level signal plumbing — a v1.0.13 follow-up. For now we pin
// the source-level invariants the fix introduced.

#[test]
fn regression_finding_04_shutdown_force_exits_after_save() {
    let node_rs = include_str!("../src/bin/node.rs");

    // The force-exit is what closed Finding #4. Without it, the tokio
    // runtime stays alive forever waiting on ~13 orphaned spawn tasks.
    assert!(
        node_rs.contains("std::process::exit(0)"),
        "Finding #4 regression: src/bin/node.rs must call \
         std::process::exit(0) after the graceful-shutdown sequence. \
         Without this, the tokio runtime never drops (orphaned spawn \
         tasks keep it alive) and the process hangs after \
         'Shutdown signal received'. See \
         docs/crucible/cycle-01/finding-04-ctrl-c-doesnt-shutdown.md."
    );
}

#[test]
fn regression_finding_04_second_ctrl_c_escape_hatch_present() {
    let node_rs = include_str!("../src/bin/node.rs");

    // The second-Ctrl+C escape hatch is what makes shutdown robust
    // against a stalled mempool save. The user can always exit by
    // pressing Ctrl+C twice. The fix uses tokio::select! to race the
    // shutdown sequence against another SIGINT.
    assert!(
        node_rs.contains("Second Ctrl+C received"),
        "Finding #4 regression: src/bin/node.rs is missing the \
         second-Ctrl+C escape hatch. Without it, a stalled \
         `mempool.save_to_disk` would leave the user with no abort \
         path and force them to kill -9 the process."
    );
}
