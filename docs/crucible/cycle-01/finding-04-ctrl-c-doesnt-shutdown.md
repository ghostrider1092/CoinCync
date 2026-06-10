# Crucible Cycle 01 — Finding #4: Ctrl+C doesn't actually shut down the node

**Status:** Fixed
**Severity:** Medium (operational annoyance, no data loss, but every operator hits it)
**Discovered:** 2026-06-09 (reported by barns)
**Fixed in:** `v1.0.11-fleet-2026-06-06` commit `86ca62f`
**Tester:** barns1253
**Time-to-fix:** ~15 minutes from report → diagnosis → fix

## TL;DR

The SIGINT handler fired and logged `"Shutdown signal received,
stopping node..."`, but the process never exited. The user's terminal
hung indefinitely; they had to kill the process forcibly or close the
terminal window.

## Symptom

Barns' report (Discord, 2026-06-09 21:42):

> I get another issue, i'm not be able to quit the node via ctrl+c ....
> "Shutdown received" but it didn't stopped the node

Two minimum reproductions:

1. Start `coincync-node ... start`. Wait 30 seconds. Press Ctrl+C
   once. The shutdown line logs. Process keeps running.
2. Press Ctrl+C a second, third, fourth time. No effect — the handler
   only listens once.

The only way to stop the process was `kill -9 <pid>` or closing the
terminal window (which sends SIGHUP to the child).

## Discovery path

1. Barns reported the symptom + the shutdown-line log message.
2. Searched `src/bin/node.rs` for the log message → `tokio::signal::ctrl_c()` call.
3. Read the handler:

   ```rust
   tokio::signal::ctrl_c().await.expect("...");
   info!("Shutdown signal received, stopping node...");
   match mempool.save_to_disk(&data_dir) { ... }
   Ok(())  // ← main returns
   ```

4. Searched for `tokio::spawn` in the same file → **13+ orphaned
   spawns** (REST API, JSON-RPC, P2P accept loop, P2P broadcast loop,
   sync engine, block-processing workers via `spawn_blocking`,
   explorer REST mount, mempool-gossip timers, peer-maintenance loop,
   eclipse-defense audit timer, others).
5. None of them have shutdown-signal plumbing. They're spawn-and-forget.
6. **Diagnosis:** the runtime drop blocks on all spawned tasks
   completing. None of them ever complete. Runtime never drops. Process
   never exits. Plus `spawn_blocking` workers run on the blocking pool
   which isn't cleaned up by task abort even when it does happen.

## Root cause

The handler is correct in shape — `tokio::signal::ctrl_c()` is the
canonical way to await SIGINT on Tokio. The bug is downstream:

- The codebase spawns long-running async tasks via `tokio::spawn`
  without keeping handles. The tasks are orphaned in the runtime.
- When `main`'s future resolves, the runtime is dropped. Drop blocks
  on all tasks finishing.
- Async tasks listening on sockets, timers, channels, etc. never
  finish — they're in `poll`-wait forever.
- The runtime drop never returns. The process hangs.

This is a well-known Tokio pitfall. The canonical fix is one of:

1. **Track shutdown explicitly** — broadcast `shutdown` to every spawned
   task via `watch::channel` or `broadcast::channel`. Every long-running
   task does `tokio::select! { _ = work(), _ = shutdown_rx.recv() }`.
2. **Force-exit** after critical state is saved.

#1 is architecturally pure but requires touching every spawn site.
#2 is one line and unblocks immediate UX.

This patch ships #2. #1 lands in v1.0.13 (already on the "graceful
shutdown" ROADMAP entry).

## Fix

```rust
tokio::signal::ctrl_c().await.expect("...");
info!("Shutdown signal received, stopping node...");

let shutdown_seq = async {
    match mempool.save_to_disk(&data_dir) {
        Ok(0) => {}
        Ok(n) => info!("Mempool: saved {} txs to disk", n),
        Err(e) => error!("Mempool: save_to_disk failed: {}", e),
    }
};

tokio::select! {
    _ = shutdown_seq => {
        info!("Shutdown complete.");
    }
    _ = tokio::signal::ctrl_c() => {
        warn!("Second Ctrl+C received — skipping mempool save, exiting immediately.");
    }
}

std::process::exit(0);
```

Two things:

1. **Second Ctrl+C aborts the save.** The mempool save normally takes
   <1s but can stall if the data directory is on a misbehaving disk.
   Without the escape, an impatient operator was stuck. Now: first
   Ctrl+C triggers shutdown sequence; second forces immediate exit.
2. **`std::process::exit(0)` forces the process to die** regardless
   of orphaned task state. Mempool state is preserved by the save
   above. RocksDB has its own atomic-write guarantees and a consistent
   on-disk state. P2P state is ephemeral by design.

Exit code 0 (clean) — not non-zero, because systemd and operators
treat non-zero as a crash and may attempt restart.

## Verification

Test 1 — single Ctrl+C:

```
$ ./coincync-node --network testnet ... start
INFO Node is running. Ctrl-C to stop.
^C
INFO Shutdown signal received, stopping node...
INFO Mempool: saved 0 txs to disk
INFO Shutdown complete.
$ echo $?
0
```

Process exits in <1 second.

Test 2 — first Ctrl+C, then a second immediately:

```
$ ./coincync-node --network testnet ... start
INFO Node is running. Ctrl-C to stop.
^C
INFO Shutdown signal received, stopping node...
^C
WARN Second Ctrl+C received — skipping mempool save, exiting immediately.
$ echo $?
0
```

## Impact

- **v1.0.10 and earlier:** affected with the same pattern. The
  graceful-shutdown code IS there but never reached because of the
  same orphaned-task issue. Workaround: kill -9 or terminal close.
- **v1.0.11 (pre-fix):** affected.
- **v1.0.11-fleet-2026-06-06 from `86ca62f` onward:** fixed.

The bug had been dormant in production for the entire v1.0.10
release cycle. Operators learned to kill -9 or close the terminal;
the workaround masked the bug from anyone who didn't think to
report it.

## Crucible learning

This is a **first-impression UX bug** — anyone running the binary
for the first time would hit it within an hour. Internal testing
had been using systemd, which sends SIGTERM (different signal path,
+ systemd is more aggressive about killing unresponsive services
after a timeout). The bug only surfaces for operators running the
binary directly from a terminal. **External Crucible testers do
this; internal testers don't.**

**Process gap:** the smoke-test should include "start node, Ctrl+C
once, assert process exits within 5 seconds, exit code is 0."
Open v1.0.13 follow-up.

## Follow-up tasks

- [ ] v1.0.13: implement proper `watch::channel` shutdown signal
      plumbed through every spawned task. The force-exit fix here
      is correct for the immediate problem but the architecturally
      right answer is for every task to honor a shared shutdown
      signal so they can clean up explicitly. Should land alongside
      the v1.0.13 "graceful shutdown" item.
- [ ] Add the smoke-test assertion described in Crucible learning.
- [ ] Document the shutdown contract in
      `docs/architecture/PRIVACY.md` under the Operational
      privacy layer (so future maintainers know the runtime
      shutdown rules are intentional, not laziness).
- [ ] Audit other binaries (`coincync-wallet`, `coincync-rig`) for
      the same pattern. If they have orphaned spawns, same fix.
