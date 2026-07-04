# Runbook: runtime deadlock watchdog + diagnostic snapshots

## What this document is

Operator guide for the `src/runtime_watchdog.rs` subsystem. Covers:

1. What the watchdog does automatically
2. How to trigger an **on-demand** snapshot without waiting for the automatic 2-minute confirmation (SIGUSR1)
3. How to interpret the diagnostic dump — every field, why it's there, what to look for
4. When and how to grant `CAP_SYS_PTRACE` to make the dumps richer
5. The known limits — what the dump still cannot tell you and how to close those gaps

Ground-truth reference for the code: [`src/runtime_watchdog.rs`](../../src/runtime_watchdog.rs).
Related deploy artifact: [`scripts/systemd-drop-in-cap-sys-ptrace.conf`](../../scripts/systemd-drop-in-cap-sys-ptrace.conf).

## Automatic path — what the node does with no operator involvement

1. On process start, `arm(data_dir)` in `src/bin/node.rs` spawns a dedicated **OS thread** (not a tokio task) named `coincync-watchdog` and installs a SIGUSR1 handler.
2. A tokio task pulses a heartbeat counter every 5s.
3. The OS thread checks the counter every 15s.
4. If the counter hasn't advanced for **45s**, the OS thread starts inspecting `/proc/self/task/*/wchan` on Linux.
5. If **≥90% of threads are parked on `futex_wait_queue`** AND this pattern persists for **120s**, the OS thread:
   - Writes `deadlock-<unix_ts>.log` to `<data_dir>` (usually `/var/lib/coincync/`)
   - Calls `std::process::abort()` — systemd's `Restart=` policy brings the node back up

No manual action is needed for this path. The dump lands on disk before abort; the operator finds it after the systemd restart.

## On-demand path — capturing a snapshot before the automatic confirmation fires

When you suspect a hang but the 2-minute confirmation hasn't triggered yet — or when you want a live snapshot of a healthy process for baseline comparison — send SIGUSR1 to the node:

```bash
sudo kill -USR1 $(pgrep -f coincync-node)
```

The watchdog OS thread polls the SIGUSR1 flag on its 15s tick, so the snapshot lands within 15 seconds of the signal. Output file is `snapshot-<unix_ts>.log` in `<data_dir>` — note the `snapshot-` prefix distinguishes it from `deadlock-*.log` (the automatic path).

**Key property**: the on-demand path **does NOT abort the process**. Safe to run against a live production node without service disruption. Uses the SAME `write_diagnostic_snapshot` code path as the automatic path — output format is identical, only the `trigger:` header line differs.

## Reading the dump file

Example output (Linux, `CAP_SYS_PTRACE` NOT granted):

```
coincync runtime diagnostic (manual_sigusr1)
trigger: manual_sigusr1
unix_ts: 1751654210
process_uptime_secs: 2314
heartbeat_last_counter: 462
heartbeat_stall_secs: 0
total_threads: 16
futex_park_threads: 3
futex_fraction: 0.19

─── per-thread snapshot (capped at 32) ───
# syscall args: on x86_64 nr=202 is futex; arg0 is the futex address.
# Two threads with the same arg0 are waiting on the same underlying lock.
# kernel_stack_head is often empty under the unprivileged sandbox and needs CAP_SYS_PTRACE.
tid=118203 comm="coincync-node" wchan=epoll_wait state=[State: S (sleeping)] syscall=[232 0x8 0x7fff... 0x0 0xffffffff 0x0 0x0 0x7fff...] kernel_stack_head=[]
tid=118207 comm="tokio-runtime-w" wchan=futex_wait_queue state=[State: S (sleeping)] syscall=[202 0x7f5c... 0x89 0x0 0x0 0x0 0x0 0x7f5c...] kernel_stack_head=[]
tid=118208 comm="tokio-runtime-w" wchan=futex_wait_queue state=[State: S (sleeping)] syscall=[202 0x7f5c... 0x89 0x0 0x0 0x0 0x0 0x7f5c...] kernel_stack_head=[]
...
```

### Field-by-field

- **`trigger:`** — `deadlock_confirmed` (automatic abort path) or `manual_sigusr1` (operator-triggered, no abort)
- **`process_uptime_secs`** — seconds since the node started. **Critical for pattern matching**: the 2026-07-02 and 2026-07-03 fires both triggered at **~8m45s uptime**, hinting at a timer-driven task or startup-phase completion
- **`heartbeat_stall_secs`** — how long the tokio heartbeat has been frozen. For `manual_sigusr1` this is usually 0 (tokio is fine); for `deadlock_confirmed` it will be 45s+
- **`futex_park_threads / total_threads`** — the raw ratio the deadlock detector uses; 90%+ trips the abort path
- **`comm=`** — thread name (kernel-capped at 15 chars). Interpretation cheat-sheet:
  - `tokio-runtime-w` — tokio worker thread (there are typically 8 of these matching `#[tokio::main(worker_threads = 8)]`)
  - `coincync-node` — the main thread (inherited from process name)
  - `coincync-watchdog` — this watchdog itself (should never be futex-parked)
  - `randomx-*` — RandomX mining worker
  - Custom names — anywhere the code calls `std::thread::Builder::name(...)`
- **`wchan=`** — kernel wait-channel:
  - `futex_wait_queue` / `do_futex` — parked on a userspace mutex (this is the deadlock signature)
  - `epoll_wait` — waiting on I/O (healthy tokio worker with no work)
  - `hrtimer_nanosleep` — waiting on a timer
  - `-` (or empty) — currently running (rare — snapshot took its scan right when this thread was on-CPU)
- **`syscall=`** — the **key correlation field**. Format: `<nr> <arg0> <arg1> ... <arg5> <sp> <pc>` (or `-1 …` when in userspace). For `futex_wait` on x86_64 (nr=`202`), **arg0 IS the futex address**. Two threads showing `202 0x7f5cAAAA…` with the same first arg are waiting on the **same futex** — i.e. the same underlying `parking_lot::Mutex` or `tokio::sync::Mutex` inside the process.

### Deadlock analysis workflow

If you see 12+ threads with `wchan=futex_wait_queue` and the same `syscall arg0`, you have a confirmed contention on one specific lock. Next steps:

1. Note the futex address (`arg0`)
2. Note the `comm` values — this tells you which subsystem's threads
3. Cross-reference with the tokio-runtime workers: 8 of them all parked on the SAME address means every worker is blocked on the same mutex, which is the classic tokio deadlock signature
4. Cross-check `heartbeat_stall_secs` — if 45s+, the heartbeat task is ALSO parked on that same mutex (or on a mutex whose owner is parked on it)
5. If `CAP_SYS_PTRACE` is granted (`kernel_stack_head` populated), the kernel-stack head gives you the Rust function at the top of the stack for each thread — enough to identify the specific `.lock()` call site

Without `kernel_stack_head` (unprivileged case), the syscall arg0 alone tells you WHICH lock but not WHICH callsite. Adding CAP_SYS_PTRACE to at least one fleet host closes that gap for the next fire.

## Granting CAP_SYS_PTRACE

The systemd drop-in at [`scripts/systemd-drop-in-cap-sys-ptrace.conf`](../../scripts/systemd-drop-in-cap-sys-ptrace.conf) grants this capability. Read the file header for security tradeoffs, the deploy sequence, and the rollout strategy.

**Do not enable fleet-wide.** Enable on 1-2 hosts (recommendation: `seed3` + `randomx2` — least-critical hosts with active tokio workload) and wait for the next fire. If it never fires again, you don't need the capability elsewhere.

## Known limits

The dump today captures:

- Per-thread wchan, comm, syscall, kernel_stack_head (when permitted)
- Heartbeat state
- Timing markers

It does **not** capture:

- **Userspace Rust backtraces per thread.** This would tell you exactly which `.lock()` call each thread is stuck at. Requires either `gdb -p <pid>` (interactive, needs a maintainer at the terminal), a `tokio-console`-instrumented build (~5-10% throughput hit, planned as a follow-up feature), or a `sigaction`-driven backtrace dump per thread (fragile in a locked-mutex environment because the `backtrace` crate itself can allocate)
- **Lock-ownership graph.** Cannot answer "which thread is HOLDING the futex the others are waiting on" without gdb or in-process instrumentation
- **What triggered the timing.** The ~8m45s trigger on both fires is a strong hint at a scheduled task, but the dump alone doesn't say which

For the current forensic gap-closing plan, see the `Fort-Knox` remaining items in `MEMORY.md` and the `Root cause tokio deadlock` pending todo.

## Emergency: node is hung right now, what do I do

1. **Capture state first** — `kill -USR1 $(pgrep -f coincync-node)`. Wait 15 seconds. Check `<data_dir>/snapshot-*.log`.
2. If the snapshot shows the deadlock signature (90%+ futex-parked, heartbeat_stall_secs 45+): **do not restart immediately**. The automatic watchdog will fire within 2 minutes anyway, and the automatic dump has richer context (`deadlock_confirmed` trigger, larger stall observation window).
3. If the snapshot shows healthy tokio (heartbeat_stall_secs 0-5, futex_fraction < 0.5) but the node is unresponsive to RPC: the problem is not a tokio deadlock. Check `journalctl -u coincync-node`, `/var/log/coincync/`, and the RPC endpoint's own logs — this is a different failure mode.
4. If the automatic watchdog doesn't fire within 5 minutes and RPC is still down: `systemctl restart coincync-node`, then investigate the captured `snapshot-*.log` offline.

## Cross-references

- Code: [`src/runtime_watchdog.rs`](../../src/runtime_watchdog.rs)
- Systemd drop-in: [`scripts/systemd-drop-in-cap-sys-ptrace.conf`](../../scripts/systemd-drop-in-cap-sys-ptrace.conf)
- Chain-stall runbook: [`runbook-chain-stall.md`](runbook-chain-stall.md)
- Fork-rollback runbook: [`runbook-fork-rollback.md`](runbook-fork-rollback.md)
- OOM runbook: [`runbook-oom.md`](runbook-oom.md)
