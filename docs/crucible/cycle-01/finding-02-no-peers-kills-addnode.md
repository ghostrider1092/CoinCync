# Crucible Cycle 01 — Finding #2: `--no-peers` silently kills `--addnode`

**Status:** Fixed
**Severity:** High (UX-blocking — broke the only path for isolated 2-node testing)
**Discovered:** 2026-06-09
**Fixed in:** `v1.0.11-fleet-2026-06-06` commit `d8b23fe`
**Tester:** operator (forced into 2-node isolation by CGNAT NAT-traversal failure)
**Time-to-fix:** ~10 minutes from repro to verified

## TL;DR

`--no-peers` was supposed to disable auto-discovery while still allowing
`--addnode` to dial known peers manually. The startup log even said so:
`"--no-peers: automatic peer discovery disabled (manual --addnode peers
still allowed)"`. But the same code path zeroed
`p2p_config.max_outbound`, eliminating the outbound slot budget that
the manual peers needed. Result: known address loaded, never dialed.

## Symptom

```
$ ./coincync-node --network testnet --p2p-bind 0.0.0.0:28080 \
                  --rpc-bind 127.0.0.1:28081 --no-peers \
                  --addnode 82.66.194.28:28080 start

INFO --no-peers: automatic peer discovery disabled (manual --addnode peers still allowed)
INFO --addnode: adding manual peer 82.66.194.28:28080
INFO Peer maintenance: 0 total peers (0 outbound), 1 known addresses
INFO Peer maintenance: 0 total peers (0 outbound), 1 known addresses   ← forever
```

5+ minutes of `0 outbound, 1 known addresses` and no dial attempt.
No error. No warning. No "max_outbound is zero — refusing to dial."

## Discovery path

1. **Context** — operator behind Cox triple-NAT (home router NAT → Cox
   modem NAT → ISP CGNAT). Both IPv4 and IPv6 inbound port-forward
   verified dead via external `nc -zv` from a Vultr fleet box.
2. **Inversion strategy** — barns (the Crucible tester) has a real
   public IPv4 with port-forward already configured. The fix:
   instead of barns dialing operator (inbound, blocked by CGNAT),
   operator dials barns (outbound, works through any NAT).
3. **Launched operator's node with `--addnode <barns-ip>:28080`.**
4. **Watched the log for 5 minutes** — saw the "0 outbound, 1 known
   addresses" pattern. The peer was registered but never dialed.
5. **Source dive on `bin/node.rs`** — found the offending line.

## Root cause

`src/bin/node.rs`, in the `--no-peers` handler:

```rust
if no_peers {
    info!("--no-peers: automatic peer discovery disabled (manual --addnode peers still allowed)");
    p2p_config.bootstrap.dns_seeds.clear();
    p2p_config.bootstrap.seed_nodes.clear();
    p2p_config.max_outbound = 0;   // ← the bug
}
```

`max_outbound = 0` means the peer-maintenance loop has zero slots for
outbound dialing. The known-addresses set still gets populated by
`--addnode`, but the loop can't act on it.

The intent was almost certainly "lock down all auto-discovery" —
which `dns_seeds.clear()` + `seed_nodes.clear()` already accomplish.
Zeroing `max_outbound` was belt-and-suspenders defensive coding that
went too far and silently broke the explicit-opt-in path.

## Fix

```rust
if no_peers {
    info!("--no-peers: automatic peer discovery disabled (manual --addnode peers still allowed)");
    p2p_config.bootstrap.dns_seeds.clear();
    p2p_config.bootstrap.seed_nodes.clear();
    p2p_config.max_outbound = extra_peers.len().max(1);
}
```

`extra_peers.len()` is the count of valid `--addnode` SocketAddrs
parsed earlier in the same function. `.max(1)` keeps the slot
reservation honest for the degenerate-but-legal case where someone
passes `--no-peers` without any `--addnode` (e.g., a node that just
listens for inbound and accepts whoever finds them).

## Verification

After the rebuild + relaunch:

```
INFO --addnode: adding manual peer 82.66.194.28:28080
INFO Peer maintenance: 0 total peers (0 outbound), 1 known addresses
INFO Noise handshake succeeded with 82.66.194.28:28080 (remote key: 3f88cc15d73cc543)
INFO Peer maintenance: 1 total peers (1 outbound), 2 known addresses
```

Outbound dial fires within seconds of node startup. Verified
end-to-end: the operator-↔-barns peering that this enabled was the
substrate for finding #3 (the GetHeaders flood) — i.e., this fix
unblocked the test environment that surfaced the next bug.

## Impact

- **v1.0.10 and earlier:** affected. Same bin/node.rs control flow.
  Probably never reproduced because the dominant `--no-peers` use
  case is "node listens, takes inbound only" rather than "manual
  outbound to a peer behind CGNAT." Crucible Cycle 01 was the first
  scenario that actually exercised the outbound-from-isolated path.
- **v1.0.11 (pre-fix):** affected.
- **v1.0.11-fleet-2026-06-06 from `d8b23fe` onward:** fixed.

## Crucible learning

The test scenario that surfaced this bug — operator-behind-CGNAT,
tester-with-public-IP — is the canonical real-world isolation case.
Any future Crucible cycle where the tester is NOT on a static-IP VPS
will hit this exact pattern. The bug had been dormant since at least
v1.0.10 because all prior internal testing used either two VPS nodes
(both publicly reachable) or local-only (one machine, no NAT).

**Process gap:** isolation-mode regression tests should include
"node A behind NAT, node B public, A dials B" as a fixture. Open
v1.0.13 follow-up.

## Follow-up tasks

- [ ] Add a regression test fixture for `--no-peers + --addnode`
      outbound dialing under a NAT'd-A → public-B topology
- [ ] Audit other places where defensive `= 0` could mask explicit
      opt-in paths
- [ ] v1.0.13 docs: document the "operator-behind-CGNAT inversion"
      as the recommended workaround when CGNAT is detected (see
      `traceroute` to identify; 100.64.0.0/10 in hop list = CGNAT)
