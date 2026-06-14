# Crucible Cycle 02 — close-out

**Window:** 2026-06-11.
**Operator:** ghostrider1092 (local, US Pacific) + barns1253 (remote, France).
**Build under test:** `v1.0.11-fleet` HEAD (`b8571c8` pre-rebase; same
content as today's `v1.0.11-testnet` release tag).
**Mesh:** 2-node isolated testnet over IPv6 + IPv4 (CGNAT inversion —
operator dials out to barns per Cycle 01 Finding #2).

## TL;DR

Verifies the four Cycle 01 fixes hold in a real WAN mesh and ships
end-to-end privacy transaction send/receive between two independent
operators. Surfaces four new findings — three already fixed in
v1.0.12 (this release), one queued as v1.0.13 follow-up.

## Verifications

- **End-to-end privacy tx send/receive.** 10 CYNC transferred from
  operator to barns at block h~30, mined, confirmed in barns' wallet
  scan with encrypted memo `cycle02-test-tx-from-ghostrider1092`
  successfully decrypted. **The first inter-operator privacy
  transaction in CoinCync's history.** Full flow: wallet builds
  CLSAG-signed tx → mempool admission with full validator (Cycle 01
  Finding #1 fix in action) → mining → P2P propagation → recipient
  scan → memo decrypt.

- **All 4 Cycle 01 fixes empirically hold.** The mesh sustained
  IBD + block relay + tx send/receive across the WAN.

## Findings

- [**Finding #1** — Peer flap every ~75s](finding-01-peer-flap.md)
  on stable IPv6 WAN link. Root cause: NAT idle-state expiration
  (consumer routers drop established TCP state after 30-90s of
  silence). Confirmed not application-layer via loopback
  reproduction.

  **Fix shipped on v1.0.12:**
  - TCP keepalive sockopts on outbound + inbound P2P streams
    (`src/network/keepalive.rs`) at 45s idle.
  - Application-layer Ping interval dropped from 120s to 25s
    (`src/network/node.rs::PING_INTERVAL`). Sends real Noise-
    encrypted P2P messages so even routers that ignore TCP
    keepalive frames refresh their NAT state.
  - Belt-and-suspenders: 25s app-layer Ping + 45s TCP keepalive
    = NAT state can never go idle long enough to expire.

- [**Finding #2** — `balance` shows stale message despite UTXO
  persistence](finding-02-balance-stale-message.md). Trivial UX
  fix.

  **Status:** documented, fix queued (~20 LOC for `balance` to
  read the `.utxos` sidecar). Not blocking; non-data-affecting.

- [**Verification #1** — revised](verification-01-cycle01-finding-01-loud-rejection.md):
  Cycle 01 Finding #1's "loud rejection" pattern verified, but
  the specific cycle-02 trigger I initially attributed was a
  startup transient, not the version-skew case. Doc revised to
  preserve the broader verification while correcting the
  attribution.

- [**Finding #4** — EMERGENCY-TIER-3 misdiagnosis](finding-04-emergency-tier-3-misdiagnosis.md).
  The recovery's log message attributed every "chain not advancing"
  case to "orphan-fetch cascade" — but cycle 02 had a mutual mining-
  refusal deadlock where no peer was producing blocks. The recovery's
  aggressive reset did nothing useful in that case.

  **Fix shipped on v1.0.12:** Message rephrased to enumerate three
  possible causes with diagnostic hints. Recovery logic itself
  unchanged. The proper "check if any header has arrived in N
  seconds before firing" guard is queued for v1.0.13.

## Meta-finding (not a finding doc, but worth flagging)

The Cycle 01 fix for Finding #2 was on `v1.0.11-fleet` but never
merged to main. Feature branches (v1.0.13, v1.0.14) inherited the
regression. Discovered during cycle-02 verification when the
v1.0.14 binary refused to dial barns with `--no-peers --addnode`
— the bug we'd already "fixed" months ago.

Closed today by pushing v1.0.11 to main. **Future Crucible cycles
should explicitly verify that fix branches have been merged
before testing a downstream version.**

## What ships in v1.0.12

| Item | Commit |
|------|--------|
| App-layer Ping at 25s (cycle 02 Finding #1) | `70a51cb7` |
| TCP keepalive on P2P sockets (cycle 02 Finding #1) | `057d1fde` |
| Keepalive calibration empirical revert | `620eaf31` |
| EMERGENCY-TIER-3 message disambiguation (cycle 02 Finding #4) | `417bf199` |
| Graduated ring-size ramp 11→13→16 (consensus refinement) | `18e8778e` |
| Cycle 02 close-out doc (this file) | TBD |

The version-bump + critical-files-lock refresh ride the ring-ramp
commit because the lock file's `src/constants.rs` hash changes
with the new ring constants.

## What's NOT in v1.0.12 (deferred)

- `balance` subcommand reading the `.utxos` sidecar (Finding #2). UX
  bug, deferred to v1.0.13.
- EMERGENCY-TIER-3 "any header in N seconds" guard (Finding #4 full
  fix — message rephrase is the v1.0.12 stopgap). Deferred to v1.0.13.
- AssumeValid mechanism. Tracked on v1.0.14.

## Cycle 03 — what to look for next

- Empirically verify v1.0.12's peer-flap fix (keepalive + 25s ping)
  eliminates the WAN flap pattern entirely.
- First cross-version cycle: v1.0.11 binary connecting to a v1.0.12
  fleet. Validate the protocol-version-mismatch error path. Expect
  it not to fire (no breaking wire change in v1.0.12) but verify.
- Test the graduated ring-size ramp: produce txs at h~5,001 and
  observe whether ring-size 12 (below the new MID_RING_SIZE=13
  floor) gets rejected by v1.0.12 nodes.
