<!-- markdownlint-disable MD036 -->
# CIP-012 — FROST coordinator deployment rehearsal

**Status:** Draft (post-launch deployment candidate)
**Type:** Process (operations / non-consensus service)
**Created:** 2026-05-08
**Layer:** Application (off-chain message relay)
**Depends on:** CIP-008 (FROST coordinator design)
**Implements:** CIP-008 phase 4-6 (WSS server + integration tests + production deploy)

---

## Purpose

CIP-008 specifies the FROST coordinator. CIP-012 is the deployment
plan: how the coordinator actually gets stood up, what we measure,
what we do when it breaks, and how we know it's safe to recommend
to wallet users.

Unlike CIP-011 (the consensus-rule activation for rolling
finality), CIP-012 is **NOT** a consensus event. The coordinator
is a non-consensus message-relay service that holds no key
material. Misbehaviour can break individual signing sessions but
cannot fork the chain or steal funds. That changes both the risk
profile and the rehearsal shape:

- **No coordinated upgrade.** Coordinator versions can roll
  independently of node versions.
- **No miner involvement.** Miners don't know or care that a
  coordinator exists.
- **No activation height.** "Live" is a service state, not a
  protocol state.
- **No rollback drama.** If the coordinator misbehaves, take it
  offline — wallets fall back to manual copy-paste of FROST
  rounds, exactly the model the coordinator was added to
  improve.

What we DO need to plan: production deployment hardening,
operational runbook, multi-region failover (eventually), and the
trust story for wallets that want to recommend a specific
coordinator instance to their users.

---

## What's already shipped

As of this CIP's creation, the `crates/coincync-frost-coordinator`
library has three phases done:

- **Phase 1** (commit `286cc40`): pure state machine for
  FROST sessions. 11 unit + property tests.
- **Phase 2** (commit `9e9729b`): invitation-token authentication
  via HMAC-SHA256, feature-gated as `invitations`. 14 tests.
- **Phase 3** (commit `1e20b8e`): JSON-file session persistence
  with atomic-write semantics, feature-gated as `persistence`.
  13 tests.

Total: 38 tests with all features. The state machine is correct,
authenticated, and durable. What's missing for a production
deployment is the **transport layer** (WSS server bin), the
**integration tests** against actual `frost_ed25519` round-trips,
and the **operational hardening** (rate limits, observability,
deploy automation).

---

## Phases of this rehearsal

### Phase 4 — WSS server bin

A new binary in `crates/coincync-frost-coordinator/src/bin/coord.rs`
that:

1. Listens on a configurable WSS endpoint (default `wss://0.0.0.0:8443`).
2. Accepts WebSocket connections; each connection is one
   participant interacting with one or more sessions.
3. Routes JSON-encoded messages between participants via the
   `Session` state machine.
4. Verifies invitation tokens at attach time (the `invitations`
   feature).
5. Persists every state transition to a `SessionStore`-backed
   file (the `persistence` feature).
6. Exposes Prometheus-format metrics on a separate HTTP port
   (default `:9100`) for the status page.

**Implementation cost:** ~3-5 days.

**Dependencies that arrive with this phase:**
- `tokio-tungstenite` for WSS (already in the workspace dep
  graph)
- `axum` for the metrics endpoint (already a workspace dep)
- `rustls` + `rcgen` for TLS termination (already workspace
  deps)
- A small `coord-cli` binary for operator tasks (mint
  invitations, list sessions, force-abort a stuck session)

### Phase 5 — Integration tests

End-to-end tests in `crates/coincync-frost-coordinator/tests/`
that drive a real `frost_ed25519` 2-of-3 signing session through
the coordinator from start to finish. Catches:

- Wire-format compatibility (the coordinator stores opaque
  bytes; phase 5 confirms those bytes round-trip correctly via
  `frost_ed25519` types).
- Failure paths (one participant disconnects mid-round, message
  arrives out of order, etc).
- Persistence + recovery (kill the coordinator process
  mid-session; restart; resume; signing completes).

**Implementation cost:** ~3 days.

**Concrete test plan:**
- Generate 3 FROST keypairs.
- Spin up coordinator on a tokio test runtime.
- Connect 3 client sessions.
- Drive a 2-of-3 signing session for a fixed message.
- Verify the aggregate signature is valid against the group
  public key.
- Repeat with one participant unattaching mid-session;
  expect timeout-then-abort.
- Repeat with coordinator restart between Round 1 and Round 2;
  expect resumption.

### Phase 6 — Operational hardening

The non-protocol code that production needs:

- **Rate limiting.** Per-IP attach rate (max 10 sessions per
  hour). Per-session message rate (max 100 messages per
  minute). Reject excess with `429 Too Many Requests`.
- **Connection limits.** Max 1000 concurrent WSS connections.
  Defends against state-exhaustion DoS.
- **Logging.** Structured tracing with per-session correlation
  IDs. No participant pubkeys in logs (privacy posture: the
  coordinator should not be a long-term audit log of who
  signed what).
- **Observability.** Prometheus metrics:
  - `coord_sessions_total` (counter, by terminal state)
  - `coord_active_sessions` (gauge)
  - `coord_round1_duration_seconds` (histogram)
  - `coord_round2_duration_seconds` (histogram)
  - `coord_aggregate_attempts_total` (counter, by success/fail)
  - `coord_invitation_verifications_total` (counter, by valid /
    invalid)
- **Deploy automation.** Systemd unit, install script, Discord
  webhook on lifecycle events (start / stop / panic).
- **Backup.** Daily snapshot of the session-store JSON to a
  separate volume. 30-day retention. (No off-host backup —
  session content is by-protocol-design public; recoverability
  is the only concern, addressed by re-bootstrapping from
  participants.)

**Implementation cost:** ~3-5 days.

---

## Deployment shape

### Pre-mainnet (testnet rehearsal)

A SINGLE coordinator instance on a dedicated VPS:

- **Hostname:** `frost.coincync.network` (one DNS record;
  no failover yet).
- **Endpoint:** `wss://frost.coincync.network:8443`
- **TLS:** Let's Encrypt via certbot (auto-renew weekly).
- **Storage:** local SSD, daily snapshot to a sibling volume.
- **Cost:** ~$5-10/mo (4GB / 2vCPU VPS). Hetzner is fine for
  this — they ban mining, not WSS servers.
- **Operator:** project maintainer monitors via the status
  page + Discord webhook.

This is sufficient for testnet because: (a) FROST coordinators
are untrusted relays — even a complete outage just means
"existing sessions abort, new sessions fall back to manual
mode," (b) the testnet user count won't exceed a few dozen
M-of-N wallet operators in the rehearsal window, (c) we want
operational data on a single instance before adding
multi-region.

### Mainnet

Two coordinator instances, geographically separated, behind a
DNS round-robin or a smarter steering layer:

- `frost-1.coincync.network` (Frankfurt)
- `frost-2.coincync.network` (Singapore)
- DNS: `frost.coincync.network` resolves to both, round-robin.
- Wallet client behavior: try resolved address; on failure,
  re-resolve and try the other; on second failure, fall back
  to manual mode and surface the error to the user.

Both instances run the same software, same configuration,
INDEPENDENT session state. A session started against
`frost-1` MUST complete against `frost-1` — the participants'
session_id binds to a specific instance via the invitation
token's HMAC. This is intentional: synchronous replication
between coordinators would couple their availability and
double the attack surface for no benefit.

The wallet client picks an instance at session-creation time
and stays there. If that instance fails mid-session, the
session aborts; the wallet creates a new session against the
other instance.

---

## Operational rehearsal — testnet

Same shape as CIP-010 / CIP-011. Adjusted for the non-consensus
character of this deployment.

### T-4 weeks: ship phases 4-6

- Implementation PRs land on `main`.
- Coordinator binary tagged `coord-v0.1.0`.
- Reproducible builds enabled per
  `docs/operations/REPRODUCIBLE_BUILDS.md`.

### T-3 weeks: stand up the testnet instance

- Provision the Hetzner VPS.
- Run `scripts/install-frost-coord.sh` (to be authored as part
  of phase 6).
- Verify TLS cert is valid, WSS endpoint accepts connections,
  metrics endpoint responds.
- Smoke test from a developer machine: 2-of-3 signing session
  end-to-end.
- Add a status-page entry for the FROST coordinator.

### T-2 weeks: announce to the community

- Discord `#announcements`: "FROST coordinator is live at
  `wss://frost.coincync.network:8443` for testnet 2-of-3 +
  3-of-5 multisig. See the wallet docs for setup."
- Wallet docs updated: how to point your wallet at the
  coordinator, how to run a 2-of-3 signing session.
- Status page lists FROST coordinator as a tracked service.

### T-2 weeks → T-0: testnet observation window

- Operators watch the metrics:
  - Are sessions completing? Median time?
  - Are any sessions hanging in `Round1` or `Round2`?
  - Are invitation-token verifications matching expected
    volume?
  - Disk-usage trend for the persistence file.
- Bug reports: file as Forgejo issues; high-severity ones
  trigger a fleet-style status page update.

### T-0: deemed production-ready

The coordinator is "production-ready" for testnet purposes
when:

- ≥ 30 days of uptime ≥ 99% (the only acceptable downtime
  reasons: announced maintenance windows, OS patches).
- ≥ 100 successful M-of-N sessions completed.
- Zero coordinator-side bugs that caused fund-affecting
  participant errors.
- Operational runbook (`docs/operations/FROST_COORDINATOR.md`,
  to be authored) documents recovery for every observed
  failure mode.

If those criteria aren't met at the originally-planned
mainnet date: defer mainnet coordinator deployment, ship
mainnet wallet WITHOUT a recommended coordinator (manual
copy-paste only). The wallet's UI surfaces the coordinator
status; if it's down, the manual flow still works.

---

## Failure modes

CIP-008 §"Trust model" already covers the cryptographic layer.
This section covers the OPERATIONAL failure modes specific to
deployment.

### Coordinator process crashes

- Systemd auto-restarts.
- Persistence file on disk is consistent (atomic-write guarantee).
- Active sessions resume from the persistence file on next
  start.
- Discord webhook fires on the restart.
- **Operator action:** read the journal log, file a Forgejo
  issue, decide whether to roll back to a known-good binary.

### Coordinator host loses network

- All active WSS connections drop.
- Sessions in flight effectively pause (participants can't
  send their next round).
- Sessions hit the timeout (Round1: 1h, Round2: 1h) and abort.
- **Participant action:** create a new session, retry. No funds
  at risk.
- **Operator action:** restore network, monitor for re-attach
  storms, file an incident report.

### Coordinator host filesystem fills up

- Persistence write fails.
- Coordinator returns I/O errors to clients; sessions abort.
- **Operator action:** clear log files, investigate why
  growth was unbounded, add log rotation if missing.

### Coordinator binary panics

- Systemd restarts. If the panic is reproducible (e.g., from
  a malicious peer message), restart loop continues.
- Discord webhook fires repeatedly.
- **Operator action:** if the panic is in the state-machine
  layer, treat as a P0 bug — rollback to previous version,
  file a security report. If the panic is in the transport
  layer (WSS / TLS), often less severe.

### Operator key for invitation tokens leaks

- An attacker who has the session secret can mint valid
  tokens for arbitrary participants in that session.
- **Mitigation:** session secrets are per-session and ephemeral
  (the secret lives only for the session's lifetime, ~hours).
  A leak compromises ONE session — easy to detect (the
  legitimate participant gets `Duplicate` errors when their
  attach attempt collides with the attacker's), and the
  affected session can be aborted + retried.
- **Mitigation 2:** the invitation token authenticates that
  the BEARER is allowed to join, but signing-key compromise
  is a separate problem. An attacker who joins via a stolen
  invitation can DoS the session but cannot forge signatures.

### Coordinator operator goes offline

- The single-instance pre-mainnet model has a single point
  of failure: the operator.
- **Mitigation pre-mainnet:** acceptable. Falling back to
  manual is a UX regression, not a security one.
- **Mitigation mainnet:** two instances, two operators,
  geographically and jurisdictionally diverse. Specified in
  the "Mainnet" section above.

---

## Decision (for the user)

- ☐ **Approve.** Schedule phases 4-6 implementation for a 2-3
  week sprint post-public-testnet launch. Stand up
  `frost.coincync.network` ~3 months before mainnet.
- ☐ **Approve, smaller scope.** Skip phase 6's "operational
  hardening" until the testnet exercise reveals which knobs
  matter. Ship phases 4 + 5, run the unhardened service,
  see what hits us.
- ☐ **Defer.** Ship mainnet wallet WITHOUT a coordinator. Users
  do FROST signing via copy-paste of round bytes. UX is bad
  but the security story is identical.
- ☐ **Reject.** No coordinator deployment, no coordinator
  recommendation in the wallet. Drop the FROST library
  entirely.

If approved at the full scope: implementation begins after
public testnet stabilizes (≥ 30 days post-launch). Cost is
roughly 2-3 weeks of focused work plus ~$60-120/year
operational cost for two coordinator instances.

---

## What this CIP teaches us about mainnet

Same shape as CIP-010 and CIP-011 §"What this CIP teaches us":

1. **Real-world session count.** Estimating mainnet demand from
   testnet usage rates.
2. **Median session duration.** Drives the
   `ROUND_1_TIMEOUT_SECS` / `ROUND_2_TIMEOUT_SECS` defaults
   for mainnet — testnet's 1h might be too tight or too loose.
3. **Invitation-token usability.** Are users actually using
   tokens, or finding workarounds (out-of-band sharing of the
   session secret directly)? If the latter, the auth model
   needs revisiting.
4. **Operator load.** Solo project today; mainnet may need
   on-call rotation if multi-region adds operational
   complexity.
5. **Wallet integration friction.** Are wallets adopting the
   coordinator API? If not, why not? Documentation? UX? API
   surface?

---

## Out of scope

- **Slashing of misbehaving coordinators.** No on-chain slashing
  exists for non-consensus services. Misbehaviour is detected
  and routed-around; a reputation system is a future
  consideration but not a phase 6 requirement.
- **Decentralized coordinator network.** Multiple operators
  running compatible coordinators is fine and expected. A
  consensus-style network of coordinators is out of scope and
  unnecessary — the protocol's untrusted-coordinator design
  obviates it.
- **Privacy of session metadata.** The coordinator sees
  participant pubkeys + session topology + timing. Tor
  transport is the long-term answer; phase 4's WSS-over-TLS
  is the testnet-acceptable middle ground.

---

## Related work

- `docs/cip/CIP-008-frost-coordinator.md` — the protocol
  specification
- `docs/cip/CIP-010-testnet-hardfork-rehearsal.md` —
  consensus activation rehearsal (different shape, similar
  spirit)
- `docs/cip/CIP-011-rolling-finality-activation.md` —
  another consensus activation rehearsal
- `crates/coincync-frost-coordinator/` — phases 1-3 already
  shipped (state machine + invitations + persistence)
- `docs/operations/INCIDENT_RUNBOOKS.md` — runbook patterns
  for service outages (will gain a FROST-coordinator section
  when phase 4 ships)
- `docs/operations/STATUS_PAGE.md` — where the coordinator's
  health surfaces to users
