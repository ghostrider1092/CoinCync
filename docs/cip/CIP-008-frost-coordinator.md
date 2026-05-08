<!-- markdownlint-disable MD036 -->
# CIP-008 — FROST Coordinator Service

**Status:** Sketch (pre-Draft)
**Type:** Standards Track (network service, off-chain)
**Created:** 2026-05-08
**Layer:** Off-chain coordination protocol
**Depends on:** existing FROST primitives in `src/wallet/multisig.rs`
(M-of-N threshold signatures via `frost_ed25519`, RFC 9591).

---

## Abstract

CoinCync's wallet already exposes FROST M-of-N threshold signatures
through six CLI subcommands: `multisig-gen`, `multisig-info`,
`multisig-round1`, `multisig-round2`, `multisig-aggregate`, and
`multisig-send`. These are the cryptographic primitives. They are not
the user experience: M participants cannot run a real M-of-N signing
flow unless they have a way to exchange round-1 commitments and
round-2 signature shares between them, with proper session state and
abort-safety. Telling users to "copy-paste these JSON blobs into
Signal" is what most multisig implementations do today; it is
unusable in practice and a real liability for users who get partway
through a signing ceremony and lose state.

This CIP specifies a **coordinator service** that mediates FROST
signing sessions between participants without ever holding key
material itself. It provides:

- Session lifecycle (create, invite, participants, sign, aggregate,
  expire).
- Persistent session state across participant disconnects and
  reconnects.
- Out-of-band invitation tokens so a session creator can invite
  signers via any messaging channel without leaking session-internal
  state.
- Authenticated channels (each participant proves possession of the
  signing share they're contributing for, without exposing it).

The coordinator is **stateless about secrets**: it holds session
public state (commitments, signature shares as they're sent in,
session metadata) but never touches signing shares, master seeds, or
unaggregated keys. A compromised coordinator cannot forge
signatures. A coordinator that disappears mid-session can be
replaced; the participants resume with their existing key material.

---

## Motivation

FROST primitives without a coordinator are unusable for the threat
model that justifies multisig:

- **"My partner and I want a 2-of-2 wallet."** Without a coordinator,
  they must manually copy-paste round 1 nonces, round 2 signature
  shares, and the aggregate signature between two devices for every
  send. A typical send takes 15-20 minutes of careful copy-paste plus
  the inevitable mistake. Most users give up.

- **"Our DAO has 5 signers, 3 must approve any spend."** Five-way
  copy-paste is genuinely impossible in practice. Threshold
  multisig becomes a write-only feature — set up once for the demo,
  never used afterward.

- **"My recovery is split across three friends."** Fine for setup,
  catastrophic for recovery: in an emergency, getting three friends
  to coordinate copy-paste under stress is a recipe for lost funds.

A coordinator that handles message exchange turns these into
real, usable workflows.

---

## Trust model

Critical: the coordinator is **untrusted**. The threat model assumes:

- **The coordinator may go offline at any time.** Sessions resume
  on a new coordinator; participants re-key the session under the
  same FROST shares.
- **The coordinator may be malicious.** A compromised coordinator
  can:
  - Refuse to relay messages (denial of service; benign).
  - Show different participants different views of the session
    (possible because participants don't sign the session-state
    themselves).
- **The coordinator cannot:**
  - Recover a signing share (never sees them).
  - Forge a signature (round 2 commits each signer to the message;
    a coordinator can't change the message after round 1 without
    invalidating round 1's nonce commitments).
  - Replay an old session (each session has a fresh nonce; reuse is
    rejected by the FROST math).

The CRITICAL anti-malicious-coordinator property is enforced by
participant-side discipline:

- Every participant verifies, before signing in round 2, that the
  message they're about to sign is what they intended. The
  coordinator can't lie about the message because changing the
  message changes round 2's response and breaks aggregation.
- Every participant verifies the OTHER participants' commitments
  in round 1 and signature shares in round 2. The coordinator
  can't forge these because they require the other participants'
  signing shares.

In short: the coordinator is a relay. It holds nothing security-
relevant. The worst outcome of a malicious coordinator is "session
fails to complete." Funds are never at risk.

---

## Architecture

```
┌──────────────┐                                ┌──────────────┐
│ Participant  │                                │ Participant  │
│      A       │                                │      B       │
│              │                                │              │
│ frost share  │                                │ frost share  │
│ (private)    │                                │ (private)    │
└─────┬────────┘                                └────────┬─────┘
      │                                                  │
      │   WSS over TLS, authenticated by participant     │
      │   pubkey; HMAC-tagged frames.                    │
      │                                                  │
      │             ┌──────────────────┐                 │
      └────────────►│   Coordinator    │◄────────────────┘
                    │                  │
                    │ session state:   │
                    │   - participants │
                    │   - commitments  │
                    │   - sig shares   │
                    │   - message      │
                    │                  │
                    │ NEVER stores:    │
                    │   - signing      │
                    │     shares       │
                    │   - secrets      │
                    └──────────────────┘
                              │
                              ▼
                    SQLite session log
                    (audit trail; pruneable)
```

Service: `coincync-frost-coordinator` (new bin in workspace).
Endpoint: WSS on port 8083 (proxied by nginx alongside the existing
faucet on 8082). One coordinator instance can host thousands of
concurrent sessions, since each session is just a small state
machine.

---

## Session state machine

```
              ┌─────────┐
              │ CREATED │
              └────┬────┘
       creator submits┤
       N invitation tokens
                   ▼
            ┌──────────────┐
            │ PARTICIPANT_ │
            │   INVITED    │
            └──────┬───────┘
participants join, ┤
M of N attached
                   ▼
            ┌──────────────┐
            │   ROUND_1    │  participants submit nonces+commitments
            │ COMMITMENTS  │  coordinator collects, broadcasts to peers
            └──────┬───────┘
threshold reached ┤
                   ▼
            ┌──────────────┐
            │   ROUND_2    │  participants verify + submit sig shares
            │ SIG_SHARES   │
            └──────┬───────┘
all M shares in   ┤
                   ▼
            ┌──────────────┐
            │  AGGREGATED  │  coordinator publishes aggregate sig
            │              │  to all participants; tx ready to broadcast
            └──────┬───────┘
                   │
              ╰── tx submitted to chain
              by any participant (typically the creator)
```

Each transition is signed by the participant making it
(participant pubkey + Ed25519 over the transition payload). The
coordinator validates the signature before applying. A malicious
coordinator can refuse to apply a transition, but cannot fabricate
one.

Timeouts:

- **CREATED → expired**: 7 days if no participants attach.
- **ROUND_1 → expired**: 1 hour after the first participant submits
  if not all M arrive. Forces participants to retry with fresh
  nonces (FROST round 1 nonces MUST NOT be reused).
- **ROUND_2 → expired**: 1 hour after the first sig share. Same
  reason.
- **AGGREGATED → archived**: session is read-only after 30 days; the
  signature has either been broadcast (success) or it hasn't
  (the coordinator's job is done either way).

---

## Wire protocol

WSS over TLS (HTTPS Upgrade or direct port-8083 if no nginx).
JSON envelope (Borsh frame inside if performance ever demands).

### Connection establishment

```
Client → Server: { "type": "auth", "participant_id": <hex_pubkey>,
                   "session_id": <uuid_v7>, "nonce": <16 bytes hex>,
                   "signature": <ed25519 over nonce+session_id> }

Server → Client: { "type": "auth_ok", "session_state": <enum> }
                or
                 { "type": "auth_err", "reason": <string> }
```

The server verifies the signature with the participant's pubkey
(provided during invitation). On success, the participant is
attached to the session.

### Session messages

All subsequent messages are typed and signed by the sending
participant. The coordinator broadcasts each message to all OTHER
participants in the session. Specific payloads:

- `commit_round1`: `{ commitment_bytes, hiding_bytes, binding_bytes }`
- `share_round2`: `{ message_bytes, sig_share_bytes }`
- `signal_abort`: `{ reason }` — anyone can abort up to AGGREGATED.

The coordinator accumulates and forwards. Once threshold is reached
in either round, it advances the session state and notifies all
participants.

### Out-of-band invitation tokens

Session creator generates `N` invitation tokens (one per intended
participant). Each token contains:

```
INV-token-v1.<base32 of (session_id, participant_pubkey, expiry, hmac)>
```

The HMAC binds the token to the session and the specific
participant pubkey, so a token can be sent over an insecure channel
(SMS, email, public Discord) without leaking ability to join the
session as a different participant.

Format choice: base32 (no ambiguous chars) with a leading prefix
`INV-token-v1.` so the token is auto-detected when pasted into
the wallet UI.

---

## Anti-features (deliberately not in scope)

- **Recovery beyond FROST.** If a participant loses their share, the
  coordinator can't help them. They lose access; the remaining M-1
  signers can either (a) accept loss of M-of-N redundancy, (b) do
  a key refresh ceremony from scratch with a new share count, or
  (c) recover funds if the threshold permits without that signer
  (the math handles M of N losses where M ≤ N - lost_count).

- **Custodial operation.** The coordinator NEVER holds shares. If
  some user wants a 1-of-1 "coordinator-managed wallet," they
  should use a regular non-multisig wallet, not this.

- **Privacy across participants.** Participants in the same session
  can see each other's pubkeys. Hiding participants from each other
  while still letting them aggregate is anonymous-FROST; that's a
  separate research project (Threshold Issuance Selective Disclosure)
  out of scope here.

- **Cross-coordinator sessions.** Each session lives on one
  coordinator. If the coordinator goes down mid-session,
  participants migrate by re-creating the session on a new
  coordinator with their existing FROST shares (round 1 nonces
  must be regenerated; that's enforced by FROST itself). No
  coordinator-to-coordinator migration protocol is specified.

---

## Implementation plan

This CIP authorizes building the service. The implementation lives
in a new workspace member:

```
crates/coincync-frost-coordinator/
├── Cargo.toml
└── src/
    ├── main.rs           — axum WSS server, session router
    ├── session.rs        — state machine + storage
    ├── auth.rs           — invitation tokens, participant auth
    └── storage.rs        — SQLite schema for session log
```

Phase order:

1. **Phase 1 — types and state machine** (1-2 days). Define the
   transition types, the in-memory state machine, no networking.
   Property tests on the state machine: invariants hold under
   adversarial transition orderings, no transition leaks state to
   wrong participant.

2. **Phase 2 — WSS server** (2 days). axum + tokio-tungstenite for
   the wire protocol. SQLite for session persistence. Auth via
   participant pubkey + nonce-signature. No message forwarding logic
   yet, just connection lifecycle.

3. **Phase 3 — message routing** (1-2 days). Wire the state
   machine to the WSS layer. End-to-end test: two clients
   connecting, exchanging round 1 + round 2, producing aggregate
   sig that verifies against the FROST group key.

4. **Phase 4 — invitation flow** (1 day). Token generation, parsing,
   HMAC verification. CLI subcommand on the wallet:
   `coincync-wallet multisig-invite --session-id ... --participants ...`.

5. **Phase 5 — wallet UI integration** (2-3 days). Update the
   `multisig-round1`, `multisig-round2`, `multisig-aggregate` CLI
   subcommands to talk to the coordinator instead of file-based
   message exchange. Keep file-based as fallback for offline /
   air-gapped signing.

6. **Phase 6 — deployment** (0.5 day). Add `coincync-frost-
   coordinator.service` systemd unit. Deploy on the api box (port
   8083). Document the operator runbook.

Total: ~9-11 days.

---

## Skeleton (this commit)

This commit creates the workspace member at
`crates/coincync-frost-coordinator/` with:

- `Cargo.toml` (declares workspace dependency on `coincync` for the
  FROST primitives, plus axum/tokio/sqlite).
- `src/main.rs` with `unimplemented!()` body and documented entry
  points for each phase.
- `src/session.rs` with the state-machine type defined; `transition`
  function returns `Result<NewState, Error>` based on the matrix
  in this CIP. Exhaustive match means a future CIP adding a new
  state forces all transition logic to update — by design.

Compiles, doesn't run. Phase 2-6 lands in subsequent CIP-008.x
patches.

---

## Open questions

1. **Authenticated transport: WSS or libp2p?** WSS is simpler to
   deploy and debug; libp2p is what the rest of CoinCync's network
   layer uses (Noise_XX over TCP). Picking WSS for now because the
   coordinator is a fundamentally HTTP-shaped service (web wallet
   UIs need to talk to it from browser contexts where libp2p is
   awkward). Revisit if we ever ship a native CLI-only wallet that
   should use libp2p.

2. **Session export format for offline-signing fallback.** The
   wallet's existing file-based round-1/round-2 flow is preserved
   as a fallback. Should the coordinator be able to import a
   partially-completed offline session and continue it? Useful for
   "I started signing on my laptop offline, I want to finish from
   my phone via the coordinator." Phase 7 (post-MVP).

3. **Federated coordinators.** Multiple project-run coordinators
   for redundancy: one in EU, one in US, one in JP. Sessions stay
   on one coordinator, but if a coordinator fails, the next one
   accepts re-creation. Doesn't need protocol changes — just
   operator practice. Document in the deployment runbook.

4. **Rate limiting and abuse.** A bad actor could create thousands
   of sessions to exhaust storage. Mitigation: per-session-creator
   rate limit (e.g., 10 active sessions per pubkey at a time).
   Add to phase 2 implementation.
