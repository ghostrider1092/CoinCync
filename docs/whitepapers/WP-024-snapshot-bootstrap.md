# WP-024 · Snapshot Bootstrap
### Trusting a database you did not build

**Status:** Shipped · **Layer:** Node / Operations · **Series:** [CoinCync Whitepapers](README.md)

---

## 1. Motivation

Syncing a chain from genesis is slow. Every operator eventually wants the
shortcut: copy a database someone else already built.

The shortcut is also the most dangerous thing an operator can do, because a chain
database *is* the node's entire belief about reality. A node that imports a
fabricated database does not detect a problem later — it validates every
subsequent block correctly against a history that never happened. It will report
balances that do not exist, accept a chain nobody else is on, and behave, from the
inside, exactly like a healthy node.

The design question is therefore not "how do we copy a database quickly" but
**"what must be true before we let one become our reality."**

---

## 2. Threat addressed

| Attack | Assumption it needs | What we removed |
|---|---|---|
| **Fabricated history** — a DB where the attacker minted themselves coins | A DB that opens cleanly and hashes consistently is genuine | Every consensus checkpoint at or below the snapshot height must match |
| **Deep alternate fork** | Correct genesis implies correct chain | Same: checkpoint binding, not just genesis binding |
| **Lying manifest** — advertises a high height over a stunted DB | The manifest describes its own payload | Manifest height and tip hash must equal what the DB actually reports |
| **Wrong chain** — a testnet DB imported into a mainnet node | Operators check | Network and genesis-hash match required |
| **Corruption** | Bytes survive transport | blake3 verification |
| **Untrusted source** | Any snapshot is as good as any other | Optional Ed25519 signer allowlist |
| **Stranded chaindata** — a failed import leaves the node with no DB at all | Failure paths are exceptional | Loud rollback with the operator's original DB restored |
| **Rejected-but-installed** | A failed check prevents use | Rollback errors are propagated, never swallowed |

---

## 3. Design

### 3.1 Two layers: accidents and malice

The design separates two concerns that are frequently conflated:

**The parent module moves bytes** and refuses *accidents* — a wrong-chain snapshot
(network or genesis mismatch) or a corrupted one (blake3 mismatch).

**The verification module refuses malice.** This is the distinction that matters:
an attacker can hand you a DB that opens cleanly, carries the correct genesis
hash, and hashes consistently, yet encodes a fabricated history. Every
accident-level gate passes. Integrity checks prove the bytes arrived intact; they
say nothing about whether the bytes were honest when they left.

### 3.2 Checkpoint binding

The malice-level check has one job: decide whether the installed DB is **bound to
the canonical chain**, using the consensus checkpoints already baked into the
binary.

Two checks, in order:

1. **Manifest integrity** — the DB's actual tip height and tip hash must equal
   what the manifest claims. This stops a manifest that lies about its own
   payload.
2. **Checkpoint binding** — every consensus checkpoint at or below the snapshot
   height must be present in the DB **with the exact expected hash**.

The security argument is simple and strong: an attacker cannot produce a divergent
history whose block hashes still match hashes compiled into the verifier's own
binary. The trust anchor is the binary the operator chose to run, not anything the
snapshot supplies.

### 3.3 A pure function with thin glue

`verify_chain_binding` is a **pure function** over plain inputs — manifest, DB tip
height, DB tip hash, checkpoints, and a `hash_at_height` closure. No I/O.
`verify_installed_db` is the thin glue that opens the real database and feeds
those facts in.

This is a deliberate testability structure: every branch of the security decision
is unit-testable without spinning up a database, including the fabricated-history
rejection (`rejects_fabricated_history_at_checkpoint`). Security logic that can
only be exercised through I/O tends to be tested on the happy path only.

### 3.4 Failure handling — the part that is usually wrong

Both failure paths were defects before they were features, and both are worth
stating because the pattern recurs in every install-then-verify design:

**A failed copy used to strand the operator.** An early `?` returned with the
operator's chaindata parked under `.pre-snapshot-<stamp>` and no restore — a node
with no database and no obvious way back. Now a copy failure triggers a **loud
rollback** that restores the original.

**A rejected snapshot used to stay installed.** The rollback call was written as
`let _ = …`, swallowing rollback errors. A snapshot that *failed verification*
could remain in place as live state — the exact opposite of what the verification
was for. Rollback errors now propagate.

Generalising: **a security check is only as good as the failure path that follows
it.** A correct rejection followed by a swallowed cleanup error is not a
rejection. `let _ =` on a security-relevant cleanup is a code smell worth grepping
for.

The pre-snapshot backup is intentionally **left on disk** and never
auto-deleted — the import stays reversible by the operator.

### 3.5 Signer allowlist

A policy may carry trusted Ed25519 signer public keys. If the list is **non-empty**,
the snapshot must carry a `manifest.sig` whose signer is on the list and whose
signature verifies over the manifest, or the import is refused. An empty list means
no signature is required — appropriate for a privately produced snapshot, where the
operator *is* the source.

### 3.6 The unverified escape hatch, stated honestly

An **empty checkpoint slice skips DB-level verification entirely.** This is an
explicit *unverified* import for controlled and test use.

It is documented as such, and the CLI **always** supplies the network's
checkpoints — which always include genesis. But it exists, and a caller
constructing a policy programmatically with an empty slice gets no
fabricated-history protection. It is listed here rather than left in a doc-comment
because an escape hatch that readers do not know about is one that gets used by
accident.

---

## 4. Security analysis

**What holds.** A snapshot cannot install a history diverging from the binary's
compiled checkpoints; a manifest cannot lie about its payload; failed imports roll
back and are recoverable; snapshots may be required to be signed.

**What this does not protect against.**

- **History between checkpoints.** Binding is checked *at* checkpoint heights. A
  snapshot could in principle contain fabricated blocks *between* two checkpoints
  while matching both — though such a chain must still be internally valid and
  reach the right hash at the next checkpoint, which is precisely as hard as
  producing a competing chain over that span. The bound is real but it is a bound.
- **The most recent history.** Blocks after the highest checkpoint are not bound
  by this mechanism at all. Their validity rests on ordinary validation and
  accumulated work.
- **A caller passing no checkpoints** (§3.6).
- **Compromised checkpoints.** The whole argument reduces to trusting the binary.
  That is WP-007's (source integrity) and WP-026's (build integrity) subject.
- **Availability and privacy of the source.** Where a snapshot is downloaded from,
  and what that host learns about the downloader, are outside this module.

---

## 5. Implementation

| Component | Location |
|---|---|
| `verify_chain_binding` (pure), `verify_installed_db` (glue) | `src/snapshot/verify.rs` |
| Install flow, rollback, marker, backup retention | `src/snapshot/mod.rs` |
| Policy: network, genesis, checkpoints, signer allowlist | `src/snapshot/mod.rs` |
| Consensus checkpoint tables | `src/constants.rs` |
| Operator tooling | `recover-chain.ps1`, snapshot CLI |

**Validation.** `rejects_fabricated_history_at_checkpoint` and a full
`verify_installed_db` path exercised against a real genesis chain DB.

**Operational note.** Snapshot restore has been used in practice to recover the
live testnet — both the home node and the Hetzner node were returned to a clean
build at height 13,279 through it.

---

## 6. Known limits

- Binding is at checkpoint heights, not continuous (§4).
- Post-final-checkpoint history is unbound by this mechanism.
- The empty-checkpoint escape hatch exists (§3.6).
- Warp sync (fast-forward from a state commitment rather than a full DB copy) is
  **not** implemented; this paper covers DB snapshot import only.
- Reduces to trust in the binary — see WP-026.

---

## 7. References

- Bitcoin Core `assumeutxo` — the closest prior art for trusted-but-bound state
  import, and its checkpoint-binding argument.
- Internal: [WP-007 Hash lock](WP-007-critical-files-hash-lock.md),
  [WP-026 Reproducible builds](WP-026-reproducible-builds.md),
  [WP-005 Reorg defense](WP-005-layered-reorg-defense.md),
  [WP-017 §3.6](WP-017-light-wallet-sync.md) — the same
  checkpoint-authentication idea on the wallet side.
