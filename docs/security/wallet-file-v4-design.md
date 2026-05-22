<!-- markdownlint-disable MD036 MD013 -->
# Wallet file v4 — design

**Status:** Design. Not yet implemented.
**Author:** 2026-05-21 hardening-session follow-up.
**Supersedes:** wallet file v3 in [src/wallet/persistence.rs](../../src/wallet/persistence.rs).
**Tracks against:** [docs/v1.0-base-chain-hardening-punchlist.md](../v1.0-base-chain-hardening-punchlist.md) `H  src/wallet/persistence.rs:501` and [docs/v1.0-mainnet-audit-prep.md](../v1.0-mainnet-audit-prep.md) §5 priority 8 / §6.5.

This document is a design conversation, not a release commitment. v4 is **unscheduled future-work** — not slotted for v1.0 mainnet, the v1.0.x point-release stream, or v1.1 (cyncswap-only). When v4 ships it will be its own coordinated release with its own backward-compat window.

---

## 1. Threat model

What v4 defends against, in concrete terms.

**Attacker capability:** can write arbitrary bytes to the user's wallet file. (Examples: malware on the user's machine, a malicious sync agent, a backup-restore that replaces the file, a network share with an unprivileged co-tenant.)

**What v3 already defends against:**

1. **Brute-forcing the password offline.** Even with file-write access, the attacker still needs the password to generate a candidate decryption. v3 is unchanged here.
2. **OOM / panic via KDF-param tampering.** [src/wallet/persistence.rs](../../src/wallet/persistence.rs) `WalletHeader::validate()` enforces upper and lower bounds on `kdf_m_cost`, `kdf_t_cost`, `kdf_p_cost`. Both bounds were discovered by fuzz crashes (`crash-6b3e53ff71c9e8e1` overnight #1 / `crash-c0a0e826...` overnight #2) and have hard-coded regression tests with the exact crash bytes. An attacker setting `m_cost = u32::MAX` or `m_cost = 1` no longer produces a panic — the file is rejected before any Argon2 work.
3. **Denial-of-service via ciphertext tampering.** The AEAD tag covers the ciphertext; any modification causes a clean decryption failure with no key-material leakage.

**What v3 does NOT defend against — v4's job:**

4. **Header tampering as a timing side-channel.** An attacker who writes to the file can change `kdf_m_cost` from `262_144` KiB (default) down to `8` KiB (the validated lower bound). The user enters their password; Argon2id runs ~32 768× faster than usual; AEAD decryption succeeds; the user sees a "wallet unlocks fast" anomaly and might or might not notice. The user's machine is now usable as a fast-unlock oracle against their password. Combined with a separate exfil step (the malware that wrote the file already has user access), the attacker now has a workable offline-brute-force pipeline.

The defense: authenticate the header BEFORE running Argon2, with a key the attacker doesn't have. That is what v4 adds.

**What v4 explicitly does NOT defend against:**

- An attacker who already has the user's password. v4 is irrelevant — the wallet was lost the moment the password leaked.
- An attacker with read-only access to the wallet file. They can still attempt offline brute force; v4 doesn't change brute-force economics (which Argon2's `m_cost` already addresses).
- An attacker who can modify the binary, not just the wallet file. Out of scope; that's the reproducible-build attestation's job.
- Side-channels in Argon2 itself (cache timing, EM emanations). Out of scope.

---

## 2. Wire format

```
v3 (current):
  ┌──────────┬──────────────┬─────────────┬───────────┬───────────┬──────────┬───────────────┐
  │ magic 4B │ version=3 1B │ hdr_len u32 │ header... │ nonce_len │ nonce... │ ct_len u32 + │
  │ (CYNC)   │              │ LE          │ (borsh)   │ u32 LE    │          │ ciphertext   │
  └──────────┴──────────────┴─────────────┴───────────┴───────────┴──────────┴───────────────┘
  ciphertext = AEAD(enc_key, nonce, plaintext_wallet, AAD = empty)

v4 (proposed):
  ┌──────────┬──────────────┬─────────────┬───────────┬───────────┬──────────┬─────────────┬─────────┐
  │ magic 4B │ version=4 1B │ hdr_len u32 │ header... │ nonce_len │ nonce... │ ct_len u32  │ hmac 32B│
  │ (CYNC)   │              │ LE          │ (borsh)   │ u32 LE    │          │ + ciphertxt │         │
  └──────────┴──────────────┴─────────────┴───────────┴───────────┴──────────┴─────────────┴─────────┘
  ciphertext = AEAD(enc_key, nonce, plaintext_wallet, AAD = empty) (unchanged from v3)
  hmac       = HMAC-BLAKE3(mac_key, all_bytes_before_hmac)
```

**The HMAC covers** every byte of the file from `magic` through the last byte of `ciphertext`. Nothing in the file is unauthenticated except the HMAC itself.

**The two keys are derived independently** from the password+salt via HKDF-BLAKE3:

```
ikm  = argon2id(password, salt, m_cost, t_cost, p_cost)  → 32 bytes
prk  = HKDF-Extract(salt = b"coincync-wallet-v4", ikm)
enc_key = HKDF-Expand(prk, info = b"enc-key v4", L = 32)
mac_key = HKDF-Expand(prk, info = b"mac-key v4", L = 32)
```

Implementation note: `blake3::Hasher::new_keyed` provides the keyed-hash primitive; HKDF-BLAKE3 can be built from it directly, or we use the `blake3::derive_key` helper which gives a keyed-derivation flow with a context string and is closer to HKDF-Expand semantics for our use case. Either is fine; pick the one that's most ergonomic at implementation time.

**Why not use Argon2's output for both keys directly?** Argon2 produces 32 bytes; using the same 32 bytes for two purposes (encryption key AND mac key) breaks the separation principle. An attacker observing one key reveals nothing about the other — that property only holds if they're derived independently. HKDF gives us that for free, with one Argon2 run.

---

## 3. Verification flow

The load path runs in this order. **HMAC first, before any expensive work.**

```
1. Read file bytes from disk
2. Parse v4 framing: magic, version, header, nonce, ct_len, ciphertext, hmac
   - Reject any framing error (size mismatch, magic mismatch, version not 3 or 4)
3. If version == 3 → run the v3 load path (separate, see §5 migration)
4. If version == 4:
   a. Run WalletHeader::validate() on the parsed header — rejects out-of-bound KDF params
   b. Run Argon2id with the header's KDF params, salt → ikm (32 bytes)
   c. HKDF-Extract + Expand → enc_key, mac_key
   d. Compute HMAC-BLAKE3(mac_key, all_bytes_before_hmac)
   e. Constant-time compare to the file's hmac field (subtle::ConstantTimeEq)
   f. If mismatch → fail with generic "invalid wallet file or password" + warn-log "v4 HMAC mismatch — file may be tampered"
   g. If match → AEAD-decrypt the ciphertext with enc_key + nonce
   h. If AEAD fails → "invalid wallet file or password" (should not happen if HMAC succeeded; this is belt-and-suspenders against an HMAC implementation bug)
   i. If AEAD succeeds → deserialize the plaintext, return the Wallet
```

Step 4a still runs before Argon2 — `validate()` is fast (3 comparisons) and catches the fuzz-crash class. Step 4d–e is the new gate.

**Order matters.** A naive implementation that runs Argon2 first, then HMAC, would re-expose the timing channel from §1.4. Argon2 MUST run after the framing parse but before the HMAC verify is impossible (the HMAC key needs `mac_key`, which needs `prk`, which needs `ikm`, which needs Argon2). So the timing channel is partially preserved: an attacker can still observe the time-to-fail varies between "framing error" (microseconds) and "HMAC mismatch" (full Argon2 time).

**That is acceptable.** The attack the attacker is trying to mount is: "modify header to make Argon2 faster so I can observe fast unlocks." If they modify the header, the HMAC fails. They get the standard Argon2-time, not a fast one. The timing channel they were trying to open is gated by their inability to forge a valid HMAC.

For an attacker who simply wants to know "is this file v4 or v3" — that's not a secret; the version byte is plaintext. v3 is what the load path attempts to autodetect first.

---

## 4. Save flow

```
1. Take the current Wallet, serialize to plaintext bytes
2. Generate fresh nonce (e.g., random 24 bytes via OsRng for XChaCha20-Poly1305, or 12 bytes for ChaCha20-Poly1305)
3. Generate fresh salt (32 bytes via OsRng) — first-save only; persistent across re-saves
4. WalletHeader::new_v4(version=4, salt, nonce, kdf_params)  — same params as v3
5. Argon2id(password, salt, params) → ikm
6. HKDF-BLAKE3 → enc_key, mac_key
7. ciphertext = AEAD-encrypt(enc_key, nonce, plaintext, AAD = empty)
8. Concatenate: magic ‖ version=4 ‖ hdr_len ‖ header ‖ nonce_len ‖ nonce ‖ ct_len ‖ ciphertext
9. hmac = HMAC-BLAKE3(mac_key, the_concatenation_above)
10. Append hmac to the file bytes
11. Atomic write: write to .tmp, fsync, rename to final path (unchanged from v3)
```

**Re-keying on every save.** Since the salt is persistent (otherwise password change would break decryption of existing files; existing wallets don't change salt on save), the Argon2 cost is incurred once per save. That matches v3. The HKDF + HMAC additions add <1 ms.

**Password change.** When the user changes their password, the wallet file is re-encrypted from plaintext: new salt, new nonce, new enc_key + mac_key, new ciphertext, new hmac. This is the only path that touches the salt.

---

## 5. Migration path (v3 → v4)

**Phase 1 — release N (the v4 release):**

- New v4 files saved by this release and after.
- v3 files load successfully via the legacy path. On the first save after v3 load, the file is auto-upgraded to v4 (new salt is generated, password unchanged from user perspective).
- A one-line `tracing::info!` logs: *"upgraded wallet file from v3 to v4 format"*.
- No user action required.

**Phase 2 — release N+1 or 6 months later:**

- v3 files still load but emit `tracing::warn!` on every unlock: *"wallet file is v3 format; will be required to upgrade. Save the wallet to upgrade in place."*
- Documentation update: a one-paragraph "v3 → v4 upgrade" note in the wallet user guide.

**Phase 3 — release N+2 or 12 months later:**

- v3 files fail to load with: *"wallet file is v3 format and no longer supported. To recover: use your mnemonic seed phrase in the 'restore' flow, which will create a new v4 wallet."*
- The fail-to-load error is verbose because the user has a clean recovery path (mnemonic restore).

**Rollback safety.** A v4 file can be downgraded to v3 only by decrypting plaintext + re-encrypting under the v3 path. The encryption/decryption round-trip is plaintext-identical, so the round-trip is safe. Whether the codebase ships a `downgrade` command is a separate question — the migration is intended one-way.

**Failed-upgrade safety.** If the v3 load succeeds but the post-upgrade v4 save fails (disk full, etc.), the v3 file is left intact (atomic rename means partial writes don't replace the v3 file). The user retries the save; the upgrade is idempotent.

---

## 6. Test plan

In-crate tests added in [src/wallet/persistence.rs](../../src/wallet/persistence.rs) `mod tests`:

1. **v3 roundtrip:** write a v3 file with the current path (still callable via internal API), load it back via the v4 loader's v3-detection branch, assert plaintext equality.
2. **v4 roundtrip:** save → load via v4 path, assert plaintext equality.
3. **v3 → v4 upgrade:** save a v3 file, load it (succeeds), save the loaded wallet, assert the resulting file is v4 (`version` byte = 4, file length = previous + 32 for the HMAC).
4. **v4 HMAC tamper rejection:** save a v4 file, flip one byte in the header, load → fails with generic error + `warn!` log.
5. **v4 ciphertext tamper rejection:** save a v4 file, flip one byte in the ciphertext, load → fails (HMAC catches this before AEAD).
6. **v4 KDF-param tamper rejection:** save a v4 file, modify `kdf_m_cost` in the header (within `validate()` bounds), load → fails with HMAC mismatch.
7. **v4 HMAC truncation rejection:** truncate the last 16 bytes of a v4 file, load → fails framing.
8. **Hardcoded crash bytes from fuzz #1 + #2 still rejected:** the v4 loader must still run `validate()` and reject the fuzz-discovered bad params; the regression tests at `wallet::persistence::tests::reject_huge_m_cost` and `reject_tiny_m_cost` extend to v4-format inputs.
9. **v4 HMAC verify is constant-time relative to ciphertext length:** property test — verify time should not vary with which byte was flipped. (Hard to assert without statistical measurement; can be a documented design check rather than an automated test.)
10. **Password change:** save, change password, load with new password (succeeds), load with old password (fails). New file's salt is different from the prior file's.
11. **v3 + v4 magic-byte fuzz:** add v4 framing variations to `fuzz_wallet_persistence`. The existing fuzz target finds crashes in `validate()`; v4 framing parse should be added so the parser itself is fuzz-tested.

**Mutation-test target.** v4 persistence code should be added to [.cargo/mutants.toml](../../.cargo/mutants.toml) as a critical-files target. The cyncswap audit achieved 100% mutation on its crypto-critical files via this approach; v4 should match.

---

## 7. Open questions deferred to implementation time

These can be decided at the keyboard, not in this doc.

1. **HMAC primitive choice:** `blake3::keyed_hash` (single-call, fast) vs explicit HKDF + HMAC-SHA256 (more familiar to auditors). Recommend `blake3::keyed_hash` for consistency with the rest of the codebase, but the auditor's preference can override.
2. **HKDF info-string format:** `b"enc-key v4"` / `b"mac-key v4"` (my sketch) vs versioned domain-separation tags like `b"coincync/wallet-file/v4/enc-key"`. Recommend the longer form for clarity; the strings are constants and don't matter for performance.
3. **AEAD primitive:** ChaCha20-Poly1305 (12-byte nonce, fast) vs XChaCha20-Poly1305 (24-byte nonce, larger nonce space). v3 uses one of these; v4 should keep whichever v3 uses for migration simplicity. (Look up at implementation time; not worth disrupting the format change for an AEAD swap.)
4. **HMAC field position:** appended last (my sketch) vs prefixed to ciphertext. Appended last is what most file-format conventions do; recommend keeping it.
5. **Whether the HMAC covers the file's path or the operator's username.** No — that would break legitimate use cases like backup-restore on a different machine. The HMAC is salted-from-password only.

---

## 8. Out of scope

To preserve the "we are not solving every wallet-file concern" discipline:

- **Streaming load.** v4 still buffers the whole file. Wallet files are small (< 100 KB typical); no streaming needed.
- **Resumable saves.** If a save is interrupted, the user retries. No partial-state recovery beyond the existing atomic-rename pattern.
- **Versioning beyond v4.** v5 / v6 will get their own design docs when they're needed.
- **Hardware-wallet integration.** Separate workstream; v4's plaintext format is unchanged so any HW-wallet path that operates on plaintext is unaffected.
- **Cloud-backup encryption layer.** Already addressed by the v1.2 cloud-backup work in the public roadmap.
- **Watch-only wallet files.** Watch-only files use the same v3 format with a sentinel master-seed value (the agent flagged this in §11 of the audit-prep doc but the design is intentional). v4 changes nothing here.

---

## 9. Implementation order (when this work is scheduled)

1. Add v4 framing constants + `WalletHeader::new_v4` constructor. No behavior change yet.
2. Add `derive_v4_keys(password, salt, params) → (enc_key, mac_key)` — pure function, unit-tested.
3. Add `save_v4` + `load_v4` paths, gated by an internal flag. Round-trip tests pass.
4. Add the v3 auto-detect branch to the public `load_wallet` API. v3 still loads correctly.
5. Add v3 → v4 auto-upgrade on save. Migration test passes.
6. Switch the public `save_wallet` API default from v3 to v4. v3 save still callable via internal API for round-trip tests.
7. Extend `fuzz_wallet_persistence` to include v4 framing variations.
8. Ship in release N. Begin Phase-1 migration window.

Each step is a separate small PR. Steps 1-6 are local to `src/wallet/persistence.rs` and its tests; step 7 touches the fuzz harness. No critical-file lockfile changes (wallet/persistence.rs is not in the lockfile).

---

## 10. Estimated cost

- Implementation: 200-300 LOC in `src/wallet/persistence.rs`, mostly in the new v4 save/load paths.
- Tests: 100-150 LOC in `src/wallet/persistence.rs::tests`.
- Fuzz harness extension: 20-30 LOC in `fuzz/fuzz_targets/fuzz_wallet_persistence.rs`.
- Documentation: this doc + a one-paragraph note in the wallet user guide.
- Total: ~1-2 focused days for an engineer familiar with the persistence layer.

Audit-firm impact: the firm's existing finding (if they identify it) for "v3 doesn't authenticate header" becomes "v3 was the audited format; v4 is the documented evolution." The firm may want to review v4 design (this doc) as part of their engagement.

---

## 11. Decision log

- **2026-05-21** — Design conversation opened. Option A (HMAC over full file with independent MAC key) selected over Option B (AEAD with header as AAD) and Option C (keyed-BLAKE3 with shared key) because only Option A closes the header-tampering timing channel. Doc written.

---

*This is a design document, not an implementation commitment. The source-of-truth for the wallet file format remains the code in `src/wallet/persistence.rs` until v4 is implemented and merged. Discrepancies between this document and the code should be resolved in favor of the code; discrepancies between this document and the intent above should be resolved by updating either, with a note in the decision log.*
