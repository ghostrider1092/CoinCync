# Light-wallet (`lightsync`) audit — 2026-05-08

**Scope:** `src/wallet/lightsync.rs` (914 lines), wire-protocol numbers in
`src/network/protocol.rs`, network handler in `src/network/node.rs`.

**Auditor:** internal review per Item 9 of the 2026-05-07 senior-review pass.

**Verdict (TL;DR):** **The code is production-quality and the protocol
design is, for privacy, BETTER than BIP-157. Three small additions are
required to ship it; no rewrite is needed. Total estimated work to make
it operational: ~2-3 days, not the 2 weeks I originally estimated.**

---

## What's there

The module defines four primitives:

1. **`OutputDigest`** (~138 bytes) — minimal per-output payload. Carries
   exactly what a wallet needs to detect ownership and decrypt amounts:
   `tx_public_key` (32B), `view_tag` (1B), `stealth_address` (32B),
   `commitment` (32B), `encrypted_amount` (~8B), `tx_hash` (32B),
   `output_index` (1B). No range proofs, no input data, no ring
   signatures. Cryptographically sufficient; nothing privacy-relevant
   stripped.

2. **`BlockDigest`** — output-only block summary (`height`, `hash`,
   `prev_hash`, `timestamp`, all output digests in the block). Replaces
   ~1-5 KB per tx with ~138 B per output.

3. **`SyncCheckpoint`** — periodic trust anchor (height, block hash,
   total outputs, UTXO-set hash). Allows fresh wallets to skip ancient
   history.

4. **`LightWalletSync`** — scan engine. View-tag fast filter (rejects
   255/256 outputs in O(1) per output), then full ECDH for survivors,
   then amount decryption for matches. Matches the heavyweight
   `WalletScanner` exactly — the same crypto helpers in `scanner.rs`,
   restated here for module independence.

   - Subaddress key fallback is correctly wired (the C9-FIX in the
     comments is for a real prior bug — primary-only checking would
     have made all subaddress receipts invisible to light sync).
   - Parallel scan via `rayon` across multiple `BlockDigest`s.

Wire-protocol message numbers are reserved (`GetOutputDigests = 62`,
`OutputDigests = 63` in `network::protocol::MessageType`).

## Privacy posture vs BIP-157 (Bitcoin's compact-filter SPV)

CoinCync's design is **stronger than BIP-157 for privacy**:

| Aspect | BIP-157 (Bitcoin) | CoinCync `lightsync` |
|---|---|---|
| Wallet query model | Wallet asks "do any of THESE addresses appear in block N?" | Wallet asks "give me ALL output digests for blocks N..M" |
| Server learns | The set of addresses the wallet cares about | Just the height range — no address info |
| Privacy floor | Address-set leak to anyone running a filter server | Server-blind: no address info ever transmitted |
| Bandwidth | ~80 B/filter element + retrieval | ~138 B/output digest, no separate retrieval |

The BIP-157 model leaks the wallet's address set to whoever serves the
filter — a real-world deanonymization vector that has been exploited
against BIP-157 wallets in academic papers. CoinCync's
"download all digests in range, scan locally" model side-steps this:
the server sees only "wallet wanted blocks N..M," not which outputs in
that range matter to the wallet.

The price is bandwidth: BIP-157 lets a wallet skip blocks that its
filter doesn't match. CoinCync's wallet downloads digests for every
block in its range. For an active wallet checking weekly, this is
identical bandwidth to BIP-157 (one round trip per check). For a
cold-start fresh install, CoinCync needs more (every digest since
checkpoint, vs BIP-157's filter-then-block-on-match). The
checkpoint mechanism mitigates this: post-launch a fresh wallet only
needs digests since the last checkpoint, not since genesis.

**The privacy trade-off is unambiguously CoinCync's favor.** Don't
abandon this for a BIP-157 port.

## What's missing to ship it

### Gap 1 — handler is parked at the network layer

`src/network/node.rs:3001-3010`:
```rust
MessageType::GetOutputDigests => {
    tracing::debug!("GetOutputDigests from {:?} ignored (lightsync disabled in P0)", &peer_id[..4]);
}
```

Peers requesting digests get nothing; their light-wallet client times
out and falls back to full sync. **No production light wallet works
against the current network today.**

Unparking is straightforward: build a `BlockDigest` for each requested
height (already supported by `BlockDigest::from_block`), wrap in
`DigestResponse`, send back. Estimated: ~50 lines, half a day with
tests.

### Gap 2 — checkpoint authentication is unimplemented

`SyncCheckpoint::verify_hash()` returns the hash of the checkpoint's
own fields. That's a checksum, not authentication. A malicious server
can fabricate a checkpoint, claim `height = K` with a bogus
`utxo_hash`, and a fresh light wallet trusts it.

Real authentication needs ONE of:

- **Miner signatures.** Each block header carries an optional
  checkpoint vote; a checkpoint at height `K` is valid only if a
  super-majority of headers in `K-N..K` voted for it. (`BlockHeader`
  already has a `checkpoint_vote: Option<...>` field — wired but
  unused.)
- **Hard-coded checkpoint set.** Project ships a known set of
  checkpoint hashes baked into the binary. Operator updates them at
  release time. Crude but effective for the early phase, fine until
  the chain is long enough that bake-in becomes painful.
- **Both.** Hard-coded for the binary's contemporaneous head, miner
  signatures for anything past that. Bitcoin Core does this.

Estimated: 1 day for hard-coded set, 2-3 days for miner signature
verification (the field exists, the verification code does not).

### Gap 3 — no bloom-filter optimization

Optional. After the server stores a per-block bloom filter of the
view tags present in that block (one byte each), wallets could
download just the bloom and skip blocks whose filter doesn't match
their key set. Reduces bandwidth ~256x for fresh-install case
(view-tag match probability is 1/256).

This is an enhancement, not a requirement. Ship without it; add later
if light-wallet UX demands it.

Estimated: 1 week if pursued. Skip for v1.0 mainnet.

### Gap 4 — RPC surface doesn't expose lightsync

`get_output_digests` is in the `RPC_ALLOWED_METHODS` list in
`src/rpc/rest.rs` but the JSON-RPC server doesn't register a
handler for it. Same parked-but-prepared pattern as the network
handler.

The JSON-RPC handler is a thin call into the wire-protocol
`GetOutputDigests` once that's unparked. Estimated: 30 minutes
after Gap 1 ships.

## Recommended path forward

Sequencing matters because Gap 1 unblocks every light-wallet
integration, but without Gap 2 the result is insecure (a
malicious server can lie about UTXO state).

1. **Ship Gap 2 first** (hard-coded checkpoints — 1 day).
   - Define `CHECKPOINTS: &[(height, block_hash, utxo_hash)]` in
     `src/constants.rs`.
   - Validator at unlock time refuses to trust a checkpoint whose
     hash isn't in the set.
   - Update at every release.

2. **Then unpark Gap 1** (network + JSON-RPC handlers — 0.5 day).

3. **Verify end-to-end** with a real light-wallet client (the
   existing `LightWalletSync` engine + new RPC).

4. **Ship miner-signed checkpoints in v1.0.1** as a soft post-launch
   enhancement (Gap 2 phase 2).

5. **Bloom filters defer to v1.1+** (Gap 3) — only if real-world
   light-wallet UX requires the bandwidth saving.

## What I'd change in the existing code (small)

These are nits — none are launch-blocking:

1. **`OutputDigest::estimated_size()` returns 138 unconditionally.**
   The actual size depends on `encrypted_amount.len()`. Consider
   `actual_size(&self) -> usize` that sums the variable bits, or
   document the 138 as "typical, varies by encrypted_amount."

2. **`compute_view_tag_light` returns `0xFF` on `PublicPoint::from_bytes`
   failure.** This is a fallback to a "tag that almost certainly
   won't match" but it conflates "decode error" with "real tag value
   0xFF". Should return `Result<u8, _>` and let the caller skip the
   output. Tiny code change.

3. **Statistics counter `view_tag_matches` is incremented per
   key-set match in `scan_digest`** — if the wallet has 3 epochs and
   one output's view tag matches in ALL 3, the counter goes up by 1
   not 3 (correct via `iter().any()`), but the comment doesn't
   make this clear.

4. **Tests cover the happy path.** Adversarial cases (mismatched view
   tag, wrong key, malformed digest) need their own tests before
   the handler ships.

## Bottom line

**The light-wallet protocol is sound. Ship Gap 2 + Gap 1, schedule
Gap 4 for v1.1, defer Gap 3. Total launch-readiness work: ~2 days,
not 2 weeks.**

The 2026-05-07 review's "this needs an audit" was correct; the
"might need a rewrite" was overcautious. The existing code is good
work — it just needs the network handler unparked and authenticated
checkpoints wired.
