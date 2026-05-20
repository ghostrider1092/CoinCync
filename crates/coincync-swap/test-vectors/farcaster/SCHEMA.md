<!-- markdownlint-disable MD036 MD013 -->
# Farcaster vector JSON schema

Schema is identical to Comit's (see [`../comit/SCHEMA.md`](../comit/SCHEMA.md))
so the same vector-loader code in `crates/coincync-swap/tests/external_vectors.rs`
processes both vendors. Only the `source_file` / `source_test` fields differ in
content.

## Example — `ed25519-adaptor/sign-roundtrip-001.json`

```json
{
  "primitive": "ed25519-adaptor",
  "operation": "create_then_recover_secret",
  "source_file": "farcaster-core/src/crypto/ed25519/adaptor.rs",
  "source_test": "adaptor_roundtrip_known_vector",
  "inputs": {
    "signing_secret_scalar": "0101010101010101010101010101010101010101010101010101010101010101",
    "adaptor_secret":        "0202020202020202020202020202020202020202020202020202020202020202",
    "message_hash":          "0303030303030303030303030303030303030303030303030303030303030303"
  },
  "expected": {
    "adaptor_signature":         "<64-byte-hex>",
    "decrypted_signature":       "<64-byte-hex>",
    "recovered_adaptor_secret":  "0202020202020202020202020202020202020202020202020202020202020202"
  },
  "notes": "Farcaster's ed25519 (cofactor-8) reference. Our impl uses Ristretto255; the scalar arithmetic should agree even though the group representation differs."
}
```

## Cross-vendor primitive map

When a primitive exists in both Comit's and Farcaster's vector set with
matching inputs, the harness in `external_vectors.rs` should run it through
*our* impl and verify the output matches *both* upstream expected values.
A divergence between Comit and Farcaster on a shared input is itself a finding
and must be triaged before proceeding.

| Primitive | Comit dir | Farcaster dir | Cross-check expected? |
| --- | --- | --- | --- |
| BIP-340 Schnorr adaptor (BTC) | `comit/btc-adaptor/` | `farcaster/btc-adaptor/` | Yes |
| Cross-curve DLEQ (Maxwell-Poelstra) | `comit/dleq-cross-curve/` | `farcaster/dleq-cross-curve/` | Yes |
| ed25519 / Ristretto adaptor (CYNC) | _N/A — Comit uses XMR-specific construction_ | `farcaster/ed25519-adaptor/` | No (Farcaster-only) |
