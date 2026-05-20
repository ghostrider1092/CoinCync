<!-- markdownlint-disable MD036 MD013 -->
# Comit vector JSON schema

Each vector is a single JSON object in its own `.json` file. Files are named
`<primitive>/<short-descriptive-name>.json` (e.g. `btc-adaptor/sign-roundtrip-001.json`).

## Schema

```json
{
  "primitive": "string — one of: btc-adaptor, dleq-cross-curve, state-machine",
  "operation": "string — primitive-specific operation name (e.g. sign, verify, prove)",
  "source_file": "string — upstream file the vector was extracted from",
  "source_test": "string — upstream test fn name, if applicable",
  "inputs": {
    "comment": "primitive-specific; all bytes hex-encoded without 0x prefix"
  },
  "expected": {
    "comment": "primitive-specific; all bytes hex-encoded without 0x prefix"
  },
  "notes": "string — any context the auditor would want (optional)"
}
```

## Example — `btc-adaptor/sign-roundtrip-001.json`

```json
{
  "primitive": "btc-adaptor",
  "operation": "create_then_recover_secret",
  "source_file": "swap/src/bitcoin/wallet.rs",
  "source_test": "sign_and_recover_known_vector",
  "inputs": {
    "signing_secret_key": "0101010101010101010101010101010101010101010101010101010101010101",
    "adaptor_secret": "0202020202020202020202020202020202020202020202020202020202020202",
    "message_hash":     "0303030303030303030303030303030303030303030303030303030303030303"
  },
  "expected": {
    "adaptor_signature":     "<64-byte-hex>",
    "decrypted_signature":   "<64-byte-hex>",
    "recovered_adaptor_secret": "0202020202020202020202020202020202020202020202020202020202020202"
  },
  "notes": "Verifies the full create → decrypt → recover cycle on a deterministic input."
}
```

Hex encoding is lowercase, no `0x` prefix, no separators. All byte arrays are
fixed-length per the primitive's specification (32 bytes for scalars and curve
points unless stated otherwise).
