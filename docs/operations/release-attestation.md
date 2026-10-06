# Release attestation (multi-signer, reproducible)

CoinCync release binaries are attested the way Bitcoin/Monero do it: the exact
hash of every artifact is pinned in a manifest, and multiple independent
maintainers sign that manifest. A release is only trusted when an **N-of-M**
threshold of known-maintainer signatures verifies over the artifact hashes — so
no single machine or person can slip a backdoored binary through.

Tool: **`coincync-release-attest`** (`src/bin/release_attest.rs`), backed by the
verified core in `src/release.rs`.

## Roles

- **Builder(s):** each independently runs the reproducible Docker build and
  produces artifacts, then a manifest, and confirms their manifests are
  byte-identical (reproducibility check).
- **Maintainers (M of them):** each signs the agreed manifest with their own
  ed25519 seed. A threshold **N** of these signatures is required to accept a
  release.
- **Verifiers (anyone):** check the downloaded artifacts against the manifest
  and confirm N-of-M maintainer signatures.

## Maintainer key

Each maintainer holds a 32-byte ed25519 seed (64 hex) in a file, stored like any
other signing secret (password manager, sops, hardware-backed store). Generate:

```
python -c "import secrets; print(secrets.token_hex(32))" > maintainer.key   # keep secret
coincync-release-attest sign --manifest /dev/null --key-file maintainer.key  # prints <pubkey>:<sig>
```

The **public** key (the `<pubkey_hex>` half) is published in `MAINTAINERS.md`
and is what verifiers pass with `--maintainer`.

## Flow

```
# 1. Builder: hash all artifacts into a manifest
coincync-release-attest manifest --version 2.0.0 --commit <git-sha> --dir ./artifacts > manifest.json

# 2. Each maintainer signs the SAME manifest.json
coincync-release-attest sign --manifest manifest.json --key-file maintainer.key
#   → prints <pubkey_hex>:<sig_hex>  (collect one per maintainer)

# 3. Anyone verifies: artifacts match the manifest AND N-of-M sigs are valid
coincync-release-attest verify \
  --manifest manifest.json --dir ./artifacts \
  --maintainer <pub1> --maintainer <pub2> --maintainer <pub3> \
  --threshold 2 \
  --sig <pub1>:<sig1> --sig <pub2>:<sig2>
```

Verify fails (non-zero exit) if any artifact's SHA-256/size doesn't match, or if
fewer than `--threshold` distinct known-maintainer signatures are valid.
Signatures from non-maintainer keys are ignored; a maintainer signing twice
counts once. The signing preimage is domain-separated and artifact-order-
independent (the manifest sorts artifacts), so it's deterministic across builders.

## Properties (tested in `src/release.rs`)

- Order-independent, deterministic signing preimage.
- N-of-M threshold enforced; duplicate and non-maintainer signatures don't count.
- Any manifest change (version/commit/artifact) invalidates existing signatures.
- Any artifact byte/size change is detected on verify.
