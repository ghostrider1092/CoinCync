<!-- markdownlint-disable MD036 MD013 -->
# `coincync-swap` external test vectors

This directory holds cryptographic test vectors imported **verbatim** from two
production cross-curve atomic-swap reference implementations:

- [`comit/`](comit/) — vectors from [`comit-network/xmr-btc-swap`](https://github.com/comit-network/xmr-btc-swap), the production XMR↔BTC atomic-swap CLI audited by Kudelski Security (2021).
- [`farcaster/`](farcaster/) — vectors from [`farcaster-project/farcaster-node`](https://github.com/farcaster-project/farcaster-node), the modular cross-chain swap framework with ongoing academic review.

These vectors exist so the audit firm can verify `coincync-swap`'s cryptographic
primitives are bit-for-bit identical to two independent reference impls without
re-deriving correctness from first principles. See
[`docs/cyncswap-farcaster-comit-alignment.md`](../../../docs/cyncswap-farcaster-comit-alignment.md)
for the full alignment plan.

## How the vectors are used

- `crates/coincync-swap/tests/external_vectors.rs` loads every vector at test time.
- For each vector, our implementation is called with the published input and the
  output is `assert_eq!`'d to the published output, byte-for-byte.
- CI fails on any mismatch. There is no "approximately equal" — only
  bit-exact match passes.

## How to import or refresh vectors

This directory currently holds **stub provenance files**. Actual vectors are
imported by hand from the upstream repos when the alignment work proper begins.

To import a new batch:

1. Check out the upstream repo at the tag/commit you want vectors from.
2. Run the upstream test suite with `cargo test -- --nocapture` capturing
   serialized inputs/outputs (or read vectors from upstream `tests/` directly).
3. Convert each vector to one JSON object per file with the schema in
   `comit/SCHEMA.md` / `farcaster/SCHEMA.md`.
4. Update the relevant `README.md` with the source git SHA, import date, and
   upstream license attribution.
5. Run `cargo test --test external_vectors` locally; CI will pick it up.

## License attribution

Vectors are derived test data, not source code; they are reproduced under fair
use for cryptographic verification purposes. The upstream projects' licenses
(MIT for Comit, LGPL/MIT for Farcaster) cover the original implementations from
which the vectors are derived. Each `README.md` records the specific license at
the time of import.
