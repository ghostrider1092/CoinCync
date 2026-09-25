# CIP-Shielded — Binding Firo `libspark` (FFI) + the connector

Status: **FEASIBILITY / design** (no code). Decision context: adopt Firo's
deployed, audited Spark rather than reimplement (see
`cip-shielded-spend-composition.md` "PINNED REFERENCE CONSTRUCTION" and
[[coincync-strategy-narrow-shielded]]). This doc records the feasibility findings
from reading `firoorg/firo/src/libspark` (`master`) and specs the connector.

## Feasibility findings (from reading the source)

- **License: MIT** ✅ (Firo `COPYING`). Vendoring/linking is fine with attribution.
- **`libspark` is NOT standalone.** It is tightly coupled to Firo/Bitcoin-core:
  - **`secp_primitives`** — Firo's C++ secp256k1 wrapper (`GroupElement`, `Scalar`,
    `MultiExponent`). ⇒ the Spark pool runs on **secp256k1**, a different curve than
    CoinCync's transparent side (curve25519/ristretto).
  - **OpenSSL** — `hash_generator` builds NUMS points via `EVP_sha512` hash-to-curve.
  - **Bitcoin-core serialization** — `CDataStream`, `SER_NETWORK`, `PROTOCOL_VERSION`.
  - **Bitcoin-core crypto** — `CSHA256`/`CHash256`, `AES256CBC`, ChaCha20 AEAD, `KDF`.
  - `chainparams.h`, `hash.h`, `support/cleanse.h`.
- **Consequence:** FFI means **vendoring a slice of Firo/Bitcoin core + OpenSSL**
  into CoinCync's build (a C++ subtree), behind a shim — not linking one clean
  library. Plus an ongoing maintenance burden (tracking upstream fixes to vendored
  C++). The build already has a C++/LLVM toolchain (RandomX), so it's *feasible*,
  but the footprint is real.

## Why the curve split is OK (no cross-curve ZK)

The shield/unshield **turnstile amount is public** (`value_balance`, Sapling-style;
CoinCync's `ShieldedPayload.value_balance: i64` already is this). The pool's
internal balance proof runs entirely inside `libspark` on secp256k1; the boundary
is a cleartext integer both sides agree on. So **no cross-curve commitment-equality
proof is needed** — the connector is marshalling + public-value accounting, not
hard cross-group crypto. This is the key de-risker for the curve split.

## FFI mechanism

Two workable options:
- **`cxx` crate** — safe, idiomatic C++/Rust bridge; good for C++ types/exceptions.
- **Hand-written C shim** (`extern "C"` over a flat API) + `bindgen`/manual FFI —
  more control, smaller surface, easier to sandbox exceptions at the boundary.

Recommendation: a **thin C shim** exposing only the operations the connector needs
(create coin, build spend, verify spend, identify/recover, tag) as flat functions
over byte buffers, then Rust FFI to that shim. Keeps the unsafe surface tiny and
serialization explicit. All `libspark`/secp_primitives/OpenSSL stays behind the
shim; Rust never touches secp256k1 types directly.

## The connector (`libspark` world ⇄ CoinCync world)

A "talking connector" (same family as the turnstile / Note Connector): one
adapter layer, no logic duplicated on either side.

1. **Serialization marshalling.** CoinCync `ShieldedPayload` / `ShieldedInput` /
   `ShieldedOutput` carry opaque `Vec<u8>` proof fields already — the connector
   fills them with `libspark`'s native serializations (`Coin`, `SpendTransaction`,
   Grootle/Chaum/BPPlus proofs) and parses them back. Wire format = libspark's.
2. **Value accounting (the turnstile).** Map libspark's public balance
   (`value_balance` / fee / transparent_value) onto CoinCync's transparent supply
   audit (`ShieldedPoolValue` + `crypto/audit.rs`). This is #3/#4 of the wiring
   list — the connector is where they land.
3. **Key/address mapping.** CoinCync wallet keys → libspark
   `(SpendKey{s1,s2,r}, FullViewKey, IncomingViewKey)` + diversified `Address`.
   Retire the flagship's fused bound-coin key path in favour of libspark's schedule.
4. **Verification entrypoint.** `verify_shielded_payload` (consensus) calls the
   shim's `verify` over the cover set; the double-spend set keys on libspark's tag
   `T`. Stays behind `SHIELDED_TX_ACTIVATION_HEIGHT = u64::MAX` + gated until the
   *integration* is reviewed (the crypto inherits libspark's audit; the glue does not).

## Honest cost & the standing alternative

FFI-to-`libspark` is **"inherit the audited crypto, pay in build/vendoring
complexity"**: a vendored C++/OpenSSL/secp256k1 subtree, a shim, a curve split,
and integration review. The alternative — a faithful **Rust port on ristretto**
(single curve, no C++), pinned to the construction already transcribed — trades
that complexity for a full-crypto audit burden. Neither is small; FFI is lower
*crypto* risk, higher *build* complexity. This doc does not itself commit to FFI;
it makes the cost explicit so the choice is informed.

## First implementation steps (only after go, all gated)

1. Prove the shim builds: vendor `libspark` + minimal `secp_primitives` + the
   Bitcoin-core crypto/serialization it needs + OpenSSL; compile a "hello, tag"
   C shim that creates a coin and computes `T`, called from a Rust integration test.
2. Define the flat C API + Rust FFI wrappers (byte-buffer in/out).
3. Build the connector marshalling for one `ShieldedOutput` round-trip, tested.
4. Wire `verify_shielded_payload` → shim (gated). Then the accounting turnstile.
5. Integration review + soak. Activation stays parked.
