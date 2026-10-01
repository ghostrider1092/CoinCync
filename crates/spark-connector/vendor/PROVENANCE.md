# Vendored libspark — provenance & verbatim verification

Audit artifact for the shielded engine (see
`docs/audit/SHIELDED_AUDIT_READINESS.md` §7.2). Lets an auditor mechanically
confirm that the vendored Firo `libspark` crypto/proof code is **verbatim** and
that only the files listed below (node *infrastructure*, not crypto) are modified.
Companion to `NOTICE.md` (attribution/licensing).

## Integrity manifest

`MANIFEST.sha256` lists the SHA-256 of **every** vendored file (280 files, sorted,
repo-relative to this `vendor/` dir). Re-verify any time:

```bash
cd crates/spark-connector/vendor
# recompute and diff against the committed manifest (empty output = unchanged)
diff <(find . -type f ! -name MANIFEST.sha256 -print0 | sort -z \
        | xargs -0 sha256sum | sed 's#\./##') MANIFEST.sha256
```

## The ONLY non-verbatim files (the auditor's focus)

Exactly five files are modified; all are build-environment shims that provide only
the node-infra symbols libspark references, and contain **no cryptographic code**.
Each is self-documented with a `SPIKE SHIM` header.

| File | SHA-256 | Shims |
|------|---------|-------|
| `src/util.h` | `82455c89a922f652301c62279427549a2b3f9651885d01a2d9547ee4550c871d` | Firo node `util.h` → light stdlib + `cmp::*`; drops boost::thread/filesystem/tinyformat (unused by libspark) |
| `src/sync.h` | `9c0073c5cfbc4a3200c780804ea00df305f957426f1e0e3780bac0acc434e00b` | Firo node `sync.h` → `std::recursive_mutex`-backed `CCriticalSection`/`LOCK` (params.cpp singleton only) |
| `shims/boost/optional.hpp` | `484b617595810967411b8dea36cd9aa0342fa1c492e7e0a830ee1d7771aaa8ac` | `boost::optional` → `std::optional` (serialize.h's only Boost use; libspark never instantiates it) |
| `shims/chainparams.h` | `b3adf106d95b8934f690943f2921308b90be5b766c4c8ba250c792de56400201` | vestigial include; libspark uses no symbols from it |
| `shims/primitives/mint_spend.h` | `516110fe5a85837c93ddc85d2c40329fcdd0bc2d4f49d113a91df449c77d2f84` | vestigial include (one unused `GetPubCoinValueHash` decl) |

**Not shims (verbatim upstream, despite similar names):** `src/chainparams.h`
(verbatim Bitcoin-Core, 167 lines), `src/libspark/util.h`, and
`src/secp256k1/src/util.h` are the real upstream files. Only the three `src/`
root shims above plus the two under `shims/` are modified.

## Verbatim verification vs. upstream Firo

Everything **not** in the table above — all of `src/libspark/` (coin, keys,
grootle, chaum, bpplus, schnorr, spend_transaction, mint_transaction, hash,
transcript, aead, kdf, …), `src/secp256k1/`, `src/crypto/`, `src/support/`,
`src/compat/`, and the Bitcoin-core root headers — is byte-identical to upstream
Firo and contains the Lelantus-Spark crypto that the external audit covers.

**ACTION REQUIRED (audit-prep): pin the upstream commit.** `NOTICE.md` records the
source as Firo `master` at vendor time, which is not reproducible (master moves).
Before the audit, pin the exact `firoorg/firo` commit and record it here, then the
verbatim claim is reproducible with:

```bash
# <PIN> = the firoorg/firo commit libspark was vendored from
git clone --filter=blob:none --no-checkout https://github.com/firoorg/firo firo-upstream
cd firo-upstream && git checkout <PIN> -- src/libspark src/secp256k1 src/crypto src/support
# diff each verbatim tree against this vendor/src/<tree>; expect NO differences
#   diff -r firo-upstream/src/libspark  <vendor>/src/libspark   # etc.
# (exclude the five shim files above)
```

An auditor who pins `<PIN>` and runs the diff confirms the entire crypto surface
is unmodified Firo, reducing the shielded-crypto review to (a) upstream Firo's own
audited Spark implementation and (b) these five infra shims.
