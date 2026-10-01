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

### Pinned upstream commit

**Upstream pin:** `firoorg/firo` commit
**`c03cd0a1c68e1af8274349d1234d142ae7d02d1e`** — tag **v0.14.18.1**
("Bump version to v0.14.18.1 (#1968)", 2026-09-25). This replaces the
non-reproducible "Firo `master` at vendor time" note; `master` has since moved
(e.g. #1973 "guard Grootle set sizes", 2026-09-28, which this vendoring
predates — see the Grootle note below).

This pin was established mechanically: every file in `MANIFEST.sha256` except
the five shims is **byte-identical to `firoorg/firo` at `c03cd0a1`, modulo line
endings** (see below). The result was derived by LF-normalized SHA-256 compare
of the whole vendored tree against upstream history; the only files that differ
from current `master` are `src/libspark/grootle.cpp` and
`src/libspark/test/grootle_test.cpp` (both changed by #1973 *after* this
vendoring), and both match `c03cd0a1` exactly. Since `master` equals `c03cd0a1`
on every other file, the entire crypto surface pins to `c03cd0a1`.

> **Line endings.** The vendored `src/` tree is stored with **CRLF** line
> endings, while upstream is **LF**. A naive `diff -r` / `sha256sum` against a
> fresh upstream checkout therefore reports *every line* as changed. Verification
> MUST normalize line endings first (e.g. `git -c core.autocrlf=false` plus
> `dos2unix`, or pipe each side through `tr -d '\r'` before hashing). The hashes
> in `MANIFEST.sha256` above are of the vendored (CRLF) bytes as they sit in this
> repo; the verbatim-vs-upstream claim is about the **LF-normalized** content.

### Reproducing the verbatim verification

```bash
PIN=c03cd0a1c68e1af8274349d1234d142ae7d02d1e   # firoorg/firo v0.14.18.1
git clone --filter=blob:none --no-checkout https://github.com/firoorg/firo firo-upstream
cd firo-upstream && git checkout "$PIN" -- src/libspark src/secp256k1 src/crypto src/support

# LF-normalized per-file compare (empty output = identical). Example for one tree;
# repeat for secp256k1 / crypto / support, and exclude the five shim files.
cd <vendor>
for f in $(cd firo-upstream && git ls-files src/libspark); do
  u=$(tr -d '\r' < "firo-upstream/$f" | sha256sum | cut -d' ' -f1)
  v=$(tr -d '\r' < "$f"               | sha256sum | cut -d' ' -f1)
  [ "$u" = "$v" ] || echo "DIFF $f"
done
# Exclude: src/util.h, src/sync.h (shims); shims/* are not upstream at all.
```

An auditor who checks out `c03cd0a1` and runs the LF-normalized compare confirms
the entire crypto surface is unmodified Firo v0.14.18.1, reducing the
shielded-crypto review to (a) upstream Firo's own audited Spark implementation
and (b) these five infra shims.
