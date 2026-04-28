# Vendored explorer assets

This directory holds CDN-fetched JavaScript / CSS / data assets that the
embedded block explorer needs, mirrored locally so the explorer works
without internet access to `cdn.jsdelivr.net` or `fonts.googleapis.com`.

**The directory is empty in a fresh checkout.** Files land here when an
operator runs `../fetch-vendor.sh` on the deploy host (or in CI). The
checksums of every fetched file are pinned in `checksums.txt` (TOFU on
first run, verified on subsequent runs).

## Why vendor at all?

1. **Tor / restrictive networks.** A privacy coin's explorer that
   breaks on Tor because it can't reach jsdelivr is a bad look.
2. **Survival.** jsdelivr was down for ~3 hours in 2023. Every site
   depending on it broke. Vendoring eliminates that single point of
   failure.
3. **CSP tightening.** Same-origin assets let the explorer web server ship
   `Content-Security-Policy: default-src 'self'`, the gold standard.
   Third-party CDNs force the CSP to allowlist every origin.
4. **Reproducibility.** Pinned checksums mean every operator ships
   byte-identical assets. CDNs are mutable.

## Layout (after `fetch-vendor.sh` runs)

```
static/vendor/
├── checksums.txt                 ← pinned SHA-256 of every file below
├── chart.js/4.4.0/chart.umd.min.js
├── d3/7/d3.min.js
├── topojson-client/3/topojson-client.min.js
├── globe.gl/2.27.3/globe.gl.min.js
└── world-atlas/2/countries-110m.json
```

Each file is namespaced by `<library>/<version>/...` so multiple
versions can coexist if a future asset bump is staged before the
HTML is patched to use it.

## Workflow

```bash
# From this directory's parent (deploy/explorer/):

# 1. First time: download everything, TOFU-pin each hash to checksums.txt
./fetch-vendor.sh

# 2. Review and commit
git add static/vendor checksums.txt
git status                            # confirm what's being added

# 3. Flip the HTML to use vendored paths
./patch-vendor.sh

# 4. Update the test in src/rpc/explorer.rs that enumerates external
#    CDNs — drop the origins that just got vendored. The test is
#    intentionally a positive enumeration and moves with the trim.

# 5. Verify
cargo test --lib -p coincync explorer

# 6. Commit the patched HTML + the test update
git add ../../src/explorer/index.html ../../src/rpc/explorer.rs
git commit -m "explorer: vendor chart.js, d3, topojson, globe.gl, world-atlas"
```

## Idempotency / re-running

`./fetch-vendor.sh` is safe to re-run any number of times:

- Files that exist AND match `checksums.txt` → reported `OK`, untouched.
- Files that exist AND mismatch → reported `MISMATCH`, script exits
  non-zero (you have to delete the line from `checksums.txt` and
  re-run if the change is intentional).
- Files that don't exist → downloaded, hash captured, `checksums.txt`
  updated.

`./fetch-vendor.sh --verify` skips downloading entirely — useful in
CI to confirm a checked-in vendor directory hasn't been tampered with.

`./patch-vendor.sh` is intentionally NOT idempotent on the HTML side
(it's a one-way string substitution), but it bails cleanly with
"already patched" warnings if the find-strings aren't present, so
running it twice is harmless.

## Should `static/vendor/*` be checked into git?

**Yes.** The whole point of vendoring is reproducibility, and that
means the artifacts ship with the source. Total weight is around
1.5 MB across all files — small enough to commit, big enough to
matter for offline operators.

If a particular operator wants to skip the vendor commit (e.g.
they're on a metered connection and would rather fetch on deploy),
they can `.gitignore` the contents of this directory but **must
still commit `checksums.txt`** so subsequent fetches verify against
a pinned set.

## Adding a new vendored asset

1. Edit `../fetch-vendor.sh` and add a new line to the `ASSETS` array:
   ```
   "<URL>|<local_path_relative_to_static/vendor>"
   ```
2. Run `./fetch-vendor.sh` — TOFU mode pins the new hash.
3. Edit `../patch-vendor.sh` and add the matching `find|replace` to
   the `PATCHES` array.
4. Run `./patch-vendor.sh`.
5. Update `src/rpc/explorer.rs::tests::explorer_html_lists_external_cdns`
   to reflect the new state.
6. Commit the file, `checksums.txt`, the patched HTML, and the test
   update — all in one commit so a future bisect lands on a
   self-consistent state.
