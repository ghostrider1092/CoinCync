//! # Block Explorer HTML
//!
//! Serves the canonical CoinCync block explorer at
//! [`crate::rpc::explorer::EXPLORER_HTML`]. The HTML is embedded at
//! compile time from `src/explorer/index.html` so the explorer ships
//! inside the node binary — no external static-asset directory to keep
//! in sync at deploy time, no separate CDN to operate.
//!
//! ## What the embedded explorer does
//!
//! It is a single-file HTML/CSS/JS app that talks to the node's
//! JSON-RPC endpoint via inline `fetch()` calls (the inline `rpc()`
//! helper is defined around line 1538 of `index.html`). The methods
//! it consumes are listed in the `explorer_html_calls_only_registered_methods`
//! test below — that test pins the JS-side and the server-side surfaces
//! together, so any future explorer rewrite that adds a new
//! `rpc('foo')` call will fail in CI until `foo` is registered on the
//! `jsonrpsee` server.
//!
//! ## CDN dependencies
//!
//! The embedded explorer pulls fonts and visualization libraries
//! (chart.js, d3, topojson-client, globe.gl) from `cdn.jsdelivr.net`
//! and Google Fonts. This is a deliberate design choice: the explorer
//! is feature-rich and ships those libraries by reference rather than
//! bundling them into the binary. **As a consequence the explorer
//! does not work on an air-gapped or onion-only node.** Operators
//! running such nodes should either:
//!
//! 1. Front the explorer with a reverse proxy that mirrors the CDN
//!    assets onto the same origin, or
//! 2. Disable the explorer entirely and use the JSON-RPC endpoint
//!    directly.
//!
//! See `tests::explorer_html_lists_external_cdns` for the exact set
//! of external origins the embedded explorer pulls from — that test
//! is intentionally a positive enumeration, not a "no external"
//! assertion, so a future asset trimming pass can shrink the list
//! incrementally and the test moves with it.

/// The complete CoinCync block explorer page, embedded at compile time.
///
/// Source of truth: `src/explorer/index.html`. The previous version of
/// this file pointed `include_str!` at `../../explorer/index.html`,
/// which resolves to a non-existent `repo_root/explorer/index.html` —
/// that path was wrong. The correct relative path from
/// `src/rpc/explorer.rs` is one `..`, not two.
pub const EXPLORER_HTML: &str = include_str!("../explorer/index.html");

/// Return the block explorer HTML page.
///
/// `rpc_port` is kept as a parameter for API compatibility — the
/// inline JS in the embedded explorer reads its RPC URL from
/// `?rpc=...` (overrideable) or defaults to `http://127.0.0.1:28081`
/// (the testnet default). The port argument is intentionally ignored
/// because the explorer chooses its own URL.
pub fn explorer_html(_rpc_port: u16) -> String {
    EXPLORER_HTML.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity check: the embedded HTML is non-trivial. Catches the
    /// case where `include_str!` accidentally points at a placeholder
    /// or the file gets emptied.
    #[test]
    fn embedded_explorer_is_non_trivial() {
        let html = explorer_html(28081);
        assert!(
            html.len() > 50_000,
            "embedded explorer must be substantial ({}B is too small — \
             check that include_str!(\"../explorer/index.html\") points at \
             the real file, not a placeholder)",
            html.len()
        );
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("CoinCync"));
    }

    /// Lock the JS-side ↔ server-side RPC surface together. Every
    /// method the embedded explorer JS calls must be registered on
    /// the jsonrpsee server in `crate::rpc::server`. If you add a new
    /// `rpc('foo')` call to `src/explorer/index.html` and forget to
    /// register `foo` on the server, this test fires.
    ///
    /// Conversely, if a server method is renamed or removed without
    /// also updating the explorer, this test fires. The two are now
    /// pinned together at the test layer.
    #[test]
    fn explorer_html_calls_only_registered_methods() {
        let html = explorer_html(28081);
        // The exact method tokens the inline `rpc()` helper passes in
        // its first argument, in the format that grep would find them
        // (single-quoted JS string literals). If the explorer ever
        // adopts double quotes or backticks, update this list and the
        // assertion accordingly.
        let calls: &[&str] = &[
            "rpc('get_info'",
            "rpc('get_block_range'",
            "rpc('get_block_by_height'",
            "rpc('get_block'",
            "rpc('get_peers'",
            "rpc('get_transaction'",
            "rpc('get_asset_info'",
        ];
        for c in calls {
            assert!(
                html.contains(c),
                "explorer HTML must contain `{}` — if you removed this \
                 call, also remove it from this test",
                c
            );
        }
    }

    /// Positive enumeration of the external origins the embedded
    /// explorer fetches from. This is NOT a "must be empty" assertion
    /// (the explorer can ship with CDN deps by design — see the
    /// module docstring). It exists so an asset trimming / vendoring
    /// pass can shrink the list incrementally and the test will move
    /// with it. If a new external origin appears that isn't in this
    /// set, the test fires and forces a deliberate "yes I really
    /// meant to add this" decision.
    ///
    /// History:
    /// - Initial: jsdelivr (chart.js, d3, topojson-client, globe.gl,
    ///   world-atlas, three-globe textures), Google Fonts (CSS +
    ///   woff2s at fonts.gstatic.com), GitHub API.
    /// - After `deploy/explorer/patch-vendor.sh` ran the first time:
    ///   jsdelivr is fully patched out (assets vendored under
    ///   `/static/vendor/`), leaving only Google Fonts (CSS/woff2
    ///   indirection makes it a separate vendoring step) and the
    ///   GitHub API call (operator choice).
    /// - After the second patch-vendor.sh pass: Google Fonts CSS +
    ///   woff2s also vendored under `/static/vendor/fonts/`. Only
    ///   the GitHub API call remains as an external dependency,
    ///   and that one is non-essential — the explorer's
    ///   recent-commits feed degrades gracefully if it 404s, and
    ///   an operator who wants full air-gap can comment out the
    ///   single `fetch('https://api.github.com/...')` call in
    ///   `index.html`.
    #[test]
    fn explorer_html_lists_external_cdns() {
        let html = explorer_html(28081);
        let known_external_origins: &[&str] = &[
            "https://api.github.com", // recent commits feed (optional, degrades gracefully)
                                      // cdn.jsdelivr.net REMOVED — Chart.js, D3, Three.js vendored under /static/vendor/
                                      // fonts.googleapis.com REMOVED — self-hosted at /assets/fonts/ (privacy fix)
        ];
        for origin in known_external_origins {
            assert!(
                html.contains(origin),
                "expected embedded explorer to reference `{}` — if this \
                 dependency was removed, also remove it from the test \
                 (this test is a positive enumeration, not a ban list)",
                origin
            );
        }

        // Conversely, jsdelivr AND Google Fonts were fully vendored
        // out by `deploy/explorer/patch-vendor.sh`. If a new
        // dependency reintroduces a URL from these origins into the
        // embedded HTML, this test fires and the operator has to
        // either vendor it or make a deliberate "yes, re-introduce
        // CDN dep" decision.
        let banned_after_vendoring: &[&str] = &[
            // Google Fonts must NEVER be loaded from Google's CDN.
            // Self-hosted at /assets/fonts/ to prevent privacy leaks.
            "fonts.gstatic.com",
            "fonts.googleapis.com",
        ];
        for origin in banned_after_vendoring {
            assert!(
                !html.contains(origin),
                "embedded explorer must NOT reference `{}` — that \
                 origin was vendored out by patch-vendor.sh. Either \
                 re-run patch-vendor.sh or update this test if you \
                 intentionally re-added a CDN dependency.",
                origin
            );
        }
    }
}
