//! # Block Explorer HTML
//!
//! Serves the canonical CoinCync block explorer from compile-time
//! embedded source assets: the assembled HTML document, the stylesheet, the
//! pre-paint theme bootstrap, and responsibility-scoped application
//! scripts. Keeping these assets separate makes the frontend reviewable without
//! requiring a runtime asset directory for the in-process explorer.
//!
//! ## What the embedded explorer does
//!
//! It is a static HTML/CSS/JS app that talks to the node's JSON-RPC
//! endpoint via `fetch()` calls in `app/*.js`. The methods it consumes
//! are listed in the `explorer_js_calls_only_registered_methods`
//! test below — that test pins the JS-side and the server-side surfaces
//! together, so any future explorer rewrite that adds a new
//! `rpc('foo')` call will fail in CI until `foo` is registered on the
//! `jsonrpsee` server.
//!
//! ## Supporting assets
//!
//! Production static deployments serve the vendored visualization
//! libraries and fonts under `/static/vendor/` and `/assets/`. The
//! in-process explorer currently embeds only the first-party entry
//! assets declared here, so its supporting-asset coverage is narrower.
//! The optional GitHub activity feed is the only remaining external
//! network origin and degrades gracefully when unavailable.
//!
//! See `tests::explorer_html_lists_external_cdns` for the exact set
//! of external origins the embedded explorer pulls from — that test
//! is intentionally a positive enumeration, not a "no external"
//! assertion, so a future asset trimming pass can shrink the list
//! incrementally and the test moves with it.

/// The CoinCync block explorer document, assembled and embedded at compile time.
pub const EXPLORER_HTML: &str = include_str!(concat!(env!("OUT_DIR"), "/explorer-index.html"));

/// The explorer stylesheet, embedded alongside the HTML shell.
pub const EXPLORER_CSS: &str = include_str!("../explorer/explorer.css");

/// The blocking theme bootstrap that runs before the first body paint.
pub const EXPLORER_THEME_JS: &str = include_str!("../explorer/theme-init.js");

// Generated from the script tags in `src/explorer/app.scripts.html`, which is
// also assembled into the document. This keeps browser and embedded route order
// on one source contract while classic scripts still depend on execution order.
include!(concat!(env!("OUT_DIR"), "/explorer-app-assets.rs"));

/// Return the block explorer HTML page.
///
/// `rpc_port` is kept as a parameter for API compatibility — the
/// application JS in the embedded explorer reads its RPC URL from
/// `?rpc=...` (overrideable) or defaults to `http://127.0.0.1:28081`
/// (the testnet default). The port argument is intentionally ignored
/// because the explorer chooses its own URL.
pub fn explorer_html(_rpc_port: u16) -> String {
    EXPLORER_HTML.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn embedded_sources() -> Vec<&'static str> {
        let mut sources = vec![EXPLORER_HTML, EXPLORER_CSS, EXPLORER_THEME_JS];
        sources.extend(EXPLORER_APP_ASSETS.iter().map(|(_, source)| *source));
        sources
    }

    fn source_contains(needle: &str) -> bool {
        embedded_sources()
            .iter()
            .any(|source| source.contains(needle))
    }

    fn app_source(path: &str) -> &'static str {
        EXPLORER_APP_ASSETS
            .iter()
            .find_map(|(asset_path, source)| (*asset_path == path).then_some(*source))
            .unwrap_or_else(|| panic!("missing embedded explorer asset: {path}"))
    }

    fn app_asset_index(path: &str) -> usize {
        EXPLORER_APP_ASSETS
            .iter()
            .position(|(asset_path, _)| *asset_path == path)
            .unwrap_or_else(|| panic!("missing embedded explorer asset: {path}"))
    }

    /// Sanity check: the embedded asset set is non-trivial and the HTML
    /// shell references every extracted first-party asset.
    #[test]
    fn embedded_explorer_is_non_trivial() {
        let html = explorer_html(28081);
        let total_len: usize = embedded_sources().iter().map(|source| source.len()).sum();
        assert!(
            total_len > 500_000,
            "embedded explorer assets must be substantial ({total_len}B is too small)"
        );
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("CoinCync"));
        assert!(html.contains("href=\"explorer.css\""));
        assert!(html.contains("src=\"theme-init.js\""));
        let mut previous_position = None;
        let mut paths = HashSet::new();
        for (path, source) in EXPLORER_APP_ASSETS {
            assert!(paths.insert(path), "duplicate explorer asset path: {path}");
            assert!(
                !source.is_empty(),
                "embedded explorer asset is empty: {path}"
            );
            let reference = format!("src=\"{path}\"");
            let position = html
                .find(&reference)
                .unwrap_or_else(|| panic!("explorer HTML must reference {path}"));
            if let Some(previous) = previous_position {
                assert!(
                    position > previous,
                    "explorer application scripts must retain their declared order"
                );
            }
            previous_position = Some(position);
        }
        assert!(EXPLORER_CSS.contains(":root,[data-theme=\"paper\"]"));
        assert!(EXPLORER_THEME_JS.contains("localStorage.getItem('cync-theme')"));
        assert!(source_contains("function _computeApiBase()"));
    }

    #[test]
    fn explorer_supply_display_uses_bigint_for_aggregate_values() {
        let core = app_source("app/01-core.js");
        let chain = app_source("app/02-chain.js");
        let operator_tools = app_source("app/15-operator-tools.js");

        assert!(core.contains("function atomicToCyncDisplayNumber(value)"));
        assert!(core.contains("BigInt(value??0)"));
        assert!(chain.contains("atomicToCyncDisplayNumber(supInfo.total_emitted)"));
        assert!(chain.contains("const emittedAtomic=BigInt(supInfo.total_emitted??0)"));
        assert!(operator_tools.contains("atomicToCyncDisplayNumber(d.circulating_supply)"));
        assert!(!chain.contains("supInfo.total_emitted/1e12"));
        assert!(!operator_tools.contains("(d.circulating_supply||0)/1e12"));
        assert!(app_asset_index("app/01-core.js") < app_asset_index("app/02-chain.js"));
        assert!(app_asset_index("app/01-core.js") < app_asset_index("app/15-operator-tools.js"));
    }

    /// Lock the JS-side ↔ server-side RPC surface together. Every
    /// method the embedded explorer JS calls must be registered on
    /// the jsonrpsee server in `crate::rpc::server`. If you add a new
    /// `rpc('foo')` call to `src/explorer/app/*.js` and forget to
    /// register `foo` on the server, this test fires.
    ///
    /// Conversely, if a server method is renamed or removed without
    /// also updating the explorer, this test fires. The two are now
    /// pinned together at the test layer.
    #[test]
    fn explorer_js_calls_only_registered_methods() {
        // The exact method tokens the `rpc()` helper passes in
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
                source_contains(c),
                "explorer application scripts must contain `{}` — if you removed this \
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
    ///   the embedded asset set.
    #[test]
    fn explorer_html_lists_external_cdns() {
        let known_external_origins: &[&str] = &[
            // Recent commits feed (optional, degrades gracefully).
            "https://api.github.com",
            // cdn.jsdelivr.net REMOVED — Chart.js, D3, Three.js vendored under /static/vendor/
            // fonts.googleapis.com REMOVED — self-hosted at /assets/fonts/ (privacy fix)
        ];
        for origin in known_external_origins {
            assert!(
                source_contains(origin),
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
                !source_contains(origin),
                "embedded explorer assets must NOT reference `{}` — that \
                 origin was vendored out by patch-vendor.sh. Either \
                 re-run patch-vendor.sh or update this test if you \
                 intentionally re-added a CDN dependency.",
                origin
            );
        }
    }
}
