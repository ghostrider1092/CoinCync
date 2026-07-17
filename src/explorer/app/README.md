# Explorer application scripts

These files are classic scripts because the assembled explorer document still
exposes functions to inline event handlers. Their numeric prefixes are the
execution order declared once in `../app.scripts.html`. Cargo generates
`rpc::explorer::EXPLORER_APP_ASSETS` from that same manifest.

The split is responsibility-based, but the existing shared global scope is a
compatibility contract. Moving to ES modules requires replacing the inline
handlers and is intentionally outside this behavior-preserving refactor.
