//! Fuzz target for JSON-RPC body parsing — DEEP shim that drives the
//! full request pipeline through an `axum::Router` via `tower::ServiceExt::oneshot`.
//!
//! Coverage:
//!   - axum body extractor (Content-Length, body limits)
//!   - `Json<Value>` extractor (serde_json depth + width)
//!   - Typed `JsonRpcCall` envelope parsing (jsonrpc field, id, method,
//!      params)
//!   - axum's reject/response path on bad bodies
//!
//! The router uses a no-op handler — the goal is to find panics in the
//! pre-handler PARSING + EXTRACTION pipeline (which is universal across
//! every RPC method). Per-method handler logic is per-method fuzz scope.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use axum::body::Body;
    use axum::extract::Json;
    use axum::http::{Request, StatusCode};
    use axum::routing::post;
    use axum::Router;
    use tower::ServiceExt;

    // ── 1. The cheapest path: raw serde_json (caught by the inner
    //       Json<> extractor before any handler runs) ──
    let _ = serde_json::from_slice::<serde_json::Value>(data);

    // ── 2. Typed JSON-RPC envelope ──
    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    struct JsonRpcCall {
        jsonrpc: String,
        id: serde_json::Value,
        method: String,
        #[serde(default)]
        params: serde_json::Value,
    }
    let _ = serde_json::from_slice::<JsonRpcCall>(data);

    // ── 3. Full axum router + ServiceExt::oneshot driving the
    //       request through the actual extractor chain ──
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return,
    };

    rt.block_on(async move {
        // Handler accepts Json<Value> (matches every JSON-RPC entrypoint).
        // Returning StatusCode::OK on parse-success is fine — we only
        // care about whether the parse pipeline panics.
        async fn handler(_body: Json<serde_json::Value>) -> StatusCode {
            StatusCode::OK
        }

        let app: Router = Router::new().route("/", post(handler));

        // Build a synthetic request body from the fuzz bytes.
        let req = Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", "application/json")
            .body(Body::from(data.to_vec()))
            .expect("Request::builder shouldn't fail for valid components");

        // Drive the request through. Any panic in body extraction,
        // Json<> extractor, or downstream handlers surfaces here.
        let _ = app.oneshot(req).await;
    });
});
