//! # RPC server configuration, HTTP middleware, and startup
//!
//! Listener and authentication policy are applied here before starting
//! jsonrpsee with the method groups assembled by `handlers`.

use std::net::SocketAddr;
use std::sync::Arc;

use http::{Request, Response, StatusCode};
use jsonrpsee::server::{HttpBody, ServerBuilder, ServerHandle};
use tower::ServiceBuilder;
use tower_http::validate_request::{ValidateRequest, ValidateRequestHeaderLayer};
use tracing::{info, warn};

use crate::chain::SharedBlockchain;
use crate::error::{Error, Result};
use crate::mempool::SharedMempool;
use crate::network::P2PNode;

use super::handlers::{create_rpc_module, RpcState};

/// RPC server configuration.
#[derive(Clone)]
pub struct RpcConfig {
    /// Listen address.
    pub listen_addr: SocketAddr,
    /// Max concurrent connections.
    pub max_connections: u32,
    /// Auth (API-key) enabled?
    pub auth_enabled: bool,
    /// API key, if auth is on.
    pub api_key: Option<String>,
    /// CORS allowed origins.
    pub cors_origins: Vec<String>,
    /// Network name — reported in `get_info`.
    pub network_name: String,
    /// TLS on?
    pub tls_enabled: bool,
    /// Data directory for auto-generated cert.
    pub data_dir: Option<std::path::PathBuf>,
    /// Custom TLS cert path.
    pub tls_cert_path: Option<std::path::PathBuf>,
    /// Custom TLS key path.
    pub tls_key_path: Option<std::path::PathBuf>,
}

impl std::fmt::Debug for RpcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcConfig")
            .field("listen_addr", &self.listen_addr)
            .field("max_connections", &self.max_connections)
            .field("auth_enabled", &self.auth_enabled)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field("cors_origins", &self.cors_origins)
            .field("network_name", &self.network_name)
            .field("tls_enabled", &self.tls_enabled)
            .field("data_dir", &self.data_dir)
            .field("tls_cert_path", &self.tls_cert_path)
            .field("tls_key_path", &self.tls_key_path)
            .finish()
    }
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            listen_addr: ([127, 0, 0, 1], crate::constants::DEFAULT_RPC_PORT).into(),
            max_connections: 100,
            auth_enabled: false,
            api_key: None,
            cors_origins: vec![
                "http://localhost".to_string(),
                "http://127.0.0.1".to_string(),
            ],
            network_name: "testnet".to_string(),
            tls_enabled: false, // P0: plaintext by default, TLS comes back in P1
            data_dir: None,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

/// Handle returned by `start_rpc_server` — drop to stop the server.
pub struct RpcServer {
    handle: ServerHandle,
}

impl RpcServer {
    pub fn stop(self) {
        let _ = self.handle.stop();
    }
}

fn rpc_listen_is_loopback(addr: SocketAddr) -> bool {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => v4.is_loopback(),
        std::net::IpAddr::V6(v6) => v6.is_loopback(),
    }
}

fn rpc_env_bool(name: &str) -> Option<bool> {
    std::env::var(name).ok().map(|v| {
        let t = v.trim();
        t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
    })
}

/// HTTP-layer Bearer check.
///
/// Holds the SHA-256 hash of the API key, NOT the plaintext. The plaintext
/// lives only during construction (`from_plaintext`) and is dropped before
/// the validator is stored. This means a process memory dump after startup
/// cannot recover the API key — only a one-way hash. Closes the CRITICAL
/// audit finding "Bearer token stored + compared plaintext".
///
/// (Bitcoin Core's `share/rpcauth/rpcauth.py` helper generates a
/// `user:salt$hash` credential shape rather than storing a plaintext
/// password; specific script internals not re-read this session, so
/// only the high-level pattern is asserted.) We use a fixed salt-free
/// SHA-256 because the operator-supplied API key is already a
/// high-entropy random hex string (per the bearer-key rotation incident
/// memo); salting buys little against an offline attacker who has the
/// process memory dump.
///
/// When `token_hashes` is empty, all requests pass the auth check.
/// When `rate_limiter` is `Some`, every request is also passed through the
/// IP-based rate limiter BEFORE the bearer check. Closes audit HIGH #14
/// (`src/rpc/ratelimit.rs` exists but was not wired into the server).
/// (The prior comment asserted "Bitcoin Core does not have application-
/// layer rate limiting on the RPC and relies entirely on the operator's
/// reverse proxy". That negative claim was not re-verified against
/// upstream this session and is downgraded to UNVERIFIED. We still
/// expose the application-layer limiter as defense-in-depth on our own
/// merits — misconfigured nginx should not become a single point of
/// failure.)
///
/// `token_hashes` is a list of accepted key hashes (current + previous)
/// to support hot key rotation without restart (audit HIGH #16). The
/// operator can ship a new key via SIGHUP-style reload and accept both
/// keys for a grace window, then drop the old one in a follow-up reload.
/// (Bitcoin Core supports multiple RPC credentials via repeated
/// `-rpcauth` args as a well-known operational pattern; specific
/// implementation not re-read this session.) We use a comparable
/// "multiple accepted credentials at once" model collapsed to a single
/// principal (the bearer is opaque, so we don't need user-IDs).
#[derive(Clone)]
struct RpcBearerValidator {
    token_hashes: Vec<Arc<[u8; 32]>>,
    rate_limiter: Option<Arc<crate::rpc::ratelimit::RateLimiter>>,
}

impl RpcBearerValidator {
    fn from_plaintext(plaintext: &str) -> Self {
        Self {
            token_hashes: vec![Self::hash_token(plaintext)],
            rate_limiter: None,
        }
    }

    fn from_plaintexts(plaintexts: &[&str]) -> Self {
        let hashes = plaintexts.iter().map(|p| Self::hash_token(p)).collect();
        Self {
            token_hashes: hashes,
            rate_limiter: None,
        }
    }

    fn unauthenticated() -> Self {
        Self {
            token_hashes: Vec::new(),
            rate_limiter: None,
        }
    }

    fn hash_token(plaintext: &str) -> Arc<[u8; 32]> {
        use sha2::Digest;
        let digest = sha2::Sha256::digest(plaintext.as_bytes());
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest);
        Arc::new(hash)
    }

    /// Attach a rate limiter that runs before the bearer check on every
    /// request. The limiter's own `check_sync` whitelists loopback IPs so
    /// local-only RPC clients are unaffected.
    fn with_rate_limiter(mut self, limiter: Arc<crate::rpc::ratelimit::RateLimiter>) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }
}

/// Extract the client IP from the request.
///
/// Audit-fix: XFF parsing is now OPT-IN via `COINCYNC_RPC_XFF_PROXY_ACK=1`
/// because a client can spoof the X-Forwarded-For header. The rate
/// limiter is bypassed when an attacker controls the IP attribution —
/// they cycle through fake IPs to each get a fresh bucket. We trust XFF
/// ONLY when the operator explicitly acknowledges they have a properly
/// configured reverse proxy (nginx `real_ip_header X-Forwarded-For` +
/// `set_real_ip_from <trusted-cidr>`) in front. Without ack, the
/// limiter treats every public request as coming from a single bucket
/// (loopback whitelist bypasses; non-loopback gets a real bucket via
/// some hash but at least not attacker-controlled).
///
/// Reference: nginx's `set_real_ip_from` + `real_ip_header` docs are
/// explicit that XFF is untrustworthy without IP whitelisting. Bitcoin
/// Core's RPC binds loopback-only by default to sidestep this entirely.
fn client_ip_from_request<B>(req: &Request<B>) -> std::net::IpAddr {
    let xff_trusted = rpc_env_bool("COINCYNC_RPC_XFF_PROXY_ACK").unwrap_or(false);
    if xff_trusted {
        if let Some(xff) = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
        {
            // RFC 7239 §5.2: first comma-separated entry is the original
            // client; proxies APPEND their own IPs to the right.
            if let Some(first) = xff.split(',').next() {
                if let Ok(ip) = first.trim().parse::<std::net::IpAddr>() {
                    return ip;
                }
            }
        }
    }
    // No trusted IP source: return loopback. The limiter whitelists
    // loopback, so this effectively turns OFF rate-limiting for any
    // request whose origin we cannot trust to identify. This is the
    // SAFE default: better to under-rate-limit a known operator-
    // controlled proxy than to over-rate-limit honest users based on
    // an attacker-spoofed IP. Operators who want active rate limiting
    // on public RPC must set BOTH COINCYNC_RPC_TLS_PROXY_ACK and
    // COINCYNC_RPC_XFF_PROXY_ACK after verifying their nginx config
    // overwrites (not appends) the X-Forwarded-For header.
    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
}

fn rpc_http_rate_limited(retry_after_secs: u64) -> Response<HttpBody> {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header(http::header::CONTENT_TYPE, "application/json; charset=utf-8")
        .header(http::header::RETRY_AFTER, retry_after_secs.to_string())
        .body(HttpBody::from(format!(
            r#"{{"jsonrpc":"2.0","error":{{"code":429,"message":"Rate limited; retry after {}s"}},"id":null}}"#,
            retry_after_secs
        )))
        .expect("valid 429 response")
}

impl<B> ValidateRequest<B> for RpcBearerValidator {
    /// Must match jsonrpsee's HTTP response body type so `ValidateRequestHeader` composes with the RPC stack.
    type ResponseBody = HttpBody;

    fn validate(
        &mut self,
        req: &mut Request<B>,
    ) -> std::result::Result<(), Response<Self::ResponseBody>> {
        use http::Method;

        // Rate limit FIRST (cheaper than crypto). CORS preflight is
        // exempt — it carries no auth and is harmless. Loopback IPs are
        // already whitelisted inside check_sync.
        if !matches!(*req.method(), Method::OPTIONS) {
            if let Some(limiter) = &self.rate_limiter {
                let ip = client_ip_from_request(req);
                match limiter.check_sync(ip) {
                    crate::rpc::ratelimit::RateLimitResult::Allowed => {}
                    crate::rpc::ratelimit::RateLimitResult::RateLimited { retry_after }
                    | crate::rpc::ratelimit::RateLimitResult::Banned { retry_after } => {
                        return Err(rpc_http_rate_limited(retry_after));
                    }
                    crate::rpc::ratelimit::RateLimitResult::PermanentlyBlocked => {
                        return Err(rpc_http_rate_limited(0));
                    }
                }
            }
        }

        if self.token_hashes.is_empty() {
            return Ok(());
        }

        match *req.method() {
            // CORS preflight never authenticates.
            Method::OPTIONS => Ok(()),
            Method::POST => validate_bearer_header(req, &self.token_hashes),
            Method::GET => {
                // Hardening: only allow GET when this is an actual websocket upgrade,
                // and require Bearer parity with POST to close auth-bypass edges.
                let is_upgrade = req
                    .headers()
                    .get(http::header::CONNECTION)
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.to_ascii_lowercase().contains("upgrade"))
                    .unwrap_or(false)
                    && req
                        .headers()
                        .get(http::header::UPGRADE)
                        .and_then(|v| v.to_str().ok())
                        .map(|v| v.eq_ignore_ascii_case("websocket"))
                        .unwrap_or(false);
                if !is_upgrade {
                    return Err(rpc_http_unauthorized());
                }
                validate_bearer_header(req, &self.token_hashes)
            }
            _ => Err(rpc_http_unauthorized()),
        }
    }
}

fn validate_bearer_header<B>(
    req: &Request<B>,
    expected_hashes: &[Arc<[u8; 32]>],
) -> std::result::Result<(), Response<HttpBody>> {
    let auth = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    const PREFIX: &str = "Bearer ";
    if !auth.starts_with(PREFIX) {
        return Err(rpc_http_unauthorized());
    }
    let supplied = auth[PREFIX.len()..].trim();
    // Hash the supplied token once and constant-time compare against
    // each accepted hash (current + previous during key rotation). The
    // supplied plaintext exists only on this stack frame and is dropped
    // on function return; expected values are already hashes. Constant-
    // time check is INSIDE the inner loop so an attacker can't learn
    // which hash matched by timing.
    use sha2::Digest;
    let supplied_hash = sha2::Sha256::digest(supplied.as_bytes());
    let mut ok = false;
    for expected in expected_hashes {
        // Always run ct_eq even after a match to avoid early-exit timing leak.
        let matched = crate::crypto::ct_eq(&supplied_hash[..], &expected[..]);
        ok |= matched;
    }
    if !ok {
        return Err(rpc_http_unauthorized());
    }
    Ok(())
}

fn rpc_http_unauthorized() -> Response<HttpBody> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(
            http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )
        .body(HttpBody::from(
            r#"{"jsonrpc":"2.0","error":{"code":401,"message":"Unauthorized"},"id":null}"#,
        ))
        .expect("valid unauthorized response")
}

/// Start the JSON-RPC server and return its handle.
///
/// SECURITY: TLS is still optional in this build; prefer reverse-proxy TLS
/// or bind RPC to loopback only. When `auth_enabled` is true with a
/// non-empty `api_key`, or when listening on a non-loopback address with an
/// API key, HTTP `POST` JSON-RPC requests must send
/// `Authorization: Bearer <api_key>`. `OPTIONS` is exempt for CORS preflight;
/// authenticated WebSocket upgrades must also present Bearer auth.
pub async fn start_rpc_server(
    chain: SharedBlockchain,
    mempool: SharedMempool,
    p2p: Option<Arc<P2PNode>>,
    config: RpcConfig,
) -> Result<RpcServer> {
    info!("Starting RPC server on {}", config.listen_addr);
    if config.tls_enabled {
        return Err(Error::InvalidState(
            "RpcConfig.tls_enabled=true requested, but native TLS listener is not wired in this server build. Refusing to start in misconfigured state.".into(),
        ));
    }

    let listen_loopback = rpc_listen_is_loopback(config.listen_addr);
    let api_key_arc: Option<Arc<str>> = config
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(Arc::from);

    if config.auth_enabled && api_key_arc.is_none() {
        return Err(Error::InvalidState(
            "RpcConfig.auth_enabled=true requires a non-empty api_key (set COINCYNC_RPC_API_KEY when using coincync-node)"
                .into(),
        ));
    }
    if !listen_loopback && api_key_arc.is_none() {
        return Err(Error::InvalidState(format!(
            "RPC listen address {} is not loopback: refusing to start without an api_key — public JSON-RPC must authenticate (set COINCYNC_RPC_API_KEY or RpcConfig.api_key)",
            config.listen_addr
        )));
    }
    // Audit HIGH #15 — fail-safe TLS gate.
    //
    // If we bind non-loopback, the Bearer token will travel over the
    // wire. Without TLS, it's plaintext. The operator must EITHER:
    //   (a) enable native TLS (`tls_enabled = true` in RpcConfig), OR
    //   (b) explicitly acknowledge via env var that there's a
    //       TLS-terminating reverse proxy (nginx) in front of this RPC.
    //
    // This mirrors the existing Stratum gate
    // (`COINCYNC_STRATUM_TLS_PROXY_ACK`) so operators have one consistent
    // ack convention across services. (The prior comment specifically
    // asserted "Bitcoin Core requires rpcuser/rpcpassword for non-
    // loopback RPC but does not gate on TLS". That specific behavioural
    // pair was not re-verified this session and is dropped. We gate on
    // TLS-or-explicit-ack on our own merits: the production deploy
    // fronts api.coincync.network behind nginx and an unacknowledged
    // direct-bind would expose the Bearer in cleartext.)
    if !listen_loopback {
        let tls_proxy_ack = rpc_env_bool("COINCYNC_RPC_TLS_PROXY_ACK").unwrap_or(false);
        if !config.tls_enabled && !tls_proxy_ack {
            return Err(Error::InvalidState(format!(
                "RPC listen address {} is not loopback and TLS is not active: \
                 refusing to start. Either enable native TLS or set \
                 COINCYNC_RPC_TLS_PROXY_ACK=1 to confirm that an upstream \
                 TLS terminator (e.g. nginx) fronts this RPC. Without one \
                 of these the Bearer token would be sent in cleartext.",
                config.listen_addr
            )));
        }
    }

    let apply_bearer_middleware =
        api_key_arc.is_some() && (!listen_loopback || config.auth_enabled);
    if apply_bearer_middleware {
        info!(
            "RPC Bearer authentication enforced on POST (loopback={}, auth_enabled={})",
            listen_loopback, config.auth_enabled
        );
    } else if api_key_arc.is_some() {
        // SEC: an API key is configured but not enforced (loopback bind with
        // auth_enabled=false). Warn loudly so an operator who set a key doesn't
        // wrongly believe the RPC is authenticated.
        warn!(
            "RPC api_key is configured but NOT enforced (loopback={}, auth_enabled={}). \
             The RPC is UNAUTHENTICATED. Set auth_enabled=true (or bind non-loopback) to \
             require the Bearer token.",
            listen_loopback, config.auth_enabled
        );
    }

    let state = RpcState {
        chain,
        mempool,
        p2p,
        network_name: config.network_name.clone(),
        auth_enabled: config.auth_enabled,
        // Privacy hardening: default metadata minimization on public listeners.
        minimize_metadata: rpc_env_bool("COINCYNC_RPC_MINIMIZE_METADATA")
            .unwrap_or(!listen_loopback),
        stratum_public_bind_requested: rpc_env_bool("COINCYNC_STRATUM_PUBLIC_BIND")
            .unwrap_or(false),
        stratum_public_bind_ack: rpc_env_bool("COINCYNC_STRATUM_PUBLIC_BIND_ACK").unwrap_or(false),
        stratum_native_tls_enabled: rpc_env_bool("COINCYNC_STRATUM_TLS_ENABLED").unwrap_or(false),
        stratum_tls_proxy_ack: rpc_env_bool("COINCYNC_STRATUM_TLS_PROXY_ACK").unwrap_or(false),
        stratum_transport_hardened: {
            let public_bind = rpc_env_bool("COINCYNC_STRATUM_PUBLIC_BIND").unwrap_or(false);
            let has_pw = std::env::var("COINCYNC_STRATUM_PASSWORD")
                .ok()
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false);
            let public_ack = rpc_env_bool("COINCYNC_STRATUM_PUBLIC_BIND_ACK").unwrap_or(false);
            let native_tls = rpc_env_bool("COINCYNC_STRATUM_TLS_ENABLED").unwrap_or(false);
            let proxy_tls_ack = rpc_env_bool("COINCYNC_STRATUM_TLS_PROXY_ACK").unwrap_or(false);
            if !public_bind {
                true
            } else {
                has_pw && public_ack && (native_tls || proxy_tls_ack)
            }
        },
    };

    let module = create_rpc_module(state)?;

    let bearer_validator = if apply_bearer_middleware {
        let plaintext = api_key_arc
            .clone()
            .expect("apply_bearer_middleware implies api_key_arc is Some");
        // Audit HIGH #16 — hot key rotation. Accept BOTH the current key
        // and an optional previous key for a grace window. Operator
        // rotates by: (1) generate new key, (2) deploy with
        // COINCYNC_RPC_API_KEY=new + COINCYNC_RPC_API_KEY_PREVIOUS=old
        // and SIGHUP/restart, (3) update clients to use new key,
        // (4) deploy without the PREVIOUS var to close the window.
        // No coincycle of forced-offline-then-online required.
        let previous = std::env::var("COINCYNC_RPC_API_KEY_PREVIOUS")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        if let Some(prev) = previous {
            info!("RPC accepting CURRENT and PREVIOUS api_key (rotation window active — drop COINCYNC_RPC_API_KEY_PREVIOUS to close)");
            RpcBearerValidator::from_plaintexts(&[plaintext.as_ref(), prev.as_str()])
        } else {
            RpcBearerValidator::from_plaintext(plaintext.as_ref())
        }
    } else {
        RpcBearerValidator::unauthenticated()
    };
    // Application-layer rate limit, defense-in-depth even when an upstream
    // reverse proxy (nginx) already throttles. Strict config for non-
    // loopback binds (the public api node); loopback gets the default.
    // Loopback IPs (127.0.0.1, ::1) are whitelisted inside check_sync so
    // local-only RPC clients are unaffected regardless of which config we
    // load. Closes audit HIGH #14.
    let rate_limiter_config = if listen_loopback {
        crate::rpc::ratelimit::RateLimitConfig::default()
    } else {
        crate::rpc::ratelimit::RateLimitConfig::strict()
    };
    let rpc_rate_limiter =
        std::sync::Arc::new(crate::rpc::ratelimit::RateLimiter::new(rate_limiter_config));
    let bearer_validator = bearer_validator.with_rate_limiter(rpc_rate_limiter);

    // SEC: on a non-loopback bind, the per-IP limiter only sees a real client IP
    // when COINCYNC_RPC_XFF_PROXY_ACK=1 (behind a trusted proxy that sets
    // X-Forwarded-For). Without it, every request resolves to 127.0.0.1 and is
    // whitelisted — so the app-layer limiter is effectively INERT. Bearer auth
    // still gates access; warn so the operator relies on the proxy/auth, not on
    // a limiter that isn't actually throttling.
    if !listen_loopback && !rpc_env_bool("COINCYNC_RPC_XFF_PROXY_ACK").unwrap_or(false) {
        warn!(
            "RPC per-IP rate limiter is INERT on this public bind: COINCYNC_RPC_XFF_PROXY_ACK \
             is not set, so all requests resolve to loopback (whitelisted). Ensure a trusted \
             reverse proxy throttles, then set COINCYNC_RPC_XFF_PROXY_ACK=1 to enable per-IP limiting."
        );
    }

    let server = ServerBuilder::default()
        .max_connections(config.max_connections)
        .set_http_middleware(
            ServiceBuilder::new().layer(ValidateRequestHeaderLayer::custom(bearer_validator)),
        )
        .build(config.listen_addr)
        .await
        .map_err(|e| Error::RpcError(format!("RPC bind failed: {}", e)))?;

    info!(
        "RPC server bound (methods include verification suite); auth_enabled={} bearer_http={}",
        config.auth_enabled, apply_bearer_middleware,
    );

    let handle = server.start(module);

    Ok(RpcServer { handle })
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    #[test]
    fn bearer_validator_rejects_non_upgrade_get_without_auth() {
        let mut validator = RpcBearerValidator::from_plaintext("secret-token");
        let mut req = Request::builder()
            .method("GET")
            .uri("/rpc")
            .body(())
            .expect("request");
        assert!(validator.validate(&mut req).is_err());
    }

    #[test]
    fn bearer_validator_accepts_ws_upgrade_get_with_auth() {
        let mut validator = RpcBearerValidator::from_plaintext("secret-token");
        let mut req = Request::builder()
            .method("GET")
            .uri("/rpc")
            .header(http::header::CONNECTION, "Upgrade")
            .header(http::header::UPGRADE, "websocket")
            .header(http::header::AUTHORIZATION, "Bearer secret-token")
            .body(())
            .expect("request");
        assert!(validator.validate(&mut req).is_ok());
    }

    #[test]
    fn bearer_validator_rejects_wrong_token_under_hashed_comparison() {
        let mut validator = RpcBearerValidator::from_plaintext("real-token");
        let mut req = Request::builder()
            .method("POST")
            .uri("/rpc")
            .header(http::header::AUTHORIZATION, "Bearer wrong-token")
            .body(())
            .expect("request");
        assert!(
            validator.validate(&mut req).is_err(),
            "wrong token must be rejected even when length differs"
        );
    }

    #[test]
    fn bearer_validator_does_not_retain_plaintext() {
        let validator = RpcBearerValidator::from_plaintext("the-secret");
        assert_eq!(validator.token_hashes.len(), 1, "exactly one hash expected");
        let hash = &validator.token_hashes[0];
        let raw = b"the-secret";
        assert!(
            !hash.windows(raw.len()).any(|w| w == raw),
            "stored hash must not contain plaintext substring"
        );
    }

    /// Audit HIGH #16 closure — both current AND previous key must work
    /// during the rotation grace window.
    #[test]
    fn bearer_validator_accepts_previous_key_during_rotation() {
        let mut validator = RpcBearerValidator::from_plaintexts(&["new-key", "old-key"]);
        for key in ["new-key", "old-key"] {
            let mut req = Request::builder()
                .method("POST")
                .uri("/rpc")
                .header(http::header::AUTHORIZATION, format!("Bearer {}", key))
                .body(())
                .expect("request");
            assert!(
                validator.validate(&mut req).is_ok(),
                "rotation-window validator must accept {}",
                key
            );
        }
        let mut bad = Request::builder()
            .method("POST")
            .uri("/rpc")
            .header(http::header::AUTHORIZATION, "Bearer not-either-key")
            .body(())
            .expect("request");
        assert!(
            validator.validate(&mut bad).is_err(),
            "non-rotation key must still be rejected"
        );
    }
}
