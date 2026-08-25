//! The hosted transport, exercised over a real socket.
//!
//! A local mock issuer signs tokens and serves a JWKS, so every rule is
//! verified end to end without an identity provider: the challenge, the
//! rejections, and above all the audience check — a token minted by the same
//! issuer for a *different* service must not work here (SC-006).
//!
//! `#[ignore]`d by default because it binds a port.

#![cfg(feature = "http")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use audit_mcp::authz::Authorizer;
use audit_mcp::config::{Config, OAuthConfig, TransportConfig, TransportKind};
use audit_mcp::http::auth::ResourceServer;
use audit_mcp::http::metadata::ProtectedResourceMetadata;
use audit_mcp::http::{HttpState, METADATA_PATH, router};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;

const ISSUER_KEY: &str = include_str!("../src/http/testdata/test-key.pem");
const ISSUER_JWKS: &str = include_str!("../src/http/testdata/test-jwks.json");
const RESOURCE: &str = "https://audit.example.test/mcp";

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn sign(claims: serde_json::Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key".to_string());
    let key = EncodingKey::from_rsa_pem(ISSUER_KEY.as_bytes()).expect("test key");
    jsonwebtoken::encode(&header, &claims, &key).expect("signs")
}

/// Serve the JWKS the way a real provider would, so the server fetches it over
/// HTTP rather than being handed keys directly.
async fn start_issuer() -> String {
    let app = axum::Router::new().route(
        "/.well-known/jwks.json",
        axum::routing::get(|| async { ISSUER_JWKS }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind issuer");
    let address = listener.local_addr().expect("issuer address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{address}")
}

async fn start_server(issuer: &str) -> SocketAddr {
    let oauth = OAuthConfig {
        issuer: issuer.to_string(),
        jwks_url: Some(format!("{issuer}/.well-known/jwks.json")),
        required_scope: Some("audit:scan".to_string()),
        authz_cache_ttl: Duration::from_secs(300),
    };
    let transport = TransportConfig {
        kind: TransportKind::Http,
        bind: "127.0.0.1:0".to_string(),
        resource_url: Some(RESOURCE.to_string()),
        oauth: Some(oauth.clone()),
        max_scans_per_caller: 2,
    };
    let config = Config {
        transport: transport.clone(),
        ..Default::default()
    };

    let state = Arc::new(HttpState::new(
        ResourceServer::new(oauth.clone(), RESOURCE.to_string()),
        Arc::new(Authorizer::new(oauth.authz_cache_ttl)),
        ProtectedResourceMetadata::from_config(&transport).expect("metadata"),
        format!("https://audit.example.test{METADATA_PATH}"),
        2,
        Arc::new(audit_mcp::observe::Metrics::new()),
    ));

    let app = router(&config, state).expect("router builds");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind server");
    let address = listener.local_addr().expect("server address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    address
}

async fn post_mcp(address: SocketAddr, token: Option<&str>) -> reqwest::Response {
    let mut request = reqwest::Client::new()
        .post(format!("http://{address}/mcp"))
        .header("Content-Type", "application/json")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_string());
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    request.send().await.expect("request completes")
}

#[tokio::test]
#[ignore]
async fn discovery_and_probes_answer_without_a_token() {
    let issuer = start_issuer().await;
    let address = start_server(&issuer).await;
    let client = reqwest::Client::new();

    // A client that cannot fetch metadata unauthenticated can never bootstrap.
    let metadata = client
        .get(format!("http://{address}{METADATA_PATH}"))
        .send()
        .await
        .expect("metadata request");
    assert_eq!(metadata.status(), 200);
    let body: serde_json::Value = metadata.json().await.expect("json");
    assert_eq!(body["resource"], RESOURCE);
    assert_eq!(body["authorization_servers"][0], issuer);

    let health = client
        .get(format!("http://{address}/healthz"))
        .send()
        .await
        .expect("healthz");
    assert_eq!(health.status(), 200);
}

#[tokio::test]
#[ignore]
async fn an_unauthenticated_request_is_challenged() {
    let issuer = start_issuer().await;
    let address = start_server(&issuer).await;

    let response = post_mcp(address, None).await;
    assert_eq!(response.status(), 401);

    let challenge = response
        .headers()
        .get("www-authenticate")
        .expect("a challenge names where to authenticate")
        .to_str()
        .expect("ascii");
    assert!(challenge.starts_with("Bearer "));
    assert!(challenge.contains(METADATA_PATH));
}

#[tokio::test]
#[ignore]
async fn a_token_for_another_resource_is_rejected() {
    // SC-006. The same issuer, a valid signature, the wrong audience — the
    // defect that lets any service sharing an IdP drive this one.
    let issuer = start_issuer().await;
    let address = start_server(&issuer).await;

    let token = sign(json!({
        "sub": "user-1",
        "iss": issuer,
        "aud": "https://some-other-service.example.test",
        "exp": now() + 300,
        "scope": "audit:scan",
    }));

    let response = post_mcp(address, Some(&token)).await;
    assert_eq!(
        response.status(),
        401,
        "a token minted for another service must not be accepted"
    );
}

#[tokio::test]
#[ignore]
async fn expired_malformed_and_foreign_tokens_are_all_rejected_alike() {
    let issuer = start_issuer().await;
    let address = start_server(&issuer).await;

    let expired = sign(json!({
        "sub": "user-1", "iss": issuer, "aud": RESOURCE,
        "exp": now() - 3600, "scope": "audit:scan",
    }));
    let foreign_issuer = sign(json!({
        "sub": "user-1", "iss": "https://attacker.example.test", "aud": RESOURCE,
        "exp": now() + 300, "scope": "audit:scan",
    }));

    for (label, token) in [
        ("garbage", "not-a-token".to_string()),
        ("expired", expired),
        ("foreign issuer", foreign_issuer),
        (
            "alg:none",
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.".to_string(),
        ),
    ] {
        let response = post_mcp(address, Some(&token)).await;
        assert_eq!(response.status(), 401, "{label} should be rejected");
        // The body must not say which check failed: that difference is a
        // probing oracle.
        let body = response.text().await.unwrap_or_default();
        assert!(
            !body.contains("expired") && !body.contains("audience") && !body.contains("issuer"),
            "{label} disclosed which check failed: {body}"
        );
    }
}

#[tokio::test]
#[ignore]
async fn a_valid_token_missing_the_required_scope_is_forbidden() {
    let issuer = start_issuer().await;
    let address = start_server(&issuer).await;

    let token = sign(json!({
        "sub": "user-1", "iss": issuer, "aud": RESOURCE,
        "exp": now() + 300, "scope": "something:else",
    }));

    // 403, not 401: we know who they are, they simply may not do this.
    assert_eq!(post_mcp(address, Some(&token)).await.status(), 403);
}

#[tokio::test]
#[ignore]
async fn a_valid_token_reaches_the_mcp_endpoint() {
    let issuer = start_issuer().await;
    let address = start_server(&issuer).await;

    let token = sign(json!({
        "sub": "user-1", "iss": issuer, "aud": RESOURCE,
        "exp": now() + 300, "scope": "audit:scan",
    }));

    let response = post_mcp(address, Some(&token)).await;
    // Whatever MCP makes of the payload, authentication let it through — which
    // is what this layer is responsible for.
    assert_ne!(response.status(), 401);
    assert_ne!(response.status(), 403);
}

#[tokio::test]
#[ignore]
async fn an_oversized_body_is_refused() {
    // MCP payloads are small; an unbounded body is a denial-of-service vector.
    let issuer = start_issuer().await;
    let address = start_server(&issuer).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/mcp"))
        .header("Content-Type", "application/json")
        .body("x".repeat(8 * 1024 * 1024))
        .send()
        .await
        .expect("request completes");

    assert!(
        response.status() == 413 || response.status() == 401,
        "an 8 MiB body should be refused, got {}",
        response.status()
    );
}

/// Pull the JSON payload out of a response, which may be SSE-framed.
fn payload(text: &str) -> serde_json::Value {
    let body = text
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap_or(text);
    serde_json::from_str(body).unwrap_or_else(|_| json!({ "raw": text }))
}

/// Open an MCP session: `initialize`, then `notifications/initialized`.
///
/// Skipping the handshake makes every later call fail with "expect initialize
/// request", which looks like a refusal and would let an authorization test
/// pass without testing anything.
async fn open_session(address: SocketAddr, token: &str) -> String {
    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://{address}/mcp"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .bearer_auth(token)
        .json(&json!({
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "audit-mcp-tests", "version": "0" }
            }
        }))
        .send()
        .await
        .expect("initialize");

    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .expect("the server issues a session id");
    let _ = response.text().await;

    client
        .post(format!("http://{address}/mcp"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Session-Id", &session)
        .bearer_auth(token)
        .json(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
        .send()
        .await
        .expect("initialized notification");

    session
}

/// Call `run_scan` through the HTTP endpoint on a real session, optionally
/// presenting a forge credential alongside the identity token.
async fn call_run_scan(
    address: SocketAddr,
    token: &str,
    forge_token: Option<&str>,
    target: &str,
) -> serde_json::Value {
    let session = open_session(address, token).await;

    let mut request = reqwest::Client::new()
        .post(format!("http://{address}/mcp"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Session-Id", session)
        .bearer_auth(token)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "run_scan",
                "arguments": { "target": target, "mode": "single", "scanner": "shellcheck" }
            }
        }));
    if let Some(forge_token) = forge_token {
        request = request.header(audit_mcp::http::FORGE_TOKEN_HEADER, forge_token);
    }

    let response = request.send().await.expect("request completes");
    let text = response.text().await.unwrap_or_default();
    let value = payload(&text);
    assert!(
        !text.contains("expect initialize"),
        "the handshake did not take, so this test proves nothing: {text}"
    );
    value
}

/// The whole point of the authorization layer: a caller cannot borrow the
/// server's reach.
#[tokio::test]
#[ignore]
async fn a_repository_scan_without_a_caller_credential_is_refused() {
    let issuer = start_issuer().await;
    let address = start_server(&issuer).await;
    let token = sign(json!({
        "sub": "user-1", "iss": issuer, "aud": RESOURCE,
        "exp": now() + 300, "scope": "audit:scan",
    }));

    // Authenticated, but presenting no credential of their own.
    let response = call_run_scan(address, &token, None, "owner/private-repo").await;
    let rendered = response.to_string();

    assert!(
        rendered.contains("X-Audit-Github-Token")
            || rendered.contains("your own GitHub credential"),
        "a repository scan must demand the caller's own credential: {rendered}"
    );
    // And it must not have gone anywhere near a clone.
    assert!(
        !rendered.contains("resolved_ref"),
        "the scan should not have run"
    );
}

#[tokio::test]
#[ignore]
async fn a_caller_credential_without_access_cannot_cause_a_scan() {
    // SC-010: even where the server's own credential would have worked, the
    // caller's is what decides.
    let issuer = start_issuer().await;
    let address = start_server(&issuer).await;
    let token = sign(json!({
        "sub": "user-1", "iss": issuer, "aud": RESOURCE,
        "exp": now() + 300, "scope": "audit:scan",
    }));

    if std::net::ToSocketAddrs::to_socket_addrs(&("api.github.com", 443)).is_err() {
        eprintln!("skipping: api.github.com is not resolvable");
        return;
    }

    // A syntactically valid token that GitHub will not accept.
    let response = call_run_scan(
        address,
        &token,
        Some("ghp_000000000000000000000000000000000000"),
        "octocat/Hello-World",
    )
    .await;
    let rendered = response.to_string();

    assert!(
        rendered.contains("does not grant read access"),
        "a credential without access must be refused: {rendered}"
    );
    // The refusal must not confirm whether the repository exists.
    assert!(!rendered.contains("not found"));
    assert!(!rendered.contains("does not exist"));
}

#[tokio::test]
#[ignore]
async fn a_local_path_needs_no_caller_credential() {
    // There is no repository to authorize, so the check does not apply.
    let issuer = start_issuer().await;
    let address = start_server(&issuer).await;
    let token = sign(json!({
        "sub": "user-1", "iss": issuer, "aud": RESOURCE,
        "exp": now() + 300, "scope": "audit:scan",
    }));

    let response = call_run_scan(address, &token, None, env!("CARGO_MANIFEST_DIR")).await;
    let rendered = response.to_string();
    assert!(
        !rendered.contains("X-Audit-Github-Token"),
        "a local path must not demand a forge credential: {rendered}"
    );
}

#[tokio::test]
#[ignore]
async fn two_callers_do_not_see_each_others_scans() {
    // FR-024. Each response must describe only its own request.
    let issuer = start_issuer().await;
    let address = start_server(&issuer).await;

    let one = sign(json!({
        "sub": "user-1", "iss": issuer, "aud": RESOURCE,
        "exp": now() + 300, "scope": "audit:scan",
    }));
    let two = sign(json!({
        "sub": "user-2", "iss": issuer, "aud": RESOURCE,
        "exp": now() + 300, "scope": "audit:scan",
    }));

    let fixture_one = format!("{}/tests/fixtures/shellcheck", env!("CARGO_MANIFEST_DIR"));
    let fixture_two = format!("{}/tests/fixtures/knip", env!("CARGO_MANIFEST_DIR"));

    let (first, second) = tokio::join!(
        call_run_scan(address, &one, None, &fixture_one),
        call_run_scan(address, &two, None, &fixture_two),
    );

    assert!(
        !first.to_string().contains("fixtures/knip"),
        "one caller's response leaked the other's target"
    );
    assert!(
        !second.to_string().contains("fixtures/shellcheck"),
        "one caller's response leaked the other's target"
    );
}

#[tokio::test]
#[ignore]
async fn metrics_are_scrapable_without_a_token() {
    // A scraper does not carry an MCP token, so requiring one would make the
    // endpoint useless.
    let issuer = start_issuer().await;
    let address = start_server(&issuer).await;

    let response = reqwest::Client::new()
        .get(format!("http://{address}/metrics"))
        .send()
        .await
        .expect("metrics request");
    assert_eq!(response.status(), 200);
    let body = response.text().await.expect("body");
    assert!(
        body.contains("audit_scans_total") || body.contains("audit_scans_in_flight"),
        "expected audit metrics: {body}"
    );
}

#[tokio::test]
#[ignore]
async fn metrics_never_carry_a_target_or_caller_in_a_label() {
    // SC-012. The endpoint is deliberately less protected than /mcp, so
    // anything in a label is effectively public — and each distinct value is a
    // time series that is never reclaimed.
    let issuer = start_issuer().await;
    let address = start_server(&issuer).await;
    let token = sign(json!({
        "sub": "user-with-a-distinctive-subject", "iss": issuer, "aud": RESOURCE,
        "exp": now() + 300, "scope": "audit:scan",
    }));

    let fixture = format!("{}/tests/fixtures/shellcheck", env!("CARGO_MANIFEST_DIR"));
    let _ = call_run_scan(address, &token, None, &fixture).await;

    let body = reqwest::Client::new()
        .get(format!("http://{address}/metrics"))
        .send()
        .await
        .expect("metrics request")
        .text()
        .await
        .expect("body");

    assert!(
        !body.contains("user-with-a-distinctive-subject"),
        "a caller subject reached a metric label"
    );
    assert!(
        !body.contains("fixtures/shellcheck"),
        "a path reached a label"
    );
    assert!(
        !body.contains(env!("CARGO_MANIFEST_DIR")),
        "a path reached a label"
    );
}

#[tokio::test]
#[ignore]
async fn a_session_belongs_to_the_caller_who_opened_it() {
    // Knowing a session id is not a credential.
    let issuer = start_issuer().await;
    let address = start_server(&issuer).await;

    let one = sign(json!({
        "sub": "user-1", "iss": issuer, "aud": RESOURCE,
        "exp": now() + 300, "scope": "audit:scan",
    }));
    let two = sign(json!({
        "sub": "user-2", "iss": issuer, "aud": RESOURCE,
        "exp": now() + 300, "scope": "audit:scan",
    }));

    let session = open_session(address, &one).await;

    let stolen = reqwest::Client::new()
        .post(format!("http://{address}/mcp"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Session-Id", &session)
        .bearer_auth(&two)
        .json(&json!({ "jsonrpc": "2.0", "id": 9, "method": "tools/list" }))
        .send()
        .await
        .expect("request completes");

    assert_eq!(
        stolen.status(),
        403,
        "a second identity must not continue the first one's session"
    );
}
